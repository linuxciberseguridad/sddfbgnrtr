using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Agent.Utils
{
    /// <summary>
    /// Utilidades avanzadas para manejo de hilos concurrentes
    /// Previene deadlocks, gestiona recursos y monitorea rendimiento
    /// </summary>
    public static class ThreadHelper
    {
        private static readonly LogManager _logManager = LogManager.Instance;
        private static readonly ConcurrentDictionary<string, ThreadPoolInfo> _threadPoolInfo = new();
        private static readonly ConcurrentDictionary<string, TaskTracker> _runningTasks = new();
        private static readonly ConcurrentDictionary<string, DeadlockInfo> _deadlockHistory = new();
        private static readonly ConcurrentQueue<PerformanceMetric> _performanceMetrics = new();
        private static readonly object _lockObject = new();
        private static Timer _monitoringTimer;
        private static bool _isMonitoring = false;
        private const int MAX_PERFORMANCE_METRICS = 10000;
        private const int MONITORING_INTERVAL_MS = 5000;
        
        /// <summary>
        /// Configura el ThreadPool para alto rendimiento
        /// </summary>
        public static void ConfigureThreadPoolForHighPerformance()
        {
            try
            {
                // Obtener número de procesadores
                int processorCount = Environment.ProcessorCount;
                
                // Configurar ThreadPool mínimo
                ThreadPool.SetMinThreads(processorCount * 2, processorCount * 2);
                
                // Configurar ThreadPool máximo (ajustado para carga pesada)
                ThreadPool.SetMaxThreads(processorCount * 100, processorCount * 100);
                
                // Configurar opciones del ThreadPool
                ConfigureThreadPoolOptions();
                
                _logManager.LogInfo($"ThreadPool configurado: {processorCount} procesadores, MinThreads: {processorCount * 2}, MaxThreads: {processorCount * 100}", "ThreadHelper");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error configurando ThreadPool: {ex}", "ThreadHelper");
            }
        }
        
        /// <summary>
        /// Ejecuta tareas en paralelo con límite de concurrencia
        /// </summary>
        public static async Task<List<TResult>> ExecuteWithConcurrencyLimit<T, TResult>(
            IEnumerable<T> items,
            Func<T, Task<TResult>> processFunction,
            int maxConcurrency,
            CancellationToken cancellationToken = default,
            Action<T, Exception> errorHandler = null)
        {
            var results = new ConcurrentBag<TResult>();
            var exceptions = new ConcurrentBag<Exception>();
            
            using (var semaphore = new SemaphoreSlim(maxConcurrency))
            {
                var tasks = new List<Task>();
                
                foreach (var item in items)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;
                    
                    await semaphore.WaitAsync(cancellationToken);
                    
                    var task = Task.Run(async () =>
                    {
                        try
                        {
                            var result = await processFunction(item);
                            results.Add(result);
                        }
                        catch (Exception ex)
                        {
                            exceptions.Add(ex);
                            errorHandler?.Invoke(item, ex);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, cancellationToken);
                    
                    tasks.Add(task);
                }
                
                await Task.WhenAll(tasks);
            }
            
            if (exceptions.Count > 0)
            {
                throw new AggregateException("Errores durante ejecución paralela", exceptions);
            }
            
            return results.ToList();
        }
        
        /// <summary>
        /// Ejecuta tareas con timeout
        /// </summary>
        public static async Task<TResult> ExecuteWithTimeout<TResult>(
            Func<Task<TResult>> taskFunction,
            TimeSpan timeout,
            CancellationToken cancellationToken = default,
            TResult defaultValue = default)
        {
            try
            {
                using (var timeoutCancellationTokenSource = new CancellationTokenSource(timeout))
                using (var linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, timeoutCancellationTokenSource.Token))
                {
                    var task = taskFunction();
                    
                    var completedTask = await Task.WhenAny(
                        task,
                        Task.Delay(timeout, linkedCancellationTokenSource.Token)
                    );
                    
                    if (completedTask == task)
                    {
                        return await task;
                    }
                    else
                    {
                        throw new TimeoutException($"La operación excedió el tiempo límite de {timeout.TotalSeconds} segundos");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logManager.LogWarning("Operación cancelada por timeout", "ThreadHelper");
                return defaultValue;
            }
            catch (TimeoutException)
            {
                _logManager.LogWarning($"Timeout después de {timeout.TotalSeconds} segundos", "ThreadHelper");
                return defaultValue;
            }
        }
        
        /// <summary>
        /// Rastrea una tarea para monitoreo
        /// </summary>
        public static TaskTracker TrackTask(string taskId, string description, Task task)
        {
            var tracker = new TaskTracker
            {
                TaskId = taskId,
                Description = description,
                StartTime = DateTime.UtcNow,
                Task = task,
                ThreadId = Thread.CurrentThread.ManagedThreadId,
                Status = TaskStatus.Running
            };
            
            _runningTasks[taskId] = tracker;
            
            // Configurar continuación para actualizar estado
            task.ContinueWith(t =>
            {
                if (_runningTasks.TryGetValue(taskId, out var existingTracker))
                {
                    existingTracker.EndTime = DateTime.UtcNow;
                    existingTracker.Duration = existingTracker.EndTime - existingTracker.StartTime;
                    existingTracker.Status = t.Status;
                    
                    if (t.IsFaulted)
                    {
                        existingTracker.Exception = t.Exception;
                        existingTracker.ErrorMessage = t.Exception?.Message;
                    }
                    
                    // Registrar métrica de rendimiento
                    RecordPerformanceMetric(existingTracker);
                }
            }, TaskContinuationOptions.ExecuteSynchronously);
            
            return tracker;
        }
        
        /// <summary>
        /// Ejecuta acción con retry exponencial
        /// </summary>
        public static async Task<TResult> ExecuteWithRetry<TResult>(
            Func<Task<TResult>> action,
            int maxRetries = 3,
            TimeSpan initialDelay = default,
            Func<Exception, bool> shouldRetry = null,
            Action<int, Exception> onRetry = null)
        {
            if (initialDelay == default)
                initialDelay = TimeSpan.FromSeconds(1);
            
            var retryCount = 0;
            var exceptions = new List<Exception>();
            
            while (true)
            {
                try
                {
                    return await action();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                    retryCount++;
                    
                    // Verificar si debemos reintentar
                    bool canRetry = retryCount <= maxRetries;
                    
                    if (shouldRetry != null)
                    {
                        canRetry = canRetry && shouldRetry(ex);
                    }
                    
                    if (!canRetry)
                    {
                        throw new AggregateException($"Falló después de {retryCount} intentos", exceptions);
                    }
                    
                    onRetry?.Invoke(retryCount, ex);
                    
                    // Retraso exponencial
                    var delay = TimeSpan.FromTicks(initialDelay.Ticks * (long)Math.Pow(2, retryCount - 1));
                    await Task.Delay(delay);
                }
            }
        }
        
        /// <summary>
        /// Previene deadlocks en operaciones sincrónicas
        /// </summary>
        public static TResult ExecuteWithDeadlockPrevention<TResult>(
            Func<TResult> action,
            TimeSpan timeout,
            string operationName = "")
        {
            var result = default(TResult);
            var completed = false;
            var deadlockDetected = false;
            
            // Ejecutar en un hilo separado
            var thread = new Thread(() =>
            {
                try
                {
                    result = action();
                    completed = true;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en operación {operationName}: {ex}", "ThreadHelper");
                }
            })
            {
                IsBackground = true,
                Name = $"DeadlockPrevention-{operationName}-{Guid.NewGuid():N}"
            };
            
            thread.Start();
            
            // Esperar con timeout
            if (!thread.Join(timeout))
            {
                deadlockDetected = true;
                
                // Intentar abortar el hilo (último recurso)
                try
                {
                    thread.Interrupt();
                    _logManager.LogWarning($"Posible deadlock detectado en {operationName}, hilo interrumpido", "ThreadHelper");
                    
                    // Registrar en historial de deadlocks
                    RecordDeadlock(operationName, timeout);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al interrumpir hilo: {ex}", "ThreadHelper");
                }
            }
            
            if (deadlockDetected)
            {
                throw new TimeoutException($"Posible deadlock detectado en operación '{operationName}' después de {timeout.TotalSeconds} segundos");
            }
            
            if (!completed)
            {
                throw new InvalidOperationException($"Operación '{operationName}' no se completó correctamente");
            }
            
            return result;
        }
        
        /// <summary>
        /// Gestiona recursos compartidos con bloqueo optimizado
        /// </summary>
        public static async Task<TResult> ExecuteWithResourceLock<TResult>(
            string resourceId,
            Func<Task<TResult>> action,
            TimeSpan lockTimeout,
            CancellationToken cancellationToken = default)
        {
            var lockKey = $"ResourceLock-{resourceId}";
            var lockAcquired = false;
            
            try
            {
                // Intentar adquirir bloqueo con timeout
                lockAcquired = await TryAcquireLockAsync(lockKey, lockTimeout, cancellationToken);
                
                if (!lockAcquired)
                {
                    throw new TimeoutException($"No se pudo adquirir bloqueo para recurso '{resourceId}' después de {lockTimeout.TotalSeconds} segundos");
                }
                
                // Ejecutar acción
                return await action();
            }
            finally
            {
                if (lockAcquired)
                {
                    ReleaseLock(lockKey);
                }
            }
        }
        
        /// <summary>
        /// Inicia monitoreo de hilos y tareas
        /// </summary>
        public static void StartMonitoring()
        {
            if (_isMonitoring)
                return;
            
            lock (_lockObject)
            {
                if (_isMonitoring)
                    return;
                
                _monitoringTimer = new Timer(MonitorThreadsCallback, null, 
                    TimeSpan.Zero, TimeSpan.FromMilliseconds(MONITORING_INTERVAL_MS));
                
                _isMonitoring = true;
                _logManager.LogInfo("Monitoreo de hilos iniciado", "ThreadHelper");
            }
        }
        
        /// <summary>
        /// Detiene el monitoreo de hilos
        /// </summary>
        public static void StopMonitoring()
        {
            if (!_isMonitoring)
                return;
            
            lock (_lockObject)
            {
                if (!_isMonitoring)
                    return;
                
                _monitoringTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _monitoringTimer?.Dispose();
                _monitoringTimer = null;
                
                _isMonitoring = false;
                _logManager.LogInfo("Monitoreo de hilos detenido", "ThreadHelper");
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del ThreadPool
        /// </summary>
        public static ThreadPoolStats GetThreadPoolStats()
        {
            ThreadPool.GetAvailableThreads(out int workerThreads, out int completionPortThreads);
            ThreadPool.GetMinThreads(out int minWorkerThreads, out int minCompletionPortThreads);
            ThreadPool.GetMaxThreads(out int maxWorkerThreads, out int maxCompletionPortThreads);
            
            return new ThreadPoolStats
            {
                Timestamp = DateTime.UtcNow,
                AvailableWorkerThreads = workerThreads,
                AvailableCompletionPortThreads = completionPortThreads,
                MinWorkerThreads = minWorkerThreads,
                MinCompletionPortThreads = minCompletionPortThreads,
                MaxWorkerThreads = maxWorkerThreads,
                MaxCompletionPortThreads = maxCompletionPortThreads,
                ProcessorCount = Environment.ProcessorCount,
                RunningTasks = _runningTasks.Count,
                LongRunningTasks = _runningTasks.Values.Count(t => 
                    t.Duration.HasValue && t.Duration.Value.TotalSeconds > 10)
            };
        }
        
        /// <summary>
        /// Obtiene información de tareas en ejecución
        /// </summary>
        public static List<TaskTracker> GetRunningTasks()
        {
            return _runningTasks.Values
                .Where(t => t.Status == TaskStatus.Running || 
                           t.Status == TaskStatus.WaitingForActivation ||
                           t.Status == TaskStatus.WaitingToRun ||
                           t.Status == TaskStatus.WaitingForChildrenToComplete)
                .ToList();
        }
        
        /// <summary>
        /// Obtiene tareas bloqueadas (potenciales deadlocks)
        /// </summary>
        public static List<BlockedTaskInfo> GetBlockedTasks(TimeSpan threshold)
        {
            var blockedTasks = new List<BlockedTaskInfo>();
            var now = DateTime.UtcNow;
            
            foreach (var tracker in _runningTasks.Values)
            {
                if (tracker.Status == TaskStatus.Running)
                {
                    var duration = now - tracker.StartTime;
                    if (duration > threshold)
                    {
                        blockedTasks.Add(new BlockedTaskInfo
                        {
                            TaskId = tracker.TaskId,
                            Description = tracker.Description,
                            StartTime = tracker.StartTime,
                            Duration = duration,
                            ThreadId = tracker.ThreadId,
                            StackTrace = GetTaskStackTrace(tracker.Task)
                        });
                    }
                }
            }
            
            return blockedTasks;
        }
        
        /// <summary>
        /// Limpia tareas completadas
        /// </summary>
        public static void CleanupCompletedTasks()
        {
            var completedTaskIds = _runningTasks
                .Where(kv => kv.Value.Status == TaskStatus.RanToCompletion ||
                            kv.Value.Status == TaskStatus.Faulted ||
                            kv.Value.Status == TaskStatus.Canceled)
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var taskId in completedTaskIds)
            {
                _runningTasks.TryRemove(taskId, out _);
            }
            
            if (completedTaskIds.Count > 0)
            {
                _logManager.LogDebug($"Limpiadas {completedTaskIds.Count} tareas completadas", "ThreadHelper");
            }
        }
        
        /// <summary>
        /// Optimiza el ThreadPool basado en métricas
        /// </summary>
        public static void OptimizeThreadPool()
        {
            try
            {
                var stats = GetThreadPoolStats();
                
                // Calcular nuevas configuraciones basadas en carga
                var targetMinThreads = Math.Max(
                    Environment.ProcessorCount * 2,
                    (int)(_runningTasks.Count * 0.1));
                
                var targetMaxThreads = Math.Min(
                    Environment.ProcessorCount * 200,
                    targetMinThreads * 10);
                
                // Aplicar nuevas configuraciones si son diferentes
                if (targetMinThreads != stats.MinWorkerThreads ||
                    targetMaxThreads != stats.MaxWorkerThreads)
                {
                    ThreadPool.SetMinThreads(targetMinThreads, targetMinThreads);
                    ThreadPool.SetMaxThreads(targetMaxThreads, targetMaxThreads);
                    
                    _logManager.LogInfo($"ThreadPool optimizado: MinThreads={targetMinThreads}, MaxThreads={targetMaxThreads}", "ThreadHelper");
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error optimizando ThreadPool: {ex}", "ThreadHelper");
            }
        }
        
        #region Métodos privados
        
        private static void ConfigureThreadPoolOptions()
        {
            // Configurar opciones adicionales del ThreadPool
            try
            {
                // Habilitar UseSmallestBuckets para mejor distribución
                if (Environment.Version.Major >= 4)
                {
                    // .NET 4.0+ tiene mejoras adicionales
                    ThreadPool.SetMinThreads(Environment.ProcessorCount, Environment.ProcessorCount);
                }
            }
            catch
            {
                // Ignorar errores en versiones anteriores
            }
        }
        
        private static async void MonitorThreadsCallback(object state)
        {
            try
            {
                // 1. Recolectar métricas
                var stats = GetThreadPoolStats();
                _threadPoolInfo[stats.Timestamp.ToString("yyyyMMddHHmmss")] = new ThreadPoolInfo
                {
                    Stats = stats,
                    Timestamp = stats.Timestamp
                };
                
                // 2. Detectar tareas bloqueadas
                var blockedTasks = GetBlockedTasks(TimeSpan.FromSeconds(30));
                if (blockedTasks.Count > 0)
                {
                    _logManager.LogWarning($"Detectadas {blockedTasks.Count} tareas bloqueadas", "ThreadHelper");
                    
                    foreach (var blockedTask in blockedTasks.Take(5)) // Limitar log
                    {
                        _logManager.LogWarning($"Tarea bloqueada: {blockedTask.Description} ({blockedTask.Duration.TotalSeconds:F1}s)", "ThreadHelper");
                    }
                }
                
                // 3. Limpiar tareas completadas
                CleanupCompletedTasks();
                
                // 4. Optimizar ThreadPool periódicamente
                if (DateTime.UtcNow.Minute % 5 == 0) // Cada 5 minutos
                {
                    OptimizeThreadPool();
                }
                
                // 5. Limpiar métricas antiguas
                CleanupOldMetrics();
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en monitor de hilos: {ex}", "ThreadHelper");
            }
        }
        
        private static void RecordPerformanceMetric(TaskTracker tracker)
        {
            var metric = new PerformanceMetric
            {
                TaskId = tracker.TaskId,
                Description = tracker.Description,
                StartTime = tracker.StartTime,
                EndTime = tracker.EndTime ?? DateTime.UtcNow,
                Duration = tracker.Duration ?? TimeSpan.Zero,
                ThreadId = tracker.ThreadId,
                Status = tracker.Status,
                ErrorMessage = tracker.ErrorMessage
            };
            
            _performanceMetrics.Enqueue(metric);
            
            // Limitar tamaño de la cola
            while (_performanceMetrics.Count > MAX_PERFORMANCE_METRICS)
            {
                _performanceMetrics.TryDequeue(out _);
            }
        }
        
        private static void RecordDeadlock(string operationName, TimeSpan timeout)
        {
            var deadlockInfo = new DeadlockInfo
            {
                OperationName = operationName,
                DetectedAt = DateTime.UtcNow,
                Timeout = timeout,
                ThreadId = Thread.CurrentThread.ManagedThreadId,
                StackTrace = Environment.StackTrace
            };
            
            var key = $"{operationName}-{deadlockInfo.DetectedAt:yyyyMMddHHmmss}";
            _deadlockHistory[key] = deadlockInfo;
            
            // Mantener solo los últimos 100 deadlocks
            if (_deadlockHistory.Count > 100)
            {
                var oldest = _deadlockHistory.Keys.OrderBy(k => k).First();
                _deadlockHistory.TryRemove(oldest, out _);
            }
        }
        
        private static async Task<bool> TryAcquireLockAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            
            while (stopwatch.Elapsed < timeout)
            {
                if (cancellationToken.IsCancellationRequested)
                    return false;
                
                // Implementación simple de bloqueo distribuido
                // En producción usar Redis o similar
                lock (_lockObject)
                {
                    if (!_threadPoolInfo.ContainsKey(lockKey))
                    {
                        _threadPoolInfo[lockKey] = new ThreadPoolInfo
                        {
                            Timestamp = DateTime.UtcNow,
                            LockHolder = Thread.CurrentThread.ManagedThreadId
                        };
                        return true;
                    }
                }
                
                await Task.Delay(10, cancellationToken);
            }
            
            return false;
        }
        
        private static void ReleaseLock(string lockKey)
        {
            lock (_lockObject)
            {
                _threadPoolInfo.TryRemove(lockKey, out _);
            }
        }
        
        private static string GetTaskStackTrace(Task task)
        {
            try
            {
                // Intentar obtener stack trace (solo para debugging)
                if (task.IsFaulted && task.Exception != null)
                {
                    return task.Exception.StackTrace;
                }
                
                return Environment.StackTrace;
            }
            catch
            {
                return "No disponible";
            }
        }
        
        private static void CleanupOldMetrics()
        {
            var cutoffTime = DateTime.UtcNow.AddHours(-1);
            
            // Limpiar ThreadPoolInfo antiguo
            var oldKeys = _threadPoolInfo
                .Where(kv => kv.Value.Timestamp < cutoffTime)
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var key in oldKeys)
            {
                _threadPoolInfo.TryRemove(key, out _);
            }
            
            // Limpiar PerformanceMetrics antiguos
            while (_performanceMetrics.TryPeek(out var metric) && metric.EndTime < cutoffTime)
            {
                _performanceMetrics.TryDequeue(out _);
            }
        }
        
        #endregion
        
        #region Métodos públicos adicionales
        
        /// <summary>
        /// Ejecuta tareas en orden FIFO
        /// </summary>
        public static TaskScheduler CreateFIFOScheduler()
        {
            return new FIFOTaskScheduler();
        }
        
        /// <summary>
        /// Crea un TaskFactory con opciones personalizadas
        /// </summary>
        public static TaskFactory CreateOptimizedTaskFactory(CancellationToken cancellationToken = default)
        {
            return new TaskFactory(
                cancellationToken,
                TaskCreationOptions.LongRunning | TaskCreationOptions.PreferFairness,
                TaskContinuationOptions.ExecuteSynchronously,
                CreateFIFOScheduler());
        }
        
        /// <summary>
        /// Obtiene métricas de rendimiento
        /// </summary>
        public static PerformanceReport GetPerformanceReport(TimeSpan period)
        {
            var cutoffTime = DateTime.UtcNow - period;
            var relevantMetrics = _performanceMetrics
                .Where(m => m.EndTime >= cutoffTime)
                .ToList();
            
            if (!relevantMetrics.Any())
            {
                return new PerformanceReport
                {
                    Period = period,
                    GeneratedAt = DateTime.UtcNow,
                    Message = "No hay métricas en el período especificado"
                };
            }
            
            var completedTasks = relevantMetrics
                .Where(m => m.Status == TaskStatus.RanToCompletion)
                .ToList();
            
            var failedTasks = relevantMetrics
                .Where(m => m.Status == TaskStatus.Faulted)
                .ToList();
            
            return new PerformanceReport
            {
                Period = period,
                GeneratedAt = DateTime.UtcNow,
                TotalTasks = relevantMetrics.Count,
                CompletedTasks = completedTasks.Count,
                FailedTasks = failedTasks.Count,
                SuccessRate = (double)completedTasks.Count / relevantMetrics.Count * 100,
                AverageDuration = completedTasks.Any() ? 
                    TimeSpan.FromMilliseconds(completedTasks.Average(m => m.Duration.TotalMilliseconds)) : 
                    TimeSpan.Zero,
                MaxDuration = completedTasks.Any() ? 
                    completedTasks.Max(m => m.Duration) : 
                    TimeSpan.Zero,
                MinDuration = completedTasks.Any() ? 
                    completedTasks.Min(m => m.Duration) : 
                    TimeSpan.Zero,
                TasksByThread = relevantMetrics
                    .GroupBy(m => m.ThreadId)
                    .ToDictionary(g => g.Key, g => g.Count()),
                CommonErrors = failedTasks
                    .GroupBy(m => m.ErrorMessage)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key ?? "Desconocido", g => g.Count())
            };
        }
        
        /// <summary>
        /// Ejecuta acción en contexto de sincronización específico
        /// </summary>
        public static async Task<TResult> ExecuteInSynchronizationContext<TResult>(
            SynchronizationContext synchronizationContext,
            Func<Task<TResult>> action)
        {
            if (synchronizationContext == null)
            {
                return await action();
            }
            
            var tcs = new TaskCompletionSource<TResult>();
            
            synchronizationContext.Post(async _ =>
            {
                try
                {
                    var result = await action();
                    tcs.SetResult(result);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
            }, null);
            
            return await tcs.Task;
        }
        
        /// <summary>
        /// Crea un CancellationToken con timeout
        /// </summary>
        public static CancellationToken CreateCancellationTokenWithTimeout(
            TimeSpan timeout,
            CancellationToken linkedToken = default)
        {
            var timeoutSource = new CancellationTokenSource(timeout);
            
            if (linkedToken != default)
            {
                var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
                    timeoutSource.Token,
                    linkedToken);
                return linkedSource.Token;
            }
            
            return timeoutSource.Token;
        }
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public class ThreadPoolInfo
    {
        public DateTime Timestamp { get; set; }
        public ThreadPoolStats Stats { get; set; }
        public int? LockHolder { get; set; }
    }
    
    public class TaskTracker
    {
        public string TaskId { get; set; }
        public string Description { get; set; }
        public Task Task { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan? Duration { get; set; }
        public int ThreadId { get; set; }
        public TaskStatus Status { get; set; }
        public AggregateException Exception { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class DeadlockInfo
    {
        public string OperationName { get; set; }
        public DateTime DetectedAt { get; set; }
        public TimeSpan Timeout { get; set; }
        public int ThreadId { get; set; }
        public string StackTrace { get; set; }
    }
    
    public class PerformanceMetric
    {
        public string TaskId { get; set; }
        public string Description { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public int ThreadId { get; set; }
        public TaskStatus Status { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class ThreadPoolStats
    {
        public DateTime Timestamp { get; set; }
        public int AvailableWorkerThreads { get; set; }
        public int AvailableCompletionPortThreads { get; set; }
        public int MinWorkerThreads { get; set; }
        public int MinCompletionPortThreads { get; set; }
        public int MaxWorkerThreads { get; set; }
        public int MaxCompletionPortThreads { get; set; }
        public int ProcessorCount { get; set; }
        public int RunningTasks { get; set; }
        public int LongRunningTasks { get; set; }
    }
    
    public class BlockedTaskInfo
    {
        public string TaskId { get; set; }
        public string Description { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan Duration { get; set; }
        public int ThreadId { get; set; }
        public string StackTrace { get; set; }
    }
    
    public class PerformanceReport
    {
        public TimeSpan Period { get; set; }
        public DateTime GeneratedAt { get; set; }
        public int TotalTasks { get; set; }
        public int CompletedTasks { get; set; }
        public int FailedTasks { get; set; }
        public double SuccessRate { get; set; }
        public TimeSpan AverageDuration { get; set; }
        public TimeSpan MaxDuration { get; set; }
        public TimeSpan MinDuration { get; set; }
        public Dictionary<int, int> TasksByThread { get; set; }
        public Dictionary<string, int> CommonErrors { get; set; }
        public string Message { get; set; }
        
        public PerformanceReport()
        {
            TasksByThread = new Dictionary<int, int>();
            CommonErrors = new Dictionary<string, int>();
        }
    }
    
    // Scheduler FIFO personalizado
    public class FIFOTaskScheduler : TaskScheduler
    {
        private readonly LinkedList<Task> _tasks = new LinkedList<Task>();
        private readonly object _lock = new object();
        
        protected override IEnumerable<Task> GetScheduledTasks()
        {
            lock (_lock)
            {
                return _tasks.ToList();
            }
        }
        
        protected override void QueueTask(Task task)
        {
            lock (_lock)
            {
                _tasks.AddLast(task);
                ThreadPool.QueueUserWorkItem(ProcessTasks);
            }
        }
        
        protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued)
        {
            return false; // No ejecutar inline
        }
        
        private void ProcessTasks(object state)
        {
            while (true)
            {
                Task task;
                lock (_lock)
                {
                    if (_tasks.Count == 0)
                        return;
                    
                    task = _tasks.First.Value;
                    _tasks.RemoveFirst();
                }
                
                TryExecuteTask(task);
            }
        }
    }
    
    #endregion
}