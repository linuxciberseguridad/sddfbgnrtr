using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.Telemetry
{
    /// <summary>
    /// Cola de telemetría de alta velocidad con persistencia, prioridad y control de flujo
    /// Diseñada para manejar millones de eventos por día con garantía de entrega
    /// </summary>
    public sealed class TelemetryQueue : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<TelemetryQueue> _instance = 
            new Lazy<TelemetryQueue>(() => new TelemetryQueue());
        
        public static TelemetryQueue Instance => _instance.Value;
        
        // Colas prioritarias (0 = más alta prioridad)
        private readonly ConcurrentPriorityQueue<TelemetryEvent>[] _priorityQueues;
        private readonly ConcurrentQueue<TelemetryEvent> _retryQueue;
        private readonly ConcurrentDictionary<string, TelemetryEvent> _inFlightEvents;
        private readonly ConcurrentDictionary<string, DateTime> _eventTimestamps;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly SemaphoreSlim _queueLock;
        private readonly Timer _flushTimer;
        private readonly Timer _retryTimer;
        private readonly Timer _cleanupTimer;
        
        private bool _isInitialized;
        private bool _isRunning;
        private long _totalEnqueued;
        private long _totalSent;
        private long _totalFailed;
        private long _totalDropped;
        private DateTime _startTime;
        
        private const int QUEUE_PRIORITY_LEVELS = 4;
        private const int FLUSH_INTERVAL_MS = 1000; // 1 segundo
        private const int RETRY_INTERVAL_MS = 5000; // 5 segundos
        private const int CLEANUP_INTERVAL_MS = 30000; // 30 segundos
        private const int MAX_QUEUE_SIZE = 100000; // 100K eventos en memoria
        private const int MAX_IN_FLIGHT = 1000; // Máximo eventos enviándose
        private const int MAX_RETRY_COUNT = 3;
        private const int RETRY_BACKOFF_MS = 1000;
        private const int IN_FLIGHT_TIMEOUT_SECONDS = 30;
        
        public string ModuleId => "TelemetryQueue";
        public string Version => "1.0.0";
        public string Description => "Cola de telemetría de alta velocidad con garantía de entrega";
        
        private TelemetryQueue()
        {
            _priorityQueues = new ConcurrentPriorityQueue<TelemetryEvent>[QUEUE_PRIORITY_LEVELS];
            for (int i = 0; i < QUEUE_PRIORITY_LEVELS; i++)
            {
                _priorityQueues[i] = new ConcurrentPriorityQueue<TelemetryEvent>();
            }
            
            _retryQueue = new ConcurrentQueue<TelemetryEvent>();
            _inFlightEvents = new ConcurrentDictionary<string, TelemetryEvent>();
            _eventTimestamps = new ConcurrentDictionary<string, DateTime>();
            
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _queueLock = new SemaphoreSlim(1, 1);
            
            _flushTimer = new Timer(FlushCallback, null, Timeout.Infinite, Timeout.Infinite);
            _retryTimer = new Timer(RetryCallback, null, Timeout.Infinite, Timeout.Infinite);
            _cleanupTimer = new Timer(CleanupCallback, null, Timeout.Infinite, Timeout.Infinite);
            
            _isInitialized = false;
            _isRunning = false;
        }
        
        /// <summary>
        /// Inicializa la cola de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                if (_isInitialized)
                    return ModuleOperationResult.SuccessResult();
                
                // Cargar eventos pendientes desde base de datos
                await LoadPendingEventsFromDatabase();
                
                // Iniciar timers
                _flushTimer.Change(TimeSpan.Zero, TimeSpan.FromMilliseconds(FLUSH_INTERVAL_MS));
                _retryTimer.Change(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(RETRY_INTERVAL_MS));
                _cleanupTimer.Change(TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(CLEANUP_INTERVAL_MS));
                
                _startTime = DateTime.UtcNow;
                _isInitialized = true;
                _isRunning = true;
                
                _logManager.LogInfo("TelemetryQueue inicializada", ModuleId, new Dictionary<string, object>
                {
                    { "priorityLevels", QUEUE_PRIORITY_LEVELS },
                    { "maxQueueSize", MAX_QUEUE_SIZE },
                    { "maxInFlight", MAX_IN_FLIGHT }
                });
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando TelemetryQueue: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia la cola de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            _isRunning = true;
            _logManager.LogInfo("TelemetryQueue iniciada", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene la cola de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            _isRunning = false;
            
            // Flush final
            await FlushAllToDatabase();
            
            _logManager.LogInfo("TelemetryQueue detenida", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Pausa la cola de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("TelemetryQueue pausada", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda la cola de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("TelemetryQueue reanudada", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Encola un evento de telemetría
        /// </summary>
        public async Task<bool> EnqueueAsync(TelemetryEvent telemetryEvent, 
                                           TelemetryPriority priority = TelemetryPriority.Normal)
        {
            if (!_isInitialized || !_isRunning || telemetryEvent == null)
                return false;
            
            try
            {
                // Asignar ID único si no tiene
                if (string.IsNullOrEmpty(telemetryEvent.EventId))
                {
                    telemetryEvent.EventId = Guid.NewGuid().ToString();
                }
                
                // Asignar timestamp si no tiene
                if (telemetryEvent.Timestamp == default)
                {
                    telemetryEvent.Timestamp = DateTime.UtcNow;
                }
                
                // Verificar límite de cola
                var totalQueueSize = GetTotalQueueSize();
                if (totalQueueSize >= MAX_QUEUE_SIZE)
                {
                    Interlocked.Increment(ref _totalDropped);
                    _logManager.LogWarning($"Cola llena, evento descartado: {telemetryEvent.EventId}", 
                        ModuleId, new Dictionary<string, object>
                        {
                            { "eventId", telemetryEvent.EventId },
                            { "queueSize", totalQueueSize },
                            { "maxSize", MAX_QUEUE_SIZE }
                        });
                    return false;
                }
                
                // Determinar prioridad (0 = más alta)
                int priorityLevel = priority switch
                {
                    TelemetryPriority.Critical => 0,
                    TelemetryPriority.High => 1,
                    TelemetryPriority.Normal => 2,
                    TelemetryPriority.Low => 3,
                    _ => 2
                };
                
                // Encolar en la cola de prioridad correspondiente
                _priorityQueues[priorityLevel].Enqueue(telemetryEvent, priorityLevel);
                _eventTimestamps[telemetryEvent.EventId] = DateTime.UtcNow;
                
                Interlocked.Increment(ref _totalEnqueued);
                
                // Guardar en base de datos para persistencia
                await _localDatabase.SaveTelemetryEventAsync(telemetryEvent);
                
                // Log para eventos críticos
                if (priority == TelemetryPriority.Critical)
                {
                    _logManager.LogInfo($"Evento crítico encolado: {telemetryEvent.EventId}", 
                        ModuleId, new Dictionary<string, object>
                        {
                            { "eventId", telemetryEvent.EventId },
                            { "type", telemetryEvent.EventType },
                            { "priority", priority },
                            { "queueSize", totalQueueSize + 1 }
                        });
                }
                
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error encolando evento: {ex}", ModuleId);
                Interlocked.Increment(ref _totalFailed);
                return false;
            }
        }
        
        /// <summary>
        /// Encola una alerta de salud
        /// </summary>
        public async Task<bool> EnqueueHealthAlertAsync(HealthAlert healthAlert)
        {
            var telemetryEvent = new TelemetryEvent
            {
                EventId = healthAlert.AlertId,
                Timestamp = healthAlert.Timestamp,
                EventType = "HealthAlert",
                Severity = healthAlert.Status.ToString(),
                Data = new Dictionary<string, object>
                {
                    { "moduleId", healthAlert.ModuleId },
                    { "status", healthAlert.Status.ToString() },
                    { "message", healthAlert.Message },
                    { "details", healthAlert.Details },
                    { "failureCount", healthAlert.FailureCount }
                }
            };
            
            return await EnqueueAsync(telemetryEvent, TelemetryPriority.High);
        }
        
        /// <summary>
        /// Obtiene el próximo lote de eventos para enviar
        /// </summary>
        public async Task<List<TelemetryEvent>> GetNextBatchAsync(int batchSize = 100)
        {
            if (!_isInitialized || !_isRunning || _inFlightEvents.Count >= MAX_IN_FLIGHT)
                return new List<TelemetryEvent>();
            
            try
            {
                await _queueLock.WaitAsync();
                
                var batch = new List<TelemetryEvent>();
                var now = DateTime.UtcNow;
                
                // Recorrer colas por prioridad (de más alta a más baja)
                for (int priority = 0; priority < QUEUE_PRIORITY_LEVELS; priority++)
                {
                    while (batch.Count < batchSize && 
                           _priorityQueues[priority].TryDequeue(out var telemetryEvent))
                    {
                        // Verificar que no sea un evento muy antiguo
                        if (_eventTimestamps.TryGetValue(telemetryEvent.EventId, out var enqueueTime))
                        {
                            var age = now - enqueueTime;
                            if (age.TotalHours > 24)
                            {
                                // Evento demasiado antiguo, descartar
                                _eventTimestamps.TryRemove(telemetryEvent.EventId, out _);
                                Interlocked.Increment(ref _totalDropped);
                                _logManager.LogWarning($"Evento demasiado antiguo descartado: {telemetryEvent.EventId}", 
                                    ModuleId, new Dictionary<string, object>
                                    {
                                        { "eventId", telemetryEvent.EventId },
                                        { "ageHours", age.TotalHours },
                                        { "priority", priority }
                                    });
                                continue;
                            }
                        }
                        
                        // Mover a in-flight
                        if (_inFlightEvents.TryAdd(telemetryEvent.EventId, telemetryEvent))
                        {
                            batch.Add(telemetryEvent);
                            _eventTimestamps[telemetryEvent.EventId] = now; // Actualizar timestamp
                        }
                    }
                    
                    if (batch.Count >= batchSize)
                        break;
                }
                
                // Si no hay eventos en colas prioritarias, intentar con retry queue
                if (batch.Count == 0)
                {
                    while (batch.Count < batchSize && 
                           _retryQueue.TryDequeue(out var telemetryEvent))
                    {
                        if (_inFlightEvents.TryAdd(telemetryEvent.EventId, telemetryEvent))
                        {
                            batch.Add(telemetryEvent);
                            _eventTimestamps[telemetryEvent.EventId] = now;
                        }
                    }
                }
                
                return batch;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo batch: {ex}", ModuleId);
                return new List<TelemetryEvent>();
            }
            finally
            {
                _queueLock.Release();
            }
        }
        
        /// <summary>
        /// Marca eventos como enviados exitosamente
        /// </summary>
        public async Task MarkAsSentAsync(List<string> eventIds)
        {
            if (eventIds == null || eventIds.Count == 0)
                return;
            
            try
            {
                await _queueLock.WaitAsync();
                
                foreach (var eventId in eventIds)
                {
                    if (_inFlightEvents.TryRemove(eventId, out var telemetryEvent))
                    {
                        _eventTimestamps.TryRemove(eventId, out _);
                        Interlocked.Increment(ref _totalSent);
                        
                        // Actualizar en base de datos
                        await _localDatabase.MarkTelemetryAsSentAsync(new List<string> { eventId });
                    }
                }
                
                // Log cada 1000 eventos enviados
                if (Interlocked.Read(ref _totalSent) % 1000 == 0)
                {
                    _logManager.LogInfo($"Eventos enviados: {_totalSent}", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error marcando eventos como enviados: {ex}", ModuleId);
            }
            finally
            {
                _queueLock.Release();
            }
        }
        
        /// <summary>
        /// Marca eventos como fallidos (para reintento)
        /// </summary>
        public async Task MarkAsFailedAsync(List<TelemetryEvent> failedEvents)
        {
            if (failedEvents == null || failedEvents.Count == 0)
                return;
            
            try
            {
                await _queueLock.WaitAsync();
                
                foreach (var telemetryEvent in failedEvents)
                {
                    // Remover de in-flight
                    if (_inFlightEvents.TryRemove(telemetryEvent.EventId, out _))
                    {
                        // Incrementar contador de reintentos
                        if (!telemetryEvent.Metadata.ContainsKey("retryCount"))
                        {
                            telemetryEvent.Metadata["retryCount"] = 1;
                        }
                        else
                        {
                            telemetryEvent.Metadata["retryCount"] = 
                                (int)telemetryEvent.Metadata["retryCount"] + 1;
                        }
                        
                        var retryCount = (int)telemetryEvent.Metadata["retryCount"];
                        
                        if (retryCount <= MAX_RETRY_COUNT)
                        {
                            // Agregar a cola de reintentos con backoff
                            telemetryEvent.Metadata["nextRetry"] = 
                                DateTime.UtcNow.AddMilliseconds(RETRY_BACKOFF_MS * retryCount);
                            _retryQueue.Enqueue(telemetryEvent);
                            
                            _logManager.LogWarning($"Evento fallido, programando reintento {retryCount}: {telemetryEvent.EventId}", 
                                ModuleId, new Dictionary<string, object>
                                {
                                    { "eventId", telemetryEvent.EventId },
                                    { "retryCount", retryCount },
                                    { "nextRetry", telemetryEvent.Metadata["nextRetry"] }
                                });
                        }
                        else
                        {
                            // Máximo de reintentos alcanzado, descartar
                            _eventTimestamps.TryRemove(telemetryEvent.EventId, out _);
                            Interlocked.Increment(ref _totalFailed);
                            
                            _logManager.LogError($"Máximo de reintentos alcanzado, evento descartado: {telemetryEvent.EventId}", 
                                ModuleId, new Dictionary<string, object>
                                {
                                    { "eventId", telemetryEvent.EventId },
                                    { "retryCount", retryCount },
                                    { "type", telemetryEvent.EventType }
                                });
                        }
                    }
                    
                    // Actualizar en base de datos
                    await _localDatabase.IncrementTelemetryRetryCountAsync(
                        new List<string> { telemetryEvent.EventId });
                }
                
                Interlocked.Add(ref _totalFailed, failedEvents.Count);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error marcando eventos como fallidos: {ex}", ModuleId);
            }
            finally
            {
                _queueLock.Release();
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas de la cola
        /// </summary>
        public TelemetryQueueStats GetStats()
        {
            var now = DateTime.UtcNow;
            
            return new TelemetryQueueStats
            {
                Timestamp = now,
                IsRunning = _isRunning,
                IsInitialized = _isInitialized,
                Uptime = now - _startTime,
                
                // Conteos por prioridad
                PriorityCounts = _priorityQueues
                    .Select((q, i) => new { Priority = i, Count = q.Count })
                    .ToDictionary(x => x.Priority, x => x.Count),
                
                RetryQueueCount = _retryQueue.Count,
                InFlightCount = _inFlightEvents.Count,
                EventTimestampCount = _eventTimestamps.Count,
                
                // Totales
                TotalEnqueued = Interlocked.Read(ref _totalEnqueued),
                TotalSent = Interlocked.Read(ref _totalSent),
                TotalFailed = Interlocked.Read(ref _totalFailed),
                TotalDropped = Interlocked.Read(ref _totalDropped),
                
                // Tasas
                EnqueueRate = CalculateRate(_totalEnqueued, _startTime),
                SendRate = CalculateRate(_totalSent, _startTime),
                FailureRate = CalculateRate(_totalFailed, _startTime),
                
                // Tamaños
                EstimatedMemoryMB = EstimateMemoryUsage(),
                MaxQueueSize = MAX_QUEUE_SIZE,
                MaxInFlight = MAX_IN_FLIGHT
            };
        }
        
        /// <summary>
        /// Verifica salud de la cola
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var stats = GetStats();
                var issues = new List<string>();
                
                // Verificar si está corriendo
                if (!_isRunning)
                {
                    issues.Add("Queue no está corriendo");
                }
                
                // Verificar tamaño de cola
                var totalQueueSize = stats.PriorityCounts.Values.Sum() + stats.RetryQueueCount;
                if (totalQueueSize >= MAX_QUEUE_SIZE * 0.9) // 90% de capacidad
                {
                    issues.Add($"Queue cerca de capacidad: {totalQueueSize}/{MAX_QUEUE_SIZE}");
                }
                
                // Verificar eventos in-flight timeout
                var timeoutEvents = _inFlightEvents.Values
                    .Where(e => _eventTimestamps.TryGetValue(e.EventId, out var timestamp) &&
                               (DateTime.UtcNow - timestamp).TotalSeconds > IN_FLIGHT_TIMEOUT_SECONDS)
                    .ToList();
                
                if (timeoutEvents.Count > 0)
                {
                    issues.Add($"{timeoutEvents.Count} eventos in-flight timeout");
                }
                
                // Verificar tasa de fallos
                if (stats.FailureRate > 0.1) // Más del 10% de fallos
                {
                    issues.Add($"Alta tasa de fallos: {stats.FailureRate:P2}");
                }
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy($"Queue saludable: {stats.TotalEnqueued} eventos procesados");
                }
                else
                {
                    return HealthCheckResult.Degraded(
                        $"Queue con problemas: {string.Join(", ", issues)}",
                        new Dictionary<string, object>
                        {
                            { "issues", issues },
                            { "stats", stats }
                        });
                }
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error verificando salud de queue: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "exception", ex.ToString() }
                    });
            }
        }
        
        /// <summary>
        /// Limpia eventos antiguos
        /// </summary>
        public async Task CleanupOldEventsAsync(TimeSpan maxAge)
        {
            try
            {
                await _queueLock.WaitAsync();
                
                var cutoff = DateTime.UtcNow - maxAge;
                var removedCount = 0;
                
                // Limpiar event timestamps
                var oldTimestamps = _eventTimestamps
                    .Where(kv => kv.Value < cutoff)
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var eventId in oldTimestamps)
                {
                    if (_eventTimestamps.TryRemove(eventId, out _))
                    {
                        removedCount++;
                    }
                }
                
                // Limpiar in-flight antiguos
                var oldInFlight = _inFlightEvents
                    .Where(kv => _eventTimestamps.TryGetValue(kv.Key, out var timestamp) && 
                                timestamp < cutoff)
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var eventId in oldInFlight)
                {
                    if (_inFlightEvents.TryRemove(eventId, out var telemetryEvent))
                    {
                        // Mover a retry queue
                        if (!telemetryEvent.Metadata.ContainsKey("retryCount"))
                        {
                            telemetryEvent.Metadata["retryCount"] = 1;
                        }
                        telemetryEvent.Metadata["nextRetry"] = DateTime.UtcNow;
                        _retryQueue.Enqueue(telemetryEvent);
                    }
                }
                
                if (removedCount > 0)
                {
                    _logManager.LogInfo($"Eventos antiguos limpiados: {removedCount}", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error limpiando eventos antiguos: {ex}", ModuleId);
            }
            finally
            {
                _queueLock.Release();
            }
        }
        
        /// <summary>
        /// Vacía toda la cola a la base de datos
        /// </summary>
        public async Task FlushAllToDatabase()
        {
            try
            {
                await _queueLock.WaitAsync();
                
                var allEvents = new List<TelemetryEvent>();
                
                // Obtener todos los eventos de las colas prioritarias
                for (int i = 0; i < QUEUE_PRIORITY_LEVELS; i++)
                {
                    while (_priorityQueues[i].TryDequeue(out var telemetryEvent))
                    {
                        allEvents.Add(telemetryEvent);
                    }
                }
                
                // Obtener todos los eventos de retry queue
                while (_retryQueue.TryDequeue(out var telemetryEvent))
                {
                    allEvents.Add(telemetryEvent);
                }
                
                // Obtener todos los eventos in-flight
                var inFlightEvents = _inFlightEvents.Values.ToList();
                allEvents.AddRange(inFlightEvents);
                
                // Guardar en base de datos
                foreach (var telemetryEvent in allEvents)
                {
                    await _localDatabase.SaveTelemetryEventAsync(telemetryEvent);
                }
                
                _logManager.LogInfo($"Queue flushed: {allEvents.Count} eventos guardados", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error flushing queue: {ex}", ModuleId);
            }
            finally
            {
                _queueLock.Release();
            }
        }
        
        /// <summary>
        /// Reinicia las estadísticas de la cola
        /// </summary>
        public void ResetStats()
        {
            Interlocked.Exchange(ref _totalEnqueued, 0);
            Interlocked.Exchange(ref _totalSent, 0);
            Interlocked.Exchange(ref _totalFailed, 0);
            Interlocked.Exchange(ref _totalDropped, 0);
            _startTime = DateTime.UtcNow;
            
            _logManager.LogInfo("Estadísticas de queue reiniciadas", ModuleId);
        }
        
        #region Métodos Privados
        
        private async Task LoadPendingEventsFromDatabase()
        {
            try
            {
                var pendingEvents = await _localDatabase.GetPendingTelemetryAsync(1000);
                
                foreach (var telemetryEvent in pendingEvents)
                {
                    // Determinar prioridad basada en severidad
                    var priority = telemetryEvent.Severity?.ToLower() switch
                    {
                        "critical" => TelemetryPriority.Critical,
                        "high" => TelemetryPriority.High,
                        "warning" => TelemetryPriority.Normal,
                        _ => TelemetryPriority.Low
                    };
                    
                    await EnqueueAsync(telemetryEvent, priority);
                }
                
                _logManager.LogInfo($"Eventos pendientes cargados: {pendingEvents.Count}", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando eventos pendientes: {ex}", ModuleId);
            }
        }
        
        private async void FlushCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                // Verificar eventos in-flight timeout
                await HandleInFlightTimeouts();
                
                // Verificar si hay espacio en la cola
                if (GetTotalQueueSize() < MAX_QUEUE_SIZE * 0.8) // 80% de capacidad
                {
                    // Cargar más eventos desde base de datos si es necesario
                    await LoadMoreEventsIfNeeded();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en FlushCallback: {ex}", ModuleId);
            }
        }
        
        private async void RetryCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                var now = DateTime.UtcNow;
                var eventsToRetry = new List<TelemetryEvent>();
                
                // Verificar eventos en retry queue listos para reintento
                var snapshot = _retryQueue.ToArray();
                foreach (var telemetryEvent in snapshot)
                {
                    if (telemetryEvent.Metadata.TryGetValue("nextRetry", out var nextRetryObj) &&
                        nextRetryObj is DateTime nextRetry &&
                        nextRetry <= now)
                    {
                        eventsToRetry.Add(telemetryEvent);
                    }
                }
                
                // Mover eventos listos a las colas prioritarias
                foreach (var telemetryEvent in eventsToRetry)
                {
                    if (_retryQueue.TryDequeue(out var dequeuedEvent) && 
                        dequeuedEvent.EventId == telemetryEvent.EventId)
                    {
                        var retryCount = telemetryEvent.Metadata.ContainsKey("retryCount") ? 
                            (int)telemetryEvent.Metadata["retryCount"] : 1;
                        
                        // Prioridad basada en número de reintentos
                        var priority = retryCount >= MAX_RETRY_COUNT ? 
                            TelemetryPriority.Critical : TelemetryPriority.High;
                        
                        await EnqueueAsync(telemetryEvent, priority);
                        
                        _logManager.LogInfo($"Evento reintentado: {telemetryEvent.EventId} (intento {retryCount})", 
                            ModuleId, new Dictionary<string, object>
                            {
                                { "eventId", telemetryEvent.EventId },
                                { "retryCount", retryCount },
                                { "priority", priority }
                            });
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en RetryCallback: {ex}", ModuleId);
            }
        }
        
        private async void CleanupCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                // Limpiar eventos muy antiguos (más de 24 horas)
                await CleanupOldEventsAsync(TimeSpan.FromHours(24));
                
                // Limpiar timestamps antiguos
                CleanupOldTimestamps();
                
                // Reportar estadísticas periódicamente
                LogPeriodicStats();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en CleanupCallback: {ex}", ModuleId);
            }
        }
        
        private async Task HandleInFlightTimeouts()
        {
            var timeoutEvents = new List<TelemetryEvent>();
            var now = DateTime.UtcNow;
            
            foreach (var kvp in _inFlightEvents)
            {
                if (_eventTimestamps.TryGetValue(kvp.Key, out var timestamp) &&
                    (now - timestamp).TotalSeconds > IN_FLIGHT_TIMEOUT_SECONDS)
                {
                    timeoutEvents.Add(kvp.Value);
                }
            }
            
            if (timeoutEvents.Count > 0)
            {
                await MarkAsFailedAsync(timeoutEvents);
                
                _logManager.LogWarning($"Eventos in-flight timeout: {timeoutEvents.Count}", 
                    ModuleId, new Dictionary<string, object>
                    {
                        { "timeoutSeconds", IN_FLIGHT_TIMEOUT_SECONDS },
                        { "eventIds", timeoutEvents.Select(e => e.EventId).ToList() }
                    });
            }
        }
        
        private async Task LoadMoreEventsIfNeeded()
        {
            var currentSize = GetTotalQueueSize();
            var availableSpace = MAX_QUEUE_SIZE - currentSize;
            
            if (availableSpace > 1000) // Cargar en lotes de 1000
            {
                var pendingEvents = await _localDatabase.GetPendingTelemetryAsync(1000);
                
                foreach (var telemetryEvent in pendingEvents)
                {
                    if (GetTotalQueueSize() >= MAX_QUEUE_SIZE)
                        break;
                    
                    await EnqueueAsync(telemetryEvent, TelemetryPriority.Normal);
                }
            }
        }
        
        private void CleanupOldTimestamps()
        {
            var cutoff = DateTime.UtcNow.AddHours(-1);
            var oldTimestamps = _eventTimestamps
                .Where(kv => kv.Value < cutoff)
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var eventId in oldTimestamps)
            {
                _eventTimestamps.TryRemove(eventId, out _);
            }
        }
        
        private void LogPeriodicStats()
        {
            var stats = GetStats();
            var totalQueueSize = stats.PriorityCounts.Values.Sum() + stats.RetryQueueCount;
            
            if (totalQueueSize > 0 || stats.InFlightCount > 0)
            {
                _logManager.LogInfo($"Queue stats: {totalQueueSize} en cola, {stats.InFlightCount} in-flight", 
                    ModuleId, new Dictionary<string, object>
                    {
                        { "queueSize", totalQueueSize },
                        { "inFlight", stats.InFlightCount },
                        { "enqueued", stats.TotalEnqueued },
                        { "sent", stats.TotalSent },
                        { "failed", stats.TotalFailed },
                        { "dropped", stats.TotalDropped }
                    });
            }
        }
        
        private int GetTotalQueueSize()
        {
            return _priorityQueues.Sum(q => q.Count) + _retryQueue.Count;
        }
        
        private double CalculateRate(long count, DateTime startTime)
        {
            var elapsed = DateTime.UtcNow - startTime;
            if (elapsed.TotalSeconds == 0)
                return 0;
            
            return count / elapsed.TotalSeconds;
        }
        
        private double EstimateMemoryUsage()
        {
            var totalEvents = GetTotalQueueSize() + _inFlightEvents.Count;
            // Estimación: 1KB por evento en promedio
            return totalEvents * 1.0 / 1024; // MB
        }
        
        #endregion
        
        #region Clases Internas
        
        private class ConcurrentPriorityQueue<T>
        {
            private readonly ConcurrentQueue<T> _queue;
            private readonly int _priority;
            
            public ConcurrentPriorityQueue(int priority = 0)
            {
                _queue = new ConcurrentQueue<T>();
                _priority = priority;
            }
            
            public void Enqueue(T item, int priority)
            {
                _queue.Enqueue(item);
            }
            
            public bool TryDequeue(out T result)
            {
                return _queue.TryDequeue(out result);
            }
            
            public int Count => _queue.Count;
        }
        
        #endregion
    }
    
    #region Clases y Enums de Soporte
    
    public class TelemetryEvent
    {
        public string EventId { get; set; }
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
        public string Severity { get; set; }
        public Dictionary<string, object> Data { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public TelemetryEvent()
        {
            Data = new Dictionary<string, object>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class HealthAlert
    {
        public string AlertId { get; set; }
        public DateTime Timestamp { get; set; }
        public string ModuleId { get; set; }
        public HealthStatus Status { get; set; }
        public string Message { get; set; }
        public Dictionary<string, object> Details { get; set; }
        public int FailureCount { get; set; }
    }
    
    public enum TelemetryPriority
    {
        Critical = 0,
        High = 1,
        Normal = 2,
        Low = 3
    }
    
    public class TelemetryQueueStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsRunning { get; set; }
        public bool IsInitialized { get; set; }
        public TimeSpan Uptime { get; set; }
        
        public Dictionary<int, int> PriorityCounts { get; set; }
        public int RetryQueueCount { get; set; }
        public int InFlightCount { get; set; }
        public int EventTimestampCount { get; set; }
        
        public long TotalEnqueued { get; set; }
        public long TotalSent { get; set; }
        public long TotalFailed { get; set; }
        public long TotalDropped { get; set; }
        
        public double EnqueueRate { get; set; }
        public double SendRate { get; set; }
        public double FailureRate { get; set; }
        
        public double EstimatedMemoryMB { get; set; }
        public int MaxQueueSize { get; set; }
        public int MaxInFlight { get; set; }
    }
    
    public enum HealthStatus
    {
        Healthy,
        Degraded,
        Unhealthy,
        Unknown
    }
    
    public class HealthCheckResult
    {
        public HealthStatus Status { get; set; }
        public string Message { get; set; }
        public Dictionary<string, object> Details { get; set; }
        public DateTime CheckTime { get; set; }
        
        public static HealthCheckResult Healthy(string message = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Healthy,
                Message = message ?? "Healthy",
                Details = new Dictionary<string, object>(),
                CheckTime = DateTime.UtcNow
            };
        }
        
        public static HealthCheckResult Unhealthy(string message, Dictionary<string, object> details = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Unhealthy,
                Message = message,
                Details = details ?? new Dictionary<string, object>(),
                CheckTime = DateTime.UtcNow
            };
        }
        
        public static HealthCheckResult Degraded(string message, Dictionary<string, object> details = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Degraded,
                Message = message,
                Details = details ?? new Dictionary<string, object>(),
                CheckTime = DateTime.UtcNow
            };
        }
    }
    
    public class ModuleOperationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static ModuleOperationResult SuccessResult()
        {
            return new ModuleOperationResult
            {
                Success = true,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static ModuleOperationResult ErrorResult(string errorMessage)
        {
            return new ModuleOperationResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public interface IAgentModule
    {
        string ModuleId { get; }
        string Version { get; }
        string Description { get; }
        
        Task<ModuleOperationResult> InitializeAsync();
        Task<ModuleOperationResult> StartAsync();
        Task<ModuleOperationResult> StopAsync();
        Task<ModuleOperationResult> PauseAsync();
        Task<ModuleOperationResult> ResumeAsync();
    }
    
    public interface IHealthCheckable
    {
        Task<HealthCheckResult> CheckHealthAsync();
    }
    
    #endregion
}