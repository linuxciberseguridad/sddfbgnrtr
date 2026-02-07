using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.SOAR
{
    /// <summary>
    /// Orquestador de acciones SOAR - Ejecuta y coordina acciones automatizadas
    /// Soporta acciones nativas, scripts, integraciones externas y workflows personalizados
    /// </summary>
    public sealed class ActionOrchestrator : IActionOrchestrator, IDisposable
    {
        private readonly ILogger<ActionOrchestrator> _logger;
        private readonly IServiceProvider _serviceProvider;
        private readonly IActionRegistry _actionRegistry;
        private readonly IScriptEngine _scriptEngine;
        private readonly IIntegrationManager _integrationManager;
        
        private readonly ConcurrentDictionary<string, ActionExecution> _executions;
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _cancellationTokens;
        private readonly ConcurrentBag<IActionHandler> _actionHandlers;
        
        private readonly ActionQueue _actionQueue;
        private readonly ActionRetryManager _retryManager;
        private readonly ActionTimeoutManager _timeoutManager;
        
        private bool _isInitialized;
        private bool _isDisposed;
        private readonly SemaphoreSlim _initLock = new SemaphoreSlim(1, 1);
        
        public event EventHandler<ActionCompletedEventArgs> ActionCompleted;
        public event EventHandler<ActionFailedEventArgs> ActionFailed;
        public event EventHandler<ActionTimeoutEventArgs> ActionTimeout;
        public event EventHandler<ActionRetryEventArgs> ActionRetry;
        
        public ActionOrchestrator(
            ILogger<ActionOrchestrator> logger,
            IServiceProvider serviceProvider,
            IActionRegistry actionRegistry = null,
            IScriptEngine scriptEngine = null,
            IIntegrationManager integrationManager = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _actionRegistry = actionRegistry;
            _scriptEngine = scriptEngine;
            _integrationManager = integrationManager;
            
            _executions = new ConcurrentDictionary<string, ActionExecution>();
            _cancellationTokens = new ConcurrentDictionary<string, CancellationTokenSource>();
            _actionHandlers = new ConcurrentBag<IActionHandler>();
            
            _actionQueue = new ActionQueue();
            _retryManager = new ActionRetryManager();
            _timeoutManager = new ActionTimeoutManager();
            
            _isInitialized = false;
            _isDisposed = false;
        }
        
        /// <summary>
        /// Inicializa el orquestador de acciones
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await _initLock.WaitAsync(cancellationToken);
            
            try
            {
                if (_isInitialized)
                    return;
                
                _logger.LogInformation("Inicializando ActionOrchestrator...");
                
                // Inicializar componentes internos
                await _actionQueue.InitializeAsync(cancellationToken);
                await _retryManager.InitializeAsync(cancellationToken);
                await _timeoutManager.InitializeAsync(cancellationToken);
                
                // Registrar acciones nativas
                await RegisterNativeActionsAsync(cancellationToken);
                
                // Cargar integraciones
                await LoadIntegrationsAsync(cancellationToken);
                
                // Iniciar procesador de cola
                StartQueueProcessor();
                
                _isInitialized = true;
                _logger.LogInformation($"ActionOrchestrator inicializado con {_actionHandlers.Count} handlers");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al inicializar ActionOrchestrator");
                throw;
            }
            finally
            {
                _initLock.Release();
            }
        }
        
        /// <summary>
        /// Ejecuta una acción
        /// </summary>
        public async Task<ActionExecutionResult> ExecuteActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(actionType))
                throw new ArgumentNullException(nameof(actionType));
            
            if (parameters == null)
                parameters = new Dictionary<string, object>();
            
            if (context == null)
                throw new ArgumentNullException(nameof(context));
            
            var executionId = GenerateExecutionId();
            var startTime = DateTime.UtcNow;
            
            try
            {
                _logger.LogInformation(
                    "Ejecutando acción: {ActionType}, Execution: {ExecutionId}, Context: {ContextId}", 
                    actionType, executionId, context.ContextId);
                
                // Crear ejecución
                var execution = new ActionExecution
                {
                    ExecutionId = executionId,
                    ActionType = actionType,
                    Parameters = parameters,
                    Context = context,
                    Status = ActionExecutionStatus.Pending,
                    CreatedAt = DateTime.UtcNow,
                    RetryCount = 0,
                    MaxRetries = GetMaxRetries(actionType, parameters),
                    Timeout = GetTimeout(actionType, parameters)
                };
                
                // Registrar ejecución
                _executions[executionId] = execution;
                
                // Crear token de cancelación
                var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(execution.Timeout);
                _cancellationTokens[executionId] = cts;
                
                // Actualizar estado
                execution.Status = ActionExecutionStatus.Running;
                execution.StartedAt = DateTime.UtcNow;
                
                // Ejecutar acción
                var result = await ExecuteActionInternalAsync(execution, outputs, cts.Token);
                
                // Actualizar ejecución
                execution.Status = result.Success ? 
                    ActionExecutionStatus.Completed : ActionExecutionStatus.Failed;
                execution.EndedAt = DateTime.UtcNow;
                execution.Duration = execution.EndedAt.Value - execution.StartedAt.Value;
                execution.Result = result.Result;
                execution.Error = result.Error;
                
                // Emitir evento
                if (result.Success)
                {
                    OnActionCompleted(new ActionCompletedEventArgs
                    {
                        ExecutionId = executionId,
                        StepId = context.StepId,
                        ActionType = actionType,
                        Result = result.Result,
                        Duration = execution.Duration
                    });
                }
                else
                {
                    OnActionFailed(new ActionFailedEventArgs
                    {
                        ExecutionId = executionId,
                        StepId = context.StepId,
                        ActionType = actionType,
                        Error = result.Error,
                        Duration = execution.Duration
                    });
                }
                
                _logger.LogInformation(
                    "Acción completada: {ActionType}, Execution: {ExecutionId}, Success: {Success}, Duration: {Duration}ms", 
                    actionType, executionId, result.Success, execution.Duration.TotalMilliseconds);
                
                return result;
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogWarning(ex, "Acción cancelada por timeout: {ActionType}, Execution: {ExecutionId}", 
                    actionType, executionId);
                
                OnActionTimeout(new ActionTimeoutEventArgs
                {
                    ExecutionId = executionId,
                    StepId = context.StepId,
                    ActionType = actionType,
                    TimeoutDuration = DateTime.UtcNow - startTime
                });
                
                return ActionExecutionResult.Failed($"Action timeout after {DateTime.UtcNow - startTime}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fatal ejecutando acción: {ActionType}, Execution: {ExecutionId}", 
                    actionType, executionId);
                
                return ActionExecutionResult.Failed($"Fatal error: {ex.Message}");
            }
            finally
            {
                // Limpiar recursos
                _cancellationTokens.TryRemove(executionId, out var cts);
                cts?.Dispose();
            }
        }
        
        /// <summary>
        /// Ejecuta una acción de forma asíncrona (en cola)
        /// </summary>
        public async Task<string> QueueActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            ActionPriority priority = ActionPriority.Normal,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(actionType))
                throw new ArgumentNullException(nameof(actionType));
            
            var queueItem = new ActionQueueItem
            {
                QueueId = GenerateQueueId(),
                ActionType = actionType,
                Parameters = parameters ?? new Dictionary<string, object>(),
                Context = context,
                Priority = priority,
                CreatedAt = DateTime.UtcNow,
                Status = QueueItemStatus.Pending
            };
            
            await _actionQueue.EnqueueAsync(queueItem, cancellationToken);
            
            _logger.LogDebug("Acción encolada: {ActionType}, Queue: {QueueId}, Priority: {Priority}", 
                actionType, queueItem.QueueId, priority);
            
            return queueItem.QueueId;
        }
        
        /// <summary>
        /// Cancela todas las acciones de una ejecución
        /// </summary>
        public async Task CancelActionsAsync(string executionId, CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(executionId))
                throw new ArgumentNullException(nameof(executionId));
            
            try
            {
                _logger.LogInformation("Cancelando acciones para ejecución: {ExecutionId}", executionId);
                
                // Cancelar token de ejecución
                if (_cancellationTokens.TryRemove(executionId, out var cts))
                {
                    cts.Cancel();
                    cts.Dispose();
                }
                
                // Cancelar ejecuciones pendientes
                var executions = _executions.Values
                    .Where(e => e.Context?.ExecutionId == executionId && 
                               (e.Status == ActionExecutionStatus.Pending || 
                                e.Status == ActionExecutionStatus.Running))
                    .ToList();
                
                foreach (var execution in executions)
                {
                    execution.Status = ActionExecutionStatus.Cancelled;
                    execution.EndedAt = DateTime.UtcNow;
                    execution.Error = "Cancelled by execution cancellation";
                }
                
                // Cancelar items en cola
                await _actionQueue.CancelByExecutionIdAsync(executionId, cancellationToken);
                
                _logger.LogInformation("Acciones canceladas para ejecución: {ExecutionId}", executionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cancelar acciones para ejecución: {ExecutionId}", executionId);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene estado de una ejecución de acción
        /// </summary>
        public async Task<ActionExecution> GetExecutionStatusAsync(
            string executionId, 
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(executionId))
                throw new ArgumentNullException(nameof(executionId));
            
            if (_executions.TryGetValue(executionId, out var execution))
            {
                return execution;
            }
            
            // Buscar en almacenamiento persistente si es necesario
            return null;
        }
        
        /// <summary>
        /// Obtiene estado de un item en cola
        /// </summary>
        public async Task<ActionQueueItem> GetQueueItemStatusAsync(
            string queueId, 
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(queueId))
                throw new ArgumentNullException(nameof(queueId));
            
            return await _actionQueue.GetItemAsync(queueId, cancellationToken);
        }
        
        /// <summary>
        /// Lista acciones disponibles
        /// </summary>
        public async Task<List<ActionDefinition>> ListAvailableActionsAsync(
            ActionCategory? category = null,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                var actions = new List<ActionDefinition>();
                
                // Agregar acciones nativas
                actions.AddRange(GetNativeActions(category));
                
                // Agregar acciones de integración
                if (_integrationManager != null)
                {
                    var integrationActions = await _integrationManager.GetAvailableActionsAsync(category, cancellationToken);
                    actions.AddRange(integrationActions);
                }
                
                // Agregar acciones personalizadas
                foreach (var handler in _actionHandlers)
                {
                    var handlerActions = await handler.GetAvailableActionsAsync(cancellationToken);
                    if (category.HasValue)
                    {
                        handlerActions = handlerActions.Where(a => a.Category == category.Value).ToList();
                    }
                    actions.AddRange(handlerActions);
                }
                
                return actions.OrderBy(a => a.Category).ThenBy(a => a.Name).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al listar acciones disponibles");
                throw;
            }
        }
        
        /// <summary>
        /// Valida parámetros de una acción
        /// </summary>
        public async Task<ValidationResult> ValidateActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(actionType))
                throw new ArgumentNullException(nameof(actionType));
            
            try
            {
                // Buscar handler para la acción
                var handler = FindHandlerForAction(actionType);
                if (handler != null)
                {
                    return await handler.ValidateAsync(actionType, parameters, cancellationToken);
                }
                
                // Si es acción de script
                if (actionType.StartsWith("script:", StringComparison.OrdinalIgnoreCase))
                {
                    return await ValidateScriptActionAsync(actionType, parameters, cancellationToken);
                }
                
                // Si es acción de integración
                if (_integrationManager != null)
                {
                    return await _integrationManager.ValidateActionAsync(actionType, parameters, cancellationToken);
                }
                
                return ValidationResult.Error($"No handler found for action type: {actionType}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al validar acción: {ActionType}", actionType);
                return ValidationResult.Error($"Validation error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Prueba una acción
        /// </summary>
        public async Task<ActionTestResult> TestActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(actionType))
                throw new ArgumentNullException(nameof(actionType));
            
            try
            {
                _logger.LogInformation("Probando acción: {ActionType}", actionType);
                
                // Crear contexto de prueba
                var testContext = new PlaybookExecutionContext
                {
                    ContextId = $"test-{Guid.NewGuid():N}",
                    ExecutionId = $"test-{Guid.NewGuid():N}",
                    StepId = "test-step",
                    EventType = "Test",
                    Severity = 5,
                    Source = "ActionOrchestrator",
                    Timestamp = DateTime.UtcNow,
                    Data = new Dictionary<string, object>
                    {
                        { "test", true },
                        { "timestamp", DateTime.UtcNow }
                    }
                };
                
                var outputs = new Dictionary<string, object>();
                
                // Ejecutar acción
                var result = await ExecuteActionAsync(
                    actionType, 
                    parameters, 
                    testContext, 
                    outputs, 
                    cancellationToken);
                
                return new ActionTestResult
                {
                    ActionType = actionType,
                    Success = result.Success,
                    Result = result.Result,
                    Error = result.Error,
                    Duration = result.Duration,
                    Outputs = outputs,
                    Timestamp = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al probar acción: {ActionType}", actionType);
                return new ActionTestResult
                {
                    ActionType = actionType,
                    Success = false,
                    Error = $"Test failed: {ex.Message}",
                    Timestamp = DateTime.UtcNow
                };
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del orquestador
        /// </summary>
        public async Task<ActionOrchestratorStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                var stats = new ActionOrchestratorStats
                {
                    Timestamp = DateTime.UtcNow,
                    TotalExecutions = _executions.Count,
                    ActiveExecutions = _executions.Count(e => 
                        e.Value.Status == ActionExecutionStatus.Running),
                    
                    QueueStats = await _actionQueue.GetStatsAsync(cancellationToken),
                    RetryStats = _retryManager.GetStats(),
                    TimeoutStats = _timeoutManager.GetStats(),
                    
                    ActionHandlers = _actionHandlers.Count,
                    AvailableActions = await GetAvailableActionCountAsync(cancellationToken),
                    
                    IsInitialized = _isInitialized,
                    Uptime = GetOrchestratorUptime()
                };
                
                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener estadísticas del orquestador");
                throw;
            }
        }
        
        /// <summary>
        /// Registra un handler de acción personalizado
        /// </summary>
        public void RegisterActionHandler(IActionHandler handler)
        {
            if (handler == null)
                throw new ArgumentNullException(nameof(handler));
            
            _actionHandlers.Add(handler);
            
            _logger.LogInformation("Handler de acción registrado: {HandlerType}", 
                handler.GetType().Name);
        }
        
        public void Dispose()
        {
            if (_isDisposed)
                return;
            
            _isDisposed = true;
            
            // Cancelar todas las ejecuciones
            foreach (var cts in _cancellationTokens.Values)
            {
                cts.Cancel();
                cts.Dispose();
            }
            
            _cancellationTokens.Clear();
            _executions.Clear();
            
            // Dispose de componentes
            _actionQueue?.Dispose();
            _retryManager?.Dispose();
            _timeoutManager?.Dispose();
            
            GC.SuppressFinalize(this);
        }
        
        #region Métodos Privados
        
        private async Task<ActionExecutionResult> ExecuteActionInternalAsync(
            ActionExecution execution,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            var actionType = execution.ActionType;
            var parameters = execution.Parameters;
            var context = execution.Context;
            
            try
            {
                // Buscar handler para la acción
                var handler = FindHandlerForAction(actionType);
                if (handler != null)
                {
                    _logger.LogDebug("Ejecutando acción con handler: {ActionType}, Handler: {HandlerType}", 
                        actionType, handler.GetType().Name);
                    
                    return await handler.ExecuteAsync(actionType, parameters, context, outputs, cancellationToken);
                }
                
                // Si es acción de script
                if (actionType.StartsWith("script:", StringComparison.OrdinalIgnoreCase))
                {
                    return await ExecuteScriptActionAsync(actionType, parameters, context, outputs, cancellationToken);
                }
                
                // Si es acción de integración
                if (_integrationManager != null && _integrationManager.CanExecute(actionType))
                {
                    return await _integrationManager.ExecuteActionAsync(
                        actionType, parameters, context, outputs, cancellationToken);
                }
                
                // Buscar en registry si está disponible
                if (_actionRegistry != null)
                {
                    var action = await _actionRegistry.GetActionAsync(actionType, cancellationToken);
                    if (action != null)
                    {
                        return await ExecuteRegisteredActionAsync(action, parameters, context, outputs, cancellationToken);
                    }
                }
                
                return ActionExecutionResult.Failed($"No handler or integration found for action type: {actionType}");
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                _logger.LogError(ex, "Error ejecutando acción: {ActionType}, Execution: {ExecutionId}", 
                    actionType, execution.ExecutionId);
                
                // Manejar reintentos
                if (execution.RetryCount < execution.MaxRetries)
                {
                    execution.RetryCount++;
                    
                    OnActionRetry(new ActionRetryEventArgs
                    {
                        ExecutionId = execution.ExecutionId,
                        StepId = context.StepId,
                        ActionType = actionType,
                        RetryCount = execution.RetryCount,
                        MaxRetries = execution.MaxRetries,
                        Error = ex.Message,
                        RetryDelay = _retryManager.GetRetryDelay(execution.RetryCount)
                    });
                    
                    // Esperar antes de reintentar
                    await Task.Delay(_retryManager.GetRetryDelay(execution.RetryCount), cancellationToken);
                    
                    // Reintentar ejecución
                    return await ExecuteActionInternalAsync(execution, outputs, cancellationToken);
                }
                
                return ActionExecutionResult.Failed($"Action failed after {execution.MaxRetries} retries: {ex.Message}");
            }
        }
        
        private async Task RegisterNativeActionsAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Registrar handlers nativos
                var nativeHandlers = new List<IActionHandler>
                {
                    new SystemActionHandler(_logger),
                    new FileSystemActionHandler(_logger),
                    new ProcessActionHandler(_logger),
                    new NetworkActionHandler(_logger),
                    new RegistryActionHandler(_logger),
                    new SecurityActionHandler(_logger),
                    new NotificationActionHandler(_logger),
                    new DataActionHandler(_logger)
                };
                
                foreach (var handler in nativeHandlers)
                {
                    _actionHandlers.Add(handler);
                    
                    if (handler is IInitializable initializable)
                    {
                        await initializable.InitializeAsync(cancellationToken);
                    }
                }
                
                _logger.LogDebug("Registrados {Count} handlers de acción nativos", nativeHandlers.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al registrar acciones nativas");
                throw;
            }
        }
        
        private async Task LoadIntegrationsAsync(CancellationToken cancellationToken)
        {
            if (_integrationManager == null)
                return;
            
            try
            {
                await _integrationManager.InitializeAsync(cancellationToken);
                
                var integrationCount = await _integrationManager.GetIntegrationCountAsync(cancellationToken);
                _logger.LogDebug("Cargadas {Count} integraciones", integrationCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cargar integraciones");
                // No lanzar excepción, permitir que el orquestador funcione sin integraciones
            }
        }
        
        private void StartQueueProcessor()
        {
            Task.Run(async () =>
            {
                while (!_isDisposed)
                {
                    try
                    {
                        await ProcessQueueItemsAsync();
                        await Task.Delay(100); // Pequeña pausa entre ciclos
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error en procesador de cola");
                        await Task.Delay(1000); // Pausa más larga en caso de error
                    }
                }
            });
        }
        
        private async Task ProcessQueueItemsAsync()
        {
            var batchSize = 10;
            var items = await _actionQueue.DequeueBatchAsync(batchSize);
            
            foreach (var item in items)
            {
                try
                {
                    item.Status = QueueItemStatus.Processing;
                    item.ProcessingStartedAt = DateTime.UtcNow;
                    
                    // Actualizar en cola
                    await _actionQueue.UpdateItemAsync(item);
                    
                    // Ejecutar acción
                    var result = await ExecuteActionAsync(
                        item.ActionType,
                        item.Parameters,
                        item.Context,
                        new Dictionary<string, object>(),
                        CancellationToken.None);
                    
                    // Actualizar resultado
                    item.Status = result.Success ? QueueItemStatus.Completed : QueueItemStatus.Failed;
                    item.ProcessingEndedAt = DateTime.UtcNow;
                    item.Result = result.Result;
                    item.Error = result.Error;
                    
                    await _actionQueue.UpdateItemAsync(item);
                    
                    _logger.LogDebug("Item de cola procesado: {QueueId}, Success: {Success}", 
                        item.QueueId, result.Success);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error procesando item de cola: {QueueId}", item.QueueId);
                    
                    item.Status = QueueItemStatus.Failed;
                    item.ProcessingEndedAt = DateTime.UtcNow;
                    item.Error = $"Processing error: {ex.Message}";
                    
                    await _actionQueue.UpdateItemAsync(item);
                }
            }
        }
        
        private IActionHandler FindHandlerForAction(string actionType)
        {
            foreach (var handler in _actionHandlers)
            {
                if (handler.CanExecute(actionType))
                {
                    return handler;
                }
            }
            
            return null;
        }
        
        private async Task<ActionExecutionResult> ExecuteScriptActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            if (_scriptEngine == null)
            {
                return ActionExecutionResult.Failed("Script engine not available");
            }
            
            try
            {
                // Extraer script de la acción
                var scriptName = actionType.Substring("script:".Length);
                
                // Ejecutar script
                var result = await _scriptEngine.ExecuteScriptAsync(
                    scriptName,
                    parameters,
                    context,
                    cancellationToken);
                
                // Procesar outputs
                if (result.Outputs != null)
                {
                    foreach (var output in result.Outputs)
                    {
                        outputs[output.Key] = output.Value;
                    }
                }
                
                return ActionExecutionResult.Success(result.Result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ejecutando script action: {ActionType}", actionType);
                return ActionExecutionResult.Failed($"Script execution failed: {ex.Message}");
            }
        }
        
        private async Task<ActionExecutionResult> ExecuteRegisteredActionAsync(
            RegisteredAction action,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            try
            {
                // Ejecutar acción registrada
                var result = await action.ExecuteAsync(parameters, context, cancellationToken);
                
                // Procesar outputs
                if (result.Outputs != null)
                {
                    foreach (var output in result.Outputs)
                    {
                        outputs[output.Key] = output.Value;
                    }
                }
                
                return ActionExecutionResult.Success(result.Result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ejecutando acción registrada: {ActionType}", action.ActionType);
                return ActionExecutionResult.Failed($"Registered action failed: {ex.Message}");
            }
        }
        
        private async Task<ValidationResult> ValidateScriptActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            CancellationToken cancellationToken)
        {
            if (_scriptEngine == null)
            {
                return ValidationResult.Error("Script engine not available");
            }
            
            try
            {
                var scriptName = actionType.Substring("script:".Length);
                return await _scriptEngine.ValidateScriptAsync(scriptName, parameters, cancellationToken);
            }
            catch (Exception ex)
            {
                return ValidationResult.Error($"Script validation error: {ex.Message}");
            }
        }
        
        private List<ActionDefinition> GetNativeActions(ActionCategory? category = null)
        {
            var actions = new List<ActionDefinition>
            {
                // Acciones de sistema
                new ActionDefinition
                {
                    ActionType = "system:execute_command",
                    Name = "Execute Command",
                    Description = "Execute system command or script",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "command", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "arguments", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "working_directory", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "timeout", Type = ParameterType.Integer, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "system:get_info",
                    Name = "Get System Info",
                    Description = "Retrieve system information",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>()
                },
                
                // Acciones de archivos
                new ActionDefinition
                {
                    ActionType = "file:copy",
                    Name = "Copy File",
                    Description = "Copy file to destination",
                    Category = ActionCategory.FileSystem,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "source", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "destination", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "overwrite", Type = ParameterType.Boolean, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "file:delete",
                    Name = "Delete File",
                    Description = "Delete file or directory",
                    Category = ActionCategory.FileSystem,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "path", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "recursive", Type = ParameterType.Boolean, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "file:quarantine",
                    Name = "Quarantine File",
                    Description = "Move file to quarantine",
                    Category = ActionCategory.Security,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "path", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "reason", Type = ParameterType.String, Required = false }
                    }
                },
                
                // Acciones de proceso
                new ActionDefinition
                {
                    ActionType = "process:terminate",
                    Name = "Terminate Process",
                    Description = "Terminate running process",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "pid", Type = ParameterType.Integer, Required = false },
                        new ActionParameter { Name = "name", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "force", Type = ParameterType.Boolean, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "process:list",
                    Name = "List Processes",
                    Description = "List running processes",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>()
                },
                
                // Acciones de red
                new ActionDefinition
                {
                    ActionType = "network:block_ip",
                    Name = "Block IP Address",
                    Description = "Block IP address in firewall",
                    Category = ActionCategory.Network,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "ip_address", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "direction", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "duration", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "network:test_connection",
                    Name = "Test Connection",
                    Description = "Test network connection",
                    Category = ActionCategory.Network,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "host", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "port", Type = ParameterType.Integer, Required = false },
                        new ActionParameter { Name = "timeout", Type = ParameterType.Integer, Required = false }
                    }
                },
                
                // Acciones de registro
                new ActionDefinition
                {
                    ActionType = "registry:set_value",
                    Name = "Set Registry Value",
                    Description = "Set registry key value",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "path", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "name", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "value", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "type", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "registry:delete_key",
                    Name = "Delete Registry Key",
                    Description = "Delete registry key",
                    Category = ActionCategory.System,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "path", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "recursive", Type = ParameterType.Boolean, Required = false }
                    }
                },
                
                // Acciones de seguridad
                new ActionDefinition
                {
                    ActionType = "security:isolate_endpoint",
                    Name = "Isolate Endpoint",
                    Description = "Isolate endpoint from network",
                    Category = ActionCategory.Security,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "endpoint_id", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "reason", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "duration", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "security:run_scan",
                    Name = "Run Security Scan",
                    Description = "Run security scan on endpoint",
                    Category = ActionCategory.Security,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "scan_type", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "target", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "intensity", Type = ParameterType.String, Required = false }
                    }
                },
                
                // Acciones de notificación
                new ActionDefinition
                {
                    ActionType = "notification:send_email",
                    Name = "Send Email",
                    Description = "Send email notification",
                    Category = ActionCategory.Notification,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "to", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "subject", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "body", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "template", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "notification:send_slack",
                    Name = "Send Slack Message",
                    Description = "Send message to Slack",
                    Category = ActionCategory.Notification,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "channel", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "message", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "attachments", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "notification:create_alert",
                    Name = "Create Alert",
                    Description = "Create security alert",
                    Category = ActionCategory.Notification,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "title", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "description", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "severity", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "source", Type = ParameterType.String, Required = false }
                    }
                },
                
                // Acciones de datos
                new ActionDefinition
                {
                    ActionType = "data:query_database",
                    Name = "Query Database",
                    Description = "Execute database query",
                    Category = ActionCategory.Data,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "query", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "database", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "parameters", Type = ParameterType.String, Required = false }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "data:export_csv",
                    Name = "Export to CSV",
                    Description = "Export data to CSV file",
                    Category = ActionCategory.Data,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "data", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "file_path", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "include_header", Type = ParameterType.Boolean, Required = false }
                    }
                },
                
                // Acciones de utilidad
                new ActionDefinition
                {
                    ActionType = "utility:delay",
                    Name = "Delay Execution",
                    Description = "Delay execution for specified time",
                    Category = ActionCategory.Utility,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "duration", Type = ParameterType.String, Required = true }
                    }
                },
                
                new ActionDefinition
                {
                    ActionType = "utility:log_message",
                    Name = "Log Message",
                    Description = "Log message to system",
                    Category = ActionCategory.Utility,
                    Parameters = new List<ActionParameter>
                    {
                        new ActionParameter { Name = "message", Type = ParameterType.String, Required = true },
                        new ActionParameter { Name = "level", Type = ParameterType.String, Required = false },
                        new ActionParameter { Name = "category", Type = ParameterType.String, Required = false }
                    }
                }
            };
            
            if (category.HasValue)
            {
                actions = actions.Where(a => a.Category == category.Value).ToList();
            }
            
            return actions;
        }
        
        private TimeSpan GetTimeout(string actionType, Dictionary<string, object> parameters)
        {
            // Configuraciones de timeout por tipo de acción
            var defaultTimeout = TimeSpan.FromMinutes(5);
            
            if (parameters.TryGetValue("timeout", out var timeoutValue))
            {
                if (timeoutValue is int timeoutSeconds)
                {
                    return TimeSpan.FromSeconds(timeoutSeconds);
                }
                else if (timeoutValue is string timeoutString && 
                         TimeSpan.TryParse(timeoutString, out var parsedTimeout))
                {
                    return parsedTimeout;
                }
            }
            
            // Timeout específicos por tipo de acción
            return actionType switch
            {
                string s when s.StartsWith("system:") => TimeSpan.FromMinutes(10),
                string s when s.StartsWith("network:") => TimeSpan.FromMinutes(2),
                string s when s.StartsWith("security:") => TimeSpan.FromMinutes(15),
                string s when s.StartsWith("data:") => TimeSpan.FromMinutes(30),
                _ => defaultTimeout
            };
        }
        
        private int GetMaxRetries(string actionType, Dictionary<string, object> parameters)
        {
            if (parameters.TryGetValue("max_retries", out var retriesValue))
            {
                if (retriesValue is int retries)
                {
                    return retries;
                }
                else if (retriesValue is string retriesString && 
                         int.TryParse(retriesString, out var parsedRetries))
                {
                    return parsedRetries;
                }
            }
            
            // Retries específicos por tipo de acción
            return actionType switch
            {
                string s when s.StartsWith("network:") => 3,
                string s when s.StartsWith("notification:") => 2,
                _ => 1
            };
        }
        
        private async Task<int> GetAvailableActionCountAsync(CancellationToken cancellationToken)
        {
            var actions = await ListAvailableActionsAsync(cancellationToken: cancellationToken);
            return actions.Count;
        }
        
        private TimeSpan GetOrchestratorUptime()
        {
            // Implementar cálculo de uptime real
            return TimeSpan.FromMinutes(0);
        }
        
        private string GenerateExecutionId()
        {
            return $"ACT-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateQueueId()
        {
            return $"QUE-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private void OnActionCompleted(ActionCompletedEventArgs e)
        {
            ActionCompleted?.Invoke(this, e);
        }
        
        private void OnActionFailed(ActionFailedEventArgs e)
        {
            ActionFailed?.Invoke(this, e);
        }
        
        private void OnActionTimeout(ActionTimeoutEventArgs e)
        {
            ActionTimeout?.Invoke(this, e);
        }
        
        private void OnActionRetry(ActionRetryEventArgs e)
        {
            ActionRetry?.Invoke(this, e);
        }
        
        private void ValidateInitialized()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException(
                    "ActionOrchestrator no está inicializado. Llame a InitializeAsync primero.");
            }
        }
        
        #endregion
    }
    
    #region Clases de Soporte
    
    public class ActionExecution
    {
        public string ExecutionId { get; set; }
        public string ActionType { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        public PlaybookExecutionContext Context { get; set; }
        
        public ActionExecutionStatus Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? StartedAt { get; set; }
        public DateTime? EndedAt { get; set; }
        public TimeSpan? Duration { get; set; }
        
        public object Result { get; set; }
        public string Error { get; set; }
        
        public int RetryCount { get; set; }
        public int MaxRetries { get; set; }
        public TimeSpan Timeout { get; set; }
        
        public ActionExecution()
        {
            Parameters = new Dictionary<string, object>();
            Status = ActionExecutionStatus.Pending;
        }
    }
    
    public class ActionQueueItem
    {
        public string QueueId { get; set; }
        public string ActionType { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        public PlaybookExecutionContext Context { get; set; }
        
        public ActionPriority Priority { get; set; }
        public QueueItemStatus Status { get; set; }
        
        public DateTime CreatedAt { get; set; }
        public DateTime? ProcessingStartedAt { get; set; }
        public DateTime? ProcessingEndedAt { get; set; }
        
        public object Result { get; set; }
        public string Error { get; set; }
        
        public ActionQueueItem()
        {
            Parameters = new Dictionary<string, object>();
            Status = QueueItemStatus.Pending;
            Priority = ActionPriority.Normal;
        }
    }
    
    public class ActionDefinition
    {
        public string ActionType { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ActionCategory Category { get; set; }
        public List<ActionParameter> Parameters { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public ActionDefinition()
        {
            Parameters = new List<ActionParameter>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class ActionParameter
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public ParameterType Type { get; set; }
        public bool Required { get; set; }
        public object DefaultValue { get; set; }
        public List<string> AllowedValues { get; set; }
        
        public ActionParameter()
        {
            AllowedValues = new List<string>();
        }
    }
    
    public class ActionTestResult
    {
        public string ActionType { get; set; }
        public bool Success { get; set; }
        public object Result { get; set; }
        public string Error { get; set; }
        public TimeSpan? Duration { get; set; }
        public Dictionary<string, object> Outputs { get; set; }
        public DateTime Timestamp { get; set; }
        
        public ActionTestResult()
        {
            Outputs = new Dictionary<string, object>();
        }
    }
    
    public class ActionOrchestratorStats
    {
        public DateTime Timestamp { get; set; }
        public int TotalExecutions { get; set; }
        public int ActiveExecutions { get; set; }
        public int AvailableActions { get; set; }
        public int ActionHandlers { get; set; }
        
        public QueueStats QueueStats { get; set; }
        public RetryStats RetryStats { get; set; }
        public TimeoutStats TimeoutStats { get; set; }
        
        public bool IsInitialized { get; set; }
        public TimeSpan Uptime { get; set; }
    }
    
    public enum ActionExecutionStatus
    {
        Pending,
        Running,
        Completed,
        Failed,
        Cancelled,
        Timeout
    }
    
    public enum QueueItemStatus
    {
        Pending,
        Processing,
        Completed,
        Failed,
        Cancelled
    }
    
    public enum ActionPriority
    {
        Low = 1,
        Normal = 2,
        High = 3,
        Critical = 4
    }
    
    public enum ActionCategory
    {
        System,
        FileSystem,
        Network,
        Security,
        Notification,
        Data,
        Utility,
        Integration,
        Custom
    }
    
    #endregion
    
    #region Handlers de Acción Nativos
    
    public class SystemActionHandler : IActionHandler, IInitializable
    {
        private readonly ILogger<SystemActionHandler> _logger;
        
        public SystemActionHandler(ILogger<SystemActionHandler> logger)
        {
            _logger = logger;
        }
        
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
        }
        
        public bool CanExecute(string actionType)
        {
            return actionType.StartsWith("system:", StringComparison.OrdinalIgnoreCase);
        }
        
        public async Task<ActionExecutionResult> ExecuteAsync(
            string actionType,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            try
            {
                return actionType.ToLowerInvariant() switch
                {
                    "system:execute_command" => await ExecuteCommandAsync(parameters, context, outputs, cancellationToken),
                    "system:get_info" => await GetSystemInfoAsync(parameters, context, outputs, cancellationToken),
                    _ => ActionExecutionResult.Failed($"Unsupported system action: {actionType}")
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing system action: {ActionType}", actionType);
                return ActionExecutionResult.Failed($"System action failed: {ex.Message}");
            }
        }
        
        public async Task<List<ActionDefinition>> GetAvailableActionsAsync(CancellationToken cancellationToken)
        {
            return await Task.FromResult(new List<ActionDefinition>
            {
                new ActionDefinition
                {
                    ActionType = "system:execute_command",
                    Name = "Execute Command",
                    Description = "Execute system command or script",
                    Category = ActionCategory.System
                },
                new ActionDefinition
                {
                    ActionType = "system:get_info",
                    Name = "Get System Info",
                    Description = "Retrieve system information",
                    Category = ActionCategory.System
                }
            });
        }
        
        public async Task<ValidationResult> ValidateAsync(
            string actionType,
            Dictionary<string, object> parameters,
            CancellationToken cancellationToken)
        {
            return actionType.ToLowerInvariant() switch
            {
                "system:execute_command" => ValidateExecuteCommand(parameters),
                "system:get_info" => ValidationResult.Success(),
                _ => ValidationResult.Error($"Unsupported system action: {actionType}")
            };
        }
        
        private async Task<ActionExecutionResult> ExecuteCommandAsync(
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            if (!parameters.TryGetValue("command", out var commandObj) || commandObj is not string command)
            {
                return ActionExecutionResult.Failed("Command parameter is required and must be a string");
            }
            
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c {command}",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                
                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync(cancellationToken);
                
                var result = new
                {
                    ExitCode = process.ExitCode,
                    StandardOutput = output,
                    StandardError = error
                };
                
                return ActionExecutionResult.Success(result);
            }
            catch (Exception ex)
            {
                return ActionExecutionResult.Failed($"Command execution failed: {ex.Message}");
            }
        }
        
        private async Task<ActionExecutionResult> GetSystemInfoAsync(
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken)
        {
            try
            {
                var info = new
                {
                    MachineName = Environment.MachineName,
                    OSVersion = Environment.OSVersion.ToString(),
                    Environment.ProcessorCount,
                    SystemDirectory = Environment.SystemDirectory,
                    UserName = Environment.UserName,
                    Is64BitProcess = Environment.Is64BitProcess,
                    Is64BitOperatingSystem = Environment.Is64BitOperatingSystem,
                    CurrentDirectory = Environment.CurrentDirectory,
                    TickCount = Environment.TickCount,
                    Version = Environment.Version.ToString(),
                    WorkingSet = Environment.WorkingSet,
                    Timestamp = DateTime.UtcNow
                };
                
                return ActionExecutionResult.Success(info);
            }
            catch (Exception ex)
            {
                return ActionExecutionResult.Failed($"Failed to get system info: {ex.Message}");
            }
        }
        
        private ValidationResult ValidateExecuteCommand(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("command"))
            {
                return ValidationResult.Error("Command parameter is required");
            }
            
            return ValidationResult.Success();
        }
    }
    
    // Implementaciones similares para otros handlers nativos:
    // FileSystemActionHandler, ProcessActionHandler, NetworkActionHandler, etc.
    
    #endregion
}