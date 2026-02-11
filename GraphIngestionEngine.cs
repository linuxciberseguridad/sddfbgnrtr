using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.Logging;
using BWP.Enterprise.Cloud.Storage;
using System.Text.Json;

namespace BWP.Enterprise.Cloud.ThreatGraph
{
    /// <summary>
    /// Motor de ingesta de eventos al grafo de amenazas
    /// Procesa eventos de telemetría y los transforma en nodos y aristas del grafo
    /// </summary>
    public sealed class GraphIngestionEngine
    {
        private static readonly Lazy<GraphIngestionEngine> _instance = 
            new Lazy<GraphIngestionEngine>(() => new GraphIngestionEngine());
        
        public static GraphIngestionEngine Instance => _instance.Value;
        
        private readonly ILogger<GraphIngestionEngine> _logger;
        private readonly ThreatGraphDatabase _graphDatabase;
        private readonly ConcurrentQueue<IngestionTask> _ingestionQueue;
        private readonly Dictionary<string, NodeTemplate> _nodeTemplates;
        private readonly Dictionary<string, EdgeTemplate> _edgeTemplates;
        private readonly List<IngestionRule> _ingestionRules;
        private readonly ConcurrentDictionary<string, BatchProcessingInfo> _activeBatches;
        private bool _isRunning;
        private int _maxBatchSize;
        private int _maxQueueSize;
        private TimeSpan _ingestionTimeout;
        
        public GraphIngestionEngine()
        {
            _logger = LogManager.CreateLogger<GraphIngestionEngine>();
            _graphDatabase = new ThreatGraphDatabase();
            _ingestionQueue = new ConcurrentQueue<IngestionTask>();
            _nodeTemplates = new Dictionary<string, NodeTemplate>();
            _edgeTemplates = new Dictionary<string, EdgeTemplate>();
            _ingestionRules = new List<IngestionRule>();
            _activeBatches = new ConcurrentDictionary<string, BatchProcessingInfo>();
            _isRunning = false;
            _maxBatchSize = 1000;
            _maxQueueSize = 10000;
            _ingestionTimeout = TimeSpan.FromSeconds(30);
        }
        
        /// <summary>
        /// Inicializa el motor de ingesta
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Inicializando GraphIngestionEngine...");
                
                // 1. Cargar plantillas de nodos y aristas
                await LoadNodeTemplatesAsync();
                await LoadEdgeTemplatesAsync();
                
                // 2. Cargar reglas de ingesta
                await LoadIngestionRulesAsync();
                
                // 3. Inicializar base de datos del grafo
                await _graphDatabase.InitializeAsync();
                
                // 4. Iniciar workers de procesamiento
                StartProcessingWorkers();
                
                _logger.LogInformation("GraphIngestionEngine inicializado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al inicializar GraphIngestionEngine");
                throw;
            }
        }
        
        /// <summary>
        /// Encola eventos para ingesta al grafo
        /// </summary>
        public async Task<IngestionResult> IngestEventsAsync(List<TelemetryEvent> events, string batchId = null)
        {
            if (events == null || events.Count == 0)
                return IngestionResult.Empty();
            
            if (events.Count > _maxBatchSize)
            {
                return IngestionResult.Error($"Lote excede tamaño máximo: {events.Count} > {_maxBatchSize}");
            }
            
            try
            {
                batchId ??= Guid.NewGuid().ToString();
                var startTime = DateTime.UtcNow;
                
                _logger.LogDebug($"Ingiriendo lote {batchId} con {events.Count} eventos");
                
                // 1. Validar eventos
                var validationResult = await ValidateEventsAsync(events);
                if (!validationResult.IsValid)
                {
                    return IngestionResult.Error($"Validación fallida: {validationResult.ErrorMessage}");
                }
                
                // 2. Encolar tareas de ingesta
                var ingestionTasks = CreateIngestionTasks(events, batchId);
                
                foreach (var task in ingestionTasks)
                {
                    if (_ingestionQueue.Count >= _maxQueueSize)
                    {
                        _logger.LogWarning($"Cola de ingesta llena: {_ingestionQueue.Count}/{_maxQueueSize}");
                        break;
                    }
                    
                    _ingestionQueue.Enqueue(task);
                }
                
                // 3. Registrar lote activo
                var batchInfo = new BatchProcessingInfo
                {
                    BatchId = batchId,
                    TotalTasks = ingestionTasks.Count,
                    ProcessedTasks = 0,
                    FailedTasks = 0,
                    StartTime = startTime,
                    Status = BatchStatus.Queued,
                    Source = "Telemetry"
                };
                
                _activeBatches[batchId] = batchInfo;
                
                // 4. Monitorear progreso
                _ = MonitorBatchProgressAsync(batchId);
                
                return new IngestionResult
                {
                    BatchId = batchId,
                    TotalEvents = events.Count,
                    CreatedTasks = ingestionTasks.Count,
                    Status = IngestionStatus.Queued,
                    QueuePosition = _ingestionQueue.Count,
                    EstimatedCompletion = EstimateCompletionTime(ingestionTasks.Count)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error ingiriendo eventos del lote {batchId}");
                return IngestionResult.Error($"Error de ingesta: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Ingesta directa (síncrona) para eventos críticos
        /// </summary>
        public async Task<IngestionResult> IngestCriticalEventAsync(TelemetryEvent criticalEvent)
        {
            if (criticalEvent == null)
                return IngestionResult.Error("Evento crítico es null");
            
            try
            {
                var startTime = DateTime.UtcNow;
                var batchId = $"critical_{Guid.NewGuid().ToString().Substring(0, 8)}";
                
                _logger.LogWarning($"Ingiriendo evento crítico: {criticalEvent.EventType}");
                
                // 1. Procesamiento prioritario
                var graphNode = await CreateGraphNodeAsync(criticalEvent, true);
                var graphEdges = await CreateGraphEdgesAsync(criticalEvent, graphNode, true);
                
                // 2. Inserción inmediata en el grafo
                await _graphDatabase.AddNodeAsync(graphNode, true); // prioridad alta
                
                foreach (var edge in graphEdges)
                {
                    await _graphDatabase.AddEdgeAsync(edge, true);
                }
                
                // 3. Actualizar índices inmediatamente
                await _graphDatabase.RefreshIndicesAsync();
                
                var processingTime = DateTime.UtcNow - startTime;
                
                _logger.LogInformation($"Evento crítico ingerido en {processingTime.TotalMilliseconds}ms");
                
                return new IngestionResult
                {
                    BatchId = batchId,
                    TotalEvents = 1,
                    CreatedTasks = 1,
                    ProcessedTasks = 1,
                    Status = IngestionStatus.Completed,
                    ProcessingTime = processingTime,
                    IsCritical = true
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ingiriendo evento crítico");
                return IngestionResult.Error($"Error crítico de ingesta: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas de ingesta
        /// </summary>
        public async Task<IngestionStats> GetStatsAsync()
        {
            try
            {
                var queueStats = await GetQueueStatisticsAsync();
                var batchStats = await GetBatchStatisticsAsync();
                var graphStats = await _graphDatabase.GetStatisticsAsync();
                
                return new IngestionStats
                {
                    Timestamp = DateTime.UtcNow,
                    IsRunning = _isRunning,
                    QueueSize = _ingestionQueue.Count,
                    ActiveBatches = _activeBatches.Count,
                    NodeTemplates = _nodeTemplates.Count,
                    EdgeTemplates = _edgeTemplates.Count,
                    IngestionRules = _ingestionRules.Count,
                    QueueStatistics = queueStats,
                    BatchStatistics = batchStats,
                    GraphStatistics = graphStats,
                    MemoryUsage = GetMemoryUsage()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo estadísticas de ingesta");
                return new IngestionStats { IsRunning = false };
            }
        }
        
        /// <summary>
        /// Limpia eventos antiguos del grafo
        /// </summary>
        public async Task<CleanupResult> CleanupOldEventsAsync(TimeSpan retentionPeriod)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow - retentionPeriod;
                
                _logger.LogInformation($"Limpiando eventos anteriores a {cutoffDate:yyyy-MM-dd}");
                
                // 1. Obtener nodos antiguos
                var oldNodes = await _graphDatabase.GetNodesOlderThanAsync(cutoffDate);
                
                if (oldNodes.Count == 0)
                {
                    return new CleanupResult
                    {
                        DeletedNodes = 0,
                        DeletedEdges = 0,
                        Status = CleanupStatus.NoDataToClean
                    };
                }
                
                // 2. Eliminar nodos y aristas relacionadas
                var deletedNodes = 0;
                var deletedEdges = 0;
                
                foreach (var node in oldNodes)
                {
                    var edgesDeleted = await _graphDatabase.DeleteNodeAndEdgesAsync(node.Id);
                    deletedNodes++;
                    deletedEdges += edgesDeleted;
                    
                    // Control de velocidad para no sobrecargar
                    if (deletedNodes % 100 == 0)
                    {
                        await Task.Delay(10);
                    }
                }
                
                // 3. Vaciar espacio liberado
                await _graphDatabase.VacuumAsync();
                
                _logger.LogInformation($"Limpieza completada: {deletedNodes} nodos y {deletedEdges} aristas eliminadas");
                
                return new CleanupResult
                {
                    DeletedNodes = deletedNodes,
                    DeletedEdges = deletedEdges,
                    Status = CleanupStatus.Completed,
                    CleanupTime = DateTime.UtcNow,
                    FreedMemory = await CalculateFreedMemoryAsync(deletedNodes, deletedEdges)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error limpiando eventos antiguos");
                return new CleanupResult
                {
                    Status = CleanupStatus.Failed,
                    ErrorMessage = ex.Message
                };
            }
        }
        
        /// <summary>
        /// Reconstruye índices del grafo para optimización
        /// </summary>
        public async Task<IndexRebuildResult> RebuildGraphIndicesAsync()
        {
            try
            {
                _logger.LogInformation("Reconstruyendo índices del grafo...");
                
                var startTime = DateTime.UtcNow;
                
                // 1. Detener ingesta temporalmente
                var wasRunning = _isRunning;
                if (_isRunning)
                {
                    await StopProcessingAsync();
                }
                
                // 2. Reconstruir índices principales
                await _graphDatabase.RebuildIndicesAsync();
                
                // 3. Reconstruir índices secundarios
                await _graphDatabase.RebuildSecondaryIndicesAsync();
                
                // 4. Actualizar estadísticas
                await _graphDatabase.UpdateStatisticsAsync();
                
                var processingTime = DateTime.UtcNow - startTime;
                
                // 5. Reanudar ingesta si estaba activa
                if (wasRunning)
                {
                    await StartProcessingAsync();
                }
                
                _logger.LogInformation($"Índices reconstruidos en {processingTime.TotalSeconds:F2} segundos");
                
                return new IndexRebuildResult
                {
                    Status = RebuildStatus.Completed,
                    ProcessingTime = processingTime,
                    IndexesRebuilt = await _graphDatabase.GetIndexCountAsync(),
                    MemoryOptimized = await _graphDatabase.GetMemoryOptimizationAsync()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reconstruyendo índices");
                return new IndexRebuildResult
                {
                    Status = RebuildStatus.Failed,
                    ErrorMessage = ex.Message
                };
            }
        }
        
        #region Métodos privados
        
        private async Task LoadNodeTemplatesAsync()
        {
            // Plantillas predefinidas para diferentes tipos de nodos
            _nodeTemplates["PROCESS"] = new NodeTemplate
            {
                TemplateId = "PROCESS",
                NodeType = "PROCESS",
                RequiredProperties = new List<string> { "ProcessId", "ProcessName", "Timestamp" },
                OptionalProperties = new List<string> { "ParentProcessId", "CommandLine", "User", "IntegrityLevel" },
                IndexProperties = new List<string> { "ProcessId", "ProcessName", "Timestamp" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "NodeColor", "#FF6B6B" },
                    { "NodeSize", 30 },
                    { "IsMalicious", false }
                }
            };
            
            _nodeTemplates["FILE"] = new NodeTemplate
            {
                TemplateId = "FILE",
                NodeType = "FILE",
                RequiredProperties = new List<string> { "FilePath", "FileSize", "Timestamp" },
                OptionalProperties = new List<string> { "FileHash", "FileOwner", "Permissions", "FileType" },
                IndexProperties = new List<string> { "FilePath", "FileHash", "Timestamp" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "NodeColor", "#4ECDC4" },
                    { "NodeSize", 25 },
                    { "IsSensitive", false }
                }
            };
            
            _nodeTemplates["NETWORK"] = new NodeTemplate
            {
                TemplateId = "NETWORK",
                NodeType = "NETWORK",
                RequiredProperties = new List<string> { "RemoteAddress", "RemotePort", "Protocol", "Timestamp" },
                OptionalProperties = new List<string> { "LocalAddress", "LocalPort", "ConnectionState", "BytesTransferred" },
                IndexProperties = new List<string> { "RemoteAddress", "RemotePort", "Protocol", "Timestamp" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "NodeColor", "#45B7D1" },
                    { "NodeSize", 28 },
                    { "IsExternal", true }
                }
            };
            
            _nodeTemplates["REGISTRY"] = new NodeTemplate
            {
                TemplateId = "REGISTRY",
                NodeType = "REGISTRY",
                RequiredProperties = new List<string> { "RegistryPath", "Operation", "Timestamp" },
                OptionalProperties = new List<string> { "ValueName", "ValueData", "ValueType", "User" },
                IndexProperties = new List<string> { "RegistryPath", "Operation", "Timestamp" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "NodeColor", "#96CEB4" },
                    { "NodeSize", 22 },
                    { "IsPersistence", false }
                }
            };
            
            _nodeTemplates["USER"] = new NodeTemplate
            {
                TemplateId = "USER",
                NodeType = "USER",
                RequiredProperties = new List<string> { "UserId", "UserName", "Domain" },
                OptionalProperties = new List<string> { "SessionId", "LoginTime", "Privileges", "Groups" },
                IndexProperties = new List<string> { "UserId", "UserName", "Domain" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "NodeColor", "#FFEAA7" },
                    { "NodeSize", 35 },
                    { "IsAdmin", false }
                }
            };
            
            await Task.CompletedTask;
        }
        
        private async Task LoadEdgeTemplatesAsync()
        {
            // Plantillas predefinidas para diferentes tipos de aristas
            _edgeTemplates["PROCESS_CREATED"] = new EdgeTemplate
            {
                TemplateId = "PROCESS_CREATED",
                EdgeType = "PROCESS_CREATED",
                SourceType = "PROCESS",
                TargetType = "PROCESS",
                RequiredProperties = new List<string> { "Timestamp", "ParentProcessId" },
                OptionalProperties = new List<string> { "CommandLine", "IntegrityLevel" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "EdgeColor", "#FF9999" },
                    { "EdgeWidth", 2 },
                    { "IsParentChild", true }
                }
            };
            
            _edgeTemplates["FILE_ACCESSED"] = new EdgeTemplate
            {
                TemplateId = "FILE_ACCESSED",
                EdgeType = "FILE_ACCESSED",
                SourceType = "PROCESS",
                TargetType = "FILE",
                RequiredProperties = new List<string> { "Timestamp", "AccessType" },
                OptionalProperties = new List<string> { "AccessMask", "Result", "ShareMode" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "EdgeColor", "#99FF99" },
                    { "EdgeWidth", 1 },
                    { "IsWriteOperation", false }
                }
            };
            
            _edgeTemplates["NETWORK_CONNECTION"] = new EdgeTemplate
            {
                TemplateId = "NETWORK_CONNECTION",
                EdgeType = "NETWORK_CONNECTION",
                SourceType = "PROCESS",
                TargetType = "NETWORK",
                RequiredProperties = new List<string> { "Timestamp", "Direction" },
                OptionalProperties = new List<string> { "Protocol", "Port", "State", "Duration" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "EdgeColor", "#9999FF" },
                    { "EdgeWidth", 1 },
                    { "IsOutbound", true }
                }
            };
            
            _edgeTemplates["REGISTRY_MODIFIED"] = new EdgeTemplate
            {
                TemplateId = "REGISTRY_MODIFIED",
                EdgeType = "REGISTRY_MODIFIED",
                SourceType = "PROCESS",
                TargetType = "REGISTRY",
                RequiredProperties = new List<string> { "Timestamp", "Operation" },
                OptionalProperties = new List<string> { "ValueType", "OldValue", "NewValue" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "EdgeColor", "#FFFF99" },
                    { "EdgeWidth", 1 },
                    { "IsPersistence", false }
                }
            };
            
            _edgeTemplates["USER_ACTION"] = new EdgeTemplate
            {
                TemplateId = "USER_ACTION",
                EdgeType = "USER_ACTION",
                SourceType = "USER",
                TargetType = "PROCESS",
                RequiredProperties = new List<string> { "Timestamp", "ActionType" },
                OptionalProperties = new List<string> { "SessionId", "PrivilegesUsed", "Result" },
                DefaultProperties = new Dictionary<string, object>
                {
                    { "EdgeColor", "#FF99FF" },
                    { "EdgeWidth", 3 },
                    { "IsPrivileged", false }
                }
            };
            
            await Task.CompletedTask;
        }
        
        private async Task LoadIngestionRulesAsync()
        {
            // Reglas para determinar cómo ingerir eventos
            _ingestionRules.Add(new IngestionRule
            {
                RuleId = "RULE_001",
                Name = "Regla de Proceso",
                Description = "Ingerir eventos de creación de procesos",
                Condition = "EventType == 'ProcessCreated'",
                NodeTemplate = "PROCESS",
                EdgeTemplates = new List<string> { "PROCESS_CREATED", "USER_ACTION" },
                Priority = 1,
                Enabled = true
            });
            
            _ingestionRules.Add(new IngestionRule
            {
                RuleId = "RULE_002",
                Name = "Regla de Archivo",
                Description = "Ingerir eventos de acceso a archivos",
                Condition = "EventType.Contains('File')",
                NodeTemplate = "FILE",
                EdgeTemplates = new List<string> { "FILE_ACCESSED" },
                Priority = 2,
                Enabled = true
            });
            
            _ingestionRules.Add(new IngestionRule
            {
                RuleId = "RULE_003",
                Name = "Regla de Red",
                Description = "Ingerir eventos de red",
                Condition = "EventType.Contains('Network')",
                NodeTemplate = "NETWORK",
                EdgeTemplates = new List<string> { "NETWORK_CONNECTION" },
                Priority = 1,
                Enabled = true
            });
            
            _ingestionRules.Add(new IngestionRule
            {
                RuleId = "RULE_004",
                Name = "Regla de Registro",
                Description = "Ingerir eventos de registro",
                Condition = "EventType.Contains('Registry')",
                NodeTemplate = "REGISTRY",
                EdgeTemplates = new List<string> { "REGISTRY_MODIFIED" },
                Priority = 2,
                Enabled = true
            });
            
            _ingestionRules.Add(new IngestionRule
            {
                RuleId = "RULE_005",
                Name = "Regla de Usuario",
                Description = "Ingerir eventos de usuario",
                Condition = "Data.ContainsKey('UserId') && !string.IsNullOrEmpty(Data['UserId'])",
                NodeTemplate = "USER",
                EdgeTemplates = new List<string> { "USER_ACTION" },
                Priority = 3,
                Enabled = true
            });
            
            await Task.CompletedTask;
        }
        
        private void StartProcessingWorkers()
        {
            // Iniciar múltiples workers para procesamiento paralelo
            var workerCount = Math.Max(Environment.ProcessorCount / 2, 2);
            
            for (int i = 0; i < workerCount; i++)
            {
                Task.Run(async () => await ProcessingWorkerAsync(i));
            }
            
            _isRunning = true;
            _logger.LogInformation($"Iniciados {workerCount} workers de procesamiento");
        }
        
        private async Task ProcessingWorkerAsync(int workerId)
        {
            _logger.LogDebug($"Worker {workerId} iniciado");
            
            while (_isRunning)
            {
                try
                {
                    if (_ingestionQueue.TryDequeue(out var task))
                    {
                        await ProcessIngestionTaskAsync(task, workerId);
                    }
                    else
                    {
                        // Esperar si la cola está vacía
                        await Task.Delay(100);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error en worker {workerId}");
                    await Task.Delay(1000); // Esperar antes de reintentar
                }
            }
            
            _logger.LogDebug($"Worker {workerId} detenido");
        }
        
        private async Task ProcessIngestionTaskAsync(IngestionTask task, int workerId)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                _logger.LogTrace($"Worker {workerId} procesando tarea {task.TaskId}");
                
                // 1. Procesar nodo
                var node = await CreateGraphNodeAsync(task.Event, task.IsCritical);
                
                // 2. Procesar aristas
                var edges = await CreateGraphEdgesAsync(task.Event, node, task.IsCritical);
                
                // 3. Insertar en base de datos
                await _graphDatabase.AddNodeAsync(node, task.IsCritical);
                
                foreach (var edge in edges)
                {
                    await _graphDatabase.AddEdgeAsync(edge, task.IsCritical);
                }
                
                // 4. Actualizar contadores de lote
                if (_activeBatches.TryGetValue(task.BatchId, out var batchInfo))
                {
                    batchInfo.ProcessedTasks++;
                    batchInfo.LastUpdate = DateTime.UtcNow;
                    
                    if (batchInfo.ProcessedTasks >= batchInfo.TotalTasks)
                    {
                        batchInfo.Status = BatchStatus.Completed;
                        batchInfo.EndTime = DateTime.UtcNow;
                        batchInfo.ProcessingTime = batchInfo.EndTime - batchInfo.StartTime;
                    }
                    
                    _activeBatches[task.BatchId] = batchInfo;
                }
                
                var processingTime = DateTime.UtcNow - startTime;
                
                if (processingTime > TimeSpan.FromSeconds(1))
                {
                    _logger.LogWarning($"Tarea {task.TaskId} tomó {processingTime.TotalMilliseconds}ms");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error procesando tarea {task.TaskId}");
                
                // Registrar fallo en lote
                if (_activeBatches.TryGetValue(task.BatchId, out var batchInfo))
                {
                    batchInfo.FailedTasks++;
                    _activeBatches[task.BatchId] = batchInfo;
                }
            }
        }
        
        private async Task<EventValidationResult> ValidateEventsAsync(List<TelemetryEvent> events)
        {
            var result = new EventValidationResult();
            
            foreach (var evt in events)
            {
                var validation = ValidateSingleEvent(evt);
                
                if (!validation.IsValid)
                {
                    result.InvalidEvents.Add(validation);
                }
                else
                {
                    result.ValidEvents.Add(evt);
                }
            }
            
            result.TotalEvents = events.Count;
            result.ValidCount = result.ValidEvents.Count;
            result.InvalidCount = result.InvalidEvents.Count;
            result.IsValid = result.InvalidCount == 0;
            
            if (result.InvalidCount > 0)
            {
                result.ErrorMessage = $"{result.InvalidCount} eventos inválidos encontrados";
                _logger.LogWarning(result.ErrorMessage);
            }
            
            return result;
        }
        
        private EventValidation ValidateSingleEvent(TelemetryEvent evt)
        {
            var validation = new EventValidation
            {
                EventId = evt.EventId,
                IsValid = true
            };
            
            // Validaciones básicas
            if (string.IsNullOrEmpty(evt.EventId))
            {
                validation.IsValid = false;
                validation.Issues.Add("EventId es requerido");
            }
            
            if (evt.Timestamp == default || evt.Timestamp > DateTime.UtcNow.AddMinutes(5))
            {
                validation.IsValid = false;
                validation.Issues.Add("Timestamp inválido o en futuro");
            }
            
            if (string.IsNullOrEmpty(evt.EventType))
            {
                validation.IsValid = false;
                validation.Issues.Add("EventType es requerido");
            }
            
            if (evt.Data == null || evt.Data.Count == 0)
            {
                validation.IsValid = false;
                validation.Issues.Add("Data no puede estar vacío");
            }
            
            return validation;
        }
        
        private List<IngestionTask> CreateIngestionTasks(List<TelemetryEvent> events, string batchId)
        {
            var tasks = new List<IngestionTask>();
            
            foreach (var evt in events)
            {
                var task = new IngestionTask
                {
                    TaskId = Guid.NewGuid().ToString(),
                    BatchId = batchId,
                    Event = evt,
                    IsCritical = IsCriticalEvent(evt),
                    CreatedAt = DateTime.UtcNow,
                    Priority = GetEventPriority(evt)
                };
                
                tasks.Add(task);
            }
            
            // Ordenar por prioridad (críticos primero)
            return tasks.OrderByDescending(t => t.Priority).ToList();
        }
        
        private bool IsCriticalEvent(TelemetryEvent evt)
        {
            // Eventos críticos para procesamiento prioritario
            var criticalTypes = new[]
            {
                "MalwareDetected",
                "RansomwareDetected",
                "DataExfiltration",
                "LateralMovement",
                "PrivilegeEscalation",
                "ZeroDayExploit"
            };
            
            return criticalTypes.Any(t => evt.EventType.Contains(t)) ||
                   (evt.Severity != null && evt.Severity.Contains("Critical")) ||
                   (evt.Data?.ContainsKey("IsCritical") == true && 
                    Convert.ToBoolean(evt.Data["IsCritical"]));
        }
        
        private int GetEventPriority(TelemetryEvent evt)
        {
            if (IsCriticalEvent(evt)) return 100;
            
            if (evt.Severity != null)
            {
                return evt.Severity.ToLower() switch
                {
                    "critical" => 90,
                    "high" => 70,
                    "medium" => 50,
                    "low" => 30,
                    "info" => 10,
                    _ => 20
                };
            }
            
            return 20; // Prioridad por defecto
        }
        
        private async Task<GraphNode> CreateGraphNodeAsync(TelemetryEvent evt, bool isCritical)
        {
            // Determinar plantilla a usar
            var templateId = DetermineNodeTemplate(evt);
            
            if (!_nodeTemplates.TryGetValue(templateId, out var template))
            {
                template = _nodeTemplates["PROCESS"]; // Fallback
            }
            
            // Crear nodo
            var node = new GraphNode
            {
                Id = GenerateNodeId(evt),
                Label = GetNodeLabel(evt),
                Type = template.NodeType,
                Properties = new Dictionary<string, object>()
            };
            
            // Añadir propiedades de la plantilla
            foreach (var prop in template.DefaultProperties)
            {
                node.Properties[prop.Key] = prop.Value;
            }
            
            // Añadir propiedades del evento
            foreach (var prop in evt.Data)
            {
                node.Properties[prop.Key] = prop.Value;
            }
            
            // Añadir metadatos
            node.Properties["EventId"] = evt.EventId;
            node.Properties["EventType"] = evt.EventType;
            node.Properties["Timestamp"] = evt.Timestamp;
            node.Properties["IngestedAt"] = DateTime.UtcNow;
            node.Properties["IsCritical"] = isCritical;
            
            if (evt.Metadata != null)
            {
                foreach (var meta in evt.Metadata)
                {
                    node.Properties[$"Meta_{meta.Key}"] = meta.Value;
                }
            }
            
            return node;
        }
        
        private async Task<List<GraphEdge>> CreateGraphEdgesAsync(
            TelemetryEvent evt, 
            GraphNode node, 
            bool isCritical)
        {
            var edges = new List<GraphEdge>();
            
            // Determinar plantillas de aristas a usar
            var edgeTemplateIds = DetermineEdgeTemplates(evt);
            
            foreach (var templateId in edgeTemplateIds)
            {
                if (_edgeTemplates.TryGetValue(templateId, out var template))
                {
                    var edge = await CreateEdgeFromTemplateAsync(evt, node, template, isCritical);
                    if (edge != null)
                    {
                        edges.Add(edge);
                    }
                }
            }
            
            // Crear aristas adicionales basadas en datos del evento
            var additionalEdges = await CreateAdditionalEdgesAsync(evt, node, isCritical);
            edges.AddRange(additionalEdges);
            
            return edges;
        }
        
        private string DetermineNodeTemplate(TelemetryEvent evt)
        {
            // Aplicar reglas para determinar plantilla
            foreach (var rule in _ingestionRules.Where(r => r.Enabled).OrderByDescending(r => r.Priority))
            {
                if (EvaluateRuleCondition(rule.Condition, evt))
                {
                    return rule.NodeTemplate;
                }
            }
            
            // Determinación por tipo de evento
            if (evt.EventType.Contains("Process")) return "PROCESS";
            if (evt.EventType.Contains("File")) return "FILE";
            if (evt.EventType.Contains("Network")) return "NETWORK";
            if (evt.EventType.Contains("Registry")) return "REGISTRY";
            if (evt.EventType.Contains("User") || evt.Data.ContainsKey("UserId")) return "USER";
            
            return "PROCESS"; // Default
        }
        
        private List<string> DetermineEdgeTemplates(TelemetryEvent evt)
        {
            var edgeTemplates = new List<string>();
            
            // Aplicar reglas
            foreach (var rule in _ingestionRules.Where(r => r.Enabled))
            {
                if (EvaluateRuleCondition(rule.Condition, evt))
                {
                    edgeTemplates.AddRange(rule.EdgeTemplates);
                }
            }
            
            // Eliminar duplicados
            return edgeTemplates.Distinct().ToList();
        }
        
        private bool EvaluateRuleCondition(string condition, TelemetryEvent evt)
        {
            // Evaluación simple de condiciones
            // En producción usar un motor de expresiones más robusto
            
            if (condition == "EventType == 'ProcessCreated'")
                return evt.EventType == "ProcessCreated";
            
            if (condition == "EventType.Contains('File')")
                return evt.EventType.Contains("File");
            
            if (condition == "EventType.Contains('Network')")
                return evt.EventType.Contains("Network");
            
            if (condition == "EventType.Contains('Registry')")
                return evt.EventType.Contains("Registry");
            
            if (condition == "Data.ContainsKey('UserId') && !string.IsNullOrEmpty(Data['UserId'])")
                return evt.Data?.ContainsKey("UserId") == true && 
                       !string.IsNullOrEmpty(evt.Data["UserId"]?.ToString());
            
            return false;
        }
        
        private string GenerateNodeId(TelemetryEvent evt)
        {
            // Generar ID único para el nodo
            var nodeType = DetermineNodeTemplate(evt);
            
            switch (nodeType)
            {
                case "PROCESS":
                    var processId = evt.Data?.ContainsKey("ProcessId") == true ? 
                        evt.Data["ProcessId"].ToString() : Guid.NewGuid().ToString();
                    return $"process_{processId}_{evt.Timestamp.Ticks}";
                
                case "FILE":
                    var filePath = evt.Data?.ContainsKey("FilePath") == true ? 
                        evt.Data["FilePath"].ToString() : Guid.NewGuid().ToString();
                    var hash = filePath.GetHashCode().ToString("X");
                    return $"file_{hash}_{evt.Timestamp.Ticks}";
                
                case "NETWORK":
                    var remoteAddr = evt.Data?.ContainsKey("RemoteAddress") == true ? 
                        evt.Data["RemoteAddress"].ToString() : Guid.NewGuid().ToString();
                    var port = evt.Data?.ContainsKey("RemotePort") == true ? 
                        evt.Data["RemotePort"].ToString() : "0";
                    return $"net_{remoteAddr}_{port}_{evt.Timestamp.Ticks}";
                
                case "REGISTRY":
                    var regPath = evt.Data?.ContainsKey("RegistryPath") == true ? 
                        evt.Data["RegistryPath"].ToString() : Guid.NewGuid().ToString();
                    var regHash = regPath.GetHashCode().ToString("X");
                    return $"reg_{regHash}_{evt.Timestamp.Ticks}";
                
                case "USER":
                    var userId = evt.Data?.ContainsKey("UserId") == true ? 
                        evt.Data["UserId"].ToString() : Guid.NewGuid().ToString();
                    return $"user_{userId}";
                
                default:
                    return $"node_{Guid.NewGuid().ToString().Substring(0, 8)}_{evt.Timestamp.Ticks}";
            }
        }
        
        private string GetNodeLabel(TelemetryEvent evt)
        {
            // Generar etiqueta legible para el nodo
            var nodeType = DetermineNodeTemplate(evt);
            
            switch (nodeType)
            {
                case "PROCESS":
                    var processName = evt.Data?.ContainsKey("ProcessName") == true ? 
                        evt.Data["ProcessName"].ToString() : "Unknown Process";
                    return $"{processName} ({evt.EventType})";
                
                case "FILE":
                    var fileName = evt.Data?.ContainsKey("FileName") == true ? 
                        evt.Data["FileName"].ToString() : 
                        evt.Data?.ContainsKey("FilePath") == true ? 
                            System.IO.Path.GetFileName(evt.Data["FilePath"].ToString()) : 
                            "Unknown File";
                    return $"{fileName}";
                
                case "NETWORK":
                    var remoteAddr = evt.Data?.ContainsKey("RemoteAddress") == true ? 
                        evt.Data["RemoteAddress"].ToString() : "Unknown";
                    var port = evt.Data?.ContainsKey("RemotePort") == true ? 
                        evt.Data["RemotePort"].ToString() : "0";
                    return $"{remoteAddr}:{port}";
                
                case "REGISTRY":
                    var regPath = evt.Data?.ContainsKey("RegistryPath") == true ? 
                        evt.Data["RegistryPath"].ToString() : "Unknown Registry";
                    var regName = System.IO.Path.GetFileName(regPath);
                    return $"{regName}";
                
                case "USER":
                    var userName = evt.Data?.ContainsKey("UserName") == true ? 
                        evt.Data["UserName"].ToString() : 
                        evt.Data?.ContainsKey("UserId") == true ? 
                            evt.Data["UserId"].ToString() : "Unknown User";
                    return $"{userName}";
                
                default:
                    return $"{evt.EventType}";
            }
        }
        
        private async Task<GraphEdge> CreateEdgeFromTemplateAsync(
            TelemetryEvent evt, 
            GraphNode node, 
            EdgeTemplate template,
            bool isCritical)
        {
            try
            {
                // Determinar nodo destino
                var targetNodeId = await DetermineTargetNodeIdAsync(evt, template);
                
                if (string.IsNullOrEmpty(targetNodeId))
                {
                    // No se puede crear arista sin nodo destino
                    return null;
                }
                
                // Crear arista
                var edge = new GraphEdge
                {
                    Id = GenerateEdgeId(node.Id, targetNodeId, template.EdgeType),
                    Source = node.Id,
                    Target = targetNodeId,
                    Label = template.EdgeType,
                    Type = template.EdgeType,
                    Weight = 1.0,
                    Properties = new Dictionary<string, object>()
                };
                
                // Añadir propiedades de la plantilla
                foreach (var prop in template.DefaultProperties)
                {
                    edge.Properties[prop.Key] = prop.Value;
                }
                
                // Añadir propiedades del evento
                edge.Properties["EventId"] = evt.EventId;
                edge.Properties["Timestamp"] = evt.Timestamp;
                edge.Properties["IngestedAt"] = DateTime.UtcNow;
                edge.Properties["IsCritical"] = isCritical;
                
                // Añadir propiedades específicas del template
                foreach (var propName in template.RequiredProperties.Concat(template.OptionalProperties))
                {
                    if (evt.Data?.ContainsKey(propName) == true)
                    {
                        edge.Properties[propName] = evt.Data[propName];
                    }
                }
                
                return edge;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creando arista desde template {template.TemplateId}");
                return null;
            }
        }
        
        private async Task<string> DetermineTargetNodeIdAsync(TelemetryEvent evt, EdgeTemplate template)
        {
            // Basado en el tipo de arista, determinar el nodo destino
            switch (template.EdgeType)
            {
                case "PROCESS_CREATED":
                    // Conectar con proceso padre
                    if (evt.Data?.ContainsKey("ParentProcessId") == true)
                    {
                        var parentId = evt.Data["ParentProcessId"].ToString();
                        return $"process_{parentId}_{evt.Timestamp.AddSeconds(-1).Ticks}";
                    }
                    break;
                
                case "FILE_ACCESSED":
                    // El archivo ya debería existir como nodo
                    if (evt.Data?.ContainsKey("FilePath") == true)
                    {
                        var filePath = evt.Data["FilePath"].ToString();
                        var hash = filePath.GetHashCode().ToString("X");
                        return $"file_{hash}_{evt.Timestamp.Ticks}";
                    }
                    break;
                
                case "NETWORK_CONNECTION":
                    // El destino de red ya debería existir como nodo
                    if (evt.Data?.ContainsKey("RemoteAddress") == true)
                    {
                        var remoteAddr = evt.Data["RemoteAddress"].ToString();
                        var port = evt.Data?.ContainsKey("RemotePort") == true ? 
                            evt.Data["RemotePort"].ToString() : "0";
                        return $"net_{remoteAddr}_{port}_{evt.Timestamp.Ticks}";
                    }
                    break;
                
                case "REGISTRY_MODIFIED":
                    // La clave de registro ya debería existir como nodo
                    if (evt.Data?.ContainsKey("RegistryPath") == true)
                    {
                        var regPath = evt.Data["RegistryPath"].ToString();
                        var regHash = regPath.GetHashCode().ToString("X");
                        return $"reg_{regHash}_{evt.Timestamp.Ticks}";
                    }
                    break;
                
                case "USER_ACTION":
                    // Conectar con usuario
                    if (evt.Data?.ContainsKey("UserId") == true)
                    {
                        var userId = evt.Data["UserId"].ToString();
                        return $"user_{userId}";
                    }
                    break;
            }
            
            return null;
        }
        
        private async Task<List<GraphEdge>> CreateAdditionalEdgesAsync(
            TelemetryEvent evt, 
            GraphNode node, 
            bool isCritical)
        {
            var additionalEdges = new List<GraphEdge>();
            
            // Crear aristas temporales (secuencia de eventos)
            if (evt.Data?.ContainsKey("PreviousEventId") == true)
            {
                var prevEventId = evt.Data["PreviousEventId"].ToString();
                var prevNodeId = await _graphDatabase.FindNodeByEventIdAsync(prevEventId);
                
                if (!string.IsNullOrEmpty(prevNodeId))
                {
                    var temporalEdge = new GraphEdge
                    {
                        Id = GenerateEdgeId(prevNodeId, node.Id, "TEMPORAL_SEQUENCE"),
                        Source = prevNodeId,
                        Target = node.Id,
                        Label = "Temporal Sequence",
                        Type = "TEMPORAL_SEQUENCE",
                        Weight = 0.5,
                        Properties = new Dictionary<string, object>
                        {
                            { "SequenceOrder", 1 },
                            { "TimeDifference", 0 },
                            { "IsTemporal", true }
                        }
                    };
                    
                    additionalEdges.Add(temporalEdge);
                }
            }
            
            // Crear aristas de similitud (eventos relacionados)
            if (evt.Data?.ContainsKey("RelatedEvents") == true)
            {
                var relatedEvents = evt.Data["RelatedEvents"] as List<string>;
                if (relatedEvents != null)
                {
                    foreach (var relatedEventId in relatedEvents)
                    {
                        var relatedNodeId = await _graphDatabase.FindNodeByEventIdAsync(relatedEventId);
                        
                        if (!string.IsNullOrEmpty(relatedNodeId))
                        {
                            var similarityEdge = new GraphEdge
                            {
                                Id = GenerateEdgeId(node.Id, relatedNodeId, "SIMILARITY"),
                                Source = node.Id,
                                Target = relatedNodeId,
                                Label = "Similarity",
                                Type = "SIMILARITY",
                                Weight = 0.3,
                                Properties = new Dictionary<string, object>
                                {
                                    { "SimilarityScore", 0.7 },
                                    { "RelationType", "RelatedEvent" },
                                    { "IsSimilarity", true }
                                }
                            };
                            
                            additionalEdges.Add(similarityEdge);
                        }
                    }
                }
            }
            
            return additionalEdges;
        }
        
        private string GenerateEdgeId(string sourceId, string targetId, string edgeType)
        {
            return $"edge_{sourceId}_{targetId}_{edgeType}_{Guid.NewGuid().ToString().Substring(0, 8)}";
        }
        
        private async Task MonitorBatchProgressAsync(string batchId)
        {
            var startTime = DateTime.UtcNow;
            
            while (_isRunning && (DateTime.UtcNow - startTime) < _ingestionTimeout)
            {
                if (_activeBatches.TryGetValue(batchId, out var batchInfo))
                {
                    if (batchInfo.Status == BatchStatus.Completed || 
                        batchInfo.Status == BatchStatus.Failed)
                    {
                        // Lote completado
                        LogBatchCompletion(batchInfo);
                        break;
                    }
                    
                    // Verificar tiempo de espera
                    if ((DateTime.UtcNow - batchInfo.StartTime) > _ingestionTimeout)
                    {
                        batchInfo.Status = BatchStatus.Timeout;
                        batchInfo.ErrorMessage = "Tiempo de procesamiento excedido";
                        _activeBatches[batchId] = batchInfo;
                        
                        _logger.LogWarning($"Lote {batchId} excedió tiempo de espera");
                        break;
                    }
                }
                
                await Task.Delay(1000);
            }
            
            // Limpiar lote después de un tiempo
            _ = CleanupBatchAsync(batchId);
        }
        
        private void LogBatchCompletion(BatchProcessingInfo batchInfo)
        {
            var completionTime = batchInfo.ProcessingTime ?? TimeSpan.Zero;
            
            if (batchInfo.Status == BatchStatus.Completed)
            {
                _logger.LogInformation(
                    $"Lote {batchInfo.BatchId} completado: " +
                    $"{batchInfo.ProcessedTasks}/{batchInfo.TotalTasks} tareas en " +
                    $"{completionTime.TotalMilliseconds:F0}ms");
            }
            else if (batchInfo.Status == BatchStatus.Failed)
            {
                _logger.LogError(
                    $"Lote {batchInfo.BatchId} falló: " +
                    $"{batchInfo.FailedTasks} fallos - {batchInfo.ErrorMessage}");
            }
        }
        
        private async Task CleanupBatchAsync(string batchId)
        {
            await Task.Delay(TimeSpan.FromMinutes(5)); // Esperar antes de limpiar
            
            if (_activeBatches.TryRemove(batchId, out _))
            {
                _logger.LogDebug($"Lote {batchId} limpiado de la memoria");
            }
        }
        
        private DateTime? EstimateCompletionTime(int taskCount)
        {
            if (taskCount == 0) return null;
            
            var avgTaskTime = TimeSpan.FromMilliseconds(50); // Estimación
            var estimatedTime = avgTaskTime * taskCount;
            
            // Ajustar por workers activos
            var workerCount = Math.Max(Environment.ProcessorCount / 2, 2);
            estimatedTime = TimeSpan.FromTicks(estimatedTime.Ticks / workerCount);
            
            return DateTime.UtcNow + estimatedTime;
        }
        
        private async Task<QueueStatistics> GetQueueStatisticsAsync()
        {
            return new QueueStatistics
            {
                CurrentSize = _ingestionQueue.Count,
                MaxSize = _maxQueueSize,
                AverageWaitTime = await CalculateAverageWaitTimeAsync(),
                Throughput = await CalculateThroughputAsync(),
                WorkerCount = Math.Max(Environment.ProcessorCount / 2, 2)
            };
        }
        
        private async Task<BatchStatistics> GetBatchStatisticsAsync()
        {
            var batches = _activeBatches.Values.ToList();
            
            return new BatchStatistics
            {
                TotalBatches = batches.Count,
                CompletedBatches = batches.Count(b => b.Status == BatchStatus.Completed),
                FailedBatches = batches.Count(b => b.Status == BatchStatus.Failed),
                QueuedBatches = batches.Count(b => b.Status == BatchStatus.Queued),
                ProcessingBatches = batches.Count(b => b.Status == BatchStatus.Processing),
                AverageBatchSize = batches.Any() ? batches.Average(b => b.TotalTasks) : 0,
                TotalTasks = batches.Sum(b => b.TotalTasks),
                ProcessedTasks = batches.Sum(b => b.ProcessedTasks),
                FailedTasks = batches.Sum(b => b.FailedTasks)
            };
        }
        
        private async Task<TimeSpan> CalculateAverageWaitTimeAsync()
        {
            // Implementar cálculo real del tiempo de espera
            await Task.CompletedTask;
            return TimeSpan.FromMilliseconds(100);
        }
        
        private async Task<double> CalculateThroughputAsync()
        {
            // Implementar cálculo real del throughput
            await Task.CompletedTask;
            return 500.0; // tareas por segundo
        }
        
        private MemoryUsage GetMemoryUsage()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            
            return new MemoryUsage
            {
                WorkingSet = process.WorkingSet64,
                PrivateBytes = process.PrivateMemorySize64,
                VirtualMemory = process.VirtualMemorySize64,
                ManagedMemory = GC.GetTotalMemory(false)
            };
        }
        
        private async Task<long> CalculateFreedMemoryAsync(int deletedNodes, int deletedEdges)
        {
            // Estimación basada en tamaño promedio de nodos y aristas
            var avgNodeSize = 1024; // 1KB por nodo
            var avgEdgeSize = 512;  // 0.5KB por arista
            
            return (deletedNodes * avgNodeSize) + (deletedEdges * avgEdgeSize);
        }
        
        private async Task StopProcessingAsync()
        {
            _isRunning = false;
            await Task.Delay(1000); // Esperar que los workers terminen
            
            _logger.LogInformation("Procesamiento de ingesta detenido");
        }
        
        private async Task StartProcessingAsync()
        {
            if (!_isRunning)
            {
                StartProcessingWorkers();
                await Task.Delay(100);
            }
        }
        
        #endregion
    }
    
    #region Clases de datos para Graph Ingestion
    
    public class IngestionTask
    {
        public string TaskId { get; set; }
        public string BatchId { get; set; }
        public TelemetryEvent Event { get; set; }
        public bool IsCritical { get; set; }
        public int Priority { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class IngestionResult
    {
        public string BatchId { get; set; }
        public int TotalEvents { get; set; }
        public int CreatedTasks { get; set; }
        public int ProcessedTasks { get; set; }
        public IngestionStatus Status { get; set; }
        public int QueuePosition { get; set; }
        public DateTime? EstimatedCompletion { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public bool IsCritical { get; set; }
        public string ErrorMessage { get; set; }
        
        public static IngestionResult Empty()
        {
            return new IngestionResult { Status = IngestionStatus.Skipped };
        }
        
        public static IngestionResult Error(string errorMessage)
        {
            return new IngestionResult
            {
                Status = IngestionStatus.Failed,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class NodeTemplate
    {
        public string TemplateId { get; set; }
        public string NodeType { get; set; }
        public List<string> RequiredProperties { get; set; }
        public List<string> OptionalProperties { get; set; }
        public List<string> IndexProperties { get; set; }
        public Dictionary<string, object> DefaultProperties { get; set; }
        
        public NodeTemplate()
        {
            RequiredProperties = new List<string>();
            OptionalProperties = new List<string>();
            IndexProperties = new List<string>();
            DefaultProperties = new Dictionary<string, object>();
        }
    }
    
    public class EdgeTemplate
    {
        public string TemplateId { get; set; }
        public string EdgeType { get; set; }
        public string SourceType { get; set; }
        public string TargetType { get; set; }
        public List<string> RequiredProperties { get; set; }
        public List<string> OptionalProperties { get; set; }
        public Dictionary<string, object> DefaultProperties { get; set; }
        
        public EdgeTemplate()
        {
            RequiredProperties = new List<string>();
            OptionalProperties = new List<string>();
            DefaultProperties = new Dictionary<string, object>();
        }
    }
    
    public class IngestionRule
    {
        public string RuleId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Condition { get; set; }
        public string NodeTemplate { get; set; }
        public List<string> EdgeTemplates { get; set; }
        public int Priority { get; set; }
        public bool Enabled { get; set; }
        
        public IngestionRule()
        {
            EdgeTemplates = new List<string>();
        }
    }
    
    public class BatchProcessingInfo
    {
        public string BatchId { get; set; }
        public int TotalTasks { get; set; }
        public int ProcessedTasks { get; set; }
        public int FailedTasks { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public DateTime? LastUpdate { get; set; }
        public BatchStatus Status { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public string Source { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class IngestionStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsRunning { get; set; }
        public int QueueSize { get; set; }
        public int ActiveBatches { get; set; }
        public int NodeTemplates { get; set; }
        public int EdgeTemplates { get; set; }
        public int IngestionRules { get; set; }
        public QueueStatistics QueueStatistics { get; set; }
        public BatchStatistics BatchStatistics { get; set; }
        public GraphDatabaseStatistics GraphStatistics { get; set; }
        public MemoryUsage MemoryUsage { get; set; }
    }
    
    public class QueueStatistics
    {
        public int CurrentSize { get; set; }
        public int MaxSize { get; set; }
        public TimeSpan AverageWaitTime { get; set; }
        public double Throughput { get; set; } // tareas/segundo
        public int WorkerCount { get; set; }
    }
    
    public class BatchStatistics
    {
        public int TotalBatches { get; set; }
        public int CompletedBatches { get; set; }
        public int FailedBatches { get; set; }
        public int QueuedBatches { get; set; }
        public int ProcessingBatches { get; set; }
        public double AverageBatchSize { get; set; }
        public int TotalTasks { get; set; }
        public int ProcessedTasks { get; set; }
        public int FailedTasks { get; set; }
    }
    
    public class EventValidationResult
    {
        public int TotalEvents { get; set; }
        public int ValidCount { get; set; }
        public int InvalidCount { get; set; }
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; }
        public List<TelemetryEvent> ValidEvents { get; set; }
        public List<EventValidation> InvalidEvents { get; set; }
        
        public EventValidationResult()
        {
            ValidEvents = new List<TelemetryEvent>();
            InvalidEvents = new List<EventValidation>();
        }
    }
    
    public class EventValidation
    {
        public string EventId { get; set; }
        public bool IsValid { get; set; }
        public List<string> Issues { get; set; }
        
        public EventValidation()
        {
            Issues = new List<string>();
        }
    }
    
    public class CleanupResult
    {
        public int DeletedNodes { get; set; }
        public int DeletedEdges { get; set; }
        public CleanupStatus Status { get; set; }
        public DateTime CleanupTime { get; set; }
        public long FreedMemory { get; set; } // bytes
        public string ErrorMessage { get; set; }
    }
    
    public class IndexRebuildResult
    {
        public RebuildStatus Status { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public int IndexesRebuilt { get; set; }
        public long MemoryOptimized { get; set; } // bytes
        public string ErrorMessage { get; set; }
    }
    
    public class MemoryUsage
    {
        public long WorkingSet { get; set; } // bytes
        public long PrivateBytes { get; set; } // bytes
        public long VirtualMemory { get; set; } // bytes
        public long ManagedMemory { get; set; } // bytes
    }
    
    public enum IngestionStatus
    {
        Queued,
        Processing,
        Completed,
        Failed,
        Skipped,
        Timeout
    }
    
    public enum BatchStatus
    {
        Queued,
        Processing,
        Completed,
        Failed,
        Timeout
    }
    
    public enum CleanupStatus
    {
        Completed,
        Failed,
        NoDataToClean,
        InProgress
    }
    
    public enum RebuildStatus
    {
        Completed,
        Failed,
        InProgress
    }
    
    #endregion
}