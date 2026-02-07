using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Telemetry;
using BWP.Enterprise.Agent.Storage;
using Microsoft.ML;
using Microsoft.ML.Data;

namespace BWP.Enterprise.Agent.Detection
{
    /// <summary>
    /// Motor de correlación de amenazas
    /// Detecta patrones de ataque mediante correlación de eventos múltiples
    /// </summary>
    public sealed class ThreatCorrelationEngine : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<ThreatCorrelationEngine> _instance = 
            new Lazy<ThreatCorrelationEngine>(() => new ThreatCorrelationEngine());
        
        public static ThreatCorrelationEngine Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly TelemetryQueue _telemetryQueue;
        private readonly LocalDatabase _localDatabase;
        private readonly ConcurrentDictionary<string, CorrelationSession> _activeSessions;
        private readonly ConcurrentDictionary<string, AttackPattern> _attackPatterns;
        private readonly ConcurrentQueue<SecurityEvent> _eventQueue;
        private readonly object _modelLock = new object();
        private MLContext _mlContext;
        private ITransformer _behaviorModel;
        private ITransformer _networkModel;
        private Timer _processingTimer;
        private Timer _cleanupTimer;
        private bool _isInitialized;
        private const int PROCESSING_INTERVAL_MS = 5000;
        private const int CLEANUP_INTERVAL_MS = 300000; // 5 minutos
        private const int MAX_SESSION_AGE_MINUTES = 60;
        private const double CONFIDENCE_THRESHOLD = 0.8;
        
        public string ModuleId => "ThreatCorrelationEngine";
        public string Version => "1.0.0";
        public string Description => "Motor de correlación de amenazas y detección de patrones de ataque";
        
        private ThreatCorrelationEngine()
        {
            _logManager = LogManager.Instance;
            _telemetryQueue = TelemetryQueue.Instance;
            _localDatabase = LocalDatabase.Instance;
            _activeSessions = new ConcurrentDictionary<string, CorrelationSession>();
            _attackPatterns = new ConcurrentDictionary<string, AttackPattern>();
            _eventQueue = new ConcurrentQueue<SecurityEvent>();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el motor de correlación
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando ThreatCorrelationEngine...", ModuleId);
                
                // Inicializar ML.NET
                _mlContext = new MLContext(seed: 1);
                
                // Cargar modelos de ML
                await LoadMachineLearningModelsAsync();
                
                // Cargar patrones de ataque desde base de datos
                await LoadAttackPatternsAsync();
                
                // Inicializar timers
                _processingTimer = new Timer(
                    ProcessEventQueueCallback,
                    null,
                    TimeSpan.FromSeconds(10),
                    TimeSpan.FromMilliseconds(PROCESSING_INTERVAL_MS));
                
                _cleanupTimer = new Timer(
                    CleanupOldSessionsCallback,
                    null,
                    TimeSpan.FromMinutes(5),
                    TimeSpan.FromMilliseconds(CLEANUP_INTERVAL_MS));
                
                _isInitialized = true;
                
                _logManager.LogInfo("ThreatCorrelationEngine inicializado correctamente", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar ThreatCorrelationEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el motor
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            _logManager.LogInfo("ThreatCorrelationEngine iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene el motor
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _processingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _cleanupTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                
                _processingTimer?.Dispose();
                _cleanupTimer?.Dispose();
                
                _logManager.LogInfo("ThreatCorrelationEngine detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener ThreatCorrelationEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Pausa el motor
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _processingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _logManager.LogInfo("ThreatCorrelationEngine pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el motor
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            if (_processingTimer != null)
            {
                _processingTimer.Change(TimeSpan.Zero, TimeSpan.FromMilliseconds(PROCESSING_INTERVAL_MS));
            }
            
            _logManager.LogInfo("ThreatCorrelationEngine reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Encola eventos para correlación
        /// </summary>
        public void EnqueueEvents(List<SecurityEvent> events)
        {
            foreach (var evt in events)
            {
                _eventQueue.Enqueue(evt);
            }
        }
        
        /// <summary>
        /// Correlaciona eventos para detectar patrones de ataque
        /// </summary>
        public async Task<List<CorrelationResult>> CorrelateEventsAsync(List<SecurityEvent> events)
        {
            var results = new List<CorrelationResult>();
            
            try
            {
                if (events == null || events.Count == 0)
                    return results;
                
                // Agrupar eventos por sesión (proceso, usuario, host)
                var groupedEvents = GroupEventsBySession(events);
                
                foreach (var sessionGroup in groupedEvents)
                {
                    // Obtener o crear sesión de correlación
                    var sessionId = sessionGroup.Key;
                    var sessionEvents = sessionGroup.Value;
                    
                    var session = GetOrCreateSession(sessionId, sessionEvents.FirstOrDefault());
                    
                    // Agregar eventos a la sesión
                    session.AddEvents(sessionEvents);
                    
                    // Analizar sesión para detectar patrones
                    var sessionResults = await AnalyzeSessionAsync(session);
                    results.AddRange(sessionResults);
                    
                    // Si se detectó un patrón de alto riesgo, marcar sesión como maliciosa
                    if (sessionResults.Any(r => r.Confidence >= CONFIDENCE_THRESHOLD && r.RiskScore >= 70))
                    {
                        session.IsMalicious = true;
                        session.LastDetectionTime = DateTime.UtcNow;
                        
                        // Generar alerta inmediata
                        foreach (var result in sessionResults.Where(r => r.Confidence >= CONFIDENCE_THRESHOLD))
                        {
                            await GenerateCorrelationAlertAsync(result, session);
                        }
                    }
                    
                    // Actualizar estadísticas de sesión
                    UpdateSessionStatistics(session);
                }
                
                // Guardar resultados en base de datos
                await SaveCorrelationResultsAsync(results);
                
                return results;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en correlación de eventos: {ex}", ModuleId);
                return results;
            }
        }
        
        /// <summary>
        /// Obtiene el historial de correlación de una entidad
        /// </summary>
        public async Task<List<CorrelationHistory>> GetCorrelationHistoryAsync(
            string entityType, 
            string entityId, 
            TimeSpan timeWindow)
        {
            try
            {
                var cutoffTime = DateTime.UtcNow - timeWindow;
                
                var history = new List<CorrelationHistory>();
                
                foreach (var session in _activeSessions.Values)
                {
                    if (session.StartTime < cutoffTime)
                        continue;
                    
                    // Filtrar por tipo de entidad
                    switch (entityType.ToLower())
                    {
                        case "process":
                            if (session.ProcessId == entityId || session.ProcessName.Contains(entityId))
                            {
                                history.AddRange(session.GetCorrelationHistory());
                            }
                            break;
                            
                        case "user":
                            if (session.UserName == entityId || session.UserSid == entityId)
                            {
                                history.AddRange(session.GetCorrelationHistory());
                            }
                            break;
                            
                        case "host":
                            if (session.HostName == entityId || session.HostIp == entityId)
                            {
                                history.AddRange(session.GetCorrelationHistory());
                            }
                            break;
                            
                        case "ip":
                            if (session.RemoteIps.Contains(entityId))
                            {
                                history.AddRange(session.GetCorrelationHistory());
                            }
                            break;
                    }
                }
                
                return history.OrderByDescending(h => h.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al obtener historial de correlación: {ex}", ModuleId);
                return new List<CorrelationHistory>();
            }
        }
        
        /// <summary>
        /// Detecta amenazas persistentes avanzadas (APT)
        /// </summary>
        public async Task<List<APTDetection>> DetectAPTActivityAsync(TimeSpan timeWindow)
        {
            var aptDetections = new List<APTDetection>();
            
            try
            {
                var cutoffTime = DateTime.UtcNow - timeWindow;
                
                // Obtener todas las sesiones en el período de tiempo
                var relevantSessions = _activeSessions.Values
                    .Where(s => s.StartTime >= cutoffTime)
                    .ToList();
                
                // Detectar patrones APT
                aptDetections.AddRange(await DetectLateralMovementAsync(relevantSessions));
                aptDetections.AddRange(await DetectCredentialDumpingAsync(relevantSessions));
                aptDetections.AddRange(await DetectDataExfiltrationAsync(relevantSessions));
                aptDetections.AddRange(await DetectPersistenceMechanismsAsync(relevantSessions));
                
                // Clasificar por gravedad
                foreach (var detection in aptDetections)
                {
                    detection.Severity = CalculateAPTSeverity(detection);
                }
                
                return aptDetections.OrderByDescending(d => d.Severity).ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en detección APT: {ex}", ModuleId);
                return aptDetections;
            }
        }
        
        /// <summary>
        /// Verifica salud del módulo
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var healthStatus = new
                {
                    IsInitialized = _isInitialized,
                    ActiveSessions = _activeSessions.Count,
                    AttackPatternsLoaded = _attackPatterns.Count,
                    EventQueueSize = _eventQueue.Count,
                    ModelsLoaded = (_behaviorModel != null && _networkModel != null),
                    MemoryUsageMB = GetMemoryUsageMB()
                };
                
                var status = healthStatus.IsInitialized && 
                           healthStatus.ModelsLoaded && 
                           healthStatus.MemoryUsageMB < 500 // Menos de 500MB
                    ? HealthStatus.Healthy
                    : HealthStatus.Degraded;
                
                return HealthCheckResult.Healthy($"ThreatCorrelationEngine funcionando: {_activeSessions.Count} sesiones activas");
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy($"Error en health check: {ex.Message}");
            }
        }
        
        #region Métodos privados
        
        private async Task LoadMachineLearningModelsAsync()
        {
            try
            {
                // En producción, cargar desde archivos .onnx o desde servidor
                // Por ahora, crear modelos dummy para desarrollo
                
                lock (_modelLock)
                {
                    // Crear pipeline simple para modelo de comportamiento
                    var behaviorData = new List<BehaviorModelInput>
                    {
                        new BehaviorModelInput { ProcessName = "normal.exe", IsElevated = false, NetworkConnections = 1, FileOperations = 10 },
                        new BehaviorModelInput { ProcessName = "malicious.exe", IsElevated = true, NetworkConnections = 50, FileOperations = 100 }
                    };
                    
                    var behaviorDataView = _mlContext.Data.LoadFromEnumerable(behaviorData);
                    
                    var behaviorPipeline = _mlContext.Transforms.Concatenate("Features",
                            nameof(BehaviorModelInput.IsElevated),
                            nameof(BehaviorModelInput.NetworkConnections),
                            nameof(BehaviorModelInput.FileOperations))
                        .Append(_mlContext.BinaryClassification.Trainers.SdcaLogisticRegression());
                    
                    _behaviorModel = behaviorPipeline.Fit(behaviorDataView);
                    
                    // Crear pipeline simple para modelo de red
                    var networkData = new List<NetworkModelInput>
                    {
                        new NetworkModelInput { RemotePort = 80, Protocol = "TCP", BytesSent = 1000, BytesReceived = 5000 },
                        new NetworkModelInput { RemotePort = 4444, Protocol = "TCP", BytesSent = 1000000, BytesReceived = 100 }
                    };
                    
                    var networkDataView = _mlContext.Data.LoadFromEnumerable(networkData);
                    
                    var networkPipeline = _mlContext.Transforms.Concatenate("Features",
                            nameof(NetworkModelInput.RemotePort),
                            nameof(NetworkModelInput.BytesSent),
                            nameof(NetworkModelInput.BytesReceived))
                        .Append(_mlContext.BinaryClassification.Trainers.SdcaLogisticRegression());
                    
                    _networkModel = networkPipeline.Fit(networkDataView);
                }
                
                _logManager.LogInfo("Modelos de ML cargados", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar modelos ML: {ex}", ModuleId);
                throw;
            }
        }
        
        private async Task LoadAttackPatternsAsync()
        {
            try
            {
                // Cargar patrones desde base de datos local
                var patterns = await _localDatabase.GetAttackPatternsAsync();
                
                foreach (var pattern in patterns)
                {
                    _attackPatterns[pattern.PatternId] = pattern;
                }
                
                // Si no hay patrones en DB, cargar algunos básicos
                if (_attackPatterns.IsEmpty)
                {
                    await LoadDefaultAttackPatternsAsync();
                }
                
                _logManager.LogInfo($"Cargados {_attackPatterns.Count} patrones de ataque", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar patrones de ataque: {ex}", ModuleId);
            }
        }
        
        private async Task LoadDefaultAttackPatternsAsync()
        {
            var defaultPatterns = new List<AttackPattern>
            {
                new AttackPattern
                {
                    PatternId = "APT_LATERAL_MOVEMENT",
                    Name = "Movimiento Lateral APT",
                    Description = "Secuencia de acceso a múltiples sistemas",
                    Steps = new List<PatternStep>
                    {
                        new PatternStep { StepNumber = 1, EventType = EventType.NetworkConnection, Required = true },
                        new PatternStep { StepNumber = 2, EventType = EventType.ProcessCreated, Required = true },
                        new PatternStep { StepNumber = 3, EventType = EventType.FileModified, Required = false }
                    },
                    ConfidenceThreshold = 0.7,
                    RiskScore = 85,
                    MitreTactic = "Lateral Movement",
                    MitreTechnique = "T1021"
                },
                new AttackPattern
                {
                    PatternId = "CREDENTIAL_DUMPING",
                    Name = "Robo de Credenciales",
                    Description = "Acceso y extracción de credenciales del sistema",
                    Steps = new List<PatternStep>
                    {
                        new PatternStep { StepNumber = 1, EventType = EventType.ProcessCreated, ProcessName = "lsass.exe", Required = true },
                        new PatternStep { StepNumber = 2, EventType = EventType.FileCreated, FileExtension = ".dmp", Required = true },
                        new PatternStep { StepNumber = 3, EventType = EventType.NetworkConnection, Required = false }
                    },
                    ConfidenceThreshold = 0.8,
                    RiskScore = 90,
                    MitreTactic = "Credential Access",
                    MitreTechnique = "T1003"
                },
                new AttackPattern
                {
                    PatternId = "DATA_EXFILTRATION",
                    Name = "Exfiltración de Datos",
                    Description = "Transferencia de datos sensibles hacia fuera de la red",
                    Steps = new List<PatternStep>
                    {
                        new PatternStep { StepNumber = 1, EventType = EventType.FileAccessed, Required = true },
                        new PatternStep { StepNumber = 2, EventType = EventType.NetworkConnection, Required = true },
                        new PatternStep { StepNumber = 3, EventType = EventType.DataTransfer, BytesThreshold = 10485760, Required = true } // 10MB
                    },
                    ConfidenceThreshold = 0.75,
                    RiskScore = 80,
                    MitreTactic = "Exfiltration",
                    MitreTechnique = "T1041"
                },
                new AttackPattern
                {
                    PatternId = "PERSISTENCE_MECHANISM",
                    Name = "Mecanismo de Persistencia",
                    Description = "Establecimiento de persistencia en el sistema",
                    Steps = new List<PatternStep>
                    {
                        new PatternStep { StepNumber = 1, EventType = EventType.RegistryModified, RegistryPath = "Run", Required = true },
                        new PatternStep { StepNumber = 2, EventType = EventType.FileCreated, Required = true },
                        new PatternStep { StepNumber = 3, EventType = EventType.ProcessCreated, Required = false }
                    },
                    ConfidenceThreshold = 0.8,
                    RiskScore = 75,
                    MitreTactic = "Persistence",
                    MitreTechnique = "T1547"
                }
            };
            
            foreach (var pattern in defaultPatterns)
            {
                _attackPatterns[pattern.PatternId] = pattern;
                await _localDatabase.SaveAttackPatternAsync(pattern);
            }
        }
        
        private Dictionary<string, List<SecurityEvent>> GroupEventsBySession(List<SecurityEvent> events)
        {
            var grouped = new Dictionary<string, List<SecurityEvent>>();
            
            foreach (var evt in events)
            {
                var sessionId = GenerateSessionId(evt);
                
                if (!grouped.ContainsKey(sessionId))
                {
                    grouped[sessionId] = new List<SecurityEvent>();
                }
                
                grouped[sessionId].Add(evt);
            }
            
            return grouped;
        }
        
        private string GenerateSessionId(SecurityEvent evt)
        {
            // Generar ID de sesión basado en entidades relacionadas
            var components = new List<string>();
            
            if (!string.IsNullOrEmpty(evt.ProcessId))
                components.Add($"PID:{evt.ProcessId}");
            
            if (!string.IsNullOrEmpty(evt.UserSid))
                components.Add($"SID:{evt.UserSid}");
            
            if (!string.IsNullOrEmpty(evt.HostName))
                components.Add($"HOST:{evt.HostName}");
            
            if (components.Count == 0)
                return $"SESSION:{Guid.NewGuid():N}";
            
            return string.Join("|", components);
        }
        
        private CorrelationSession GetOrCreateSession(string sessionId, SecurityEvent firstEvent)
        {
            return _activeSessions.GetOrAdd(sessionId, id =>
            {
                return new CorrelationSession
                {
                    SessionId = id,
                    StartTime = DateTime.UtcNow,
                    ProcessId = firstEvent?.ProcessId,
                    ProcessName = firstEvent?.ProcessName,
                    UserSid = firstEvent?.UserSid,
                    UserName = firstEvent?.UserName,
                    HostName = firstEvent?.HostName,
                    HostIp = firstEvent?.HostIp
                };
            });
        }
        
        private async Task<List<CorrelationResult>> AnalyzeSessionAsync(CorrelationSession session)
        {
            var results = new List<CorrelationResult>();
            
            try
            {
                // 1. Analizar contra patrones conocidos
                foreach (var pattern in _attackPatterns.Values)
                {
                    var matchResult = await MatchPatternAsync(session, pattern);
                    if (matchResult.Confidence >= pattern.ConfidenceThreshold)
                    {
                        results.Add(matchResult);
                    }
                }
                
                // 2. Análisis de comportamiento con ML
                var behaviorResult = await AnalyzeBehaviorWithMLAsync(session);
                if (behaviorResult.Confidence >= CONFIDENCE_THRESHOLD)
                {
                    results.Add(behaviorResult);
                }
                
                // 3. Análisis de anomalías en red
                var networkResult = await AnalyzeNetworkWithMLAsync(session);
                if (networkResult.Confidence >= CONFIDENCE_THRESHOLD)
                {
                    results.Add(networkResult);
                }
                
                return results;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis de sesión: {ex}", ModuleId);
                return results;
            }
        }
        
        private async Task<CorrelationResult> MatchPatternAsync(CorrelationSession session, AttackPattern pattern)
        {
            try
            {
                var events = session.GetRecentEvents(TimeSpan.FromMinutes(30));
                var matchedSteps = new List<PatternStep>();
                var confidence = 0.0;
                
                foreach (var step in pattern.Steps.OrderBy(s => s.StepNumber))
                {
                    var stepMatched = await MatchPatternStepAsync(step, events);
                    
                    if (stepMatched)
                    {
                        matchedSteps.Add(step);
                        confidence += step.Required ? 0.4 : 0.2; // Pasos requeridos aportan más confianza
                    }
                    else if (step.Required)
                    {
                        // Si un paso requerido no coincide, el patrón no se cumple
                        confidence = 0;
                        break;
                    }
                }
                
                // Normalizar confianza
                confidence = Math.Min(confidence, 1.0);
                
                // Calcular score de riesgo
                var riskScore = CalculateRiskScore(pattern, matchedSteps.Count, session);
                
                return new CorrelationResult
                {
                    CorrelationId = Guid.NewGuid().ToString(),
                    SessionId = session.SessionId,
                    PatternId = pattern.PatternId,
                    PatternName = pattern.Name,
                    Confidence = confidence,
                    RiskScore = riskScore,
                    MatchedSteps = matchedSteps,
                    Timestamp = DateTime.UtcNow,
                    MitreTactic = pattern.MitreTactic,
                    MitreTechnique = pattern.MitreTechnique,
                    Details = $"Patrón detectado: {pattern.Name}. Pasos coincidentes: {matchedSteps.Count}/{pattern.Steps.Count}"
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en coincidencia de patrón: {ex}", ModuleId);
                return new CorrelationResult
                {
                    Confidence = 0,
                    RiskScore = 0
                };
            }
        }
        
        private async Task<bool> MatchPatternStepAsync(PatternStep step, List<SecurityEvent> events)
        {
            foreach (var evt in events)
            {
                // Verificar tipo de evento
                if (evt.EventType != step.EventType)
                    continue;
                
                // Verificar condiciones específicas
                if (!string.IsNullOrEmpty(step.ProcessName) && 
                    evt.ProcessName != step.ProcessName)
                    continue;
                
                if (!string.IsNullOrEmpty(step.FileExtension) &&
                    !string.IsNullOrEmpty(evt.FilePath) &&
                    !evt.FilePath.EndsWith(step.FileExtension, StringComparison.OrdinalIgnoreCase))
                    continue;
                
                if (!string.IsNullOrEmpty(step.RegistryPath) &&
                    !string.IsNullOrEmpty(evt.RegistryPath) &&
                    !evt.RegistryPath.Contains(step.RegistryPath))
                    continue;
                
                if (step.BytesThreshold > 0 &&
                    evt.BytesTransferred < step.BytesThreshold)
                    continue;
                
                return true;
            }
            
            return false;
        }
        
        private async Task<CorrelationResult> AnalyzeBehaviorWithMLAsync(CorrelationSession session)
        {
            try
            {
                var events = session.GetRecentEvents(TimeSpan.FromMinutes(15));
                
                // Preparar datos para ML
                var behaviorInput = new BehaviorModelInput
                {
                    ProcessName = session.ProcessName,
                    IsElevated = events.Any(e => e.IsElevated),
                    NetworkConnections = events.Count(e => e.EventType == EventType.NetworkConnection),
                    FileOperations = events.Count(e => 
                        e.EventType == EventType.FileCreated || 
                        e.EventType == EventType.FileModified || 
                        e.EventType == EventType.FileDeleted),
                    RegistryOperations = events.Count(e => e.EventType.ToString().Contains("Registry")),
                    HasSuspiciousArguments = events.Any(e => 
                        !string.IsNullOrEmpty(e.CommandLine) && 
                        e.CommandLine.Contains("-enc", StringComparison.OrdinalIgnoreCase))
                };
                
                lock (_modelLock)
                {
                    if (_behaviorModel == null)
                        return new CorrelationResult { Confidence = 0 };
                    
                    var predictionEngine = _mlContext.Model.CreatePredictionEngine<BehaviorModelInput, BehaviorModelOutput>(_behaviorModel);
                    var prediction = predictionEngine.Predict(behaviorInput);
                    
                    return new CorrelationResult
                    {
                        CorrelationId = Guid.NewGuid().ToString(),
                        SessionId = session.SessionId,
                        PatternId = "ML_BEHAVIOR_ANOMALY",
                        PatternName = "Anomalía de Comportamiento (ML)",
                        Confidence = prediction.Probability,
                        RiskScore = (int)(prediction.Probability * 100),
                        Timestamp = DateTime.UtcNow,
                        Details = $"Anomalía detectada por ML en proceso {session.ProcessName}"
                    };
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis ML de comportamiento: {ex}", ModuleId);
                return new CorrelationResult { Confidence = 0 };
            }
        }
        
        private async Task<CorrelationResult> AnalyzeNetworkWithMLAsync(CorrelationSession session)
        {
            try
            {
                var networkEvents = session.GetRecentEvents(TimeSpan.FromMinutes(10))
                    .Where(e => e.EventType == EventType.NetworkConnection || 
                               e.EventType == EventType.DataTransfer)
                    .ToList();
                
                if (networkEvents.Count == 0)
                    return new CorrelationResult { Confidence = 0 };
                
                // Agrupar por conexión
                var connections = networkEvents
                    .GroupBy(e => new { e.RemoteAddress, e.RemotePort })
                    .Select(g => new
                    {
                        RemoteAddress = g.Key.RemoteAddress,
                        RemotePort = g.Key.RemotePort,
                        TotalBytes = g.Sum(e => e.BytesTransferred),
                        ConnectionCount = g.Count()
                    })
                    .ToList();
                
                var networkInput = new NetworkModelInput
                {
                    RemotePort = connections.FirstOrDefault()?.RemotePort ?? 0,
                    Protocol = "TCP", // Simplificado
                    BytesSent = connections.Sum(c => c.TotalBytes),
                    BytesReceived = 0, // Simplificado
                    ConnectionFrequency = connections.Count / 10.0, // Conexiones por minuto
                    IsKnownMaliciousPort = IsSuspiciousPort(connections.FirstOrDefault()?.RemotePort ?? 0)
                };
                
                lock (_modelLock)
                {
                    if (_networkModel == null)
                        return new CorrelationResult { Confidence = 0 };
                    
                    var predictionEngine = _mlContext.Model.CreatePredictionEngine<NetworkModelInput, NetworkModelOutput>(_networkModel);
                    var prediction = predictionEngine.Predict(networkInput);
                    
                    return new CorrelationResult
                    {
                        CorrelationId = Guid.NewGuid().ToString(),
                        SessionId = session.SessionId,
                        PatternId = "ML_NETWORK_ANOMALY",
                        PatternName = "Anomalía de Red (ML)",
                        Confidence = prediction.Probability,
                        RiskScore = (int)(prediction.Probability * 100),
                        Timestamp = DateTime.UtcNow,
                        Details = $"Anomalía de red detectada por ML"
                    };
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis ML de red: {ex}", ModuleId);
                return new CorrelationResult { Confidence = 0 };
            }
        }
        
        private int CalculateRiskScore(AttackPattern pattern, int matchedSteps, CorrelationSession session)
        {
            var baseScore = pattern.RiskScore;
            var stepMultiplier = (double)matchedSteps / pattern.Steps.Count;
            var sessionMultiplier = session.IsMalicious ? 1.2 : 1.0;
            
            var calculatedScore = (int)(baseScore * stepMultiplier * sessionMultiplier);
            
            return Math.Min(calculatedScore, 100);
        }
        
        private ThreatSeverity CalculateAPTSeverity(APTDetection detection)
        {
            if (detection.Confidence >= 0.9 && detection.RiskScore >= 90)
                return ThreatSeverity.Critical;
            
            if (detection.Confidence >= 0.8 && detection.RiskScore >= 80)
                return ThreatSeverity.High;
            
            if (detection.Confidence >= 0.7 && detection.RiskScore >= 70)
                return ThreatSeverity.Medium;
            
            return ThreatSeverity.Low;
        }
        
        private async Task<List<APTDetection>> DetectLateralMovementAsync(List<CorrelationSession> sessions)
        {
            var detections = new List<APTDetection>();
            
            // Buscar patrones de movimiento lateral
            var sessionsByUser = sessions.GroupBy(s => s.UserSid);
            
            foreach (var userGroup in sessionsByUser)
            {
                var userSessions = userGroup.ToList();
                
                // Detectar acceso a múltiples hosts en corto tiempo
                var uniqueHosts = userSessions.Select(s => s.HostName).Distinct().Count();
                var timeSpan = userSessions.Max(s => s.StartTime) - userSessions.Min(s => s.StartTime);
                
                if (uniqueHosts >= 3 && timeSpan.TotalMinutes < 30)
                {
                    detections.Add(new APTDetection
                    {
                        DetectionId = Guid.NewGuid().ToString(),
                        Type = APTDetectionType.LateralMovement,
                        Description = $"Posible movimiento lateral detectado: usuario accedió a {uniqueHosts} hosts en {timeSpan.TotalMinutes} minutos",
                        Confidence = Math.Min(uniqueHosts / 10.0, 0.9),
                        RiskScore = 85,
                        AffectedEntities = userSessions.Select(s => s.HostName).Distinct().ToList(),
                        FirstSeen = userSessions.Min(s => s.StartTime),
                        LastSeen = userSessions.Max(s => s.StartTime),
                        MitreTactic = "Lateral Movement",
                        MitreTechnique = "T1021"
                    });
                }
            }
            
            return detections;
        }
        
        private async Task<List<APTDetection>> DetectCredentialDumpingAsync(List<CorrelationSession> sessions)
        {
            var detections = new List<APTDetection>();
            
            // Buscar acceso a lsass.exe y creación de dumps
            foreach (var session in sessions)
            {
                var events = session.GetRecentEvents(TimeSpan.FromMinutes(15));
                
                var lsassAccess = events.Any(e => 
                    e.ProcessName?.Contains("lsass", StringComparison.OrdinalIgnoreCase) == true ||
                    e.EventType == EventType.ProcessCreated && e.ProcessName == "lsass.exe");
                
                var dumpCreated = events.Any(e => 
                    e.EventType == EventType.FileCreated && 
                    e.FilePath?.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase) == true);
                
                if (lsassAccess && dumpCreated)
                {
                    detections.Add(new APTDetection
                    {
                        DetectionId = Guid.NewGuid().ToString(),
                        Type = APTDetectionType.CredentialDumping,
                        Description = "Posible robo de credenciales detectado: acceso a lsass.exe y creación de dump",
                        Confidence = 0.85,
                        RiskScore = 90,
                        AffectedEntities = new List<string> { session.ProcessName, session.HostName },
                        FirstSeen = session.StartTime,
                        LastSeen = DateTime.UtcNow,
                        MitreTactic = "Credential Access",
                        MitreTechnique = "T1003"
                    });
                }
            }
            
            return detections;
        }
        
        private async Task<List<APTDetection>> DetectDataExfiltrationAsync(List<CorrelationSession> sessions)
        {
            var detections = new List<APTDetection>();
            
            foreach (var session in sessions)
            {
                var events = session.GetRecentEvents(TimeSpan.FromMinutes(30));
                
                // Calcular total de datos transferidos
                var totalBytes = events
                    .Where(e => e.EventType == EventType.DataTransfer)
                    .Sum(e => e.BytesTransferred);
                
                // Buscar transferencias grandes a IPs externas
                var externalTransfers = events
                    .Where(e => e.EventType == EventType.DataTransfer &&
                               !string.IsNullOrEmpty(e.RemoteAddress) &&
                               !IsPrivateIpAddress(e.RemoteAddress))
                    .ToList();
                
                var externalBytes = externalTransfers.Sum(e => e.BytesTransferred);
                
                if (externalBytes > 50 * 1024 * 1024) // 50MB
                {
                    detections.Add(new APTDetection
                    {
                        DetectionId = Guid.NewGuid().ToString(),
                        Type = APTDetectionType.DataExfiltration,
                        Description = $"Posible exfiltración de datos: {externalBytes / (1024 * 1024)}MB transferidos a direcciones externas",
                        Confidence = Math.Min(externalBytes / (100 * 1024 * 1024.0), 0.95),
                        RiskScore = 80,
                        AffectedEntities = new List<string> { session.ProcessName, session.HostName },
                        FirstSeen = session.StartTime,
                        LastSeen = DateTime.UtcNow,
                        MitreTactic = "Exfiltration",
                        MitreTechnique = "T1041",
                        AdditionalData = new Dictionary<string, object>
                        {
                            { "TotalBytesExfiltrated", externalBytes },
                            { "DestinationIPs", externalTransfers.Select(e => e.RemoteAddress).Distinct() }
                        }
                    });
                }
            }
            
            return detections;
        }
        
        private async Task<List<APTDetection>> DetectPersistenceMechanismsAsync(List<CorrelationSession> sessions)
        {
            var detections = new List<APTDetection>();
            
            foreach (var session in sessions)
            {
                var events = session.GetRecentEvents(TimeSpan.FromMinutes(60));
                
                // Buscar modificaciones en claves de autostart
                var autoStartChanges = events.Count(e => 
                    e.EventType == EventType.RegistryModified &&
                    !string.IsNullOrEmpty(e.RegistryPath) &&
                    (e.RegistryPath.Contains(@"Run\", StringComparison.OrdinalIgnoreCase) ||
                     e.RegistryPath.Contains(@"RunOnce\", StringComparison.OrdinalIgnoreCase) ||
                     e.RegistryPath.Contains(@"Services\", StringComparison.OrdinalIgnoreCase)));
                
                // Buscar creación de scheduled tasks
                var taskChanges = events.Count(e => 
                    e.EventType == EventType.FileCreated &&
                    !string.IsNullOrEmpty(e.FilePath) &&
                    (e.FilePath.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase) ||
                     e.FilePath.EndsWith(".job", StringComparison.OrdinalIgnoreCase)));
                
                if (autoStartChanges >= 2 || taskChanges >= 2)
                {
                    detections.Add(new APTDetection
                    {
                        DetectionId = Guid.NewGuid().ToString(),
                        Type = APTDetectionType.Persistence,
                        Description = $"Múltiples mecanismos de persistencia detectados: {autoStartChanges} cambios en autostart, {taskChanges} tareas programadas",
                        Confidence = 0.8,
                        RiskScore = 75,
                        AffectedEntities = new List<string> { session.ProcessName, session.HostName },
                        FirstSeen = session.StartTime,
                        LastSeen = DateTime.UtcNow,
                        MitreTactic = "Persistence",
                        MitreTechnique = "T1547",
                        AdditionalData = new Dictionary<string, object>
                        {
                            { "AutoStartChanges", autoStartChanges },
                            { "TaskChanges", taskChanges }
                        }
                    });
                }
            }
            
            return detections;
        }
        
        private bool IsSuspiciousPort(int port)
        {
            var suspiciousPorts = new[] { 4444, 5555, 6666, 6667, 6668, 6669, 31337, 12345, 12346, 20034, 27374 };
            return suspiciousPorts.Contains(port);
        }
        
        private bool IsPrivateIpAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;
            
            var privateRanges = new[] 
            {
                "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
            };
            
            return privateRanges.Any(range => ipAddress.StartsWith(range));
        }
        
        private async Task GenerateCorrelationAlertAsync(CorrelationResult result, CorrelationSession session)
        {
            try
            {
                var alert = new SecurityAlert
                {
                    AlertId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    Type = AlertType.Correlation,
                    Severity = result.RiskScore >= 90 ? ThreatSeverity.Critical : 
                              result.RiskScore >= 80 ? ThreatSeverity.High : 
                              result.RiskScore >= 70 ? ThreatSeverity.Medium : ThreatSeverity.Low,
                    Title = $"Correlación detectada: {result.PatternName}",
                    Description = result.Details,
                    Source = ModuleId,
                    Confidence = result.Confidence,
                    Status = AlertStatus.Active,
                    AffectedEntities = new Dictionary<string, string>
                    {
                        { "SessionId", session.SessionId },
                        { "Process", session.ProcessName ?? "Unknown" },
                        { "User", session.UserName ?? "Unknown" },
                        { "Host", session.HostName ?? "Unknown" }
                    },
                    CorrelationData = new CorrelationAlertData
                    {
                        PatternId = result.PatternId,
                        RiskScore = result.RiskScore,
                        MitreTactic = result.MitreTactic,
                        MitreTechnique = result.MitreTechnique,
                        SessionEvents = session.GetRecentEvents(TimeSpan.FromMinutes(30)).Count
                    }
                };
                
                // Guardar en base de datos local
                await _localDatabase.SaveAlertAsync(alert);
                
                // Enviar a telemetría
                await _telemetryQueue.EnqueueAlertAsync(alert);
                
                _logManager.LogWarning($"Alerta de correlación generada: {alert.Title} (Score: {result.RiskScore})", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al generar alerta de correlación: {ex}", ModuleId);
            }
        }
        
        private async Task SaveCorrelationResultsAsync(List<CorrelationResult> results)
        {
            try
            {
                foreach (var result in results.Where(r => r.Confidence >= CONFIDENCE_THRESHOLD))
                {
                    await _localDatabase.SaveCorrelationResultAsync(result);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar resultados de correlación: {ex}", ModuleId);
            }
        }
        
        private void UpdateSessionStatistics(CorrelationSession session)
        {
            session.TotalEvents += session.GetRecentEvents(TimeSpan.FromMinutes(5)).Count;
            session.LastActivityTime = DateTime.UtcNow;
            
            // Actualizar IPs remotas únicas
            var recentEvents = session.GetRecentEvents(TimeSpan.FromMinutes(30));
            var uniqueIps = recentEvents
                .Where(e => !string.IsNullOrEmpty(e.RemoteAddress))
                .Select(e => e.RemoteAddress)
                .Distinct();
            
            foreach (var ip in uniqueIps)
            {
                if (!session.RemoteIps.Contains(ip))
                {
                    session.RemoteIps.Add(ip);
                }
            }
        }
        
        private void ProcessEventQueueCallback(object state)
        {
            try
            {
                // Procesar eventos en cola
                var events = new List<SecurityEvent>();
                while (_eventQueue.TryDequeue(out var evt))
                {
                    events.Add(evt);
                    
                    if (events.Count >= 100) // Procesar en lotes de 100
                    {
                        ProcessEventsBatch(events);
                        events.Clear();
                    }
                }
                
                if (events.Count > 0)
                {
                    ProcessEventsBatch(events);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en procesamiento de cola de eventos: {ex}", ModuleId);
            }
        }
        
        private void ProcessEventsBatch(List<SecurityEvent> events)
        {
            try
            {
                _ = Task.Run(async () =>
                {
                    var results = await CorrelateEventsAsync(events);
                    
                    // Si hay resultados con alta confianza, generar alertas
                    foreach (var result in results.Where(r => r.Confidence >= 0.9))
                    {
                        if (_activeSessions.TryGetValue(result.SessionId, out var session))
                        {
                            await GenerateCorrelationAlertAsync(result, session);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en procesamiento de lote de eventos: {ex}", ModuleId);
            }
        }
        
        private void CleanupOldSessionsCallback(object state)
        {
            try
            {
                var cutoffTime = DateTime.UtcNow.AddMinutes(-MAX_SESSION_AGE_MINUTES);
                var sessionsToRemove = new List<string>();
                
                foreach (var kvp in _activeSessions)
                {
                    if (kvp.Value.LastActivityTime < cutoffTime && !kvp.Value.IsMalicious)
                    {
                        sessionsToRemove.Add(kvp.Key);
                    }
                }
                
                foreach (var sessionId in sessionsToRemove)
                {
                    _activeSessions.TryRemove(sessionId, out _);
                }
                
                if (sessionsToRemove.Count > 0)
                {
                    _logManager.LogInfo($"Limpiadas {sessionsToRemove.Count} sesiones antiguas", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en limpieza de sesiones: {ex}", ModuleId);
            }
        }
        
        private double GetMemoryUsageMB()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            return process.WorkingSet64 / (1024.0 * 1024.0);
        }
        
        #endregion
        
        #region Clases de datos
        
        public class CorrelationSession
        {
            public string SessionId { get; set; }
            public DateTime StartTime { get; set; }
            public DateTime LastActivityTime { get; set; }
            public DateTime? LastDetectionTime { get; set; }
            public string ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string UserSid { get; set; }
            public string UserName { get; set; }
            public string HostName { get; set; }
            public string HostIp { get; set; }
            public List<string> RemoteIps { get; set; }
            public bool IsMalicious { get; set; }
            public int TotalEvents { get; set; }
            private readonly ConcurrentQueue<SecurityEvent> _events;
            private readonly ConcurrentQueue<CorrelationHistory> _history;
            
            public CorrelationSession()
            {
                RemoteIps = new List<string>();
                _events = new ConcurrentQueue<SecurityEvent>();
                _history = new ConcurrentQueue<CorrelationHistory>();
                LastActivityTime = DateTime.UtcNow;
            }
            
            public void AddEvents(List<SecurityEvent> events)
            {
                foreach (var evt in events)
                {
                    _events.Enqueue(evt);
                    
                    // Mantener máximo 1000 eventos en cola
                    while (_events.Count > 1000)
                    {
                        _events.TryDequeue(out _);
                    }
                }
                
                LastActivityTime = DateTime.UtcNow;
            }
            
            public List<SecurityEvent> GetRecentEvents(TimeSpan timeWindow)
            {
                var cutoffTime = DateTime.UtcNow - timeWindow;
                return _events.Where(e => e.Timestamp >= cutoffTime).ToList();
            }
            
            public void AddHistory(CorrelationHistory history)
            {
                _history.Enqueue(history);
                
                // Mantener máximo 100 entradas en historial
                while (_history.Count > 100)
                {
                    _history.TryDequeue(out _);
                }
            }
            
            public List<CorrelationHistory> GetCorrelationHistory()
            {
                return _history.ToList();
            }
        }
        
        public class AttackPattern
        {
            public string PatternId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public List<PatternStep> Steps { get; set; }
            public double ConfidenceThreshold { get; set; }
            public int RiskScore { get; set; }
            public string MitreTactic { get; set; }
            public string MitreTechnique { get; set; }
            public DateTime LastUpdated { get; set; }
        }
        
        public class PatternStep
        {
            public int StepNumber { get; set; }
            public EventType EventType { get; set; }
            public string ProcessName { get; set; }
            public string FileExtension { get; set; }
            public string RegistryPath { get; set; }
            public long BytesThreshold { get; set; }
            public bool Required { get; set; }
        }
        
        public class CorrelationResult
        {
            public string CorrelationId { get; set; }
            public string SessionId { get; set; }
            public string PatternId { get; set; }
            public string PatternName { get; set; }
            public double Confidence { get; set; }
            public int RiskScore { get; set; }
            public List<PatternStep> MatchedSteps { get; set; }
            public DateTime Timestamp { get; set; }
            public string MitreTactic { get; set; }
            public string MitreTechnique { get; set; }
            public string Details { get; set; }
        }
        
        public class CorrelationHistory
        {
            public string HistoryId { get; set; }
            public string SessionId { get; set; }
            public string PatternId { get; set; }
            public double Confidence { get; set; }
            public int RiskScore { get; set; }
            public DateTime Timestamp { get; set; }
            public string Details { get; set; }
        }
        
        public class APTDetection
        {
            public string DetectionId { get; set; }
            public APTDetectionType Type { get; set; }
            public string Description { get; set; }
            public double Confidence { get; set; }
            public int RiskScore { get; set; }
            public ThreatSeverity Severity { get; set; }
            public List<string> AffectedEntities { get; set; }
            public DateTime FirstSeen { get; set; }
            public DateTime LastSeen { get; set; }
            public string MitreTactic { get; set; }
            public string MitreTechnique { get; set; }
            public Dictionary<string, object> AdditionalData { get; set; }
        }
        
        public enum APTDetectionType
        {
            LateralMovement,
            CredentialDumping,
            DataExfiltration,
            Persistence,
            CommandAndControl,
            DefenseEvasion
        }
        
        // Modelos ML
        private class BehaviorModelInput
        {
            public string ProcessName { get; set; }
            public bool IsElevated { get; set; }
            public float NetworkConnections { get; set; }
            public float FileOperations { get; set; }
            public float RegistryOperations { get; set; }
            public bool HasSuspiciousArguments { get; set; }
        }
        
        private class BehaviorModelOutput
        {
            [ColumnName("PredictedLabel")]
            public bool IsMalicious { get; set; }
            
            [ColumnName("Probability")]
            public float Probability { get; set; }
        }
        
        private class NetworkModelInput
        {
            public float RemotePort { get; set; }
            public string Protocol { get; set; }
            public float BytesSent { get; set; }
            public float BytesReceived { get; set; }
            public float ConnectionFrequency { get; set; }
            public bool IsKnownMaliciousPort { get; set; }
        }
        
        private class NetworkModelOutput
        {
            [ColumnName("PredictedLabel")]
            public bool IsAnomalous { get; set; }
            
            [ColumnName("Probability")]
            public float Probability { get; set; }
        }
        
        #endregion
    }
}