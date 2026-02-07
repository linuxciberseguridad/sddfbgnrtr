using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Sensors;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.ML;
using Microsoft.ML;

namespace BWP.Enterprise.Agent.Detection
{
    /// <summary>
    /// Analizador de comportamiento para detección de amenazas desconocidas
    /// Usa aprendizaje automático para detectar comportamientos anómalos
    /// </summary>
    public sealed class BehaviorAnalyzer : IAgentModule, IDetectionEngine
    {
        private static readonly Lazy<BehaviorAnalyzer> _instance = 
            new Lazy<BehaviorAnalyzer>(() => new BehaviorAnalyzer());
        
        public static BehaviorAnalyzer Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly MLContext _mlContext;
        private readonly ConcurrentDictionary<string, ProcessBehaviorProfile> _processProfiles;
        private readonly ConcurrentDictionary<string, UserBehaviorProfile> _userProfiles;
        private readonly ConcurrentDictionary<string, SystemBehaviorProfile> _systemProfiles;
        private readonly BehaviorMLModel _behaviorModel;
        private readonly NetworkMLModel _networkModel;
        private bool _isInitialized;
        private bool _isRunning;
        private Task _processingTask;
        private CancellationTokenSource _cancellationTokenSource;
        private const int PROFILE_HISTORY_SIZE = 1000;
        private const double ANOMALY_THRESHOLD = 0.7;
        private const double SUSPICIOUS_THRESHOLD = 0.5;
        
        public string ModuleId => "BehaviorAnalyzer";
        public string Version => "1.0.0";
        public string Description => "Analizador de comportamiento basado en machine learning";
        
        private BehaviorAnalyzer()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _mlContext = new MLContext(seed: 1);
            _processProfiles = new ConcurrentDictionary<string, ProcessBehaviorProfile>();
            _userProfiles = new ConcurrentDictionary<string, UserBehaviorProfile>();
            _systemProfiles = new ConcurrentDictionary<string, SystemBehaviorProfile>();
            _behaviorModel = new BehaviorMLModel(_mlContext);
            _networkModel = new NetworkMLModel(_mlContext);
            _isInitialized = false;
            _isRunning = false;
            _cancellationTokenSource = new CancellationTokenSource();
        }
        
        /// <summary>
        /// Inicializa el analizador de comportamiento
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando BehaviorAnalyzer...", ModuleId);
                
                // Cargar perfiles desde base de datos
                await LoadBehaviorProfilesAsync();
                
                // Inicializar modelos de ML
                await InitializeMLModelsAsync();
                
                // Establecer línea base de comportamiento
                await EstablishBehaviorBaselineAsync();
                
                _isInitialized = true;
                _logManager.LogInfo($"BehaviorAnalyzer inicializado: {_processProfiles.Count} perfiles de proceso, {_userProfiles.Count} perfiles de usuario", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar BehaviorAnalyzer: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el análisis de comportamiento
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                {
                    return initResult;
                }
            }
            
            try
            {
                _cancellationTokenSource = new CancellationTokenSource();
                _isRunning = true;
                
                // Iniciar tarea de análisis continuo
                _processingTask = Task.Run(() => AnalyzeBehaviorContinuouslyAsync(_cancellationTokenSource.Token));
                
                _logManager.LogInfo("BehaviorAnalyzer iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar BehaviorAnalyzer: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el analizador de comportamiento
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isRunning = false;
                _cancellationTokenSource.Cancel();
                
                if (_processingTask != null)
                {
                    await _processingTask;
                }
                
                // Guardar perfiles antes de detener
                await SaveBehaviorProfilesAsync();
                
                _logManager.LogInfo("BehaviorAnalyzer detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener BehaviorAnalyzer: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Pausa el analizador
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("BehaviorAnalyzer pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el analizador
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("BehaviorAnalyzer reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Analiza eventos para detectar comportamientos anómalos
        /// </summary>
        public async Task<List<DetectionResult>> AnalyzeEventsAsync(List<SensorEvent> events)
        {
            var results = new ConcurrentBag<DetectionResult>();
            
            if (events == null || events.Count == 0)
            {
                return results.ToList();
            }
            
            try
            {
                // Procesar eventos en paralelo
                var tasks = events.Select(async evt =>
                {
                    try
                    {
                        var detectionResults = await AnalyzeSingleEventAsync(evt);
                        foreach (var result in detectionResults)
                        {
                            results.Add(result);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error al analizar evento: {ex}", ModuleId);
                    }
                });
                
                await Task.WhenAll(tasks);
                
                // Analizar correlaciones entre eventos
                var correlationResults = await AnalyzeEventCorrelationsAsync(events);
                foreach (var result in correlationResults)
                {
                    results.Add(result);
                }
                
                _logManager.LogDebug($"BehaviorAnalyzer analizó {events.Count} eventos, detectó {results.Count} anomalías", ModuleId);
                
                return results.ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en AnalyzeEventsAsync: {ex}", ModuleId);
                return new List<DetectionResult>();
            }
        }
        
        /// <summary>
        /// Analiza un solo evento
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeSingleEventAsync(SensorEvent sensorEvent)
        {
            var detectionResults = new List<DetectionResult>();
            
            switch (sensorEvent.SensorType)
            {
                case SensorType.Process:
                    detectionResults.AddRange(await AnalyzeProcessBehaviorAsync(sensorEvent));
                    break;
                    
                case SensorType.FileSystem:
                    detectionResults.AddRange(await AnalyzeFileSystemBehaviorAsync(sensorEvent));
                    break;
                    
                case SensorType.Network:
                    detectionResults.AddRange(await AnalyzeNetworkBehaviorAsync(sensorEvent));
                    break;
                    
                case SensorType.Registry:
                    detectionResults.AddRange(await AnalyzeRegistryBehaviorAsync(sensorEvent));
                    break;
            }
            
            return detectionResults;
        }
        
        /// <summary>
        /// Analiza comportamiento de proceso
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeProcessBehaviorAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // Obtener o crear perfil del proceso
            var processKey = GetProcessKey(eventData.ProcessName, eventData.ImagePath);
            var processProfile = GetOrCreateProcessProfile(processKey, eventData);
            
            // Actualizar perfil con nuevo evento
            UpdateProcessProfile(processProfile, sensorEvent);
            
            // Analizar anomalías en el proceso
            var processAnomalies = await DetectProcessAnomaliesAsync(processProfile, sensorEvent);
            results.AddRange(processAnomalies);
            
            // Analizar comportamiento del usuario
            if (!string.IsNullOrEmpty(eventData.UserSid))
            {
                var userAnomalies = await DetectUserProcessAnomaliesAsync(eventData.UserSid, processProfile, sensorEvent);
                results.AddRange(userAnomalies);
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza comportamiento de sistema de archivos
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeFileSystemBehaviorAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // Obtener perfil del proceso que realiza la operación
            if (!string.IsNullOrEmpty(eventData.ProcessName))
            {
                var processKey = GetProcessKey(eventData.ProcessName, eventData.ImagePath);
                if (_processProfiles.TryGetValue(processKey, out var processProfile))
                {
                    // Actualizar estadísticas de operaciones de archivo
                    UpdateFileOperationsProfile(processProfile, sensorEvent);
                    
                    // Detectar anomalías en operaciones de archivo
                    var fileAnomalies = await DetectFileOperationAnomaliesAsync(processProfile, sensorEvent);
                    results.AddRange(fileAnomalies);
                }
            }
            
            // Detectar patrones de ransomware
            var ransomwareDetection = await DetectRansomwarePatternsAsync(sensorEvent);
            if (ransomwareDetection != null)
            {
                results.Add(ransomwareDetection);
            }
            
            // Detectar exfiltración de datos
            var exfiltrationDetection = await DetectDataExfiltrationAsync(sensorEvent);
            if (exfiltrationDetection != null)
            {
                results.Add(exfiltrationDetection);
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza comportamiento de red
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeNetworkBehaviorAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // Usar modelo de ML para análisis de red
            var networkPrediction = await _networkModel.PredictAsync(sensorEvent);
            
            if (networkPrediction != null && networkPrediction.AnomalyScore > ANOMALY_THRESHOLD)
            {
                var detection = CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Network behavior anomaly",
                    $"Anomalía en comportamiento de red: score {networkPrediction.AnomalyScore:P0}",
                    networkPrediction.AnomalyScore,
                    DetectionType.NetworkBehavior,
                    new Dictionary<string, object>
                    {
                        { "AnomalyScore", networkPrediction.AnomalyScore },
                        { "PredictionType", networkPrediction.PredictionType },
                        { "Features", networkPrediction.Features }
                    }
                );
                
                results.Add(detection);
            }
            
            // Detectar beaconing
            var beaconingDetection = await DetectBeaconingAsync(sensorEvent);
            if (beaconingDetection != null)
            {
                results.Add(beaconingDetection);
            }
            
            // Detectar escaneo de puertos
            var portScanDetection = await DetectPortScanningAsync(sensorEvent);
            if (portScanDetection != null)
            {
                results.Add(portScanDetection);
            }
            
            // Detectar comunicación C2
            var c2Detection = await DetectC2CommunicationAsync(sensorEvent);
            if (c2Detection != null)
            {
                results.Add(c2Detection);
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza comportamiento del registro
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeRegistryBehaviorAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // Detectar técnicas de persistencia
            var persistenceDetection = await DetectPersistenceTechniquesAsync(sensorEvent);
            if (persistenceDetection != null)
            {
                results.Add(persistenceDetection);
            }
            
            // Detectar desactivación de seguridad
            var securityDisableDetection = await DetectSecurityDisablingAsync(sensorEvent);
            if (securityDisableDetection != null)
            {
                results.Add(securityDisableDetection);
            }
            
            // Detectar modificación de configuraciones críticas
            var configModificationDetection = await DetectCriticalConfigModificationAsync(sensorEvent);
            if (configModificationDetection != null)
            {
                results.Add(configModificationDetection);
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza correlaciones entre eventos
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeEventCorrelationsAsync(List<SensorEvent> events)
        {
            var results = new List<DetectionResult>();
            
            // Agrupar eventos por proceso
            var eventsByProcess = events
                .Where(e => !string.IsNullOrEmpty(e.Data.ProcessName))
                .GroupBy(e => GetProcessKey(e.Data.ProcessName, e.Data.ImagePath));
            
            foreach (var processGroup in eventsByProcess)
            {
                var processEvents = processGroup.ToList();
                
                // Detectar cadenas de ataque
                var attackChainDetection = await DetectAttackChainAsync(processEvents);
                if (attackChainDetection != null)
                {
                    results.Add(attackChainDetection);
                }
                
                // Detectar living-off-the-land (LOLBAS)
                var lolbasDetection = await DetectLOLBASAsync(processEvents);
                if (lolbasDetection != null)
                {
                    results.Add(lolbasDetection);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Obtiene o crea perfil de proceso
        /// </summary>
        private ProcessBehaviorProfile GetOrCreateProcessProfile(string processKey, EventData eventData)
        {
            if (_processProfiles.TryGetValue(processKey, out var existingProfile))
            {
                return existingProfile;
            }
            
            var newProfile = new ProcessBehaviorProfile
            {
                ProcessKey = processKey,
                ProcessName = eventData.ProcessName,
                ImagePath = eventData.ImagePath,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow,
                ExecutionCount = 0,
                FileOperations = new BehaviorMetrics(),
                NetworkOperations = new BehaviorMetrics(),
                RegistryOperations = new BehaviorMetrics(),
                ProcessOperations = new BehaviorMetrics(),
                UserContexts = new HashSet<string>(),
                ParentProcesses = new HashSet<string>(),
                ChildProcesses = new HashSet<string>(),
                CommandLinePatterns = new HashSet<string>(),
                AccessedFiles = new HashSet<string>(),
                NetworkConnections = new HashSet<string>(),
                RegistryKeys = new HashSet<string>()
            };
            
            _processProfiles[processKey] = newProfile;
            return newProfile;
        }
        
        /// <summary>
        /// Actualiza perfil de proceso
        /// </summary>
        private void UpdateProcessProfile(ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            profile.LastSeen = DateTime.UtcNow;
            profile.ExecutionCount++;
            
            // Actualizar contexto de usuario
            if (!string.IsNullOrEmpty(sensorEvent.Data.UserSid))
            {
                profile.UserContexts.Add(sensorEvent.Data.UserSid);
            }
            
            // Actualizar estadísticas según tipo de evento
            switch (sensorEvent.SensorType)
            {
                case SensorType.Process:
                    UpdateProcessOperationsProfile(profile, sensorEvent);
                    break;
                    
                case SensorType.FileSystem:
                    UpdateFileOperationsProfile(profile, sensorEvent);
                    break;
                    
                case SensorType.Network:
                    UpdateNetworkOperationsProfile(profile, sensorEvent);
                    break;
                    
                case SensorType.Registry:
                    UpdateRegistryOperationsProfile(profile, sensorEvent);
                    break;
            }
            
            // Limitar tamaño del historial
            TrimProfileHistory(profile);
        }
        
        /// <summary>
        /// Actualiza operaciones de proceso en perfil
        /// </summary>
        private void UpdateProcessOperationsProfile(ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var metrics = profile.ProcessOperations;
            metrics.TotalCount++;
            metrics.LastActivity = DateTime.UtcNow;
            
            // Actualizar por tipo de evento
            switch (sensorEvent.EventType)
            {
                case EventType.ProcessCreated:
                    metrics.CreatedCount++;
                    break;
                    
                case EventType.ProcessTerminated:
                    metrics.TerminatedCount++;
                    break;
            }
            
            // Registrar proceso padre/hijo
            if (!string.IsNullOrEmpty(sensorEvent.Data.ParentProcessId))
            {
                profile.ParentProcesses.Add(sensorEvent.Data.ParentProcessId);
            }
        }
        
        /// <summary>
        /// Actualiza operaciones de archivo en perfil
        /// </summary>
        private void UpdateFileOperationsProfile(ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var metrics = profile.FileOperations;
            metrics.TotalCount++;
            metrics.LastActivity = DateTime.UtcNow;
            
            // Actualizar por tipo de operación
            if (!string.IsNullOrEmpty(sensorEvent.Data.OperationType))
            {
                switch (sensorEvent.Data.OperationType.ToUpperInvariant())
                {
                    case "CREATE":
                        metrics.CreatedCount++;
                        break;
                        
                    case "MODIFY":
                        metrics.ModifiedCount++;
                        break;
                        
                    case "DELETE":
                        metrics.DeletedCount++;
                        break;
                        
                    case "RENAME":
                        metrics.RenamedCount++;
                        break;
                }
            }
            
            // Registrar archivos accedidos
            if (!string.IsNullOrEmpty(sensorEvent.Data.FilePath))
            {
                profile.AccessedFiles.Add(sensorEvent.Data.FilePath);
            }
        }
        
        /// <summary>
        /// Actualiza operaciones de red en perfil
        /// </summary>
        private void UpdateNetworkOperationsProfile(ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var metrics = profile.NetworkOperations;
            metrics.TotalCount++;
            metrics.LastActivity = DateTime.UtcNow;
            
            // Registrar conexiones
            if (!string.IsNullOrEmpty(sensorEvent.Data.RemoteAddress))
            {
                var connectionKey = $"{sensorEvent.Data.RemoteAddress}:{sensorEvent.Data.RemotePort}";
                profile.NetworkConnections.Add(connectionKey);
            }
        }
        
        /// <summary>
        /// Actualiza operaciones de registro en perfil
        /// </summary>
        private void UpdateRegistryOperationsProfile(ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var metrics = profile.RegistryOperations;
            metrics.TotalCount++;
            metrics.LastActivity = DateTime.UtcNow;
            
            // Registrar claves de registro
            if (!string.IsNullOrEmpty(sensorEvent.Data.RegistryPath))
            {
                profile.RegistryKeys.Add(sensorEvent.Data.RegistryPath);
            }
        }
        
        /// <summary>
        /// Limita tamaño del historial del perfil
        /// </summary>
        private void TrimProfileHistory(ProcessBehaviorProfile profile)
        {
            // Limitar conjuntos de datos si son muy grandes
            if (profile.AccessedFiles.Count > PROFILE_HISTORY_SIZE)
            {
                profile.AccessedFiles = new HashSet<string>(
                    profile.AccessedFiles.Take(PROFILE_HISTORY_SIZE));
            }
            
            if (profile.NetworkConnections.Count > PROFILE_HISTORY_SIZE)
            {
                profile.NetworkConnections = new HashSet<string>(
                    profile.NetworkConnections.Take(PROFILE_HISTORY_SIZE));
            }
            
            if (profile.RegistryKeys.Count > PROFILE_HISTORY_SIZE)
            {
                profile.RegistryKeys = new HashSet<string>(
                    profile.RegistryKeys.Take(PROFILE_HISTORY_SIZE));
            }
        }
        
        /// <summary>
        /// Detecta anomalías en proceso
        /// </summary>
        private async Task<List<DetectionResult>> DetectProcessAnomaliesAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            
            // 1. Anomalía en frecuencia de ejecución
            var executionAnomaly = await DetectExecutionFrequencyAnomalyAsync(profile, sensorEvent);
            if (executionAnomaly != null)
            {
                results.Add(executionAnomaly);
            }
            
            // 2. Anomalía en tiempo de ejecución
            
                        // 2. Anomalía en tiempo de ejecución
            var runtimeAnomaly = await DetectRuntimeAnomalyAsync(profile, sensorEvent);
            if (runtimeAnomaly != null)
            {
                results.Add(runtimeAnomaly);
            }
            
            // 3. Anomalía en contexto de usuario
            var userContextAnomaly = await DetectUserContextAnomalyAsync(profile, sensorEvent);
            if (userContextAnomaly != null)
            {
                results.Add(userContextAnomaly);
            }
            
            // 4. Anomalía en línea de comandos
            var cmdLineAnomaly = await DetectCommandLineAnomalyAsync(profile, sensorEvent);
            if (cmdLineAnomaly != null)
            {
                results.Add(cmdLineAnomaly);
            }
            
            // 5. Uso del modelo de ML para anomalías de proceso
            var mlAnomaly = await DetectProcessMLAnomalyAsync(profile, sensorEvent);
            if (mlAnomaly != null)
            {
                results.Add(mlAnomaly);
            }
            
            return results;
        }
        
        /// <summary>
        /// Detecta anomalía en frecuencia de ejecución
        /// </summary>
        private async Task<DetectionResult> DetectExecutionFrequencyAnomalyAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            // Calcular frecuencia actual
            var timeSinceLastExecution = DateTime.UtcNow - profile.LastSeen;
            var executionRate = profile.ExecutionCount / (DateTime.UtcNow - profile.FirstSeen).TotalHours;
            
            // Línea base para este tipo de proceso
            var baselineRate = GetProcessExecutionBaseline(profile.ProcessName);
            
            // Si la frecuencia es significativamente mayor a la línea base
            if (baselineRate > 0 && executionRate > baselineRate * 3)
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Process execution frequency anomaly",
                    $"Frecuencia de ejecución anómala: {executionRate:F2}/hora (línea base: {baselineRate:F2}/hora)",
                    Math.Min(0.8, (executionRate - baselineRate) / baselineRate),
                    DetectionType.ProcessFrequency,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "ExecutionRate", executionRate },
                        { "BaselineRate", baselineRate },
                        { "ExecutionCount", profile.ExecutionCount },
                        { "TimeSinceFirstSeen", DateTime.UtcNow - profile.FirstSeen }
                    }
                );
            }
            
            // Si se ejecuta en ráfagas (muchas ejecuciones en poco tiempo)
            if (profile.ExecutionCount > 10 && timeSinceLastExecution.TotalSeconds < 5)
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Process execution burst detected",
                    $"Ráfaga de ejecuciones detectada: {profile.ExecutionCount} ejecuciones en {timeSinceLastExecution.TotalSeconds:F1} segundos",
                    0.7,
                    DetectionType.ProcessBurst,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "BurstCount", profile.ExecutionCount },
                        { "BurstDuration", timeSinceLastExecution },
                        { "LastSeen", profile.LastSeen }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta anomalía en tiempo de ejecución
        /// </summary>
        private async Task<DetectionResult> DetectRuntimeAnomalyAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            // Procesos que normalmente son de corta duración ejecutándose por mucho tiempo
            var shortLivedProcesses = new[] { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe" };
            
            if (shortLivedProcesses.Contains(profile.ProcessName.ToLowerInvariant()))
            {
                var runtime = DateTime.UtcNow - profile.FirstSeen;
                
                if (runtime.TotalMinutes > 30) // Más de 30 minutos es sospechoso
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Long-running short-lived process",
                        $"Proceso de corta duración ejecutándose por mucho tiempo: {runtime.TotalMinutes:F1} minutos",
                        0.75,
                        DetectionType.ProcessRuntime,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "Runtime", runtime },
                            { "FirstSeen", profile.FirstSeen },
                            { "IsShortLivedProcess", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta anomalía en contexto de usuario
        /// </summary>
        private async Task<DetectionResult> DetectUserContextAnomalyAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var currentUser = sensorEvent.Data.UserSid;
            
            // Si el proceso se ejecuta bajo múltiples usuarios (posible impersonation)
            if (profile.UserContexts.Count > 3 && !string.IsNullOrEmpty(currentUser))
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Process running under multiple users",
                    $"Proceso ejecutándose bajo {profile.UserContexts.Count} usuarios diferentes",
                    0.65,
                    DetectionType.UserContext,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "UserCount", profile.UserContexts.Count },
                        { "CurrentUser", currentUser },
                        { "AllUsers", string.Join(", ", profile.UserContexts) }
                    }
                );
            }
            
            // Si un proceso de sistema se ejecuta bajo usuario no privilegiado
            var systemProcesses = new[] { "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe" };
            if (systemProcesses.Contains(profile.ProcessName.ToLowerInvariant()) && 
                !string.IsNullOrEmpty(currentUser) &&
                !currentUser.Contains("SYSTEM") && !currentUser.Contains("LOCAL SERVICE") && !currentUser.Contains("NETWORK SERVICE"))
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "System process running under non-system account",
                    $"Proceso de sistema ejecutándose bajo cuenta de usuario: {currentUser}",
                    0.8,
                    DetectionType.UserPrivilege,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "UserAccount", currentUser },
                        { "IsSystemProcess", true }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta anomalía en línea de comandos
        /// </summary>
        private async Task<DetectionResult> DetectCommandLineAnomalyAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var commandLine = sensorEvent.Data.CommandLine;
            
            if (string.IsNullOrEmpty(commandLine))
            {
                return null;
            }
            
            // Verificar si la línea de comandos es inusual para este proceso
            var normalPatterns = GetNormalCommandLinePatterns(profile.ProcessName);
            var isNormal = normalPatterns.Any(pattern => 
                commandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase));
            
            if (!isNormal)
            {
                // Verificar técnicas de ofuscación
                var obfuscationIndicators = new[]
                {
                    "-enc ", "-e ", "iex(", "invoke-expression",
                    "frombase64", "downloadstring", "[char]",
                    "::", "++", "--", "~~"  // Dobles caracteres para ofuscación
                };
                
                var obfuscationCount = obfuscationIndicators.Count(indicator => 
                    commandLine.Contains(indicator, StringComparison.OrdinalIgnoreCase));
                
                if (obfuscationCount > 0)
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Obfuscated command line detected",
                        $"Línea de comandos ofuscada detectada en {profile.ProcessName}",
                        0.85,
                        DetectionType.CommandLineObfuscation,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "CommandLine", commandLine },
                            { "ObfuscationIndicators", obfuscationCount },
                            { "IsNormalPattern", false }
                        }
                    );
                }
            }
            
            // Verificar parámetros inusuales
            var suspiciousParameters = new[]
            {
                "-windowstyle hidden", "-w hidden", "-noprofile",
                "-nologo", "-noninteractive", "-executionpolicy bypass",
                "-bypass", "hidden", "silent", "stealth"
            };
            
            var suspiciousCount = suspiciousParameters.Count(param => 
                commandLine.Contains(param, StringComparison.OrdinalIgnoreCase));
            
            if (suspiciousCount > 0)
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Suspicious command line parameters",
                    $"Parámetros sospechosos detectados en {profile.ProcessName}",
                    0.7,
                    DetectionType.CommandLineParameters,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "CommandLine", commandLine },
                        { "SuspiciousParameterCount", suspiciousCount },
                        { "Parameters", suspiciousParameters.Where(p => 
                            commandLine.Contains(p, StringComparison.OrdinalIgnoreCase)).ToList() }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta anomalías usando modelo de ML
        /// </summary>
        private async Task<DetectionResult> DetectProcessMLAnomalyAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            try
            {
                var prediction = await _behaviorModel.PredictAsync(profile, sensorEvent);
                
                if (prediction != null && prediction.AnomalyScore > ANOMALY_THRESHOLD)
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Machine learning process anomaly",
                        $"Anomalía en proceso detectada por ML: score {prediction.AnomalyScore:P0}",
                        prediction.AnomalyScore,
                        DetectionType.MLAnomaly,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "AnomalyScore", prediction.AnomalyScore },
                            { "PredictionType", prediction.PredictionType },
                            { "Features", prediction.Features },
                            { "ModelVersion", _behaviorModel.ModelVersion }
                        }
                    );
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en modelo ML de proceso: {ex}", ModuleId);
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta anomalías en operaciones de archivo
        /// </summary>
        private async Task<List<DetectionResult>> DetectFileOperationAnomaliesAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            
            // 1. Ráfaga de operaciones de archivo
            var burstDetection = await DetectFileOperationBurstAsync(profile, sensorEvent);
            if (burstDetection != null)
            {
                results.Add(burstDetection);
            }
            
            // 2. Patrón de ransomware (muchos renames o deletes)
            var ransomwarePattern = await DetectRansomwareFilePatternAsync(profile, sensorEvent);
            if (ransomwarePattern != null)
            {
                results.Add(ransomwarePattern);
            }
            
            // 3. Acceso a ubicaciones sensibles
            var sensitiveLocationDetection = await DetectSensitiveFileAccessAsync(profile, sensorEvent);
            if (sensitiveLocationDetection != null)
            {
                results.Add(sensitiveLocationDetection);
            }
            
            // 4. Exfiltración de datos (muchas lecturas de archivos)
            var exfiltrationDetection = await DetectDataExfiltrationFilePatternAsync(profile, sensorEvent);
            if (exfiltrationDetection != null)
            {
                results.Add(exfiltrationDetection);
            }
            
            return results;
        }
        
        /// <summary>
        /// Detecta ráfaga de operaciones de archivo
        /// </summary>
        private async Task<DetectionResult> DetectFileOperationBurstAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var fileMetrics = profile.FileOperations;
            
            // Si muchas operaciones en poco tiempo
            if (fileMetrics.TotalCount > 50 && 
                (DateTime.UtcNow - fileMetrics.FirstActivity).TotalSeconds < 10)
            {
                var rate = fileMetrics.TotalCount / (DateTime.UtcNow - fileMetrics.FirstActivity).TotalSeconds;
                
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "File operation burst detected",
                    $"Ráfaga de operaciones de archivo: {fileMetrics.TotalCount} operaciones en {rate:F1}/segundo",
                    0.75,
                    DetectionType.FileOperationBurst,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "OperationCount", fileMetrics.TotalCount },
                        { "OperationRate", rate },
                        { "FirstActivity", fileMetrics.FirstActivity },
                        { "LastActivity", fileMetrics.LastActivity }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta patrón de ransomware en operaciones de archivo
        /// </summary>
        private async Task<DetectionResult> DetectRansomwareFilePatternAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var fileMetrics = profile.FileOperations;
            
            // Ransomware típicamente hace muchos renames o deletes
            var renameDeleteRatio = (fileMetrics.RenamedCount + fileMetrics.DeletedCount) / 
                                   (double)Math.Max(1, fileMetrics.TotalCount);
            
            if (renameDeleteRatio > 0.5 && fileMetrics.TotalCount > 20)
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Possible ransomware file activity",
                    $"Posible actividad de ransomware: {renameDeleteRatio:P0} de operaciones son renames/deletes",
                    0.85,
                    DetectionType.RansomwarePattern,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", profile.ProcessName },
                        { "RenameDeleteRatio", renameDeleteRatio },
                        { "TotalOperations", fileMetrics.TotalCount },
                        { "RenamedCount", fileMetrics.RenamedCount },
                        { "DeletedCount", fileMetrics.DeletedCount }
                    }
                );
            }
            
            // También verificar extensiones específicas de ransomware
            var ransomwareExtensions = new[] { ".locked", ".encrypted", ".crypt", ".ransom", ".xtbl" };
            var filePath = sensorEvent.Data.FilePath;
            
            if (!string.IsNullOrEmpty(filePath))
            {
                var extension = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
                if (ransomwareExtensions.Contains(extension))
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Ransomware file extension detected",
                        $"Extensión de ransomware detectada: {extension}",
                        0.9,
                        DetectionType.RansomwareExtension,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "FilePath", filePath },
                            { "Extension", extension },
                            { "IsRansomwareExtension", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta acceso a ubicaciones sensibles
        /// </summary>
        private async Task<DetectionResult> DetectSensitiveFileAccessAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            var filePath = sensorEvent.Data.FilePath;
            
            if (string.IsNullOrEmpty(filePath))
            {
                return null;
            }
            
            var lowerPath = filePath.ToLowerInvariant();
            
            // Ubicaciones sensibles del sistema
            var sensitiveLocations = new[]
            {
                @"c:\windows\system32\config\",
                @"c:\windows\system32\catroot\",
                @"c:\windows\system32\catroot2\",
                @"c:\windows\system32\winevt\logs\",
                @"c:\windows\debug\",
                @"c:\windows\minidump\",
                @"c:\pagefile.sys",
                @"c:\hiberfil.sys",
                @"c:\swapfile.sys"
            };
            
            foreach (var location in sensitiveLocations)
            {
                if (lowerPath.StartsWith(location))
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Access to sensitive system location",
                        $"Acceso a ubicación sensible del sistema: {filePath}",
                        0.8,
                        DetectionType.SensitiveFileAccess,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "FilePath", filePath },
                            { "SensitiveLocation", location },
                            { "OperationType", sensorEvent.Data.OperationType }
                        }
                    );
                }
            }
            
            // Directorios de backup/ shadow copies
            if (lowerPath.Contains(@"\windows\shadow\") || 
                lowerPath.Contains(@"\system volume information\") ||
                lowerPath.Contains(@"\~") || // Archivos temporales/backup
                lowerPath.EndsWith(".bak") || 
                lowerPath.EndsWith(".old") ||
                lowerPath.EndsWith(".tmp"))
            {
                // Operaciones de delete en archivos de backup son sospechosas
                if (sensorEvent.Data.OperationType?.ToUpperInvariant() == "DELETE")
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Deletion of backup/shadow files",
                        $"Eliminación de archivos de backup/shadow: {filePath}",
                        0.7,
                        DetectionType.BackupFileDeletion,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "FilePath", filePath },
                            { "OperationType", "DELETE" },
                            { "IsBackupFile", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta patrón de exfiltración de datos
        /// </summary>
        private async Task<DetectionResult> DetectDataExfiltrationFilePatternAsync(
            ProcessBehaviorProfile profile, SensorEvent sensorEvent)
        {
            // Muchas lecturas de diferentes archivos en poco tiempo
            if (profile.AccessedFiles.Count > 50 && 
                (DateTime.UtcNow - profile.FileOperations.FirstActivity).TotalMinutes < 5)
            {
                var fileReadRate = profile.AccessedFiles.Count / 
                                  (DateTime.UtcNow - profile.FileOperations.FirstActivity).TotalMinutes;
                
                if (fileReadRate > 10) // Más de 10 archivos por minuto
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Possible data exfiltration file access pattern",
                        $"Posible patrón de exfiltración de datos: {fileReadRate:F1} archivos/minuto",
                        0.7,
                        DetectionType.DataExfiltrationFile,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", profile.ProcessName },
                            { "FileReadRate", fileReadRate },
                            { "UniqueFilesAccessed", profile.AccessedFiles.Count },
                            { "AccessDuration", DateTime.UtcNow - profile.FileOperations.FirstActivity }
                        }
                    );
                }
            }
            
            // Acceso a archivos de documentos/ datos sensibles
            var documentExtensions = new[] { ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".csv", ".sql", ".mdb" };
            var filePath = sensorEvent.Data.FilePath;
            
            if (!string.IsNullOrEmpty(filePath))
            {
                var extension = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
                if (documentExtensions.Contains(extension))
                {
                    // Muchos accesos a documentos en poco tiempo
                    var documentAccessCount = profile.AccessedFiles.Count(f => 
                        documentExtensions.Any(ext => f.ToLowerInvariant().EndsWith(ext)));
                    
                    if (documentAccessCount > 20)
                    {
                        return CreateBehaviorDetectionResult(
                            sensorEvent,
                            "Mass access to document files",
                            $"Acceso masivo a archivos de documentos: {documentAccessCount} archivos",
                            0.75,
                            DetectionType.DocumentExfiltration,
                            new Dictionary<string, object>
                            {
                                { "ProcessName", profile.ProcessName },
                                { "DocumentAccessCount", documentAccessCount },
                                { "FileExtension", extension },
                                { "FilePath", filePath }
                            }
                        );
                    }
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta beaconing en red
        /// </summary>
        private async Task<DetectionResult> DetectBeaconingAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            // Beaconing: conexiones periódicas a la misma dirección
            // Necesitaríamos historial para detectar esto completamente
            // Por ahora, detectar conexiones frecuentes a la misma IP
            
            if (!string.IsNullOrEmpty(eventData.RemoteAddress))
            {
                var connectionKey = $"{eventData.ProcessName}|{eventData.RemoteAddress}:{eventData.RemotePort}";
                
                // Buscar en historial de conexiones del proceso
                var processKey = GetProcessKey(eventData.ProcessName, eventData.ImagePath);
                if (_processProfiles.TryGetValue(processKey, out var profile))
                {
                    var sameConnections = profile.NetworkConnections.Count(c => 
                        c.Contains(eventData.RemoteAddress));
                    
                    if (sameConnections > 10) // Muchas conexiones a la misma IP
                    {
                        return CreateBehaviorDetectionResult(
                            sensorEvent,
                            "Possible beaconing detected",
                            $"Posible beaconing detectado: {sameConnections} conexiones a {eventData.RemoteAddress}",
                            0.8,
                            DetectionType.NetworkBeaconing,
                            new Dictionary<string, object>
                            {
                                { "ProcessName", eventData.ProcessName },
                                { "RemoteAddress", eventData.RemoteAddress },
                                { "ConnectionCount", sameConnections },
                                { "Port", eventData.RemotePort }
                            }
                        );
                    }
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta escaneo de puertos
        /// </summary>
        private async Task<DetectionResult> DetectPortScanningAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            // Escaneo de puertos: muchas conexiones a diferentes puertos de la misma IP
            if (!string.IsNullOrEmpty(eventData.RemoteAddress))
            {
                var processKey = GetProcessKey(eventData.ProcessName, eventData.ImagePath);
                if (_processProfiles.TryGetValue(processKey, out var profile))
                {
                    var connectionsToSameHost = profile.NetworkConnections
                        .Where(c => c.Contains(eventData.RemoteAddress))
                        .Select(c => 
                        {
                            var parts = c.Split(':');
                            return parts.Length > 1 ? int.Parse(parts[1]) : 0;
                        })
                        .Where(port => port > 0)
                        .Distinct()
                        .Count();
                    
                    if (connectionsToSameHost > 20) // Muchos puertos diferentes en la misma IP
                    {
                        return CreateBehaviorDetectionResult(
                            sensorEvent,
                            "Possible port scanning detected",
                            $"Posible escaneo de puertos: {connectionsToSameHost} puertos diferentes en {eventData.RemoteAddress}",
                            0.85,
                            DetectionType.PortScanning,
                            new Dictionary<string, object>
                            {
                                { "ProcessName", eventData.ProcessName },
                                { "RemoteAddress", eventData.RemoteAddress },
                                { "UniquePorts", connectionsToSameHost },
                                { "IsOutbound", eventData.IsOutbound }
                            }
                        );
                    }
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta comunicación C2
        /// </summary>
        private async Task<DetectionResult> DetectC2CommunicationAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            // Comunicación C2: conexiones a IPs/Dominios sospechosos con patrones específicos
            
            // Verificar dominios DGA-like
            if (!string.IsNullOrEmpty(eventData.DnsName))
            {
                var domain = eventData.DnsName.ToLowerInvariant();
                
                // Características de dominios generados por algoritmos (DGA)
                var isDGADomain = IsDGADomain(domain);
                
                if (isDGADomain)
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Possible DGA domain C2 communication",
                        $"Posible comunicación C2 con dominio DGA: {domain}",
                        0.9,
                        DetectionType.C2Communication,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "Domain", domain },
                            { "IsDGADomain", true },
                            { "DomainLength", domain.Length },
                            { "DigitCount", domain.Count(char.IsDigit) }
                        }
                    );
                }
            }
            
            // Verificar conexiones a IPs en países de alto riesgo
            if (!string.IsNullOrEmpty(eventData.RemoteAddress))
            {
                var country = GetIPCountry(eventData.RemoteAddress);
                var highRiskCountries = new[] { "CN", "RU", "IR", "KP", "SY" };
                
                if (highRiskCountries.Contains(country))
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Connection to high-risk country",
                        $"Conexión a país de alto riesgo: {country} ({eventData.RemoteAddress})",
                        0.7,
                        DetectionType.HighRiskCountry,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RemoteAddress", eventData.RemoteAddress },
                            { "Country", country },
                            { "IsHighRisk", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta técnicas de persistencia
        /// </summary>
        private async Task<DetectionResult> DetectPersistenceTechniquesAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            if (string.IsNullOrEmpty(eventData.RegistryPath) || 
                string.IsNullOrEmpty(eventData.NewValueData))
            {
                return null;
            }
            
            // Técnicas comunes de persistencia
            
            // 1. DLL Hijacking
            if (eventData.RegistryPath.ToUpperInvariant().Contains("KNOWN DLLS") ||
                eventData.RegistryPath.ToUpperInvariant().Contains("APPINIT_DLLS"))
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Possible DLL hijacking persistence",
                    $"Posible DLL hijacking detectado en: {eventData.RegistryPath}",
                    0.85,
                    DetectionType.PersistenceDLL,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", eventData.ProcessName },
                        { "RegistryPath", eventData.RegistryPath },
                        { "ValueData", eventData.NewValueData },
                        { "Technique", "DLL Hijacking" }
                    }
                );
            }
            
            // 2. Scheduled Tasks
            if (eventData.RegistryPath.ToUpperInvariant().Contains("SCHEDULE") ||
                eventData.RegistryPath.ToUpperInvariant().Contains("TASKCACHE"))
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Scheduled task persistence",
                    $"Persistencia mediante tarea programada: {eventData.RegistryPath}",
                    0.8,
                    DetectionType.PersistenceScheduledTask,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", eventData.ProcessName },
                        { "RegistryPath", eventData.RegistryPath },
                        { "ValueData", eventData.NewValueData },
                        { "Technique", "Scheduled Task" }
                    }
                );
            }
            
            // 3. Services
            if (eventData.RegistryPath.ToUpperInvariant().Contains(@"SYSTEM\CURRENTCONTROLSET\SERVICES\"))
            {
                return CreateBehaviorDetectionResult(
                    sensorEvent,
                    "Service persistence",
                    $"Persistencia mediante servicio: {eventData.RegistryPath}",
                    0.9,
                    DetectionType.PersistenceService,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", eventData.ProcessName },
                        { "RegistryPath", eventData.RegistryPath },
                        { "ValueData", eventData.NewValueData },
                        { "Technique", "Service" }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta desactivación de seguridad
        /// </summary>
        private async Task<DetectionResult> DetectSecurityDisablingAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            if (string.IsNullOrEmpty(eventData.RegistryPath) || 
                string.IsNullOrEmpty(eventData.NewValueData))
            {
                return null;
            }
            
            var upperPath = eventData.RegistryPath.ToUpperInvariant();
            var lowerValue = eventData.NewValueData.ToLowerInvariant();
            
            // Desactivación de Windows Defender
            if (upperPath.Contains("WINDOWS DEFENDER") || upperPath.Contains("ANTIMALWARE"))
            {
                if (lowerValue.Contains("disable") || lowerValue.Contains("0") || 
                    lowerValue == "false" || lowerValue == "off")
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Antivirus/Defender disabling",
                        $"Desactivación de antivirus/Windows Defender: {eventData.RegistryPath}",
                        0.95,
                        DetectionType.SecurityDisable,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RegistryPath", eventData.RegistryPath },
                            { "ValueData", eventData.NewValueData },
                            { "SecurityFeature", "Windows Defender" }
                        }
                    );
                }
            }
            
            // Desactivación de UAC
            if (upperPath.Contains("POLICIES\\SYSTEM") && 
                eventData.ValueName?.ToUpperInvariant() == "ENABLELUA")
            {
                if (lowerValue == "0" || lowerValue == "false")
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "UAC disabling",
                        $"Desactivación de UAC (User Account Control)",
                        0.9,
                        DetectionType.UACDisable,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RegistryPath", eventData.RegistryPath },
                            { "ValueName", eventData.ValueName },
                            { "ValueData", eventData.NewValueData },
                            { "SecurityFeature", "UAC" }
                        }
                    );
                }
            }
            
            // Desactivación de Firewall
            if (upperPath.Contains("FIREWALL") || upperPath.Contains("SHAREDACCESS"))
            {
                if (lowerValue.Contains("disable") || lowerValue.Contains("0") || 
                    lowerValue == "false" || lowerValue == "off")
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Firewall disabling",
                        $"Desactivación de firewall: {eventData.RegistryPath}",
                        0.85,
                        DetectionType.FirewallDisable,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RegistryPath", eventData.RegistryPath },
                            { "ValueData", eventData.NewValueData },
                            { "SecurityFeature", "Firewall" }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta modificación de configuraciones críticas
        /// </summary>
        private async Task<DetectionResult> DetectCriticalConfigModificationAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            if (string.IsNullOrEmpty(eventData.RegistryPath))
            {
                return null;
            }
            
            var upperPath = eventData.RegistryPath.ToUpperInvariant();
            
            // Configuraciones críticas del sistema
            var criticalConfigs = new[]
            {
                @"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON",
                @"SYSTEM\CURRENTCONTROLSET\CONTROL\LSA",
                @"SYSTEM\CURRENTCONTROLSET\CONTROL\SECURITYPROVIDERS",
                @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM",
                @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
                @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE"
            };
            
            foreach (var config in criticalConfigs)
            {
                if (upperPath.Contains(config))
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Critical system configuration modification",
                        $"Modificación de configuración crítica del sistema: {eventData.RegistryPath}",
                        0.8,
                        DetectionType.CriticalConfigMod,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RegistryPath", eventData.RegistryPath },
                            { "ValueName", eventData.ValueName },
                            { "ValueData", eventData.NewValueData },
                            { "IsCriticalConfig", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta patrón de ransomware en eventos
        /// </summary>
        private async Task<DetectionResult> DetectRansomwarePatternsAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            // Ransomware suele acceder a muchos archivos con extensiones específicas
            // y modificar extensiones o añadir nuevas
            
            if (!string.IsNullOrEmpty(eventData.FilePath))
            {
                var extension = System.IO.Path.GetExtension(eventData.FilePath).ToLowerInvariant();
                
                // Extensiones comúnmente afectadas por ransomware
                var commonExtensions = new[]
                {
                    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".pdf", ".jpg", ".jpeg", ".png", ".bmp", ".gif",
                    ".mp4", ".avi", ".mov", ".wmv", ".zip", ".rar",
                    ".txt", ".csv", ".sql", ".mdb", ".accdb"
                };
                
                if (commonExtensions.Contains(extension))
                {
                    // Operación de rename o delete en archivos comunes
                    if (eventData.OperationType?.ToUpperInvariant() == "RENAME" ||
                        eventData.OperationType?.ToUpperInvariant() == "DELETE")
                    {
                        return CreateBehaviorDetectionResult(
                            sensorEvent,
                            "Ransomware-like file operation",
                            $"Operación tipo ransomware en archivo: {eventData.FilePath}",
                            0.7,
                            DetectionType.RansomwareFileOp,
                            new Dictionary<string, object>
                            {
                                { "ProcessName", eventData.ProcessName },
                                { "FilePath", eventData.FilePath },
                                { "OperationType", eventData.OperationType },
                                { "FileExtension", extension },
                                { "IsCommonFileType", true }
                            }
                        );
                    }
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta exfiltración de datos
        /// </summary>
        private async Task<DetectionResult> DetectDataExfiltrationAsync(SensorEvent sensorEvent)
        {
            var eventData = sensorEvent.Data;
            
            // Exfiltración: grandes transferencias de datos a destinos externos
            if (eventData.BytesSent.HasValue && eventData.BytesSent > 10 * 1024 * 1024) // 10MB
            {
                // A destinos externos (no IPs locales)
                if (!string.IsNullOrEmpty(eventData.RemoteAddress) && 
                    !IsLocalOrPrivateIP(eventData.RemoteAddress))
                {
                    return CreateBehaviorDetectionResult(
                        sensorEvent,
                        "Large data transfer to external destination",
                        $"Gran transferencia de datos a destino externo: {eventData.BytesSent / 1024 / 1024}MB a {eventData.RemoteAddress}",
                        0.8,
                        DetectionType.DataExfiltration,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", eventData.ProcessName },
                            { "RemoteAddress", eventData.RemoteAddress },
                            { "BytesSent", eventData.BytesSent },
                            { "BytesSentMB", eventData.BytesSent / 1024 / 1024 },
                            { "IsExternal", true }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta cadenas de ataque
        /// </summary>
        private async Task<DetectionResult> DetectAttackChainAsync(List<SensorEvent> processEvents)
        {
            // Buscar patrones de cadenas de ataque comunes
            
            // Ejemplo: Process creation -> Network connection -> File modification
            var hasProcessCreation = processEvents.Any(e => 
                e.EventType == EventType.ProcessCreated);
            var hasNetworkConnection = processEvents.Any(e => 
                e.SensorType == SensorType.Network);
            var hasFileModification = processEvents.Any(e => 
                e.SensorType == SensorType.FileSystem && 
                e.Data.OperationType == "MODIFY");
            
            if (hasProcessCreation && hasNetworkConnection && hasFileModification)
            {
                var firstEvent = processEvents.First();
                return CreateBehaviorDetectionResult(
                    firstEvent,
                    "Possible attack chain detected",
                    "Posible cadena de ataque detectada: Creación proceso -> Conexión red -> Modificación archivo",
                    0.75,
                    DetectionType.AttackChain,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", firstEvent.Data.ProcessName },
                        { "EventCount", processEvents.Count },
                        { "HasProcessCreation", hasProcessCreation },
                        { "HasNetworkConnection", hasNetworkConnection },
                        { "HasFileModification", hasFileModification },
                        { "ChainPattern", "Process->Network->File" }
                    }
                );
            }
            
            // Otro patrón: Registry modification -> Process creation -> Network connection
            var hasRegistryMod = processEvents.Any(e => 
                e.SensorType == SensorType.Registry);
            
            if (hasRegistryMod && hasProcessCreation && hasNetworkConnection)
            {
                var firstEvent = processEvents.First();
                return CreateBehaviorDetectionResult(
                    firstEvent,
                    "Possible persistence attack chain",
                    "Posible cadena de ataque con persistencia: Modificación registro -> Creación proceso -> Conexión red",
                    0.8,
                    DetectionType.PersistenceChain,
                    new Dictionary<string, object>
                    {
                        { "ProcessName", firstEvent.Data.ProcessName },
                        { "EventCount", processEvents.Count },
                        { "HasRegistryModification", hasRegistryMod },
                        { "HasProcessCreation", hasProcessCreation },
                        { "HasNetworkConnection", hasNetworkConnection },
                        { "ChainPattern", "Registry->Process->Network" }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Detecta uso de LOLBAS (Living Off The Land Binaries and Scripts)
        /// </summary>
        private async Task<DetectionResult> DetectLOLBASAsync(List<SensorEvent> processEvents)
        {
            // Binarios legítimos del sistema usados maliciosamente
            var lolbasBinaries = new[]
            {
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
                "certutil.exe", "wmic.exe", "schtasks.exe", "net.exe",
                "sc.exe", "netsh.exe", "ftp.exe", "telnet.exe"
            };
            
            var firstEvent = processEvents.FirstOrDefault();
            if (firstEvent == null)
            {
                return null;
            }
            
            var processName = firstEvent.Data.ProcessName;
            
            if (lolbasBinaries.Contains(processName.ToLowerInvariant()))
            {
                // Verificar actividades sospechosas para este LOLBAS
                var suspiciousActivities = new List<string>();
                
                // PowerShell con parámetros sospechosos
                if (processName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var hasEncodedCommand = processEvents.Any(e => 
                        !string.IsNullOrEmpty(e.Data.CommandLine) && 
                        e.Data.CommandLine.Contains("-enc ", StringComparison.OrdinalIgnoreCase));
                    
                    if (hasEncodedCommand)
                    {
                        suspiciousActivities.Add("Encoded command execution");
                    }
                }
                
                // COM script execution
                if (processName.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase) ||
                    processName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var hasScriptExecution = processEvents.Any(e => 
                        !string.IsNullOrEmpty(e.Data.CommandLine) && 
                        (e.Data.CommandLine.Contains(".sct", StringComparison.OrdinalIgnoreCase) ||
                         e.Data.CommandLine.Contains("javascript:", StringComparison.OrdinalIgnoreCase)));
                    
                    if (hasScriptExecution)
                    {
                        suspiciousActivities.Add("Script execution via COM");
                    }
                }
                
                if (suspiciousActivities.Any())
                {
                    return CreateBehaviorDetectionResult(
                        firstEvent,
                        "LOLBAS binary with suspicious activity",
                        $"Binario LOLBAS con actividad sospechosa: {processName} - {string.Join(", ", suspiciousActivities)}",
                        0.85,
                        DetectionType.LOLBAS,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", processName },
                            { "IsLOLBAS", true },
                            { "SuspiciousActivities", suspiciousActivities },
                            { "EventCount", processEvents.Count }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Crea resultado de detección de comportamiento
        /// </summary>
        private DetectionResult CreateBehaviorDetectionResult(
            SensorEvent sensorEvent,
            string threatName,
            string description,
            double confidence,
            DetectionType detectionType,
            Dictionary<string, object> details)
        {
            var severity = confidence >= 0.8 ? ThreatSeverity.High :
                          confidence >= 0.6 ? ThreatSeverity.Medium :
                          ThreatSeverity.Low;
            
            return new DetectionResult
            {
                DetectionId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                EventId = sensorEvent.EventId,
                EventType = sensorEvent.EventType,
                SensorType = sensorEvent.SensorType,
                SourceModule = ModuleId,
                ThreatName = threatName,
                Description = description,
                Severity = severity,
                DetectionType = detectionType,
                Confidence = confidence,
                SourceEvent = sensorEvent,
                Details = details,
                RecommendedActions = GetBehaviorRecommendedActions(detectionType, severity, confidence)
            };
        }
        
        /// <summary>
        /// Obtiene acciones recomendadas para detecciones de comportamiento
        /// </summary>
        private List<string> GetBehaviorRecommendedActions(
            DetectionType detectionType, ThreatSeverity severity, double confidence)
        {
            var actions = new List<string>();
            
            // Acciones basadas en severidad
            if (severity >= ThreatSeverity.High && confidence >= 0.8)
            {
                actions.Add("Quarantine");
                actions.Add("Block");
                actions.Add("AlertSecurityTeam");
            }
            else if (severity >= ThreatSeverity.Medium || confidence >= 0.6)
            {
                actions.Add("Monitor");
                actions.Add("Investigate");
                actions.Add("Alert");
            }
            else
            {
                actions.Add("Log");
                actions.Add("Monitor");
            }
            
            // Acciones específicas por tipo
            switch (detectionType)
            {
                case DetectionType.RansomwarePattern:
                case DetectionType.RansomwareExtension:
                case DetectionType.RansomwareFileOp:
                    actions.Add("IsolateEndpoint");
                    actions.Add("CheckBackups");
                    actions.Add("ScanForEncryptedFiles");
                    break;
                    
                case DetectionType.DataExfiltration:
                case DetectionType.DocumentExfiltration:
                    actions.Add("BlockNetwork");
                    actions.Add("ReviewDLP");
                    actions.Add("CheckDataLoss");
                    break;
                    
                case DetectionType.C2Communication:
                case DetectionType.NetworkBeaconing:
                    actions.Add("BlockIP");
                    actions.Add("IsolateNetwork");
                    actions.Add("ForensicAnalysis");
                    break;
                    
                case DetectionType.PersistenceChain:
                case DetectionType.PersistenceService:
                case DetectionType.PersistenceDLL:
                case DetectionType.PersistenceScheduledTask:
                    actions.Add("RemovePersistence");
                    actions.Add("ScanForRootkits");
                    actions.Add("RebootSystem");
                    break;
                    
                case DetectionType.SecurityDisable:
                case DetectionType.UACDisable:
                case DetectionType.FirewallDisable:
                    actions.Add("RestoreSecuritySettings");
                    actions.Add("EnableSecurityFeatures");
                    actions.Add("AuditSystem");
                    break;
            }
            
            return actions;
        }
        
        /// <summary>
        /// Procesa análisis de comportamiento continuo
        /// </summary>
        private async Task AnalyzeBehaviorContinuouslyAsync(CancellationToken cancellationToken)
        {
            _logManager.LogInfo("Iniciando análisis de comportamiento continuo", ModuleId);
            
            while (!cancellationToken.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Obtener eventos para análisis
                    var events = await GetEventsForAnalysisAsync(50);
                    
                    if (events.Count > 0)
                    {
                        // Analizar eventos
                        var results = await AnalyzeEventsAsync(events);
                        
                        // Procesar resultados
                        await ProcessBehaviorResultsAsync(results);
                        
                        // Actualizar modelos ML con nuevo aprendizaje
                        await UpdateMLModelsAsync(events, results);
                        
                        _logManager.LogDebug($"BehaviorAnalyzer procesó {events.Count} eventos, {results.Count} anomalías", ModuleId);
                    }
                    
                    // Periódicamente guardar perfiles y limpiar
                    await PeriodicMaintenanceAsync();
                    
                    // Esperar antes de siguiente ciclo
                    await Task.Delay(2000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en AnalyzeBehaviorContinuouslyAsync: {ex}", ModuleId);
                    await Task.Delay(5000, cancellationToken);
                }
            }
            
            _logManager.LogInfo("Análisis de comportamiento detenido", ModuleId);
        }
        
        /// <summary>
        /// Obtiene eventos para análisis
        /// </summary>
        private async Task<List<SensorEvent>> GetEventsForAnalysisAsync(int maxCount)
        {
            // Implementar obtención desde cola compartida
            // Por ahora retornar lista vacía
            return new List<SensorEvent>();
        }
        
        /// <summary>
        /// Procesa resultados de análisis de comportamiento
        /// </summary>
        private async Task ProcessBehaviorResultsAsync(List<DetectionResult> results)
        {
            foreach (var result in results)
            {
                try
                {
                    // Guardar en base de datos
                    await _localDatabase.SaveDetectionResultAsync(result);
                    
                    // Enviar a telemetría si es crítico
                    if (result.Severity >= ThreatSeverity.High || result.Confidence >= 0.8)
                    {
                        await SendToTelemetryAsync(result);
                    }
                    
                    // Actualizar perfiles con detección
                    UpdateProfilesWithDetection(result);
                    
                    // Log detección
                    _logManager.LogWarning(
                        $"Detección de comportamiento: {result.ThreatName} - Severidad: {result.Severity} - Confianza: {result.Confidence:P0}",
                        ModuleId);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al procesar resultado de comportamiento: {ex}", ModuleId);
                }
            }
        }
        
        /// <summary>
        /// Envía resultado a telemetría
        /// </summary>
        private async Task SendToTelemetryAsync(DetectionResult result)
        {
            // Implementar envío a telemetría
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Actualiza perfiles con información de detección
        /// </summary>
        private void UpdateProfilesWithDetection(DetectionResult result)
        {
            // Marcar procesos detectados como sospechosos en sus perfiles
            var sourceEvent = result.SourceEvent;
            if (sourceEvent != null && !string.IsNullOrEmpty(sourceEvent.Data.ProcessName))
            {
                var processKey = GetProcessKey(
                    sourceEvent.Data.ProcessName, 
                    sourceEvent.Data.ImagePath);
                
                if (_processProfiles.TryGetValue(processKey, out var profile))
                {
                    profile.DetectionCount++;
                    profile.LastDetection = DateTime.UtcNow;
                    profile.DetectionSeverity = result.Severity;
                }
            }
        }
        
        /// <summary>
        /// Actualiza modelos ML con nuevo aprendizaje
        /// </summary>
        private async Task UpdateMLModelsAsync(List<SensorEvent> events, List<DetectionResult> results)
        {
            try
            {
                // Solo actualizar periódicamente
                if (DateTime.UtcNow.Minute % 15 == 0) // Cada 15 minutos
                {
                    await _behaviorModel.UpdateModelAsync(events, results);
                    await _networkModel.UpdateModelAsync(events, results);
                    
                    _logManager.LogInfo("Modelos ML actualizados", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar modelos ML: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Mantenimiento periódico
        /// </summary>
        private async Task PeriodicMaintenanceAsync()
        {
            // Guardar perfiles cada 5 minutos
            if (DateTime.UtcNow.Minute % 5 == 0)
            {
                await SaveBehaviorProfilesAsync();
                
                // Limpiar perfiles antiguos
                CleanupOldProfiles();
                
                _logManager.LogDebug("Mantenimiento periódico completado", ModuleId);
            }
        }
        
        /// <summary>
        /// Carga perfiles de comportamiento desde base de datos
        /// </summary>
        private async Task LoadBehaviorProfilesAsync()
        {
            try
            {
                var profiles = await _localDatabase.GetBehaviorProfilesAsync();
                
                foreach (var profile in profiles)
                {
                    _processProfiles[profile.ProcessKey] = profile;
                }
                
                _logManager.LogInfo($"Cargados {profiles.Count} perfiles de comportamiento", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar perfiles de comportamiento: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda perfiles de comportamiento
        /// </summary>
        private async Task SaveBehaviorProfilesAsync()
        {
            try
            {
                var profiles = _processProfiles.Values.ToList();
                await _localDatabase.SaveBehaviorProfilesAsync(profiles);
                
                _logManager.LogDebug($"Guardados {profiles.Count} perfiles de comportamiento", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar perfiles: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Inicializa modelos de ML
        /// </summary>
        private async Task InitializeMLModelsAsync()
        {
            try
            {
                await _behaviorModel.InitializeAsync();
                await _networkModel.InitializeAsync();
                
                _logManager.LogInfo("Modelos ML inicializados", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar modelos ML: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Establece línea base de comportamiento
        /// </summary>
        private async Task EstablishBehaviorBaselineAsync()
        {
            // Recolectar datos iniciales para establecer línea base
            // Esto podría tomar algunos minutos/horas en producción
            
            _logManager.LogInfo("Estableciendo línea base de comportamiento...", ModuleId);
            
            // En producción, recolectar datos del sistema por un período
            // Por ahora, establecer valores por defecto
            
            await Task.Delay(1000); // Simular establecimiento de línea base
            
            _logManager.LogInfo("Línea base de comportamiento establecida", ModuleId);
        }
        
        /// <summary>
        /// Limpia perfiles antiguos
        /// </summary>
        private void CleanupOldProfiles()
        {
            var cutoffTime = DateTime.UtcNow.AddDays(-7); // Mantener 7 días
            
            var oldProfiles = _processProfiles
                .Where(kv => kv.Value.LastSeen < cutoffTime)
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var key in oldProfiles)
            {
                _processProfiles.TryRemove(key, out _);
            }
            
            if (oldProfiles.Count > 0)
            {
                _logManager.LogDebug($"Eliminados {oldProfiles.Count} perfiles antiguos", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene clave única para proceso
        /// </summary>
        private string GetProcessKey(string processName, string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath))
            {
                return processName?.ToLowerInvariant() ?? "unknown";
            }
            
            return $"{processName?.ToLowerInvariant()}|{imagePath.ToLowerInvariant()}";
        }
        
        /// <summary>
        /// Obtiene línea base de ejecución para proceso
        /// </summary>
        private double GetProcessExecutionBaseline(string processName)
        {
            // Valores por defecto para procesos comunes
            var baselines = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
            {
                { "explorer.exe", 1.0 },      // Normalmente 1 por sesión
                { "svchost.exe", 10.0 },      // Múltiples instancias
                { "chrome.exe", 0.5 },        // Depende del uso
                { "firefox.exe", 0.3 },
                { "outlook.exe", 0.2 },
                { "winword.exe", 0.1 },
                { "excel.exe", 0.1 },
                { "powerpnt.exe", 0.05 },
                { "powershell.exe", 0.1 },
                { "cmd.exe", 0.2 }
            };
            
            return baselines.TryGetValue(processName, out var baseline) ? baseline : 0.1;
        }
        
        /// <summary>
        /// Obtiene patrones normales de línea de comandos
        /// </summary>
        private List<string> GetNormalCommandLinePatterns(string processName)
        {
            var patterns = new List<string>();
            
            switch (processName.ToLowerInvariant())
            {
                case "powershell.exe":
                    patterns.AddRange(new[] { "-Command", "-File", "-NoExit", "-NoLogo" });
                    break;
                    
                case "cmd.exe":
                    patterns.AddRange(new[] { "/c", "/k", "dir", "cd", "echo" });
                    break;
                    
                case "chrome.exe":
                case "firefox.exe":
                    patterns.AddRange(new[] { "--", "http://", "https://" });
                    break;
                    
                case "explorer.exe":
                    patterns.AddRange(new[] { "/e,", "/root,", "/select," });
                    break;
            }
            
            return patterns;
        }
        
        /// <summary>
        /// Verifica si dominio es DGA
        /// </summary>
        private bool IsDGADomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;
            
            // Características de dominios DGA
            var length = domain.Length;
            var digitCount = domain.Count(char.IsDigit);
            var hyphenCount = domain.Count(c => c == '-');
            var consonantCount = domain.Count(c => "bcdfghjklmnpqrstvwxyz".Contains(char.ToLower(c)));
            var vowelCount = domain.Count(c => "aeiou".Contains(char.ToLower(c)));
            
            // Dominios DGA suelen ser largos, con muchos números y pocas vocales
            var digitRatio = (double)digitCount / length;
            var vowelRatio = (double)vowelCount / length;
            var hyphenRatio = (double)hyphenCount / length;
            
            return length > 20 || 
                   digitRatio > 0.3 || 
                   vowelRatio < 0.1 || 
                   hyphenRatio > 0.2 ||
                   (digitCount > 5 && hyphenCount > 2);
        }
        
        /// <summary>
        /// Obtiene país de IP (simplificado)
        /// </summary>
        private string GetIPCountry(string ipAddress)
        {
            // Implementación simplificada
            // En producción usar servicio de geolocalización
            
            if (ipAddress.StartsWith("10.") || 
                ipAddress.StartsWith("192.168.") ||
                ipAddress.StartsWith("172.16.") || ipAddress.StartsWith("172.17.") ||
                ipAddress.StartsWith("172.18.") || ipAddress.StartsWith("172.19.") ||
                ipAddress.StartsWith("172.20.") || ipAddress.StartsWith("172.21.") ||
                ipAddress.StartsWith("172.22.") || ipAddress.StartsWith("172.23.") ||
                ipAddress.StartsWith("172.24.") || ipAddress.StartsWith("172.25.") ||
                ipAddress.StartsWith("172.26.") || ipAddress.StartsWith("172.27.") ||
                ipAddress.StartsWith("172.28.") || ipAddress.StartsWith("172.29.") ||
                ipAddress.StartsWith("172.30.") || ipAddress.StartsWith("172.31."))
            {
                return "PRIVATE"; // IP privada
            }
            
            // Simulación básica por rangos
            if (ipAddress.StartsWith("1.")) return "CN"; // China
            if (ipAddress.StartsWith("5.")) return "RU"; // Rusia
            if (ipAddress.StartsWith("46.")) return "IR"; // Iran
            
            return "UNKNOWN";
        }
        
        /// <summary>
        /// Verifica si IP es local o privada
        /// </summary>
        private bool IsLocalOrPrivateIP(string ipAddress)
        {
            return ipAddress.StartsWith("127.") ||
                   ipAddress.StartsWith("10.") ||
                   ipAddress.StartsWith("192.168.") ||
                   ipAddress.StartsWith("172.16.") || ipAddress.StartsWith("172.17.") ||
                   ipAddress.StartsWith("172.18.") || ipAddress.StartsWith("172.19.") ||
                   ipAddress.StartsWith("172.20.") || ipAddress.StartsWith("172.21.") ||
                   ipAddress.StartsWith("172.22.") || ipAddress.StartsWith("172.23.") ||
                   ipAddress.StartsWith("172.24.") || ipAddress.StartsWith("172.25.") ||
                   ipAddress.StartsWith("172.26.") || ipAddress.StartsWith("172.27.") ||
                   ipAddress.StartsWith("172.28.") || ipAddress.StartsWith("172.29.") ||
                   ipAddress.StartsWith("172.30.") || ipAddress.StartsWith("172.31.") ||
                   ipAddress == "::1" || ipAddress == "0:0:0:0:0:0:0:1" ||
                   ipAddress.StartsWith("fe80:"); // IPv6 link-local
        }
        
        /// <summary>
        /// Obtiene estadísticas del analizador
        /// </summary>
        public BehaviorAnalyzerStats GetStats()
        {
            return new BehaviorAnalyzerStats
            {
                Timestamp = DateTime.UtcNow,
                ProcessProfileCount = _processProfiles.Count,
                UserProfileCount = _userProfiles.Count,
                SystemProfileCount = _systemProfiles.Count,
                BehaviorModelVersion = _behaviorModel.ModelVersion,
                NetworkModelVersion = _networkModel.ModelVersion,
                IsRunning = _isRunning,
                IsInitialized = _isInitialized,
                AnomalyThreshold = ANOMALY_THRESHOLD,
                SuspiciousThreshold = SUSPICIOUS_THRESHOLD
            };
        }
        
        /// <summary>
        /// Reinicia aprendizaje de modelos
        /// </summary>
        public async Task<bool> RetrainModelsAsync()
        {
            try
            {
                _logManager.LogInfo("Reentrenando modelos ML...", ModuleId);
                
                await _behaviorModel.RetrainAsync();
                await _networkModel.RetrainAsync();
                
                _logManager.LogInfo("Modelos ML reentrenados", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al reentrenar modelos: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Exporta perfiles de comportamiento
        /// </summary>
        public async Task<string> ExportProfilesAsync()
        {
            try
            {
                var profiles = _processProfiles.Values
                    .Select(p => new
                    {
                        p.ProcessKey,
                        p.ProcessName,
                        p.ExecutionCount,
                        p.FirstSeen,
                        p.LastSeen,
                        p.DetectionCount,
                        FileOperations = p.FileOperations.TotalCount,
                        NetworkOperations = p.NetworkOperations.TotalCount,
                        RegistryOperations = p.RegistryOperations.TotalCount
                    })
                    .ToList();
                
                return System.Text.Json.JsonSerializer.Serialize(profiles, 
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al exportar perfiles: {ex}", ModuleId);
                return $"{{ \"error\": \"{ex.Message}\" }}";
            }
        }
    }
    
    #region Clases y estructuras de datos
    
    /// <summary>
    /// Perfil de comportamiento de proceso
    /// </summary>
    public class ProcessBehaviorProfile
    {
        public string ProcessKey { get; set; }
        public string ProcessName { get; set; }
        public string ImagePath { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int ExecutionCount { get; set; }
        public BehaviorMetrics FileOperations { get; set; }
        public BehaviorMetrics NetworkOperations { get; set; }
        public BehaviorMetrics RegistryOperations { get; set; }
        public BehaviorMetrics ProcessOperations { get; set; }
        public HashSet<string> UserContexts { get; set; }
        public HashSet<string> ParentProcesses { get; set; }
        public HashSet<string> ChildProcesses { get; set; }
        public HashSet<string> CommandLinePatterns { get; set; }
        public HashSet<string> AccessedFiles { get; set; }
        public HashSet<string> NetworkConnections { get; set; }
        public HashSet<string> RegistryKeys { get; set; }
        public int DetectionCount { get; set; }
        public DateTime? LastDetection { get; set; }
        public ThreatSeverity? DetectionSeverity { get; set; }
        
        public ProcessBehaviorProfile()
        {
            FileOperations = new BehaviorMetrics();
            NetworkOperations = new BehaviorMetrics();
            RegistryOperations = new BehaviorMetrics();
            ProcessOperations = new BehaviorMetrics();
            UserContexts = new HashSet<string>();
            ParentProcesses = new HashSet<string>();
            ChildProcesses = new HashSet<string>();
            CommandLinePatterns = new HashSet<string>();
            AccessedFiles = new HashSet<string>();
            NetworkConnections = new HashSet<string>();
            RegistryKeys = new HashSet<string>();
        }
    }
    
    /// <summary>
    /// Perfil de comportamiento de usuario
    /// </summary>
    public class UserBehaviorProfile
    {
        public string UserSid { get; set; }
        public string UserName { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public HashSet<string> ProcessesExecuted { get; set; }
        public HashSet<string> FilesAccessed { get; set; }
        public HashSet<string> NetworkDestinations { get; set; }
        public BehaviorMetrics ActivityMetrics { get; set; }
        public Dictionary<DayOfWeek, TimeSpan> TypicalActivityTimes { get; set; }
        
        public UserBehaviorProfile()
        {
            ProcessesExecuted = new HashSet<string>();
            FilesAccessed = new HashSet<string>();
            NetworkDestinations = new HashSet<string>();
            ActivityMetrics = new BehaviorMetrics();
            TypicalActivityTimes = new Dictionary<DayOfWeek, TimeSpan>();
        }
    }
    
    /// <summary>
    /// Perfil de comportamiento del sistema
    /// </summary>
    public class SystemBehaviorProfile
    {
        public string SystemId { get; set; }
        public DateTime ProfileStartTime { get; set; }
        public Dictionary<string, double> ProcessExecutionBaselines { get; set; }
        public Dictionary<string, double> NetworkActivityBaselines { get; set; }
        public Dictionary<string, double> FileActivityBaselines { get; set; }
        public Dictionary<TimeSpan, double> HourlyActivityPattern { get; set; }
        public Dictionary<DayOfWeek, double> DailyActivityPattern { get; set; }
        
        public SystemBehaviorProfile()
        {
            ProcessExecutionBaselines = new Dictionary<string, double>();
            NetworkActivityBaselines = new Dictionary<string, double>();
            FileActivityBaselines = new Dictionary<string, double>();
            HourlyActivityPattern = new Dictionary<TimeSpan, double>();
            DailyActivityPattern = new Dictionary<DayOfWeek, double>();
        }
    }
    
    /// <summary>
    /// Métricas de comportamiento
    /// </summary>
    public class BehaviorMetrics
    {
        public int TotalCount { get; set; }
        public int CreatedCount { get; set; }
        public int ModifiedCount { get; set; }
        public int DeletedCount { get; set; }
        public int RenamedCount { get; set; }
        public DateTime FirstActivity { get; set; }
        public DateTime LastActivity { get; set; }
        public double AveragePerHour { get; set; }
        public double PeakRate { get; set; }
        
        public BehaviorMetrics()
        {
            FirstActivity = DateTime.UtcNow;
            LastActivity = DateTime.UtcNow;
        }
    }
    
    /// <summary>
    /// Predicción de modelo ML
    /// </summary>
    public class MLPrediction
    {
        public double AnomalyScore { get; set; }
        public string PredictionType { get; set; }
        public Dictionary<string, double> Features { get; set; }
        public List<string> ContributingFactors { get; set; }
        public DateTime PredictionTime { get; set; }
        
        public MLPrediction()
        {
            Features = new Dictionary<string, double>();
            ContributingFactors = new List<string>();
            PredictionTime = DateTime.UtcNow;
        }
    }
    
    /// <summary>
    /// Estadísticas del analizador de comportamiento
    /// </summary>
    public class BehaviorAnalyzerStats
    {
        public DateTime Timestamp { get; set; }
        public int ProcessProfileCount { get; set; }
        public int UserProfileCount { get; set; }
        public int SystemProfileCount { get; set; }
        public string BehaviorModelVersion { get; set; }
        public string NetworkModelVersion { get; set; }
        public bool IsRunning { get; set; }
        public bool IsInitialized { get; set; }
        public double AnomalyThreshold { get; set; }
        public double SuspiciousThreshold { get; set; }
    }
    
    #endregion
}
        