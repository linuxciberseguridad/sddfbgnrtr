using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Transforms.Onnx;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Sensors;

namespace BWP.Enterprise.Agent.ML
{
    /// <summary>
    /// Motor de inferencia de Machine Learning para detección de amenazas
    /// Usa modelos ONNX pre-entrenados para análisis de comportamiento
    /// </summary>
    public sealed class MLInferenceEngine : IAgentModule, IDetectionEngine
    {
        private static readonly Lazy<MLInferenceEngine> _instance = 
            new Lazy<MLInferenceEngine>(() => new MLInferenceEngine());
        
        public static MLInferenceEngine Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private MLContext _mlContext;
        private OnnxTransformer _behaviorModel;
        private OnnxTransformer _networkModel;
        private PredictionEngine<BehaviorFeatures, BehaviorPrediction> _behaviorPredictor;
        private PredictionEngine<NetworkFeatures, NetworkPrediction> _networkPredictor;
        private bool _isInitialized;
        private bool _isRunning;
        private const double CONFIDENCE_THRESHOLD = 0.85;
        private const int FEATURE_WINDOW_SIZE = 100;
        private readonly Queue<BehaviorFeatures> _behaviorFeatureWindow;
        private readonly Queue<NetworkFeatures> _networkFeatureWindow;
        
        public string ModuleId => "MLInferenceEngine";
        public string Version => "1.0.0";
        public string Description => "Motor de inferencia ML para detección de amenazas";
        
        private MLInferenceEngine()
        {
            _logManager = LogManager.Instance;
            _mlContext = new MLContext(seed: 1);
            _behaviorFeatureWindow = new Queue<BehaviorFeatures>(FEATURE_WINDOW_SIZE);
            _networkFeatureWindow = new Queue<NetworkFeatures>(FEATURE_WINDOW_SIZE);
            _isInitialized = false;
            _isRunning = false;
        }
        
        /// <summary>
        /// Inicializa el motor ML
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando MLInferenceEngine...", ModuleId);
                
                // 1. Cargar modelos ONNX
                await LoadModelsAsync();
                
                // 2. Crear pipelines de predicción
                CreatePredictionPipelines();
                
                // 3. Inicializar ventanas de características
                InitializeFeatureWindows();
                
                // 4. Verificar modelos
                var modelStatus = await VerifyModelsAsync();
                if (!modelStatus.Success)
                {
                    return ModuleOperationResult.ErrorResult($"Error en modelos: {modelStatus.ErrorMessage}");
                }
                
                _isInitialized = true;
                _logManager.LogInfo("MLInferenceEngine inicializado exitosamente", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar MLInferenceEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Carga modelos ONNX desde archivos
        /// </summary>
        private async Task LoadModelsAsync()
        {
            try
            {
                var behaviorModelPath = GetModelPath("behavior_model.onnx");
                var networkModelPath = GetModelPath("network_anomaly_model.onnx");
                
                if (!File.Exists(behaviorModelPath) || !File.Exists(networkModelPath))
                {
                    throw new FileNotFoundException("Modelos ONNX no encontrados");
                }
                
                // Cargar modelo de comportamiento
                var behaviorPipeline = _mlContext.Transforms.ApplyOnnxModel(
                    modelFile: behaviorModelPath,
                    outputColumnNames: new[] { "behavior_output" },
                    inputColumnNames: new[] { "behavior_features" });
                
                // Cargar modelo de red
                var networkPipeline = _mlContext.Transforms.ApplyOnnxModel(
                    modelFile: networkModelPath,
                    outputColumnNames: new[] { "network_output" },
                    inputColumnNames: new[] { "network_features" });
                
                // Crear transformadores
                var emptyBehaviorData = _mlContext.Data.LoadFromEnumerable(new List<BehaviorFeatures>());
                _behaviorModel = behaviorPipeline.Fit(emptyBehaviorData);
                
                var emptyNetworkData = _mlContext.Data.LoadFromEnumerable(new List<NetworkFeatures>());
                _networkModel = networkPipeline.Fit(emptyNetworkData);
                
                _logManager.LogInfo("Modelos ONNX cargados exitosamente", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando modelos: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Crea pipelines de predicción
        /// </summary>
        private void CreatePredictionPipelines()
        {
            // Pipeline para comportamiento
            var behaviorPipeline = _mlContext.Transforms.Concatenate(
                "behavior_features",
                nameof(BehaviorFeatures.ProcessCount),
                nameof(BehaviorFeatures.FileOperations),
                nameof(BehaviorFeatures.RegistryOperations),
                nameof(BehaviorFeatures.NetworkConnections),
                nameof(BehaviorFeatures.CPUUsage),
                nameof(BehaviorFeatures.MemoryUsage),
                nameof(BehaviorFeatures.ThreadCount),
                nameof(BehaviorFeatures.HandleCount))
                .Append(_behaviorModel);
                
            var behaviorData = _mlContext.Data.LoadFromEnumerable(new List<BehaviorFeatures>());
            var behaviorTransformer = behaviorPipeline.Fit(behaviorData);
            _behaviorPredictor = _mlContext.Model.CreatePredictionEngine<BehaviorFeatures, BehaviorPrediction>(behaviorTransformer);
            
            // Pipeline para red
            var networkPipeline = _mlContext.Transforms.Concatenate(
                "network_features",
                nameof(NetworkFeatures.PacketCount),
                nameof(NetworkFeatures.ByteRate),
                nameof(NetworkFeatures.PacketRate),
                nameof(NetworkFeatures.DestinationPorts),
                nameof(NetworkFeatures.SourcePorts),
                nameof(NetworkFeatures.ProtocolDistribution),
                nameof(NetworkFeatures.ConnectionDuration),
                nameof(NetworkFeatures.PayloadEntropy))
                .Append(_networkModel);
                
            var networkData = _mlContext.Data.LoadFromEnumerable(new List<NetworkFeatures>());
            var networkTransformer = networkPipeline.Fit(networkData);
            _networkPredictor = _mlContext.Model.CreatePredictionEngine<NetworkFeatures, NetworkPrediction>(networkTransformer);
        }
        
        /// <summary>
        /// Analiza eventos usando ML
        /// </summary>
        public async Task<List<DetectionResult>> AnalyzeEventsAsync(List<SensorEvent> events)
        {
            var results = new List<DetectionResult>();
            
            if (!_isInitialized || events == null || events.Count == 0)
                return results;
            
            try
            {
                // Agrupar eventos por tipo
                var processEvents = events.Where(e => e.SensorType == SensorType.Process).ToList();
                var fileEvents = events.Where(e => e.SensorType == SensorType.FileSystem).ToList();
                var networkEvents = events.Where(e => e.SensorType == SensorType.Network).ToList();
                var registryEvents = events.Where(e => e.SensorType == SensorType.Registry).ToList();
                
                // Extraer características
                var behaviorFeatures = ExtractBehaviorFeatures(processEvents, fileEvents, registryEvents, networkEvents);
                var networkFeatures = ExtractNetworkFeatures(networkEvents);
                
                // Añadir a ventanas
                AddToFeatureWindows(behaviorFeatures, networkFeatures);
                
                // Realizar predicciones
                if (_behaviorFeatureWindow.Count >= FEATURE_WINDOW_SIZE)
                {
                    var behaviorResult = await AnalyzeBehaviorAsync();
                    if (behaviorResult != null)
                    {
                        results.Add(behaviorResult);
                    }
                }
                
                if (_networkFeatureWindow.Count >= FEATURE_WINDOW_SIZE)
                {
                    var networkResult = await AnalyzeNetworkAsync();
                    if (networkResult != null)
                    {
                        results.Add(networkResult);
                    }
                }
                
                return results;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis ML: {ex}", ModuleId);
                return results;
            }
        }
        
        /// <summary>
        /// Extrae características de comportamiento
        /// </summary>
        private BehaviorFeatures ExtractBehaviorFeatures(
            List<SensorEvent> processEvents,
            List<SensorEvent> fileEvents,
            List<SensorEvent> registryEvents,
            List<SensorEvent> networkEvents)
        {
            return new BehaviorFeatures
            {
                Timestamp = DateTime.UtcNow,
                ProcessCount = processEvents.Count,
                FileOperations = fileEvents.Count,
                RegistryOperations = registryEvents.Count,
                NetworkConnections = networkEvents.Count(e => e.EventType == EventType.NetworkConnection),
                CPUUsage = CalculateCpuUsage(processEvents),
                MemoryUsage = CalculateMemoryUsage(processEvents),
                ThreadCount = CalculateThreadCount(processEvents),
                HandleCount = CalculateHandleCount(processEvents),
                SuspiciousProcessNames = CountSuspiciousProcesses(processEvents),
                SuspiciousFilePaths = CountSuspiciousFiles(fileEvents),
                SuspiciousRegistryKeys = CountSuspiciousRegistry(registryEvents),
                ProcessTreeDepth = CalculateProcessTreeDepth(processEvents),
                CrossProcessOperations = CalculateCrossProcessOps(processEvents, fileEvents)
            };
        }
        
        /// <summary>
        /// Extrae características de red
        /// </summary>
        private NetworkFeatures ExtractNetworkFeatures(List<SensorEvent> networkEvents)
        {
            return new NetworkFeatures
            {
                Timestamp = DateTime.UtcNow,
                PacketCount = networkEvents.Count,
                ByteRate = CalculateByteRate(networkEvents),
                PacketRate = CalculatePacketRate(networkEvents),
                DestinationPorts = ExtractDestinationPorts(networkEvents),
                SourcePorts = ExtractSourcePorts(networkEvents),
                ProtocolDistribution = CalculateProtocolDistribution(networkEvents),
                ConnectionDuration = CalculateConnectionDuration(networkEvents),
                PayloadEntropy = CalculatePayloadEntropy(networkEvents),
                GeographicDispersion = CalculateGeographicDispersion(networkEvents),
                PortScanIndicator = DetectPortScan(networkEvents),
                DataExfiltrationIndicator = DetectDataExfiltration(networkEvents)
            };
        }
        
        /// <summary>
        /// Analiza comportamiento usando ML
        /// </summary>
        private async Task<DetectionResult> AnalyzeBehaviorAsync()
        {
            try
            {
                // Calcular características agregadas
                var aggregatedFeatures = AggregateBehaviorFeatures();
                
                // Realizar predicción
                var prediction = _behaviorPredictor.Predict(aggregatedFeatures);
                
                // Evaluar resultado
                if (prediction.MaliciousScore >= CONFIDENCE_THRESHOLD)
                {
                    return CreateBehaviorDetectionResult(
                        aggregatedFeatures,
                        prediction,
                        "Comportamiento anómalo detectado por ML",
                        ThreatSeverity.High,
                        prediction.MaliciousScore);
                }
                
                return null;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis de comportamiento: {ex}", ModuleId);
                return null;
            }
        }
        
        /// <summary>
        /// Analiza tráfico de red usando ML
        /// </summary>
        private async Task<DetectionResult> AnalyzeNetworkAsync()
        {
            try
            {
                // Calcular características agregadas
                var aggregatedFeatures = AggregateNetworkFeatures();
                
                // Realizar predicción
                var prediction = _networkPredictor.Predict(aggregatedFeatures);
                
                // Evaluar resultado
                if (prediction.AnomalyScore >= CONFIDENCE_THRESHOLD)
                {
                    return CreateNetworkDetectionResult(
                        aggregatedFeatures,
                        prediction,
                        "Tráfico de red anómalo detectado por ML",
                        ThreatSeverity.Medium,
                        prediction.AnomalyScore);
                }
                
                return null;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en análisis de red: {ex}", ModuleId);
                return null;
            }
        }
        
        #region Métodos auxiliares
        
        private string GetModelPath(string modelName)
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(appData, "BWP Enterprise", "Models", modelName);
        }
        
        private void InitializeFeatureWindows()
        {
            _behaviorFeatureWindow.Clear();
            _networkFeatureWindow.Clear();
        }
        
        private void AddToFeatureWindows(BehaviorFeatures behaviorFeatures, NetworkFeatures networkFeatures)
        {
            _behaviorFeatureWindow.Enqueue(behaviorFeatures);
            while (_behaviorFeatureWindow.Count > FEATURE_WINDOW_SIZE)
            {
                _behaviorFeatureWindow.Dequeue();
            }
            
            _networkFeatureWindow.Enqueue(networkFeatures);
            while (_networkFeatureWindow.Count > FEATURE_WINDOW_SIZE)
            {
                _networkFeatureWindow.Dequeue();
            }
        }
        
        private BehaviorFeatures AggregateBehaviorFeatures()
        {
            if (!_behaviorFeatureWindow.Any())
                return new BehaviorFeatures();
            
            return new BehaviorFeatures
            {
                Timestamp = DateTime.UtcNow,
                ProcessCount = (int)_behaviorFeatureWindow.Average(f => f.ProcessCount),
                FileOperations = (int)_behaviorFeatureWindow.Average(f => f.FileOperations),
                RegistryOperations = (int)_behaviorFeatureWindow.Average(f => f.RegistryOperations),
                NetworkConnections = (int)_behaviorFeatureWindow.Average(f => f.NetworkConnections),
                CPUUsage = _behaviorFeatureWindow.Average(f => f.CPUUsage),
                MemoryUsage = _behaviorFeatureWindow.Average(f => f.MemoryUsage),
                ThreadCount = (int)_behaviorFeatureWindow.Average(f => f.ThreadCount),
                HandleCount = (int)_behaviorFeatureWindow.Average(f => f.HandleCount)
            };
        }
        
        private NetworkFeatures AggregateNetworkFeatures()
        {
            if (!_networkFeatureWindow.Any())
                return new NetworkFeatures();
            
            return new NetworkFeatures
            {
                Timestamp = DateTime.UtcNow,
                PacketCount = (int)_networkFeatureWindow.Average(f => f.PacketCount),
                ByteRate = _networkFeatureWindow.Average(f => f.ByteRate),
                PacketRate = _networkFeatureWindow.Average(f => f.PacketRate),
                ConnectionDuration = _networkFeatureWindow.Average(f => f.ConnectionDuration),
                PayloadEntropy = _networkFeatureWindow.Average(f => f.PayloadEntropy)
            };
        }
        
        private float CalculateCpuUsage(List<SensorEvent> processEvents)
        {
            // Implementar cálculo de uso de CPU
            return 0.0f;
        }
        
        private float CalculateMemoryUsage(List<SensorEvent> processEvents)
        {
            // Implementar cálculo de uso de memoria
            return 0.0f;
        }
        
        private int CalculateThreadCount(List<SensorEvent> processEvents)
        {
            return processEvents.Count(e => e.Data?.OperationType == "ThreadCreated");
        }
        
        private int CalculateHandleCount(List<SensorEvent> processEvents)
        {
            return processEvents.Count(e => e.Data?.OperationType == "HandleCreated");
        }
        
        private int CountSuspiciousProcesses(List<SensorEvent> processEvents)
        {
            var suspiciousNames = new[] { "powershell", "cmd", "wscript", "cscript", "mshta" };
            return processEvents.Count(e => 
                suspiciousNames.Any(name => e.Data?.ProcessName?.ToLower().Contains(name) == true));
        }
        
        private int CountSuspiciousFiles(List<SensorEvent> fileEvents)
        {
            var suspiciousExtensions = new[] { ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd" };
            return fileEvents.Count(e => 
                suspiciousExtensions.Any(ext => e.Data?.FilePath?.EndsWith(ext, StringComparison.OrdinalIgnoreCase) == true));
        }
        
        private int CountSuspiciousRegistry(List<SensorEvent> registryEvents)
        {
            var suspiciousKeys = new[] { "Run", "RunOnce", "Winlogon", "Policies" };
            return registryEvents.Count(e => 
                suspiciousKeys.Any(key => e.Data?.RegistryPath?.Contains(key) == true));
        }
        
        private int CalculateProcessTreeDepth(List<SensorEvent> processEvents)
        {
            // Implementar cálculo de profundidad del árbol de procesos
            return 1;
        }
        
        private int CalculateCrossProcessOps(List<SensorEvent> processEvents, List<SensorEvent> fileEvents)
        {
            // Implementar cálculo de operaciones entre procesos
            return 0;
        }
        
        private float CalculateByteRate(List<SensorEvent> networkEvents)
        {
            // Implementar cálculo de tasa de bytes
            return 0.0f;
        }
        
        private float CalculatePacketRate(List<SensorEvent> networkEvents)
        {
            // Implementar cálculo de tasa de paquetes
            return 0.0f;
        }
        
        private float[] ExtractDestinationPorts(List<SensorEvent> networkEvents)
        {
            var ports = networkEvents
                .Where(e => e.Data?.RemotePort.HasValue == true)
                .Select(e => (float)e.Data.RemotePort.Value)
                .Distinct()
                .ToArray();
            
            return ports.Length > 0 ? ports : new float[] { 0 };
        }
        
        private float[] ExtractSourcePorts(List<SensorEvent> networkEvents)
        {
            var ports = networkEvents
                .Where(e => e.Data?.LocalPort.HasValue == true)
                .Select(e => (float)e.Data.LocalPort.Value)
                .Distinct()
                .ToArray();
            
            return ports.Length > 0 ? ports : new float[] { 0 };
        }
        
        private float[] CalculateProtocolDistribution(List<SensorEvent> networkEvents)
        {
            // Implementar distribución de protocolos
            return new float[] { 0.5f, 0.3f, 0.2f }; // TCP, UDP, Other
        }
        
        private float CalculateConnectionDuration(List<SensorEvent> networkEvents)
        {
            // Implementar cálculo de duración de conexión
            return 0.0f;
        }
        
        private float CalculatePayloadEntropy(List<SensorEvent> networkEvents)
        {
            // Implementar cálculo de entropía del payload
            return 0.0f;
        }
        
        private float CalculateGeographicDispersion(List<SensorEvent> networkEvents)
        {
            // Implementar cálculo de dispersión geográfica
            return 0.0f;
        }
        
        private float DetectPortScan(List<SensorEvent> networkEvents)
        {
            // Detectar escaneo de puertos
            var distinctPorts = networkEvents
                .Where(e => e.Data?.RemotePort.HasValue == true)
                .Select(e => e.Data.RemotePort.Value)
                .Distinct()
                .Count();
            
            return distinctPorts > 10 ? 1.0f : 0.0f;
        }
        
        private float DetectDataExfiltration(List<SensorEvent> networkEvents)
        {
            // Detectar exfiltración de datos
            var largeTransfers = networkEvents
                .Count(e => e.Data?.BytesSent > 1024 * 1024); // > 1MB
            
            return largeTransfers > 5 ? 1.0f : 0.0f;
        }
        
        private DetectionResult CreateBehaviorDetectionResult(
            BehaviorFeatures features,
            BehaviorPrediction prediction,
            string description,
            ThreatSeverity severity,
            double confidence)
        {
            return new DetectionResult
            {
                DetectionId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                SourceModule = ModuleId,
                ThreatName = "Comportamiento malicioso detectado por ML",
                Description = description,
                Severity = severity,
                DetectionType = DetectionType.MachineLearning,
                Confidence = confidence,
                Details = new Dictionary<string, object>
                {
                    { "MLModel", "behavior_model.onnx" },
                    { "MaliciousScore", prediction.MaliciousScore },
                    { "Features", features },
                    { "Prediction", prediction },
                    { "FeatureWindowSize", _behaviorFeatureWindow.Count }
                },
                RecommendedActions = new List<string>
                {
                    "Monitor",
                    "Investigate",
                    "CollectForensicData",
                    "UpdateMLModel"
                }
            };
        }
        
        private DetectionResult CreateNetworkDetectionResult(
            NetworkFeatures features,
            NetworkPrediction prediction,
            string description,
            ThreatSeverity severity,
            double confidence)
        {
            return new DetectionResult
            {
                DetectionId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                SourceModule = ModuleId,
                ThreatName = "Tráfico de red anómalo detectado por ML",
                Description = description,
                Severity = severity,
                DetectionType = DetectionType.MachineLearning,
                Confidence = confidence,
                Details = new Dictionary<string, object>
                {
                    { "MLModel", "network_anomaly_model.onnx" },
                    { "AnomalyScore", prediction.AnomalyScore },
                    { "Features", features },
                    { "Prediction", prediction },
                    { "FeatureWindowSize", _networkFeatureWindow.Count }
                },
                RecommendedActions = new List<string>
                {
                    "BlockNetworkTraffic",
                    "Investigate",
                    "UpdateFirewallRules",
                    "UpdateMLModel"
                }
            };
        }
        
        #endregion
        
        #region Implementación IAgentModule
        
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                    return initResult;
            }
            
            _isRunning = true;
            _logManager.LogInfo("MLInferenceEngine iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> StopAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("MLInferenceEngine detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("MLInferenceEngine pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("MLInferenceEngine reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        #endregion
        
        #region Health Check
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                
                if (!_isInitialized)
                    issues.Add("No inicializado");
                
                if (_behaviorPredictor == null)
                    issues.Add("Predictor de comportamiento no disponible");
                
                if (_networkPredictor == null)
                    issues.Add("Predictor de red no disponible");
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("MLInferenceEngine funcionando correctamente");
                }
                
                return HealthCheckResult.Degraded(
                    string.Join(", ", issues),
                    new Dictionary<string, object>
                    {
                        { "IsInitialized", _isInitialized },
                        { "IsRunning", _isRunning },
                        { "BehaviorWindowSize", _behaviorFeatureWindow.Count },
                        { "NetworkWindowSize", _networkFeatureWindow.Count },
                        { "BehaviorPredictor", _behaviorPredictor != null },
                        { "NetworkPredictor", _networkPredictor != null }
                    });
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error en health check: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "Exception", ex.ToString() }
                    });
            }
        }
        
        private async Task<ModelVerificationResult> VerifyModelsAsync()
        {
            try
            {
                // Verificar que los modelos pueden realizar predicciones
                var testFeatures = new BehaviorFeatures
                {
                    ProcessCount = 10,
                    FileOperations = 5,
                    RegistryOperations = 2,
                    NetworkConnections = 3,
                    CPUUsage = 0.5f,
                    MemoryUsage = 0.3f,
                    ThreadCount = 50,
                    HandleCount = 100
                };
                
                var testPrediction = _behaviorPredictor.Predict(testFeatures);
                
                if (testPrediction == null)
                {
                    return ModelVerificationResult.Failed("Modelo de comportamiento no responde");
                }
                
                return ModelVerificationResult.Success();
            }
            catch (Exception ex)
            {
                return ModelVerificationResult.Failed($"Error verificando modelos: {ex.Message}");
            }
        }
        
        #endregion
        
        #region Métodos públicos para integración
        
        public async Task<double> PredictBehaviorAnomalyAsync(BehaviorFeatures features)
        {
            if (!_isInitialized || _behaviorPredictor == null)
                return 0.0;
            
            try
            {
                var prediction = _behaviorPredictor.Predict(features);
                return prediction.MaliciousScore;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en predicción de comportamiento: {ex}", ModuleId);
                return 0.0;
            }
        }
        
        public async Task<double> PredictNetworkAnomalyAsync(NetworkFeatures features)
        {
            if (!_isInitialized || _networkPredictor == null)
                return 0.0;
            
            try
            {
                var prediction = _networkPredictor.Predict(features);
                return prediction.AnomalyScore;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en predicción de red: {ex}", ModuleId);
                return 0.0;
            }
        }
        
        public async Task<bool> UpdateModelAsync(string modelType, byte[] modelData)
        {
            try
            {
                var modelPath = GetModelPath($"{modelType}_model.onnx");
                var tempPath = modelPath + ".tmp";
                
                // Guardar nuevo modelo
                await File.WriteAllBytesAsync(tempPath, modelData);
                
                // Reemplazar modelo existente
                File.Replace(tempPath, modelPath, modelPath + ".bak");
                
                // Recargar modelo
                await LoadModelsAsync();
                CreatePredictionPipelines();
                
                _logManager.LogInfo($"Modelo {modelType} actualizado exitosamente", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error actualizando modelo {modelType}: {ex}", ModuleId);
                return false;
            }
        }
        
        public MLInferenceStats GetStats()
        {
            return new MLInferenceStats
            {
                Timestamp = DateTime.UtcNow,
                IsInitialized = _isInitialized,
                IsRunning = _isRunning,
                BehaviorWindowSize = _behaviorFeatureWindow.Count,
                NetworkWindowSize = _networkFeatureWindow.Count,
                BehaviorModelLoaded = _behaviorPredictor != null,
                NetworkModelLoaded = _networkPredictor != null,
                LastBehaviorPrediction = _behaviorFeatureWindow.LastOrDefault()?.Timestamp,
                LastNetworkPrediction = _networkFeatureWindow.LastOrDefault()?.Timestamp
            };
        }
        
        #endregion
    }
    
    #region Clases de características y predicciones
    
    public class BehaviorFeatures
    {
        [LoadColumn(0)] public DateTime Timestamp { get; set; }
        [LoadColumn(1)] public int ProcessCount { get; set; }
        [LoadColumn(2)] public int FileOperations { get; set; }
        [LoadColumn(3)] public int RegistryOperations { get; set; }
        [LoadColumn(4)] public int NetworkConnections { get; set; }
        [LoadColumn(5)] public float CPUUsage { get; set; }
        [LoadColumn(6)] public float MemoryUsage { get; set; }
        [LoadColumn(7)] public int ThreadCount { get; set; }
        [LoadColumn(8)] public int HandleCount { get; set; }
        [LoadColumn(9)] public int SuspiciousProcessNames { get; set; }
        [LoadColumn(10)] public int SuspiciousFilePaths { get; set; }
        [LoadColumn(11)] public int SuspiciousRegistryKeys { get; set; }
        [LoadColumn(12)] public int ProcessTreeDepth { get; set; }
        [LoadColumn(13)] public int CrossProcessOperations { get; set; }
    }
    
    public class BehaviorPrediction
    {
        [ColumnName("behavior_output")]
        public float MaliciousScore { get; set; }
        
        [ColumnName("behavior_features")]
        public float[] Features { get; set; }
    }
    
    public class NetworkFeatures
    {
        [LoadColumn(0)] public DateTime Timestamp { get; set; }
        [LoadColumn(1)] public int PacketCount { get; set; }
        [LoadColumn(2)] public float ByteRate { get; set; }
        [LoadColumn(3)] public float PacketRate { get; set; }
        [LoadColumn(4)] public float[] DestinationPorts { get; set; }
        [LoadColumn(5)] public float[] SourcePorts { get; set; }
        [LoadColumn(6)] public float[] ProtocolDistribution { get; set; }
        [LoadColumn(7)] public float ConnectionDuration { get; set; }
        [LoadColumn(8)] public float PayloadEntropy { get; set; }
        [LoadColumn(9)] public float GeographicDispersion { get; set; }
        [LoadColumn(10)] public float PortScanIndicator { get; set; }
        [LoadColumn(11)] public float DataExfiltrationIndicator { get; set; }
    }
    
    public class NetworkPrediction
    {
        [ColumnName("network_output")]
        public float AnomalyScore { get; set; }
        
        [ColumnName("network_features")]
        public float[] Features { get; set; }
    }
    
    public class ModelVerificationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static ModelVerificationResult Success()
        {
            return new ModelVerificationResult { Success = true };
        }
        
        public static ModelVerificationResult Failed(string errorMessage)
        {
            return new ModelVerificationResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class MLInferenceStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsInitialized { get; set; }
        public bool IsRunning { get; set; }
        public int BehaviorWindowSize { get; set; }
        public int NetworkWindowSize { get; set; }
        public bool BehaviorModelLoaded { get; set; }
        public bool NetworkModelLoaded { get; set; }
        public DateTime? LastBehaviorPrediction { get; set; }
        public DateTime? LastNetworkPrediction { get; set; }
    }
    
    #endregion
}