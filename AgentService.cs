using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Modules;
using BWP.Enterprise.Agent.Sensors;
using BWP.Enterprise.Agent.Detection;
using BWP.Enterprise.Agent.Telemetry;
using BWP.Enterprise.Agent.Remediation;
using BWP.Enterprise.Agent.Policy;
using BWP.Enterprise.Agent.SelfProtection;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;

namespace BWP.Enterprise.Agent.Core
{
    /// <summary>
    /// Servicio principal del agente BWP-Enterprise
    /// Se ejecuta como servicio Windows con privilegios de administrador
    /// </summary>
    public partial class AgentService : ServiceBase
    {
        private readonly ModuleRegistry _moduleRegistry;
        private readonly HealthMonitor _healthMonitor;
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _isInitialized = false;
        private const string SERVICE_NAME = "BWPEnterpriseAgent";
        private const string DISPLAY_NAME = "BWP Enterprise Security Agent";
        private const string DESCRIPTION = "Protección avanzada de endpoints BWP Enterprise";

        public AgentService()
        {
            ServiceName = SERVICE_NAME;
            _logManager = LogManager.Instance;
            _moduleRegistry = ModuleRegistry.Instance;
            _healthMonitor = HealthMonitor.Instance;
            _localDatabase = LocalDatabase.Instance;
            _cancellationTokenSource = new CancellationTokenSource();
            
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            Task.Run(() => StartAgentAsync(_cancellationTokenSource.Token));
        }

        protected override void OnStop()
        {
            StopAgent();
        }

        protected override void OnShutdown()
        {
            StopAgent();
            base.OnShutdown();
        }

        /// <summary>
        /// Inicializa todos los módulos del agente de forma asíncrona
        /// </summary>
        private async Task StartAgentAsync(CancellationToken cancellationToken)
        {
            try
            {
                _logManager.LogInfo("Iniciando BWP Enterprise Agent...", "AgentService");
                
                // 1. Inicializar componentes base
                await InitializeCoreComponentsAsync();
                
                // 2. Inicializar y registrar módulos
                await InitializeAndRegisterModulesAsync();
                
                // 3. Iniciar monitoreo de salud
                _healthMonitor.StartMonitoring();
                
                // 4. Verificar integridad
                await VerifySystemIntegrityAsync();
                
                // 5. Iniciar procesamiento continuo
                await StartContinuousProcessingAsync(cancellationToken);
                
                _isInitialized = true;
                _logManager.LogInfo("BWP Enterprise Agent iniciado correctamente", "AgentService");
            }
            catch (Exception ex)
            {
                _logManager.LogCritical($"Error al iniciar agente: {ex}", "AgentService");
                throw;
            }
        }

        /// <summary>
        /// Inicializa componentes base del agente
        /// </summary>
        private async Task InitializeCoreComponentsAsync()
        {
            // Inicializar base de datos local
            await _localDatabase.InitializeAsync();
            
            // Configurar logging
            _logManager.Configure(new LogConfiguration
            {
                LogLevel = LogLevel.Info,
                MaxFileSizeMB = 100,
                RetentionDays = 30,
                EnableCompression = true
            });
            
            // Registrar tipos de eventos
            RegisterEventTypes();
        }

        /// <summary>
        /// Inicializa y registra todos los módulos del agente
        /// </summary>
        private async Task InitializeAndRegisterModulesAsync()
        {
            // 1. Sensores
            var processSensor = new ProcessSensor();
            var fileSystemSensor = new FileSystemSensor();
            var networkSensor = new NetworkSensor();
            var registrySensor = new RegistrySensor();
            
            await _moduleRegistry.RegisterModuleAsync(processSensor, ModuleType.Sensor);
            await _moduleRegistry.RegisterModuleAsync(fileSystemSensor, ModuleType.Sensor);
            await _moduleRegistry.RegisterModuleAsync(networkSensor, ModuleType.Sensor);
            await _moduleRegistry.RegisterModuleAsync(registrySensor, ModuleType.Sensor);
            
            // 2. Motores de detección
            var ruleEngine = new RuleEngine();
            var behaviorAnalyzer = new BehaviorAnalyzer();
            var threatCorrelationEngine = new ThreatCorrelationEngine();
            var riskScoreCalculator = new RiskScoreCalculator();
            
            await _moduleRegistry.RegisterModuleAsync(ruleEngine, ModuleType.Detection);
            await _moduleRegistry.RegisterModuleAsync(behaviorAnalyzer, ModuleType.Detection);
            await _moduleRegistry.RegisterModuleAsync(threatCorrelationEngine, ModuleType.Detection);
            await _moduleRegistry.RegisterModuleAsync(riskScoreCalculator, ModuleType.Detection);
            
            // 3. Telemetría
            var telemetryQueue = new TelemetryQueue();
            var telemetryBatchSender = new TelemetryBatchSender();
            var eventSerializer = new EventSerializer();
            
            await _moduleRegistry.RegisterModuleAsync(telemetryQueue, ModuleType.Telemetry);
            await _moduleRegistry.RegisterModuleAsync(telemetryBatchSender, ModuleType.Telemetry);
            await _moduleRegistry.RegisterModuleAsync(eventSerializer, ModuleType.Telemetry);
            
            // 4. Remediation
            var responseExecutor = new ResponseExecutor();
            var quarantineManager = new QuarantineManager();
            
            await _moduleRegistry.RegisterModuleAsync(responseExecutor, ModuleType.Remediation);
            await _moduleRegistry.RegisterModuleAsync(quarantineManager, ModuleType.Remediation);
            
            // 5. Políticas
            var policyManager = new PolicyManager();
            var policyEvaluator = new PolicyEvaluator();
            
            await _moduleRegistry.RegisterModuleAsync(policyManager, ModuleType.Policy);
            await _moduleRegistry.RegisterModuleAsync(policyEvaluator, ModuleType.Policy);
            
            // 6. Auto-protección
            var integrityVerifier = new IntegrityVerifier();
            var serviceGuardian = new ServiceGuardian();
            
            await _moduleRegistry.RegisterModuleAsync(integrityVerifier, ModuleType.SelfProtection);
            await _moduleRegistry.RegisterModuleAsync(serviceGuardian, ModuleType.SelfProtection);
            
            // 7. Comunicación
            var apiClient = new ApiClient();
            var deviceAuthenticator = new DeviceAuthenticator();
            
            await _moduleRegistry.RegisterModuleAsync(apiClient, ModuleType.Communication);
            await _moduleRegistry.RegisterModuleAsync(deviceAuthenticator, ModuleType.Communication);
            
            _logManager.LogInfo($"Registrados {_moduleRegistry.GetModuleCount()} módulos", "AgentService");
        }

        /// <summary>
        /// Registra tipos de eventos en el sistema
        /// </summary>
        private void RegisterEventTypes()
        {
            EventTypeRegistry.Register(EventType.ProcessCreated, "Creación de proceso");
            EventTypeRegistry.Register(EventType.ProcessTerminated, "Terminación de proceso");
            EventTypeRegistry.Register(EventType.FileCreated, "Creación de archivo");
            EventTypeRegistry.Register(EventType.FileModified, "Modificación de archivo");
            EventTypeRegistry.Register(EventType.FileDeleted, "Eliminación de archivo");
            EventTypeRegistry.Register(EventType.NetworkConnection, "Conexión de red");
            EventTypeRegistry.Register(EventType.DNSQuery, "Consulta DNS");
            EventTypeRegistry.Register(EventType.RegistryModified, "Modificación de registro");
            EventTypeRegistry.Register(EventType.ThreatDetected, "Amenaza detectada");
            EventTypeRegistry.Register(EventType.RemediationApplied, "Remediación aplicada");
            EventTypeRegistry.Register(EventType.AlertGenerated, "Alerta generada");
        }

        /// <summary>
        /// Verifica integridad del sistema
        /// </summary>
        private async Task VerifySystemIntegrityAsync()
        {
            var integrityVerifier = _moduleRegistry.GetModule<IntegrityVerifier>();
            if (integrityVerifier != null)
            {
                var result = await integrityVerifier.VerifyAllAsync();
                if (!result.IsValid)
                {
                    _logManager.LogCritical($"Integridad comprometida: {result.Details}", "AgentService");
                    // Tomar acciones correctivas
                    await integrityVerifier.RestoreIntegrityAsync();
                }
            }
        }

        /// <summary>
        /// Inicia procesamiento continuo
        /// </summary>
        private async Task StartContinuousProcessingAsync(CancellationToken cancellationToken)
        {
            // Iniciar sensores
            await _moduleRegistry.StartAllModulesAsync(ModuleType.Sensor);
            
            // Iniciar motores de detección
            await _moduleRegistry.StartAllModulesAsync(ModuleType.Detection);
            
            // Iniciar telemetría
            await _moduleRegistry.StartAllModulesAsync(ModuleType.Telemetry);
            
            // Iniciar loop de procesamiento principal
            _ = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        await ProcessEventQueueAsync();
                        await SendTelemetryBatchAsync();
                        await CheckForUpdatesAsync();
                        
                        await Task.Delay(1000, cancellationToken);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error en loop principal: {ex}", "AgentService");
                    }
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Procesa la cola de eventos
        /// </summary>
        private async Task ProcessEventQueueAsync()
        {
            var eventQueue = EventQueue.Instance;
            var batchSize = 100;
            
            while (eventQueue.Count > 0)
            {
                var events = await eventQueue.DequeueBatchAsync(batchSize);
                if (events.Count == 0) break;
                
                // Procesar eventos a través de motores de detección
                await ProcessEventsThroughEnginesAsync(events);
            }
        }

        /// <summary>
        /// Procesa eventos a través de motores de detección
        /// </summary>
        private async Task ProcessEventsThroughEnginesAsync(List<SecurityEvent> events)
        {
            var ruleEngine = _moduleRegistry.GetModule<RuleEngine>();
            var behaviorAnalyzer = _moduleRegistry.GetModule<BehaviorAnalyzer>();
            var threatCorrelationEngine = _moduleRegistry.GetModule<ThreatCorrelationEngine>();
            
            if (ruleEngine != null)
            {
                var ruleResults = await ruleEngine.AnalyzeEventsAsync(events);
                await ProcessDetectionResultsAsync(ruleResults);
            }
            
            if (behaviorAnalyzer != null)
            {
                var behaviorResults = await behaviorAnalyzer.AnalyzeEventsAsync(events);
                await ProcessDetectionResultsAsync(behaviorResults);
            }
            
            if (threatCorrelationEngine != null)
            {
                var correlationResults = await threatCorrelationEngine.CorrelateEventsAsync(events);
                await ProcessCorrelationResultsAsync(correlationResults);
            }
        }

        /// <summary>
        /// Procesa resultados de detección
        /// </summary>
        private async Task ProcessDetectionResultsAsync(List<DetectionResult> results)
        {
            foreach (var result in results)
            {
                if (result.Severity >= ThreatSeverity.High)
                {
                    // Ejecutar remediación automática
                    var responseExecutor = _moduleRegistry.GetModule<ResponseExecutor>();
                    if (responseExecutor != null)
                    {
                        await responseExecutor.ExecuteRemediationAsync(result);
                    }
                    
                    // Enviar alerta
                    await GenerateAlertAsync(result);
                }
                
                // Enviar a telemetría
                await EnqueueForTelemetryAsync(result);
            }
        }

        /// <summary>
        /// Procesa resultados de correlación
        /// </summary>
        private async Task ProcessCorrelationResultsAsync(List<CorrelationResult> results)
        {
            foreach (var result in results)
            {
                if (result.Confidence >= 0.8) // 80% de confianza
                {
                    _logManager.LogWarning($"Correlación detectada: {result.PatternName}", "AgentService");
                    
                    // Calcular score de riesgo
                    var riskScoreCalculator = _moduleRegistry.GetModule<RiskScoreCalculator>();
                    if (riskScoreCalculator != null)
                    {
                        var riskScore = await riskScoreCalculator.CalculateRiskAsync(result);
                        if (riskScore >= 70) // Alto riesgo
                        {
                            await GenerateCriticalAlertAsync(result, riskScore);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Envía lote de telemetría
        /// </summary>
        private async Task SendTelemetryBatchAsync()
        {
            var telemetryBatchSender = _moduleRegistry.GetModule<TelemetryBatchSender>();
            if (telemetryBatchSender != null)
            {
                await telemetryBatchSender.SendBatchAsync();
            }
        }

        /// <summary>
        /// Verifica actualizaciones
        /// </summary>
        private async Task CheckForUpdatesAsync()
        {
            var updateManager = _moduleRegistry.GetModule<UpdateManager>();
            if (updateManager != null)
            {
                var updateAvailable = await updateManager.CheckForUpdatesAsync();
                if (updateAvailable)
                {
                    _logManager.LogInfo("Actualización disponible, programando instalación", "AgentService");
                    await updateManager.ScheduleUpdateAsync();
                }
            }
        }

        /// <summary>
        /// Encola evento para telemetría
        /// </summary>
        private async Task EnqueueForTelemetryAsync(DetectionResult result)
        {
            var telemetryQueue = _moduleRegistry.GetModule<TelemetryQueue>();
            if (telemetryQueue != null)
            {
                var telemetryEvent = new TelemetryEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = result.EventType,
                    Severity = result.Severity,
                    Data = result.ToJson()
                };
                
                await telemetryQueue.EnqueueAsync(telemetryEvent);
            }
        }

        /// <summary>
        /// Genera alerta
        /// </summary>
        private async Task GenerateAlertAsync(DetectionResult result)
        {
            var alert = new SecurityAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                Severity = result.Severity,
                Title = result.Description,
                Details = result.ToJson(),
                Source = result.Source,
                Status = AlertStatus.Active
            };
            
            // Guardar en base de datos local
            await _localDatabase.SaveAlertAsync(alert);
            
            // Mostrar en dashboard local si es crítico
            if (result.Severity >= ThreatSeverity.Critical)
            {
                ShowLocalAlert(alert);
            }
            
            _logManager.LogWarning($"Alerta generada: {alert.Title}", "AgentService");
        }

        /// <summary>
        /// Genera alerta crítica
        /// </summary>
        private async Task GenerateCriticalAlertAsync(CorrelationResult result, int riskScore)
        {
            var alert = new SecurityAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                Severity = ThreatSeverity.Critical,
                Title = $"Ataque correlacionado detectado: {result.PatternName}",
                Details = $"Confianza: {result.Confidence:P0}, Score de riesgo: {riskScore}, Detalles: {result.ToJson()}",
                Source = "ThreatCorrelationEngine",
                Status = AlertStatus.Active
            };
            
            await _localDatabase.SaveAlertAsync(alert);
            ShowLocalAlert(alert);
            
            _logManager.LogCritical($"ALERTA CRÍTICA: {alert.Title}", "AgentService");
        }

        /// <summary>
        /// Muestra alerta en dashboard local
        /// </summary>
        private void ShowLocalAlert(SecurityAlert alert)
        {
            // Implementar notificación en UI
            // Esto se integraría con el dashboard WPF
        }

        /// <summary>
        /// Detiene el agente de forma ordenada
        /// </summary>
        private void StopAgent()
        {
            try
            {
                _logManager.LogInfo("Deteniendo BWP Enterprise Agent...", "AgentService");
                
                _cancellationTokenSource.Cancel();
                
                // Detener módulos en orden inverso
                _moduleRegistry.StopAllModulesAsync().Wait(TimeSpan.FromSeconds(30));
                
                // Detener monitoreo de salud
                _healthMonitor.StopMonitoring();
                
                // Cerrar base de datos
                _localDatabase.CloseAsync().Wait(TimeSpan.FromSeconds(10));
                
                _logManager.LogInfo("BWP Enterprise Agent detenido correctamente", "AgentService");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener agente: {ex}", "AgentService");
            }
        }

        #region Métodos de utilidad para debugging/administración
        public async Task<string> GetAgentStatusAsync()
        {
            var status = new
            {
                Initialized = _isInitialized,
                ModuleCount = _moduleRegistry?.GetModuleCount() ?? 0,
                HealthStatus = _healthMonitor?.GetHealthStatus()?.Status ?? "Unknown",
                DatabaseStatus = _localDatabase?.IsConnected ?? false ? "Connected" : "Disconnected",
                Uptime = GetUptime(),
                MemoryUsage = GetMemoryUsageMB()
            };
            
            return SerializationHelper.ToJson(status);
        }
        
        public async Task<string> GetModuleStatusAsync()
        {
            return await _moduleRegistry.GetStatusReportAsync();
        }
        
        private TimeSpan GetUptime()
        {
            // Implementar lógica de uptime
            return TimeSpan.Zero;
        }
        
        private double GetMemoryUsageMB()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            return process.WorkingSet64 / (1024.0 * 1024.0);
        }
        #endregion
    }
    
    // Enums auxiliares
    public enum ModuleType
    {
        Sensor,
        Detection,
        Telemetry,
        Remediation,
        Policy,
        SelfProtection,
        Communication,
        Update,
        UI,
        Logging,
        Storage
    }
    
    public enum EventType
    {
        ProcessCreated = 1001,
        ProcessTerminated = 1002,
        FileCreated = 2001,
        FileModified = 2002,
        FileDeleted = 2003,
        NetworkConnection = 3001,
        DNSQuery = 3002,
        RegistryModified = 4001,
        ThreatDetected = 5001,
        RemediationApplied = 6001,
        AlertGenerated = 7001
    }
    
    public enum ThreatSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
    
    public enum AlertStatus
    {
        Active,
        Acknowledged,
        Resolved,
        FalsePositive
    }
}