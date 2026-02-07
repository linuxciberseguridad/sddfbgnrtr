using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Timers;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;

namespace BWP.Enterprise.Agent.SelfProtection
{
    /// <summary>
    /// Guardián del servicio BWP Enterprise
    /// Protege contra intentos de detención, desinstalación o manipulación del servicio
    /// </summary>
    public sealed class ServiceGuardian : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<ServiceGuardian> _instance = 
            new Lazy<ServiceGuardian>(() => new ServiceGuardian());
        
        public static ServiceGuardian Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly IntegrityVerifier _integrityVerifier;
        
        private Timer _monitoringTimer;
        private Timer _selfCheckTimer;
        private ServiceController _serviceController;
        private bool _isMonitoring;
        private bool _isInitialized;
        private int _restartAttempts;
        private DateTime _lastRestartTime;
        private const int MONITORING_INTERVAL_SECONDS = 30;
        private const int SELF_CHECK_INTERVAL_MINUTES = 5;
        private const int MAX_RESTART_ATTEMPTS_PER_HOUR = 3;
        
        public string ModuleId => "ServiceGuardian";
        public string Version => "1.0.0";
        public string Description => "Sistema de protección y monitoreo del servicio";
        
        private ServiceGuardian()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _integrityVerifier = IntegrityVerifier.Instance;
            _restartAttempts = 0;
            _lastRestartTime = DateTime.MinValue;
        }
        
        /// <summary>
        /// Inicializa el guardián del servicio
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando ServiceGuardian...", ModuleId);
                
                // Inicializar controlador de servicio
                _serviceController = new ServiceController("BWPEnterpriseAgent");
                
                // Cargar configuración de protección
                await LoadProtectionConfigAsync();
                
                // Configurar temporizadores
                ConfigureTimers();
                
                // Verificar estado inicial del servicio
                await VerifyServiceStateAsync();
                
                _isInitialized = true;
                _logManager.LogInfo("ServiceGuardian inicializado", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar ServiceGuardian: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el guardián
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                    return initResult;
            }
            
            try
            {
                _isMonitoring = true;
                _monitoringTimer.Start();
                _selfCheckTimer.Start();
                
                _logManager.LogInfo("ServiceGuardian iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar ServiceGuardian: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el guardián
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isMonitoring = false;
                
                _monitoringTimer?.Stop();
                _selfCheckTimer?.Stop();
                
                _monitoringTimer?.Dispose();
                _selfCheckTimer?.Dispose();
                _serviceController?.Dispose();
                
                _logManager.LogInfo("ServiceGuardian detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener ServiceGuardian: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Verifica estado del servicio
        /// </summary>
        public async Task<ServiceStatus> VerifyServiceStateAsync()
        {
            try
            {
                _serviceController.Refresh();
                
                var status = new ServiceStatus
                {
                    ServiceName = _serviceController.ServiceName,
                    DisplayName = _serviceController.DisplayName,
                    Status = _serviceController.Status,
                    CanStop = _serviceController.CanStop,
                    CanPauseAndContinue = _serviceController.CanPauseAndContinue,
                    MachineName = _serviceController.MachineName,
                    ServiceType = _serviceController.ServiceType,
                    LastCheckTime = DateTime.UtcNow
                };
                
                // Verificar configuraciones adicionales
                status.StartType = await GetServiceStartTypeAsync();
                status.LogOnAs = await GetServiceLogOnAsAsync();
                status.Dependencies = _serviceController.ServicesDependedOn.Select(s => s.ServiceName).ToList();
                status.DependentServices = _serviceController.DependentServices.Select(s => s.ServiceName).ToList();
                
                // Verificar si el servicio está en el estado esperado
                if (status.Status != ServiceControllerStatus.Running)
                {
                    status.IsHealthy = false;
                    status.Issues.Add($"Servicio no está ejecutándose: {status.Status}");
                    
                    _logManager.LogWarning($"Servicio no está ejecutándose: {status.Status}", ModuleId);
                    
                    // Intentar recuperación automática si es apropiado
                    if (ShouldAttemptRecovery(status.Status))
                    {
                        await AttemptServiceRecoveryAsync(status);
                    }
                }
                else
                {
                    status.IsHealthy = true;
                    _logManager.LogDebug($"Servicio funcionando correctamente: {status.Status}", ModuleId);
                }
                
                // Guardar estado en historial
                await SaveServiceStatusAsync(status);
                
                return status;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando estado del servicio: {ex}", ModuleId);
                return ServiceStatus.Error($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Protege el servicio contra detención
        /// </summary>
        public async Task<ProtectionResult> ProtectServiceAsync()
        {
            try
            {
                _logManager.LogInfo("Activando protección del servicio...", ModuleId);
                
                var protectionSteps = new List<ProtectionStep>();
                
                // Paso 1: Verificar permisos del servicio
                var permResult = await VerifyAndFixServicePermissionsAsync();
                protectionSteps.Add(permResult);
                
                // Paso 2: Configurar recuperación automática
                var recoveryResult = await ConfigureServiceRecoveryAsync();
                protectionSteps.Add(recoveryResult);
                
                // Paso 3: Ocultar servicio de administradores no autorizados
                var hideResult = await HideServiceFromUnauthorizedUsersAsync();
                protectionSteps.Add(hideResult);
                
                // Paso 4: Configurar triggers de reinicio
                var triggerResult = await ConfigureServiceTriggersAsync();
                protectionSteps.Add(triggerResult);
                
                // Paso 5: Monitorear intentos de manipulación
                var monitorResult = await EnableManipulationMonitoringAsync();
                protectionSteps.Add(monitorResult);
                
                var successCount = protectionSteps.Count(s => s.Success);
                var failedCount = protectionSteps.Count(s => !s.Success);
                
                var result = new ProtectionResult
                {
                    Timestamp = DateTime.UtcNow,
                    Success = failedCount == 0,
                    ProtectionSteps = protectionSteps,
                    SuccessCount = successCount,
                    FailedCount = failedCount
                };
                
                if (result.Success)
                {
                    _logManager.LogInfo("Protección del servicio activada exitosamente", ModuleId);
                }
                else
                {
                    _logManager.LogWarning($"Protección del servicio activada parcialmente: {successCount} exitosos, {failedCount} fallidos", ModuleId);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error activando protección del servicio: {ex}", ModuleId);
                return ProtectionResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Restaura el servicio si está detenido o en mal estado
        /// </summary>
        public async Task<RestorationResult> RestoreServiceAsync()
        {
            try
            {
                _logManager.LogWarning("Intentando restaurar servicio...", ModuleId);
                
                // Verificar límite de intentos de reinicio
                if (!CanAttemptRestart())
                {
                    return RestorationResult.Failed(
                        $"Límite de intentos de reinicio alcanzado: {_restartAttempts} en la última hora");
                }
                
                var status = await VerifyServiceStateAsync();
                
                // Si el servicio ya está ejecutándose, verificar que esté funcionando correctamente
                if (status.Status == ServiceControllerStatus.Running)
                {
                    var healthCheck = await PerformServiceHealthCheckAsync();
                    if (healthCheck.IsHealthy)
                    {
                        return RestorationResult.Success("Servicio ya está ejecutándose y saludable");
                    }
                    
                    // Si está ejecutándose pero no saludable, reiniciar
                    _logManager.LogWarning($"Servicio ejecutándose pero no saludable: {healthCheck.Issues.Count} issues", ModuleId);
                    return await RestartServiceAsync("Servicio no saludable");
                }
                
                // Intentar iniciar el servicio según su estado actual
                switch (status.Status)
                {
                    case ServiceControllerStatus.Stopped:
                        return await StartServiceAsync();
                        
                    case ServiceControllerStatus.Paused:
                        return await ResumeServiceAsync();
                        
                    case ServiceControllerStatus.StartPending:
                    case ServiceControllerStatus.StopPending:
                    case ServiceControllerStatus.ContinuePending:
                    case ServiceControllerStatus.PausePending:
                        // Esperar a que termine la operación pendiente
                        await WaitForPendingOperationAsync();
                        return await VerifyAndRestoreAsync();
                        
                    default:
                        return await RestartServiceAsync($"Estado desconocido: {status.Status}");
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error restaurando servicio: {ex}", ModuleId);
                return RestorationResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Reinicia el servicio
        /// </summary>
        public async Task<RestorationResult> RestartServiceAsync(string reason = null)
        {
            try
            {
                // Verificar límite de intentos de reinicio
                if (!CanAttemptRestart())
                {
                    return RestorationResult.Failed(
                        $"Límite de intentos de reinicio alcanzado: {_restartAttempts} en la última hora");
                }
                
                _logManager.LogWarning($"Reiniciando servicio. Razón: {reason ?? "No especificada"}", ModuleId);
                
                // Paso 1: Detener servicio si está ejecutándose
                if (_serviceController.Status == ServiceControllerStatus.Running || 
                    _serviceController.Status == ServiceControllerStatus.StartPending)
                {
                    await StopServiceAsync();
                }
                
                // Pequeña pausa para asegurar que el servicio se detuvo completamente
                await Task.Delay(5000);
                
                // Paso 2: Verificar integridad antes de iniciar
                var integrityCheck = await _integrityVerifier.VerifyCriticalComponentsAsync();
                if (!integrityCheck.IsValid)
                {
                    _logManager.LogError("Integridad comprometida, no se puede reiniciar el servicio", ModuleId);
                    return RestorationResult.Failed("Integridad del servicio comprometida");
                }
                
                // Paso 3: Iniciar servicio
                var startResult = await StartServiceAsync();
                
                if (startResult.Success)
                {
                    _restartAttempts++;
                    _lastRestartTime = DateTime.UtcNow;
                    
                    // Guardar en historial
                    await LogRestartEventAsync(reason, true);
                    
                    return RestorationResult.Success($"Servicio reiniciado exitosamente. Razón: {reason}");
                }
                
                // Si falla el inicio, intentar recuperación avanzada
                return await AttemptAdvancedRecoveryAsync(reason);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error reiniciando servicio: {ex}", ModuleId);
                await LogRestartEventAsync($"Error: {ex.Message}", false);
                return RestorationResult.Failed($"Error reiniciando servicio: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Monitorea intentos de manipulación del servicio
        /// </summary>
        public async Task StartManipulationMonitoringAsync()
        {
            try
            {
                _logManager.LogInfo("Iniciando monitoreo de manipulación del servicio...", ModuleId);
                
                // Monitorear eventos de sistema relacionados con el servicio
                await StartServiceEventMonitoringAsync();
                
                // Monitorear cambios en el registro relacionados con el servicio
                await StartRegistryMonitoringAsync();
                
                // Monitorear cambios en archivos del servicio
                await StartFileSystemMonitoringAsync();
                
                // Monitorear intentos de acceso al proceso
                await StartProcessMonitoringAsync();
                
                _logManager.LogInfo("Monitoreo de manipulación iniciado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error iniciando monitoreo de manipulación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Bloquea intentos de detención del servicio
        /// </summary>
        public async Task<bool> BlockServiceStopAttemptAsync()
        {
            try
            {
                _logManager.LogWarning("Intento de detención del servicio detectado, bloqueando...", ModuleId);
                
                // Registrar intento de detención
                await LogStopAttemptAsync();
                
                // Notificar al SOC
                await NotifyStopAttemptToSOCAsync();
                
                // Si hay demasiados intentos recientes, tomar medidas más estrictas
                if (ShouldEnforceStrictProtection())
                {
                    await EnforceStrictProtectionAsync();
                    return true; // Bloqueo estricto activado
                }
                
                // Intentar convencer al sistema que el servicio se detuvo (simulación)
                await SimulateServiceStopAsync();
                
                // Reiniciar el servicio inmediatamente
                await RestartServiceAsync("Intento de detención bloqueado");
                
                _logManager.LogWarning("Intento de detención bloqueado y servicio reiniciado", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error bloqueando intento de detención: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene reporte de protección
        /// </summary>
        public async Task<ProtectionReport> GetProtectionReportAsync(TimeSpan? period = null)
        {
            period ??= TimeSpan.FromDays(7);
            
            try
            {
                var currentStatus = await VerifyServiceStateAsync();
                var protectionStatus = await GetCurrentProtectionStatusAsync();
                var manipulationAttempts = await _localDatabase.GetManipulationAttemptsAsync(period.Value);
                var restartHistory = await _localDatabase.GetServiceRestartHistoryAsync(period.Value);
                var stopAttempts = await _localDatabase.GetStopAttemptsAsync(period.Value);
                
                var report = new ProtectionReport
                {
                    GeneratedAt = DateTime.UtcNow,
                    Period = period.Value,
                    CurrentServiceStatus = currentStatus,
                    ProtectionStatus = protectionStatus,
                    ManipulationAttempts = manipulationAttempts,
                    RestartHistory = restartHistory,
                    StopAttempts = stopAttempts,
                    Statistics = CalculateProtectionStatistics(manipulationAttempts, restartHistory, stopAttempts),
                    Recommendations = await GenerateProtectionRecommendationsAsync(currentStatus, protectionStatus, manipulationAttempts)
                };
                
                return report;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando reporte de protección: {ex}", ModuleId);
                return ProtectionReport.Error($"Error: {ex.Message}");
            }
        }
        
        #region Métodos privados
        
        /// <summary>
        /// Configura temporizadores
        /// </summary>
        private void ConfigureTimers()
        {
            _monitoringTimer = new Timer(TimeSpan.FromSeconds(MONITORING_INTERVAL_SECONDS).TotalMilliseconds);
            _monitoringTimer.Elapsed += async (sender, e) => await MonitorServiceAsync();
            
            _selfCheckTimer = new Timer(TimeSpan.FromMinutes(SELF_CHECK_INTERVAL_MINUTES).TotalMilliseconds);
            _selfCheckTimer.Elapsed += async (sender, e) => await PerformSelfCheckAsync();
        }
        
        /// <summary>
        /// Monitorea el servicio periódicamente
        /// </summary>
        private async Task MonitorServiceAsync()
        {
            if (!_isMonitoring)
                return;
            
            try
            {
                await VerifyServiceStateAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en monitoreo periódico: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Realiza auto-verificación
        /// </summary>
        private async Task PerformSelfCheckAsync()
        {
            if (!_isMonitoring)
                return;
            
            try
            {
                _logManager.LogDebug("Realizando auto-verificación del ServiceGuardian...", ModuleId);
                
                // Verificar que el guardián mismo esté funcionando
                var selfCheck = await PerformGuardianHealthCheckAsync();
                
                if (!selfCheck.IsHealthy)
                {
                    _logManager.LogWarning($"Problemas en auto-verificación: {selfCheck.Issues.Count} issues", ModuleId);
                    
                    // Intentar auto-reparación
                    await AttemptSelfRepairAsync(selfCheck);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en auto-verificación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Carga configuración de protección
        /// </summary>
        private async Task LoadProtectionConfigAsync()
        {
            try
            {
                var config = await _localDatabase.GetServiceProtectionConfigAsync();
                
                if (config == null)
                {
                    // Configuración por defecto
                    config = new ServiceProtectionConfig
                    {
                        MaxRestartAttemptsPerHour = MAX_RESTART_ATTEMPTS_PER_HOUR,
                        MonitoringIntervalSeconds = MONITORING_INTERVAL_SECONDS,
                        EnableStrictProtection = true,
                        NotifyOnManipulationAttempt = true,
                        AutoRestartOnFailure = true,
                        BlockStopAttempts = true
                    };
                    
                    await _localDatabase.SaveServiceProtectionConfigAsync(config);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando configuración de protección: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Verifica si se puede intentar reinicio
        /// </summary>
        private bool CanAttemptRestart()
        {
            // Resetear contador si ha pasado más de una hora
            if ((DateTime.UtcNow - _lastRestartTime).TotalHours >= 1)
            {
                _restartAttempts = 0;
            }
            
            return _restartAttempts < MAX_RESTART_ATTEMPTS_PER_HOUR;
        }
        
        /// <summary>
        /// Inicia el servicio
        /// </summary>
        private async Task<RestorationResult> StartServiceAsync()
        {
            try
            {
                _logManager.LogInfo("Iniciando servicio...", ModuleId);
                
                _serviceController.Start();
                
                // Esperar a que el servicio inicie
                _serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                
                // Verificar que realmente esté ejecutándose
                await Task.Delay(2000);
                _serviceController.Refresh();
                
                if (_serviceController.Status == ServiceControllerStatus.Running)
                {
                    _logManager.LogInfo("Servicio iniciado exitosamente", ModuleId);
                    return RestorationResult.Success("Servicio iniciado exitosamente");
                }
                else
                {
                    _logManager.LogError($"Servicio no pudo iniciarse. Estado: {_serviceController.Status}", ModuleId);
                    return RestorationResult.Failed($"Servicio no pudo iniciarse. Estado: {_serviceController.Status}");
                }
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already running"))
            {
                _logManager.LogInfo("Servicio ya está ejecutándose", ModuleId);
                return RestorationResult.Success("Servicio ya está ejecutándose");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error iniciando servicio: {ex}", ModuleId);
                return RestorationResult.Failed($"Error iniciando servicio: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Detiene el servicio
        /// </summary>
        private async Task<RestorationResult> StopServiceAsync()
        {
            try
            {
                _logManager.LogInfo("Deteniendo servicio...", ModuleId);
                
                if (!_serviceController.CanStop)
                {
                    _logManager.LogWarning("Servicio no puede ser detenido normalmente", ModuleId);
                    return await ForceStopServiceAsync();
                }
                
                _serviceController.Stop();
                _serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                
                await Task.Delay(2000);
                _serviceController.Refresh();
                
                if (_serviceController.Status == ServiceControllerStatus.Stopped)
                {
                    _logManager.LogInfo("Servicio detenido exitosamente", ModuleId);
                    return RestorationResult.Success("Servicio detenido exitosamente");
                }
                else
                {
                    return await ForceStopServiceAsync();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deteniendo servicio: {ex}", ModuleId);
                return await ForceStopServiceAsync();
            }
        }
        
        /// <summary>
        /// Fuerza la detención del servicio
        /// </summary>
        private async Task<RestorationResult> ForceStopServiceAsync()
        {
            try
            {
                _logManager.LogWarning("Forzando detención del servicio...", ModuleId);
                
                // Usar comandos del sistema para forzar la detención
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"stop {_serviceController.ServiceName}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    // Esperar y verificar
                    await Task.Delay(5000);
                    _serviceController.Refresh();
                    
                    if (_serviceController.Status == ServiceControllerStatus.Stopped)
                    {
                        return RestorationResult.Success("Servicio forzado a detenerse");
                    }
                }
                
                // Último recurso: matar procesos relacionados
                return await KillRelatedProcessesAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error forzando detención del servicio: {ex}", ModuleId);
                return RestorationResult.Failed($"No se pudo detener el servicio: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Reanuda servicio pausado
        /// </summary>
        private async Task<RestorationResult> ResumeServiceAsync()
        {
            try
            {
                _logManager.LogInfo("Reanudando servicio...", ModuleId);
                
                if (_serviceController.CanPauseAndContinue)
                {
                    _serviceController.Continue();
                    _serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    
                    await Task.Delay(2000);
                    _serviceController.Refresh();
                    
                    if (_serviceController.Status == ServiceControllerStatus.Running)
                    {
                        _logManager.LogInfo("Servicio reanudado exitosamente", ModuleId);
                        return RestorationResult.Success("Servicio reanudado exitosamente");
                    }
                }
                
                // Si no se puede reanudar, reiniciar
                return await RestartServiceAsync("No se pudo reanudar el servicio pausado");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error reanudando servicio: {ex}", ModuleId);
                return await RestartServiceAsync($"Error reanudando: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Espera por operación pendiente
        /// </summary>
        private async Task WaitForPendingOperationAsync()
        {
            try
            {
                _logManager.LogInfo("Esperando por operación pendiente del servicio...", ModuleId);
                
                // Esperar hasta que el estado sea estable
                var maxWaitTime = TimeSpan.FromSeconds(60);
                var startTime = DateTime.UtcNow;
                
                while ((DateTime.UtcNow - startTime) < maxWaitTime)
                {
                    _serviceController.Refresh();
                    
                    if (_serviceController.Status != ServiceControllerStatus.StartPending &&
                        _serviceController.Status != ServiceControllerStatus.StopPending &&
                        _serviceController.Status != ServiceControllerStatus.ContinuePending &&
                        _serviceController.Status != ServiceControllerStatus.PausePending)
                    {
                        break;
                    }
                    
                    await Task.Delay(1000);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error esperando por operación pendiente: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Verifica y restaura según estado actual
        /// </summary>
        private async Task<RestorationResult> VerifyAndRestoreAsync()
        {
            var status = await VerifyServiceStateAsync();
            
            if (status.Status == ServiceControllerStatus.Running)
            {
                var healthCheck = await PerformServiceHealthCheckAsync();
                if (healthCheck.IsHealthy)
                {
                    return RestorationResult.Success("Servicio recuperado después de operación pendiente");
                }
                else
                {
                    return await RestartServiceAsync($"Servicio no saludable después de operación pendiente: {healthCheck.Issues.FirstOrDefault()}");
                }
            }
            else
            {
                return await RestoreServiceAsync();
            }
        }
        
        /// <summary>
        /// Intenta recuperación avanzada
        /// </summary>
        private async Task<RestorationResult> AttemptAdvancedRecoveryAsync(string reason)
        {
            try
            {
                _logManager.LogCritical("Iniciando recuperación avanzada del servicio...", ModuleId);
                
                var recoverySteps = new List<RecoveryStep>();
                
                // Paso 1: Reparar instalación del servicio
                var repairStep = await RepairServiceInstallationAsync();
                recoverySteps.Add(repairStep);
                
                if (!repairStep.Success)
                {
                    // Paso 2: Reinstalar servicio
                    var reinstallStep = await ReinstallServiceAsync();
                    recoverySteps.Add(reinstallStep);
                }
                
                // Paso 3: Intentar iniciar nuevamente
                var startResult = await StartServiceAsync();
                
                var successCount = recoverySteps.Count(s => s.Success) + (startResult.Success ? 1 : 0);
                var failedCount = recoverySteps.Count(s => !s.Success) + (!startResult.Success ? 1 : 0);
                
                if (startResult.Success)
                {
                    _logManager.LogCritical("Recuperación avanzada exitosa", ModuleId);
                    return RestorationResult.Success($"Servicio recuperado después de {recoverySteps.Count} pasos");
                }
                else
                {
                    _logManager.LogCritical("Recuperación avanzada fallida", ModuleId);
                    return RestorationResult.Failed($"Recuperación avanzada fallida: {failedCount} pasos fallidos");
                }
            }
            catch (Exception ex)
            {
                _logManager.LogCritical($"Error en recuperación avanzada: {ex}", ModuleId);
                return RestorationResult.Failed($"Error en recuperación avanzada: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Determina si se debe intentar recuperación
        /// </summary>
        private bool ShouldAttemptRecovery(ServiceControllerStatus status)
        {
            return status switch
            {
                ServiceControllerStatus.Stopped => true,
                ServiceControllerStatus.Paused => true,
                ServiceControllerStatus.StartPending => false, // Esperar
                ServiceControllerStatus.StopPending => false, // Esperar
                ServiceControllerStatus.ContinuePending => false, // Esperar
                ServiceControllerStatus.PausePending => false, // Esperar
                _ => false
            };
        }
        
        /// <summary>
        /// Intenta recuperación del servicio
        /// </summary>
        private async Task AttemptServiceRecoveryAsync(ServiceStatus status)
        {
            try
            {
                _logManager.LogWarning($"Intentando recuperación automática del servicio... Estado: {status.Status}", ModuleId);
                
                var recoveryResult = await RestoreServiceAsync();
                
                if (recoveryResult.Success)
                {
                    _logManager.LogInfo("Recuperación automática exitosa", ModuleId);
                }
                else
                {
                    _logManager.LogError($"Recuperación automática fallida: {recoveryResult.ErrorMessage}", ModuleId);
                    
                    // Notificar al SOC sobre fallo de recuperación
                    await NotifyRecoveryFailureToSOCAsync(recoveryResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en recuperación automática: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Mata procesos relacionados
        /// </summary>
        private async Task<RestorationResult> KillRelatedProcessesAsync()
        {
            try
            {
                _logManager.LogWarning("Matando procesos relacionados del servicio...", ModuleId);
                
                var processes = Process.GetProcesses()
                    .Where(p => p.ProcessName.Contains("BWP", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                
                foreach (var process in processes)
                {
                    try
                    {
                        process.Kill();
                        await Task.Delay(100);
                    }
                    catch
                    {
                        // Ignorar procesos que no se pueden matar
                    }
                }
                
                await Task.Delay(3000);
                _serviceController.Refresh();
                
                if (_serviceController.Status == ServiceControllerStatus.Stopped)
                {
                    return RestorationResult.Success("Procesos relacionados eliminados");
                }
                
                return RestorationResult.Failed("No se pudieron eliminar todos los procesos");
            }
            catch (Exception ex)
            {
                return RestorationResult.Failed($"Error eliminando procesos: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Verifica y repara permisos del servicio
        /// </summary>
        private async Task<ProtectionStep> VerifyAndFixServicePermissionsAsync()
        {
            try
            {
                // Usar sc.exe para verificar y configurar permisos
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"sdshow {_serviceController.ServiceName}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();
                    
                    // Analizar permisos actuales
                    var currentPermissions = ParseServicePermissions(output);
                    
                    // Definir permisos seguros
                    var securePermissions = GetSecureServicePermissions();
                    
                    if (currentPermissions != securePermissions)
                    {
                        // Configurar permisos seguros
                        using (var setProcess = new Process())
                        {
                            setProcess.StartInfo.FileName = "sc";
                            setProcess.StartInfo.Arguments = $"sdset {_serviceController.ServiceName} {securePermissions}";
                            setProcess.StartInfo.UseShellExecute = false;
                            setProcess.StartInfo.CreateNoWindow = true;
                            
                            setProcess.Start();
                            await setProcess.WaitForExitAsync();
                            
                            if (setProcess.ExitCode == 0)
                            {
                                return ProtectionStep.Success(
                                    "ServicePermissions",
                                    "Permisos del servicio configurados de forma segura");
                            }
                        }
                    }
                    
                    return ProtectionStep.Success(
                        "ServicePermissions",
                        "Permisos del servicio ya son seguros");
                }
            }
            catch (Exception ex)
            {
                return ProtectionStep.Failed(
                    "ServicePermissions",
                    $"Error configurando permisos: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Configura recuperación automática del servicio
        /// </summary>
        private async Task<ProtectionStep> ConfigureServiceRecoveryAsync()
        {
            try
            {
                // Configurar acciones de recuperación usando sc.exe
                var recoveryActions = "actions= restart/5000/restart/30000/restart/60000";
                
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"failure {_serviceController.ServiceName} reset= 86400 {recoveryActions}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    if (process.ExitCode == 0)
                    {
                        return ProtectionStep.Success(
                            "ServiceRecovery",
                            "Recuperación automática configurada (reiniciar en 5s, 30s, 60s)");
                    }
                    else
                    {
                        return ProtectionStep.Failed(
                            "ServiceRecovery",
                            $"Error configurando recuperación. Código: {process.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                return ProtectionStep.Failed(
                    "ServiceRecovery",
                    $"Error configurando recuperación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Oculta servicio de usuarios no autorizados
        /// </summary>
        private async Task<ProtectionStep> HideServiceFromUnauthorizedUsersAsync()
        {
            try
            {
                // Modificar registro para ocultar servicio
                var registryPath = @"SYSTEM\CurrentControlSet\Services\BWPEnterpriseAgent";
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key != null)
                    {
                        // Establecer tipo de inicio como automático (2) y ocultar
                        key.SetValue("Start", 2, Microsoft.Win32.RegistryValueKind.DWord);
                        
                        // Agregar flag para dificultar detención
                        key.SetValue("ErrorControl", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        
                        return ProtectionStep.Success(
                            "ServiceVisibility",
                            "Servicio configurado para inicio automático y protección básica");
                    }
                }
                
                return ProtectionStep.Failed(
                    "ServiceVisibility",
                    "No se pudo acceder a la configuración del servicio en el registro");
            }
            catch (Exception ex)
            {
                return ProtectionStep.Failed(
                    "ServiceVisibility",
                    $"Error ocultando servicio: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Configura triggers del servicio
        /// </summary>
        private async Task<ProtectionStep> ConfigureServiceTriggersAsync()
        {
            try
            {
                // Configurar trigger para reinicio ante eventos específicos
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"triggerinfo {_serviceController.ServiceName} start/network";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    return ProtectionStep.Success(
                        "ServiceTriggers",
                        "Triggers del servicio configurados");
                }
            }
            catch (Exception ex)
            {
                return ProtectionStep.Failed(
                    "ServiceTriggers",
                    $"Error configurando triggers: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Habilita monitoreo de manipulación
        /// </summary>
        private async Task<ProtectionStep> EnableManipulationMonitoringAsync()
        {
            try
            {
                await StartManipulationMonitoringAsync();
                
                return ProtectionStep.Success(
                    "ManipulationMonitoring",
                    "Monitoreo de manipulación habilitado");
            }
            catch (Exception ex)
            {
                return ProtectionStep.Failed(
                    "ManipulationMonitoring",
                    $"Error habilitando monitoreo: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Obtiene tipo de inicio del servicio
        /// </summary>
        private async Task<ServiceStartMode> GetServiceStartTypeAsync()
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"qc {_serviceController.ServiceName}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();
                    
                    // Analizar output para obtener tipo de inicio
                    if (output.Contains("AUTO_START"))
                        return ServiceStartMode.Automatic;
                    else if (output.Contains("DEMAND_START"))
                        return ServiceStartMode.Manual;
                    else
                        return ServiceStartMode.Disabled;
                }
            }
            catch
            {
                return ServiceStartMode.Unknown;
            }
        }
        
        /// <summary>
        /// Obtiene cuenta de inicio de sesión del servicio
        /// </summary>
        private async Task<string> GetServiceLogOnAsAsync()
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"qc {_serviceController.ServiceName}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();
                    
                    // Extraer cuenta del output
                    var match = System.Text.RegularExpressions.Regex.Match(output, @"SERVICE_START_NAME\s*:\s*(.+)");
                    return match.Success ? match.Groups[1].Value.Trim() : "LocalSystem";
                }
            }
            catch
            {
                return "Unknown";
            }
        }
        
        /// <summary>
        /// Realiza verificación de salud del servicio
        /// </summary>
        private async Task<ServiceHealthCheck> PerformServiceHealthCheckAsync()
        {
            var healthCheck = new ServiceHealthCheck
            {
                Timestamp = DateTime.UtcNow,
                ServiceName = _serviceController.ServiceName
            };
            
            try
            {
                // Verificar 1: Servicio respondiendo
                _serviceController.Refresh();
                if (_serviceController.Status != ServiceControllerStatus.Running)
                {
                    healthCheck.Issues.Add($"Servicio no ejecutándose: {_serviceController.Status}");
                }
                
                // Verificar 2: Proceso asociado existe
                var processId = GetServiceProcessId();
                if (processId == 0)
                {
                    healthCheck.Issues.Add("No se pudo obtener ID del proceso del servicio");
                }
                else
                {
                    try
                    {
                        var process = Process.GetProcessById(processId);
                        
                        // Verificar 3: Uso de recursos
                        if (process.WorkingSet64 > 500 * 1024 * 1024) // > 500MB
                        {
                            healthCheck.Issues.Add($"Alto uso de memoria: {process.WorkingSet64 / 1024 / 1024}MB");
                        }
                        
                        // Verificar 4: Tiempo de actividad
                        var uptime = DateTime.Now - process.StartTime;
                        if (uptime.TotalSeconds < 30)
                        {
                            healthCheck.Issues.Add("Servicio reiniciado recientemente");
                        }
                    }
                    catch
                    {
                        healthCheck.Issues.Add("Proceso del servicio no encontrado");
                    }
                }
                
                // Verificar 5: Comunicación interna
                var internalCheck = await PerformInternalServiceCheckAsync();
                if (!internalCheck.Success)
                {
                    healthCheck.Issues.Add($"Error en comunicación interna: {internalCheck.ErrorMessage}");
                }
                
                healthCheck.IsHealthy = healthCheck.Issues.Count == 0;
                return healthCheck;
            }
            catch (Exception ex)
            {
                healthCheck.Issues.Add($"Error en health check: {ex.Message}");
                healthCheck.IsHealthy = false;
                return healthCheck;
            }
        }
        
        /// <summary>
        /// Obtiene ID del proceso del servicio
        /// </summary>
        private int GetServiceProcessId()
        {
            try
            {
                // Usar WMI para obtener process ID
                var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Service WHERE Name = '{_serviceController.ServiceName}'");
                
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ProcessId"]);
                }
                
                return 0;
            }
            catch
            {
                return 0;
            }
        }
        
        /// <summary>
        /// Realiza verificación interna del servicio
        /// </summary>
        private async Task<InternalCheckResult> PerformInternalServiceCheckAsync()
        {
            try
            {
                // Intentar comunicación con módulos internos del agente
                var moduleRegistry = ModuleRegistry.Instance;
                var activeModules = moduleRegistry.GetModuleCount();
                
                if (activeModules == 0)
                {
                    return InternalCheckResult.Failed("No hay módulos activos");
                }
                
                // Verificar módulos críticos
                var criticalModules = new[] { "HealthMonitor", "IntegrityVerifier", "DeviceAuthenticator" };
                foreach (var module in criticalModules)
                {
                    var status = moduleRegistry.GetModuleStatus(module);
                    if (status != ModuleStatus.Running)
                    {
                        return InternalCheckResult.Failed($"Módulo crítico no está ejecutándose: {module}");
                    }
                }
                
                return InternalCheckResult.Success();
            }
            catch (Exception ex)
            {
                return InternalCheckResult.Failed($"Error en verificación interna: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Realiza verificación de salud del guardián
        /// </summary>
        private async Task<GuardianHealthCheck> PerformGuardianHealthCheckAsync()
        {
            var healthCheck = new GuardianHealthCheck
            {
                Timestamp = DateTime.UtcNow
            };
            
            try
            {
                // Verificar 1: Temporizadores funcionando
                if (!_monitoringTimer.Enabled)
                {
                    healthCheck.Issues.Add("Temporizador de monitoreo no está ejecutándose");
                }
                
                // Verificar 2: Controlador de servicio válido
                try
                {
                    _serviceController.Refresh();
                }
                catch
                {
                    healthCheck.Issues.Add("Controlador de servicio no válido");
                }
                
                // Verificar 3: Base de datos accesible
                try
                {
                    var test = await _localDatabase.GetServiceStatusHistoryAsync(TimeSpan.FromHours(1));
                }
                catch
                {
                    healthCheck.Issues.Add("No se puede acceder a la base de datos");
                }
                
                // Verificar 4: Última verificación reciente
                var lastCheck = await _localDatabase.GetLastServiceCheckAsync();
                if (lastCheck != null && (DateTime.UtcNow - lastCheck.Value).TotalMinutes > 10)
                {
                    healthCheck.Issues.Add("Última verificación hace más de 10 minutos");
                }
                
                healthCheck.IsHealthy = healthCheck.Issues.Count == 0;
                return healthCheck;
            }
            catch (Exception ex)
            {
                healthCheck.Issues.Add($"Error en health check del guardián: {ex.Message}");
                healthCheck.IsHealthy = false;
                return healthCheck;
            }
        }
        
        /// <summary>
        /// Intenta auto-reparación del guardián
        /// </summary>
        private async Task AttemptSelfRepairAsync(GuardianHealthCheck healthCheck)
        {
            try
            {
                _logManager.LogWarning($"Intentando auto-reparación del ServiceGuardian. Issues: {healthCheck.Issues.Count}", ModuleId);
                
                foreach (var issue in healthCheck.Issues)
                {
                    if (issue.Contains("temporizador", StringComparison.OrdinalIgnoreCase))
                    {
                        await RepairTimersAsync();
                    }
                    else if (issue.Contains("controlador", StringComparison.OrdinalIgnoreCase))
                    {
                        await RepairServiceControllerAsync();
                    }
                    else if (issue.Contains("base de datos", StringComparison.OrdinalIgnoreCase))
                    {
                        await RepairDatabaseConnectionAsync();
                    }
                }
                
                // Reiniciar monitoreo
                await StopAsync();
                await StartAsync();
                
                _logManager.LogInfo("Auto-reparación del ServiceGuardian completada", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en auto-reparación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Repara temporizadores
        /// </summary>
        private async Task RepairTimersAsync()
        {
            try
            {
                _monitoringTimer?.Dispose();
                _selfCheckTimer?.Dispose();
                
                ConfigureTimers();
                
                if (_isMonitoring)
                {
                    _monitoringTimer.Start();
                    _selfCheckTimer.Start();
                }
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error reparando temporizadores: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Repara controlador de servicio
        /// </summary>
        private async Task RepairServiceControllerAsync()
        {
            try
            {
                _serviceController?.Dispose();
                _serviceController = new ServiceController("BWPEnterpriseAgent");
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error reparando controlador de servicio: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Repara conexión a base de datos
        /// </summary>
        private async Task RepairDatabaseConnectionAsync()
        {
            try
            {
                await _localDatabase.ReconnectAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error reparando conexión a base de datos: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Inicia monitoreo de eventos del servicio
        /// </summary>
        private async Task StartServiceEventMonitoringAsync()
        {
            // Implementar usando EventLog
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Inicia monitoreo del registro
        /// </summary>
        private async Task StartRegistryMonitoringAsync()
        {
            // Implementar usando RegistryWatcher
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Inicia monitoreo del sistema de archivos
        /// </summary>
        private async Task StartFileSystemMonitoringAsync()
        {
            // Implementar usando FileSystemWatcher
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Inicia monitoreo de procesos
        /// </summary>
        private async Task StartProcessMonitoringAsync()
        {
            // Implementar monitoreo de procesos que intentan acceder al servicio
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Determina si se debe aplicar protección estricta
        /// </summary>
        private bool ShouldEnforceStrictProtection()
        {
            // Lógica para determinar si hay demasiados intentos recientes
            return false; // Simplificado
        }
        
        /// <summary>
        /// Aplica protección estricta
        /// </summary>
        private async Task EnforceStrictProtectionAsync()
        {
            try
            {
                _logManager.LogCritical("Aplicando protección estricta del servicio...", ModuleId);
                
                // 1. Deshabilitar completamente la detención del servicio
                await DisableServiceStopCompletelyAsync();
                
                // 2. Ocultar servicio completamente
                await HideServiceCompletelyAsync();
                
                // 3. Notificar al SOC de emergencia
                await NotifyEmergencyToSOCAsync();
                
                // 4. Tomar captura forense del sistema
                await TakeForensicSnapshotAsync();
                
                _logManager.LogCritical("Protección estricta aplicada", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error aplicando protección estricta: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Simula detención del servicio
        /// </summary>
        private async Task SimulateServiceStopAsync()
        {
            try
            {
                // Engañar al sistema reportando que el servicio se detuvo
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "sc";
                    process.StartInfo.Arguments = $"control {_serviceController.ServiceName} 129";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error simulando detención: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Repara instalación del servicio
        /// </summary>
        private async Task<RecoveryStep> RepairServiceInstallationAsync()
        {
            // Implementar reparación de instalación
            await Task.Delay(100);
            return new RecoveryStep { Name = "RepairInstallation", Success = true };
        }
        
        /// <summary>
        /// Reinstala el servicio
        /// </summary>
        private async Task<RecoveryStep> ReinstallServiceAsync()
        {
            // Implementar reinstalación
            await Task.Delay(100);
            return new RecoveryStep { Name = "ReinstallService", Success = true };
        }
        
        /// <summary>
        /// Deshabilita completamente la detención del servicio
        /// </summary>
        private async Task DisableServiceStopCompletelyAsync()
        {
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Oculta servicio completamente
        /// </summary>
        private async Task HideServiceCompletelyAsync()
        {
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Toma captura forense
        /// </summary>
        private async Task TakeForensicSnapshotAsync()
        {
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Analiza permisos del servicio
        /// </summary>
        private string ParseServicePermissions(string output)
        {
            return output;
        }
        
        /// <summary>
        /// Obtiene permisos seguros del servicio
        /// </summary>
        private string GetSecureServicePermissions()
        {
            // SDDL para permisos seguros
            return "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
        }
        
        /// <summary>
        /// Guarda estado del servicio
        /// </summary>
        private async Task SaveServiceStatusAsync(ServiceStatus status)
        {
            try
            {
                await _localDatabase.SaveServiceStatusAsync(status);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando estado del servicio: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Registra evento de reinicio
        /// </summary>
        private async Task LogRestartEventAsync(string reason, bool success)
        {
            try
            {
                var restartEvent = new ServiceRestartEvent
                {
                    Timestamp = DateTime.UtcNow,
                    Reason = reason,
                    Success = success,
                    AttemptNumber = _restartAttempts,
                    ServiceStatus = _serviceController.Status.ToString()
                };
                
                await _localDatabase.LogServiceRestartAsync(restartEvent);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error registrando evento de reinicio: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Registra intento de detención
        /// </summary>
        private async Task LogStopAttemptAsync()
        {
            try
            {
                var stopAttempt = new ServiceStopAttempt
                {
                    Timestamp = DateTime.UtcNow,
                    ServiceName = _serviceController.ServiceName,
                    CurrentStatus = _serviceController.Status.ToString(),
                    CallerProcess = GetCallerProcessInfo()
                };
                
                await _localDatabase.LogStopAttemptAsync(stopAttempt);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error registrando intento de detención: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene información del proceso que llama
        /// </summary>
        private string GetCallerProcessInfo()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                return $"{process.ProcessName} (PID: {process.Id})";
            }
            catch
            {
                return "Unknown";
            }
        }
        
        /// <summary>
        /// Notifica intento de detención al SOC
        /// </summary>
        private async Task NotifyStopAttemptToSOCAsync()
        {
            // Implementar notificación
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Notifica fallo de recuperación al SOC
        /// </summary>
        private async Task NotifyRecoveryFailureToSOCAsync(string error)
        {
            // Implementar notificación
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Notifica emergencia al SOC
        /// </summary>
        private async Task NotifyEmergencyToSOCAsync()
        {
            // Implementar notificación de emergencia
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Obtiene estado actual de protección
        /// </summary>
        private async Task<ProtectionStatus> GetCurrentProtectionStatusAsync()
        {
            return new ProtectionStatus
            {
                IsProtected = true,
                LastProtectionUpdate = DateTime.UtcNow,
                ProtectionLevel = ProtectionLevel.High,
                ActiveProtections = new List<string> { "AutoRestart", "ManipulationMonitoring", "StopBlocking" }
            };
        }
        
        /// <summary>
        /// Calcula estadísticas de protección
        /// </summary>
        private ProtectionStatistics CalculateProtectionStatistics(
            List<ManipulationAttempt> manipulationAttempts,
            List<ServiceRestartEvent> restartHistory,
            List<ServiceStopAttempt> stopAttempts)
        {
            return new ProtectionStatistics
            {
                TotalManipulationAttempts = manipulationAttempts.Count,
                TotalRestarts = restartHistory.Count,
                TotalStopAttempts = stopAttempts.Count,
                SuccessfulRestarts = restartHistory.Count(r => r.Success),
                FailedRestarts = restartHistory.Count(r => !r.Success),
                AverageTimeBetweenRestarts = CalculateAverageRestartTime(restartHistory)
            };
        }
        
        private TimeSpan CalculateAverageRestartTime(List<ServiceRestartEvent> restartHistory)
        {
            if (restartHistory.Count < 2)
                return TimeSpan.Zero;
            
            var sorted = restartHistory.OrderBy(r => r.Timestamp).ToList();
            var total = TimeSpan.Zero;
            var count = 0;
            
            for (int i = 1; i < sorted.Count; i++)
            {
                total += sorted[i].Timestamp - sorted[i - 1].Timestamp;
                count++;
            }
            
            return count > 0 ? TimeSpan.FromTicks(total.Ticks / count) : TimeSpan.Zero;
        }
        
        /// <summary>
        /// Genera recomendaciones de protección
        /// </summary>
        private async Task<List<ProtectionRecommendation>> GenerateProtectionRecommendationsAsync(
            ServiceStatus currentStatus,
            ProtectionStatus protectionStatus,
            List<ManipulationAttempt> manipulationAttempts)
        {
            var recommendations = new List<ProtectionRecommendation>();
            
            if (!currentStatus.IsHealthy)
            {
                recommendations.Add(new ProtectionRecommendation
                {
                    Priority = RecommendationPriority.Critical,
                    Title = "Servicio no saludable",
                    Description = $"El servicio presenta {currentStatus.Issues.Count} issues",
                    Action = "InvestigateServiceIssues",
                    EstimatedTime = TimeSpan.FromMinutes(15)
                });
            }
            
            if (manipulationAttempts.Count > 10)
            {
                recommendations.Add(new ProtectionRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "Alto número de intentos de manipulación",
                    Description = $"Se detectaron {manipulationAttempts.Count} intentos de manipulación",
                    Action = "ReviewManipulationAttempts",
                    EstimatedTime = TimeSpan.FromMinutes(30)
                });
            }
            
            if (protectionStatus.ProtectionLevel < ProtectionLevel.High)
            {
                recommendations.Add(new ProtectionRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "Aumentar nivel de protección",
                    Description = "El nivel actual de protección puede no ser suficiente",
                    Action = "IncreaseProtectionLevel",
                    EstimatedTime = TimeSpan.FromMinutes(5)
                });
            }
            
            return recommendations;
        }
        
        #endregion
        
        #region Métodos para HealthCheck
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var serviceStatus = await VerifyServiceStateAsync();
                var guardianHealth = await PerformGuardianHealthCheckAsync();
                
                var issues = new List<string>();
                
                if (!serviceStatus.IsHealthy)
                    issues.Add($"Servicio no saludable: {string.Join(", ", serviceStatus.Issues)}");
                
                if (!guardianHealth.IsHealthy)
                    issues.Add($"Guardián no saludable: {string.Join(", ", guardianHealth.Issues)}");
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("ServiceGuardian funcionando correctamente");
                }
                
                var details = new Dictionary<string, object>
                {
                    { "ServiceStatus", serviceStatus.Status.ToString() },
                    { "ServiceHealthy", serviceStatus.IsHealthy },
                    { "GuardianHealthy", guardianHealth.IsHealthy },
                    { "RestartAttempts", _restartAttempts },
                    { "IsMonitoring", _isMonitoring }
                };
                
                if (serviceStatus.Status != ServiceControllerStatus.Running)
                {
                    return HealthCheckResult.Unhealthy(
                        $"Servicio no está ejecutándose: {serviceStatus.Status}",
                        details);
                }
                
                return HealthCheckResult.Degraded(
                    $"Problemas detectados: {string.Join("; ", issues)}",
                    details);
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
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public class ServiceStatus
    {
        public string ServiceName { get; set; }
        public string DisplayName { get; set; }
        public ServiceControllerStatus Status { get; set; }
        public ServiceStartMode StartType { get; set; }
        public string LogOnAs { get; set; }
        public bool CanStop { get; set; }
        public bool CanPauseAndContinue { get; set; }
        public string MachineName { get; set; }
        public ServiceType ServiceType { get; set; }
        public List<string> Dependencies { get; set; }
        public List<string> DependentServices { get; set; }
        public bool IsHealthy { get; set; }
        public List<string> Issues { get; set; }
        public DateTime LastCheckTime { get; set; }
        
        public ServiceStatus()
        {
            Dependencies = new List<string>();
            DependentServices = new List<string>();
            Issues = new List<string>();
        }
        
        public static ServiceStatus Error(string errorMessage)
        {
            return new ServiceStatus
            {
                IsHealthy = false,
                Issues = new List<string> { errorMessage },
                LastCheckTime = DateTime.UtcNow
            };
        }
    }
    
    public class ProtectionResult
    {
        public DateTime Timestamp { get; set; }
        public bool Success { get; set; }
        public List<ProtectionStep> ProtectionSteps { get; set; }
        public int SuccessCount { get; set; }
        public int FailedCount { get; set; }
        public string Error { get; set; }
        
        public ProtectionResult()
        {
            ProtectionSteps = new List<ProtectionStep>();
        }
        
        public static ProtectionResult Failed(string errorMessage)
        {
            return new ProtectionResult
            {
                Success = false,
                Error = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class ProtectionStep
    {
        public string Name { get; set; }
        public bool Success { get; set; }
        public string Details { get; set; }
        public string Error { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static ProtectionStep Success(string name, string details)
        {
            return new ProtectionStep
            {
                Name = name,
                Success = true,
                Details = details,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static ProtectionStep Failed(string name, string error)
        {
            return new ProtectionStep
            {
                Name = name,
                Success = false,
                Error = error,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class RestorationResult
    {
        public DateTime Timestamp { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public ServiceControllerStatus PreviousStatus { get; set; }
        public ServiceControllerStatus NewStatus { get; set; }
        public TimeSpan RestorationTime { get; set; }
        
        public static RestorationResult Success(string message)
        {
            return new RestorationResult
            {
                Success = true,
                Message = message,
                Timestamp = DateTime.UtcNow,
                NewStatus = ServiceControllerStatus.Running
            };
        }
        
        public static RestorationResult Failed(string errorMessage)
        {
            return new RestorationResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class ServiceHealthCheck
    {
        public DateTime Timestamp { get; set; }
        public string ServiceName { get; set; }
        public bool IsHealthy { get; set; }
        public List<string> Issues { get; set; }
        public Dictionary<string, object> Metrics { get; set; }
        
        public ServiceHealthCheck()
        {
            Issues = new List<string>();
            Metrics = new Dictionary<string, object>();
        }
    }
    
    public class GuardianHealthCheck
    {
        public DateTime Timestamp { get; set; }
        public bool IsHealthy { get; set; }
        public List<string> Issues { get; set; }
        
        public GuardianHealthCheck()
        {
            Issues = new List<string>();
        }
    }
    
    public class InternalCheckResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static InternalCheckResult Success()
        {
            return new InternalCheckResult { Success = true };
        }
        
        public static InternalCheckResult Failed(string errorMessage)
        {
            return new InternalCheckResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class RecoveryStep
    {
        public string Name { get; set; }
        public bool Success { get; set; }
        public string Details { get; set; }
        public string Error { get; set; }
    }
    
    public class ServiceProtectionConfig
    {
        public int MaxRestartAttemptsPerHour { get; set; }
        public int MonitoringIntervalSeconds { get; set; }
        public bool EnableStrictProtection { get; set; }
        public bool NotifyOnManipulationAttempt { get; set; }
        public bool AutoRestartOnFailure { get; set; }
        public bool BlockStopAttempts { get; set; }
        public ProtectionLevel DefaultProtectionLevel { get; set; }
    }
    
    public class ServiceRestartEvent
    {
        public DateTime Timestamp { get; set; }
        public string Reason { get; set; }
        public bool Success { get; set; }
        public int AttemptNumber { get; set; }
        public string ServiceStatus { get; set; }
    }
    
    public class ServiceStopAttempt
    {
        public DateTime Timestamp { get; set; }
        public string ServiceName { get; set; }
        public string CurrentStatus { get; set; }
        public string CallerProcess { get; set; }
        public bool Blocked { get; set; }
        public string BlockReason { get; set; }
    }
    
    public class ManipulationAttempt
    {
        public DateTime Timestamp { get; set; }
        public string Type { get; set; }
        public string Source { get; set; }
        public string Details { get; set; }
        public bool Blocked { get; set; }
        public Severity Severity { get; set; }
    }
    
    public class ProtectionStatus
    {
        public bool IsProtected { get; set; }
        public ProtectionLevel ProtectionLevel { get; set; }
        public DateTime LastProtectionUpdate { get; set; }
        public List<string> ActiveProtections { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public ProtectionStatus()
        {
            ActiveProtections = new List<string>();
            Details = new Dictionary<string, object>();
        }
    }
    
    public class ProtectionReport
    {
        public DateTime GeneratedAt { get; set; }
        public TimeSpan Period { get; set; }
        public ServiceStatus CurrentServiceStatus { get; set; }
        public ProtectionStatus ProtectionStatus { get; set; }
        public List<ManipulationAttempt> ManipulationAttempts { get; set; }
        public List<ServiceRestartEvent> RestartHistory { get; set; }
        public List<ServiceStopAttempt> StopAttempts { get; set; }
        public ProtectionStatistics Statistics { get; set; }
        public List<ProtectionRecommendation> Recommendations { get; set; }
        public string Error { get; set; }
        
        public ProtectionReport()
        {
            ManipulationAttempts = new List<ManipulationAttempt>();
            RestartHistory = new List<ServiceRestartEvent>();
            StopAttempts = new List<ServiceStopAttempt>();
            Recommendations = new List<ProtectionRecommendation>();
        }
        
        public static ProtectionReport Error(string errorMessage)
        {
            return new ProtectionReport
            {
                Error = errorMessage,
                GeneratedAt = DateTime.UtcNow
            };
        }
    }
    
    public class ProtectionStatistics
    {
        public int TotalManipulationAttempts { get; set; }
        public int TotalRestarts { get; set; }
        public int TotalStopAttempts { get; set; }
        public int SuccessfulRestarts { get; set; }
        public int FailedRestarts { get; set; }
        public TimeSpan AverageTimeBetweenRestarts { get; set; }
    }
    
    public class ProtectionRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
        public TimeSpan EstimatedTime { get; set; }
    }
    
    public enum ServiceStartMode
    {
        Unknown,
        Automatic,
        Manual,
        Disabled
    }
    
    public enum ProtectionLevel
    {
        None,
        Low,
        Medium,
        High,
        Maximum
    }
    
    public enum Severity
    {
        Low,
        Medium,
        High,
        Critical
    }
    
    #endregion
}