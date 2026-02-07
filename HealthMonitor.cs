using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Telemetry;

namespace BWP.Enterprise.Agent.Core
{
    /// <summary>
    /// Monitor de salud del sistema
    /// Monitorea que los sensores y motores estén activos
    /// Envía alertas al cloud si algún módulo falla
    /// </summary>
    public sealed class HealthMonitor : IHealthMonitor
    {
        private static readonly Lazy<HealthMonitor> _instance = 
            new Lazy<HealthMonitor>(() => new HealthMonitor());
        
        public static HealthMonitor Instance => _instance.Value;
        
        private readonly ConcurrentDictionary<string, HealthCheckInfo> _healthChecks;
        private readonly ConcurrentDictionary<string, ModuleHealthHistory> _healthHistory;
        private readonly LogManager _logManager;
        private readonly TelemetryQueue _telemetryQueue;
        private Timer _monitoringTimer;
        private Timer _reportingTimer;
        private bool _isMonitoring;
        private readonly object _lock = new object();
        private const int MONITORING_INTERVAL_MS = 30000; // 30 segundos
        private const int REPORTING_INTERVAL_MS = 60000; // 1 minuto
        private const int MAX_HEALTH_HISTORY = 1000;
        
        private HealthMonitor()
        {
            _healthChecks = new ConcurrentDictionary<string, HealthCheckInfo>();
            _healthHistory = new ConcurrentDictionary<string, ModuleHealthHistory>();
            _logManager = LogManager.Instance;
            _telemetryQueue = TelemetryQueue.Instance;
            _isMonitoring = false;
        }
        
        /// <summary>
        /// Inicia el monitoreo de salud
        /// </summary>
        public void StartMonitoring()
        {
            lock (_lock)
            {
                if (_isMonitoring)
                    return;
                
                try
                {
                    _monitoringTimer = new Timer(
                        MonitorHealthCallback,
                        null,
                        TimeSpan.Zero,
                        TimeSpan.FromMilliseconds(MONITORING_INTERVAL_MS));
                    
                    _reportingTimer = new Timer(
                        ReportHealthCallback,
                        null,
                        TimeSpan.FromSeconds(30),
                        TimeSpan.FromMilliseconds(REPORTING_INTERVAL_MS));
                    
                    _isMonitoring = true;
                    _logManager.LogInfo("HealthMonitor iniciado", nameof(HealthMonitor));
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al iniciar HealthMonitor: {ex}", nameof(HealthMonitor));
                }
            }
        }
        
        /// <summary>
        /// Detiene el monitoreo de salud
        /// </summary>
        public void StopMonitoring()
        {
            lock (_lock)
            {
                if (!_isMonitoring)
                    return;
                
                try
                {
                    _monitoringTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                    _reportingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                    
                    _monitoringTimer?.Dispose();
                    _reportingTimer?.Dispose();
                    
                    _isMonitoring = false;
                    _logManager.LogInfo("HealthMonitor detenido", nameof(HealthMonitor));
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al detener HealthMonitor: {ex}", nameof(HealthMonitor));
                }
            }
        }
        
        /// <summary>
        /// Registra una función de verificación de salud para un módulo
        /// </summary>
        public void RegisterHealthCheck(string moduleId, Func<Task<HealthCheckResult>> healthCheckFunc)
        {
            if (string.IsNullOrEmpty(moduleId))
                throw new ArgumentNullException(nameof(moduleId));
            
            if (healthCheckFunc == null)
                throw new ArgumentNullException(nameof(healthCheckFunc));
            
            var healthCheckInfo = new HealthCheckInfo
            {
                ModuleId = moduleId,
                HealthCheckFunc = healthCheckFunc,
                LastCheckTime = DateTime.UtcNow,
                LastResult = HealthCheckResult.Unknown(),
                FailureCount = 0,
                LastFailureTime = null
            };
            
            _healthChecks[moduleId] = healthCheckInfo;
            
            // Inicializar historial
            _healthHistory[moduleId] = new ModuleHealthHistory
            {
                ModuleId = moduleId,
                HealthHistory = new ConcurrentQueue<HealthHistoryEntry>()
            };
            
            _logManager.LogInfo($"HealthCheck registrado para módulo: {moduleId}", nameof(HealthMonitor));
        }
        
        /// <summary>
        /// Elimina el registro de verificación de salud de un módulo
        /// </summary>
        public void UnregisterHealthCheck(string moduleId)
        {
            _healthChecks.TryRemove(moduleId, out _);
            _healthHistory.TryRemove(moduleId, out _);
            
            _logManager.LogInfo($"HealthCheck eliminado para módulo: {moduleId}", nameof(HealthMonitor));
        }
        
        /// <summary>
        /// Verifica la salud de un módulo específico
        /// </summary>
        public async Task<HealthCheckResult> CheckModuleHealthAsync(string moduleId)
        {
            if (!_healthChecks.TryGetValue(moduleId, out var healthCheckInfo))
            {
                return HealthCheckResult.Unknown($"Módulo no registrado: {moduleId}");
            }
            
            try
            {
                var result = await healthCheckInfo.HealthCheckFunc();
                healthCheckInfo.LastResult = result;
                healthCheckInfo.LastCheckTime = DateTime.UtcNow;
                
                // Actualizar contador de fallos
                if (result.Status == HealthStatus.Unhealthy)
                {
                    healthCheckInfo.FailureCount++;
                    healthCheckInfo.LastFailureTime = DateTime.UtcNow;
                    
                    // Si es primera falla o ha pasado suficiente tiempo desde la última alerta
                    if (healthCheckInfo.FailureCount == 1 || 
                        (healthCheckInfo.LastAlertTime == null || 
                         (DateTime.UtcNow - healthCheckInfo.LastAlertTime.Value).TotalMinutes >= 5))
                    {
                        await SendHealthAlertAsync(moduleId, result);
                        healthCheckInfo.LastAlertTime = DateTime.UtcNow;
                    }
                }
                else if (result.Status == HealthStatus.Healthy)
                {
                    // Resetear contador si se recuperó
                    if (healthCheckInfo.FailureCount > 0)
                    {
                        _logManager.LogInfo($"Módulo recuperado: {moduleId}", nameof(HealthMonitor));
                        healthCheckInfo.FailureCount = 0;
                        healthCheckInfo.LastFailureTime = null;
                    }
                }
                
                // Guardar en historial
                AddToHealthHistory(moduleId, result);
                
                return result;
            }
            catch (Exception ex)
            {
                var errorResult = HealthCheckResult.Unhealthy($"Error en health check: {ex.Message}");
                healthCheckInfo.LastResult = errorResult;
                healthCheckInfo.FailureCount++;
                healthCheckInfo.LastFailureTime = DateTime.UtcNow;
                
                _logManager.LogError($"Error en health check para módulo {moduleId}: {ex}", nameof(HealthMonitor));
                
                return errorResult;
            }
        }
        
        /// <summary>
        /// Verifica la salud de todos los módulos registrados
        /// </summary>
        public async Task<SystemHealthReport> CheckAllModulesHealthAsync()
        {
            var tasks = new List<Task<KeyValuePair<string, HealthCheckResult>>>();
            
            foreach (var moduleId in _healthChecks.Keys)
            {
                tasks.Add(Task.Run(async () =>
                {
                    var result = await CheckModuleHealthAsync(moduleId);
                    return new KeyValuePair<string, HealthCheckResult>(moduleId, result);
                }));
            }
            
            await Task.WhenAll(tasks);
            
            var results = tasks.Select(t => t.Result).ToDictionary(kv => kv.Key, kv => kv.Value);
            
            var report = new SystemHealthReport
            {
                Timestamp = DateTime.UtcNow,
                TotalModules = results.Count,
                HealthyModules = results.Count(r => r.Value.Status == HealthStatus.Healthy),
                UnhealthyModules = results.Count(r => r.Value.Status == HealthStatus.Unhealthy),
                DegradedModules = results.Count(r => r.Value.Status == HealthStatus.Degraded),
                ModuleDetails = results.ToDictionary(
                    kv => kv.Key,
                    kv => new ModuleHealthDetail
                    {
                        Status = kv.Value.Status,
                        Message = kv.Value.Message,
                        LastCheckTime = _healthChecks[kv.Key].LastCheckTime,
                        FailureCount = _healthChecks[kv.Key].FailureCount
                    }),
                OverallStatus = CalculateOverallStatus(results.Values)
            };
            
            return report;
        }
        
        /// <summary>
        /// Obtiene el estado de salud actual de un módulo
        /// </summary>
        public HealthCheckResult GetModuleHealth(string moduleId)
        {
            if (_healthChecks.TryGetValue(moduleId, out var healthCheckInfo))
            {
                return healthCheckInfo.LastResult;
            }
            
            return HealthCheckResult.Unknown($"Módulo no encontrado: {moduleId}");
        }
        
        /// <summary>
        /// Obtiene el historial de salud de un módulo
        /// </summary>
        public List<HealthHistoryEntry> GetModuleHealthHistory(string moduleId, int maxEntries = 100)
        {
            if (!_healthHistory.TryGetValue(moduleId, out var history))
                return new List<HealthHistoryEntry>();
            
            return history.HealthHistory.Take(maxEntries).ToList();
        }
        
        /// <summary>
        /// Obtiene el estado general del sistema
        /// </summary>
        public SystemHealthStatus GetHealthStatus()
        {
            var now = DateTime.UtcNow;
            var unhealthyModules = new List<string>();
            var degradedModules = new List<string>();
            
            foreach (var kvp in _healthChecks)
            {
                var result = kvp.Value.LastResult;
                
                if (result.Status == HealthStatus.Unhealthy)
                {
                    unhealthyModules.Add(kvp.Key);
                }
                else if (result.Status == HealthStatus.Degraded)
                {
                    degradedModules.Add(kvp.Key);
                }
            }
            
            var overallStatus = HealthStatus.Healthy;
            
            if (unhealthyModules.Count > 0)
            {
                overallStatus = HealthStatus.Unhealthy;
            }
            else if (degradedModules.Count > 0)
            {
                overallStatus = HealthStatus.Degraded;
            }
            
            return new SystemHealthStatus
            {
                Timestamp = now,
                Status = overallStatus,
                UnhealthyModules = unhealthyModules,
                DegradedModules = degradedModules,
                TotalModules = _healthChecks.Count,
                HealthyModules = _healthChecks.Count - unhealthyModules.Count - degradedModules.Count
            };
        }
        
        /// <summary>
        /// Envía alerta de salud al sistema de telemetría
        /// </summary>
        private async Task SendHealthAlertAsync(string moduleId, HealthCheckResult result)
        {
            try
            {
                var alert = new HealthAlert
                {
                    AlertId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    ModuleId = moduleId,
                    Status = result.Status,
                    Message = result.Message,
                    Details = result.Details,
                    FailureCount = _healthChecks[moduleId].FailureCount
                };
                
                // Enviar a telemetría
                await _telemetryQueue.EnqueueHealthAlertAsync(alert);
                
                // Log local
                _logManager.LogWarning($"Alerta de salud: Módulo {moduleId} - {result.Status}: {result.Message}", 
                    nameof(HealthMonitor));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al enviar alerta de salud: {ex}", nameof(HealthMonitor));
            }
        }
        
        /// <summary>
        /// Añade entrada al historial de salud
        /// </summary>
        private void AddToHealthHistory(string moduleId, HealthCheckResult result)
        {
            if (!_healthHistory.TryGetValue(moduleId, out var history))
                return;
            
            var entry = new HealthHistoryEntry
            {
                Timestamp = DateTime.UtcNow,
                Status = result.Status,
                Message = result.Message,
                Details = result.Details
            };
            
            history.HealthHistory.Enqueue(entry);
            
            // Limitar tamaño del historial
            while (history.HealthHistory.Count > MAX_HEALTH_HISTORY)
            {
                history.HealthHistory.TryDequeue(out _);
            }
        }
        
        /// <summary>
        /// Callback del timer de monitoreo
        /// </summary>
        private async void MonitorHealthCallback(object state)
        {
            try
            {
                await CheckAllModulesHealthAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en MonitorHealthCallback: {ex}", nameof(HealthMonitor));
            }
        }
        
        /// <summary>
        /// Callback del timer de reportes
        /// </summary>
        private async void ReportHealthCallback(object state)
        {
            try
            {
                var healthStatus = GetHealthStatus();
                
                // Solo reportar si hay problemas o cada 10 reportes normales
                if (healthStatus.Status != HealthStatus.Healthy || 
                    DateTime.UtcNow.Minute % 10 == 0) // Reportar cada 10 minutos si todo está bien
                {
                    await SendHealthReportAsync(healthStatus);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en ReportHealthCallback: {ex}", nameof(HealthMonitor));
            }
        }
        
        /// <summary>
        /// Envía reporte de salud al cloud
        /// </summary>
        private async Task SendHealthReportAsync(SystemHealthStatus healthStatus)
        {
            try
            {
                var telemetryEvent = new TelemetryEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = "HealthReport",
                    Severity = healthStatus.Status == HealthStatus.Healthy ? "Info" : "Warning",
                    Data = new
                    {
                        healthStatus.Status,
                        healthStatus.HealthyModules,
                        healthStatus.UnhealthyModules,
                        healthStatus.DegradedModules,
                        healthStatus.TotalModules,
                        ModuleDetails = healthStatus.UnhealthyModules
                            .Concat(healthStatus.DegradedModules)
                            .ToDictionary(
                                m => m,
                                m => new
                                {
                                    Status = _healthChecks[m].LastResult.Status.ToString(),
                                    Message = _healthChecks[m].LastResult.Message,
                                    FailureCount = _healthChecks[m].FailureCount
                                })
                    }
                };
                
                await _telemetryQueue.EnqueueAsync(telemetryEvent);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al enviar reporte de salud: {ex}", nameof(HealthMonitor));
            }
        }
        
        /// <summary>
        /// Calcula el estado general del sistema
        /// </summary>
        private HealthStatus CalculateOverallStatus(IEnumerable<HealthCheckResult> results)
        {
            if (!results.Any())
                return HealthStatus.Unknown;
            
            if (results.Any(r => r.Status == HealthStatus.Unhealthy))
                return HealthStatus.Unhealthy;
            
            if (results.Any(r => r.Status == HealthStatus.Degraded))
                return HealthStatus.Degraded;
            
            if (results.All(r => r.Status == HealthStatus.Healthy))
                return HealthStatus.Healthy;
            
            return HealthStatus.Unknown;
        }
        
        /// <summary>
        /// Reinicia el contador de fallos de un módulo
        /// </summary>
        public void ResetFailureCount(string moduleId)
        {
            if (_healthChecks.TryGetValue(moduleId, out var healthCheckInfo))
            {
                healthCheckInfo.FailureCount = 0;
                healthCheckInfo.LastFailureTime = null;
                _logManager.LogInfo($"Contador de fallos reiniciado para módulo: {moduleId}", nameof(HealthMonitor));
            }
        }
        
        /// <summary>
        /// Obtiene módulos con problemas crónicos
        /// </summary>
        public List<ChronicHealthIssue> GetChronicHealthIssues(int minFailureCount = 3)
        {
            var issues = new List<ChronicHealthIssue>();
            
            foreach (var kvp in _healthChecks)
            {
                if (kvp.Value.FailureCount >= minFailureCount && 
                    kvp.Value.LastFailureTime.HasValue &&
                    (DateTime.UtcNow - kvp.Value.LastFailureTime.Value).TotalHours < 24)
                {
                    issues.Add(new ChronicHealthIssue
                    {
                        ModuleId = kvp.Key,
                        FailureCount = kvp.Value.FailureCount,
                        LastFailureTime = kvp.Value.LastFailureTime.Value,
                        LastErrorMessage = kvp.Value.LastResult.Message
                    });
                }
            }
            
            return issues;
        }
        
        #region Clases internas
        private class HealthCheckInfo
        {
            public string ModuleId { get; set; }
            public Func<Task<HealthCheckResult>> HealthCheckFunc { get; set; }
            public DateTime LastCheckTime { get; set; }
            public HealthCheckResult LastResult { get; set; }
            public int FailureCount { get; set; }
            public DateTime? LastFailureTime { get; set; }
            public DateTime? LastAlertTime { get; set; }
        }
        
        private class ModuleHealthHistory
        {
            public string ModuleId { get; set; }
            public ConcurrentQueue<HealthHistoryEntry> HealthHistory { get; set; }
        }
        #endregion
    }
    
    #region Clases y estructuras de datos
    public interface IHealthMonitor
    {
        void StartMonitoring();
        void StopMonitoring();
        void RegisterHealthCheck(string moduleId, Func<Task<HealthCheckResult>> healthCheckFunc);
        void UnregisterHealthCheck(string moduleId);
        Task<HealthCheckResult> CheckModuleHealthAsync(string moduleId);
        Task<SystemHealthReport> CheckAllModulesHealthAsync();
        HealthCheckResult GetModuleHealth(string moduleId);
        List<HealthHistoryEntry> GetModuleHealthHistory(string moduleId, int maxEntries = 100);
        SystemHealthStatus GetHealthStatus();
        void ResetFailureCount(string moduleId);
        List<ChronicHealthIssue> GetChronicHealthIssues(int minFailureCount = 3);
    }
    
    public class SystemHealthReport
    {
        public DateTime Timestamp { get; set; }
        public int TotalModules { get; set; }
        public int HealthyModules { get; set; }
        public int UnhealthyModules { get; set; }
        public int DegradedModules { get; set; }
        public HealthStatus OverallStatus { get; set; }
        public Dictionary<string, ModuleHealthDetail> ModuleDetails { get; set; }
    }
    
    public class ModuleHealthDetail
    {
        public HealthStatus Status { get; set; }
        public string Message { get; set; }
        public DateTime LastCheckTime { get; set; }
        public int FailureCount { get; set; }
    }
    
    public class SystemHealthStatus
    {
        public DateTime Timestamp { get; set; }
        public HealthStatus Status { get; set; }
        public List<string> UnhealthyModules { get; set; }
        public List<string> DegradedModules { get; set; }
        public int TotalModules { get; set; }
        public int HealthyModules { get; set; }
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
    
    public class HealthHistoryEntry
    {
        public DateTime Timestamp { get; set; }
        public HealthStatus Status { get; set; }
        public string Message { get; set; }
        public Dictionary<string, object> Details { get; set; }
    }
    
    public class ChronicHealthIssue
    {
        public string ModuleId { get; set; }
        public int FailureCount { get; set; }
        public DateTime LastFailureTime { get; set; }
        public string LastErrorMessage { get; set; }
    }
    
    public static class HealthCheckResultExtensions
    {
        public static HealthCheckResult Unknown(this HealthCheckResult result, string message = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Unknown,
                Message = message ?? "Status unknown",
                CheckTime = DateTime.UtcNow,
                Details = new Dictionary<string, object>()
            };
        }
        
        public static HealthCheckResult Healthy(this HealthCheckResult result, string message = null)
        {
            return HealthCheckResult.Healthy(message);
        }
        
        public static HealthCheckResult Unhealthy(this HealthCheckResult result, string message, Dictionary<string, object> details = null)
        {
            return HealthCheckResult.Unhealthy(message, details);
        }
        
        public static HealthCheckResult Degraded(this HealthCheckResult result, string message, Dictionary<string, object> details = null)
        {
            return HealthCheckResult.Degraded(message, details);
        }
    }
    #endregion
}