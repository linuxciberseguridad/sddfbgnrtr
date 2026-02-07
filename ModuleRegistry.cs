using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Agent.Core
{
    /// <summary>
    /// Registro centralizado de módulos del agente
    /// Permite habilitar/deshabilitar módulos dinámicamente
    /// </summary>
    public sealed class ModuleRegistry : IModuleRegistry
    {
        private static readonly Lazy<ModuleRegistry> _instance = 
            new Lazy<ModuleRegistry>(() => new ModuleRegistry());
        
        public static ModuleRegistry Instance => _instance.Value;
        
        private readonly ConcurrentDictionary<string, ModuleEntry> _modules;
        private readonly ConcurrentDictionary<ModuleType, List<string>> _modulesByType;
        private readonly LogManager _logManager;
        private readonly object _lock = new object();
        
        private ModuleRegistry()
        {
            _modules = new ConcurrentDictionary<string, ModuleEntry>();
            _modulesByType = new ConcurrentDictionary<ModuleType, List<string>>();
            _logManager = LogManager.Instance;
            
            InitializeModuleTypes();
        }
        
        private void InitializeModuleTypes()
        {
            foreach (ModuleType type in Enum.GetValues(typeof(ModuleType)))
            {
                _modulesByType[type] = new List<string>();
            }
        }
        
        /// <summary>
        /// Registra un módulo en el sistema
        /// </summary>
        public async Task<bool> RegisterModuleAsync(IAgentModule module, ModuleType type)
        {
            if (module == null)
                throw new ArgumentNullException(nameof(module));
            
            var moduleId = module.ModuleId;
            
            if (_modules.ContainsKey(moduleId))
            {
                _logManager.LogWarning($"Módulo ya registrado: {moduleId}", nameof(ModuleRegistry));
                return false;
            }
            
            try
            {
                var entry = new ModuleEntry
                {
                    Module = module,
                    ModuleId = moduleId,
                    Type = type,
                    Status = ModuleStatus.Registered,
                    RegistrationTime = DateTime.UtcNow,
                    IsEnabled = true
                };
                
                // Inicializar módulo
                var initResult = await module.InitializeAsync();
                if (!initResult.Success)
                {
                    _logManager.LogError($"Error al inicializar módulo {moduleId}: {initResult.ErrorMessage}", 
                        nameof(ModuleRegistry));
                    return false;
                }
                
                // Registrar en diccionarios
                if (_modules.TryAdd(moduleId, entry))
                {
                    _modulesByType[type].Add(moduleId);
                    
                    _logManager.LogInfo($"Módulo registrado: {moduleId} ({type})", nameof(ModuleRegistry));
                    
                    // Si el módulo implementa IHealthCheckable, registrarlo en HealthMonitor
                    if (module is IHealthCheckable healthCheckable)
                    {
                        HealthMonitor.Instance.RegisterHealthCheck(moduleId, 
                            () => healthCheckable.CheckHealthAsync());
                    }
                    
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al registrar módulo {moduleId}: {ex}", nameof(ModuleRegistry));
                return false;
            }
        }
        
        /// <summary>
        /// Desregistra un módulo del sistema
        /// </summary>
        public async Task<bool> UnregisterModuleAsync(string moduleId)
        {
            if (!_modules.TryRemove(moduleId, out var entry))
            {
                _logManager.LogWarning($"Módulo no encontrado: {moduleId}", nameof(ModuleRegistry));
                return false;
            }
            
            try
            {
                // Detener módulo si está en ejecución
                if (entry.Status == ModuleStatus.Running)
                {
                    await entry.Module.StopAsync();
                }
                
                // Eliminar de módulos por tipo
                if (_modulesByType.TryGetValue(entry.Type, out var typeList))
                {
                    lock (_lock)
                    {
                        typeList.Remove(moduleId);
                    }
                }
                
                // Eliminar de HealthMonitor
                HealthMonitor.Instance.UnregisterHealthCheck(moduleId);
                
                _logManager.LogInfo($"Módulo desregistrado: {moduleId}", nameof(ModuleRegistry));
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al desregistrar módulo {moduleId}: {ex}", nameof(ModuleRegistry));
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene un módulo por su ID
        /// </summary>
        public T GetModule<T>(string moduleId = null) where T : class, IAgentModule
        {
            if (moduleId != null)
            {
                if (_modules.TryGetValue(moduleId, out var entry) && entry.Module is T module)
                {
                    return module;
                }
                return null;
            }
            
            // Buscar primer módulo del tipo T
            var foundEntry = _modules.Values.FirstOrDefault(e => e.Module is T);
            return foundEntry?.Module as T;
        }
        
        /// <summary>
        /// Obtiene todos los módulos de un tipo específico
        /// </summary>
        public List<T> GetModules<T>(ModuleType? type = null) where T : class, IAgentModule
        {
            var result = new List<T>();
            
            if (type.HasValue)
            {
                if (_modulesByType.TryGetValue(type.Value, out var moduleIds))
                {
                    foreach (var moduleId in moduleIds)
                    {
                        if (_modules.TryGetValue(moduleId, out var entry) && entry.Module is T module)
                        {
                            result.Add(module);
                        }
                    }
                }
            }
            else
            {
                foreach (var entry in _modules.Values)
                {
                    if (entry.Module is T module)
                    {
                        result.Add(module);
                    }
                }
            }
            
            return result;
        }
        
        /// <summary>
        /// Habilita o deshabilita un módulo
        /// </summary>
        public async Task<bool> SetModuleEnabledAsync(string moduleId, bool enabled)
        {
            if (!_modules.TryGetValue(moduleId, out var entry))
            {
                _logManager.LogWarning($"Módulo no encontrado: {moduleId}", nameof(ModuleRegistry));
                return false;
            }
            
            if (entry.IsEnabled == enabled)
                return true;
            
            try
            {
                if (enabled)
                {
                    // Habilitar módulo
                    var startResult = await entry.Module.StartAsync();
                    if (startResult.Success)
                    {
                        entry.IsEnabled = true;
                        entry.Status = ModuleStatus.Running;
                        _logManager.LogInfo($"Módulo habilitado: {moduleId}", nameof(ModuleRegistry));
                        return true;
                    }
                    else
                    {
                        _logManager.LogError($"Error al habilitar módulo {moduleId}: {startResult.ErrorMessage}", 
                            nameof(ModuleRegistry));
                        return false;
                    }
                }
                else
                {
                    // Deshabilitar módulo
                    var stopResult = await entry.Module.StopAsync();
                    if (stopResult.Success)
                    {
                        entry.IsEnabled = false;
                        entry.Status = ModuleStatus.Stopped;
                        _logManager.LogInfo($"Módulo deshabilitado: {moduleId}", nameof(ModuleRegistry));
                        return true;
                    }
                    else
                    {
                        _logManager.LogError($"Error al deshabilitar módulo {moduleId}: {stopResult.ErrorMessage}", 
                            nameof(ModuleRegistry));
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cambiar estado de módulo {moduleId}: {ex}", nameof(ModuleRegistry));
                return false;
            }
        }
        
        /// <summary>
        /// Inicia todos los módulos de un tipo específico
        /// </summary>
        public async Task StartAllModulesAsync(ModuleType type)
        {
            if (!_modulesByType.TryGetValue(type, out var moduleIds))
                return;
            
            var tasks = new List<Task>();
            
            foreach (var moduleId in moduleIds)
            {
                if (_modules.TryGetValue(moduleId, out var entry) && !entry.IsEnabled)
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            await SetModuleEnabledAsync(moduleId, true);
                        }
                        catch (Exception ex)
                        {
                            _logManager.LogError($"Error al iniciar módulo {moduleId}: {ex}", nameof(ModuleRegistry));
                        }
                    }));
                }
            }
            
            await Task.WhenAll(tasks);
        }
        
        /// <summary>
        /// Detiene todos los módulos
        /// </summary>
        public async Task StopAllModulesAsync()
        {
            var tasks = new List<Task>();
            
            foreach (var entry in _modules.Values)
            {
                if (entry.IsEnabled)
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            await entry.Module.StopAsync();
                            entry.IsEnabled = false;
                            entry.Status = ModuleStatus.Stopped;
                        }
                        catch (Exception ex)
                        {
                            _logManager.LogError($"Error al detener módulo {entry.ModuleId}: {ex}", 
                                nameof(ModuleRegistry));
                        }
                    }));
                }
            }
            
            await Task.WhenAll(tasks);
        }
        
        /// <summary>
        /// Obtiene el estado de un módulo
        /// </summary>
        public ModuleStatus GetModuleStatus(string moduleId)
        {
            if (_modules.TryGetValue(moduleId, out var entry))
            {
                return entry.Status;
            }
            
            return ModuleStatus.NotFound;
        }
        
        /// <summary>
        /// Obtiene información detallada de un módulo
        /// </summary>
        public ModuleInfo GetModuleInfo(string moduleId)
        {
            if (!_modules.TryGetValue(moduleId, out var entry))
            {
                return null;
            }
            
            return new ModuleInfo
            {
                ModuleId = entry.ModuleId,
                Type = entry.Type,
                Status = entry.Status,
                IsEnabled = entry.IsEnabled,
                RegistrationTime = entry.RegistrationTime,
                LastActivity = entry.LastActivity,
                Version = entry.Module.Version,
                Description = entry.Module.Description
            };
        }
        
        /// <summary>
        /// Obtiene reporte de estado de todos los módulos
        /// </summary>
        public async Task<string> GetStatusReportAsync()
        {
            var report = new
            {
                Timestamp = DateTime.UtcNow,
                TotalModules = _modules.Count,
                ModulesByType = _modulesByType.ToDictionary(
                    kvp => kvp.Key.ToString(),
                    kvp => new
                    {
                        Count = kvp.Value.Count,
                        ModuleIds = kvp.Value
                    }),
                ModuleDetails = _modules.Values.Select(entry => new
                {
                    entry.ModuleId,
                    Type = entry.Type.ToString(),
                    Status = entry.Status.ToString(),
                    entry.IsEnabled,
                    Uptime = DateTime.UtcNow - entry.RegistrationTime,
                    entry.Module.Version,
                    Health = GetModuleHealthStatus(entry.ModuleId)
                }).ToList()
            };
            
            return SerializationHelper.ToJson(report, true);
        }
        
        /// <summary>
        /// Obtiene el estado de salud de un módulo
        /// </summary>
        private string GetModuleHealthStatus(string moduleId)
        {
            try
            {
                var healthResult = HealthMonitor.Instance.GetModuleHealth(moduleId);
                return healthResult?.Status.ToString() ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }
        
        /// <summary>
        /// Obtiene el número total de módulos registrados
        /// </summary>
        public int GetModuleCount()
        {
            return _modules.Count;
        }
        
        /// <summary>
        /// Verifica si un módulo está registrado y habilitado
        /// </summary>
        public bool IsModuleActive(string moduleId)
        {
            return _modules.TryGetValue(moduleId, out var entry) && 
                   entry.IsEnabled && 
                   entry.Status == ModuleStatus.Running;
        }
        
        /// <summary>
        /// Actualiza la última actividad de un módulo
        /// </summary>
        public void UpdateModuleActivity(string moduleId)
        {
            if (_modules.TryGetValue(moduleId, out var entry))
            {
                entry.LastActivity = DateTime.UtcNow;
            }
        }
        
        /// <summary>
        /// Reinicia un módulo específico
        /// </summary>
        public async Task<bool> RestartModuleAsync(string moduleId)
        {
            if (!_modules.TryGetValue(moduleId, out var entry))
                return false;
            
            try
            {
                _logManager.LogInfo($"Reiniciando módulo: {moduleId}", nameof(ModuleRegistry));
                
                // Detener módulo
                await entry.Module.StopAsync();
                
                // Pequeña pausa
                await Task.Delay(1000);
                
                // Iniciar módulo
                var startResult = await entry.Module.StartAsync();
                
                if (startResult.Success)
                {
                    entry.Status = ModuleStatus.Running;
                    entry.IsEnabled = true;
                    _logManager.LogInfo($"Módulo reiniciado: {moduleId}", nameof(ModuleRegistry));
                    return true;
                }
                
                _logManager.LogError($"Error al reiniciar módulo {moduleId}: {startResult.ErrorMessage}", 
                    nameof(ModuleRegistry));
                return false;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al reiniciar módulo {moduleId}: {ex}", nameof(ModuleRegistry));
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene módulos con problemas de salud
        /// </summary>
        public async Task<List<string>> GetUnhealthyModulesAsync()
        {
            var unhealthyModules = new List<string>();
            
            foreach (var moduleId in _modules.Keys)
            {
                var health = await HealthMonitor.Instance.CheckModuleHealthAsync(moduleId);
                if (health != null && health.Status != HealthStatus.Healthy)
                {
                    unhealthyModules.Add(moduleId);
                }
            }
            
            return unhealthyModules;
        }
        
        #region Clases internas
        private class ModuleEntry
        {
            public string ModuleId { get; set; }
            public IAgentModule Module { get; set; }
            public ModuleType Type { get; set; }
            public ModuleStatus Status { get; set; }
            public bool IsEnabled { get; set; }
            public DateTime RegistrationTime { get; set; }
            public DateTime? LastActivity { get; set; }
        }
        #endregion
    }
    
    #region Interfaces y clases relacionadas
    public interface IModuleRegistry
    {
        Task<bool> RegisterModuleAsync(IAgentModule module, ModuleType type);
        Task<bool> UnregisterModuleAsync(string moduleId);
        T GetModule<T>(string moduleId = null) where T : class, IAgentModule;
        List<T> GetModules<T>(ModuleType? type = null) where T : class, IAgentModule;
        Task<bool> SetModuleEnabledAsync(string moduleId, bool enabled);
        Task StartAllModulesAsync(ModuleType type);
        Task StopAllModulesAsync();
        ModuleStatus GetModuleStatus(string moduleId);
        ModuleInfo GetModuleInfo(string moduleId);
        Task<string> GetStatusReportAsync();
        int GetModuleCount();
        bool IsModuleActive(string moduleId);
        void UpdateModuleActivity(string moduleId);
        Task<bool> RestartModuleAsync(string moduleId);
        Task<List<string>> GetUnhealthyModulesAsync();
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
    
    public enum ModuleStatus
    {
        Unknown,
        Registered,
        Initialized,
        Running,
        Paused,
        Stopped,
        Error,
        NotFound
    }
    
    public class ModuleInfo
    {
        public string ModuleId { get; set; }
        public ModuleType Type { get; set; }
        public ModuleStatus Status { get; set; }
        public bool IsEnabled { get; set; }
        public DateTime RegistrationTime { get; set; }
        public DateTime? LastActivity { get; set; }
        public string Version { get; set; }
        public string Description { get; set; }
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
                Message = message ?? "Module is healthy",
                CheckTime = DateTime.UtcNow,
                Details = new Dictionary<string, object>()
            };
        }
        
        public static HealthCheckResult Unhealthy(string message, Dictionary<string, object> details = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Unhealthy,
                Message = message,
                CheckTime = DateTime.UtcNow,
                Details = details ?? new Dictionary<string, object>()
            };
        }
        
        public static HealthCheckResult Degraded(string message, Dictionary<string, object> details = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Degraded,
                Message = message,
                CheckTime = DateTime.UtcNow,
                Details = details ?? new Dictionary<string, object>()
            };
        }
    }
    
    public enum HealthStatus
    {
        Healthy,
        Degraded,
        Unhealthy,
        Unknown
    }
    #endregion
}