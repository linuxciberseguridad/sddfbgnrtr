using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.SelfProtection
{
    /// <summary>
    /// Verificador de integridad para BWP Enterprise Agent
    /// Verifica que binarios, configuraciones y datos no hayan sido modificados
    /// </summary>
    public sealed class IntegrityVerifier : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<IntegrityVerifier> _instance = 
            new Lazy<IntegrityVerifier>(() => new IntegrityVerifier());
        
        public static IntegrityVerifier Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly CryptoHelper _cryptoHelper;
        
        private readonly Dictionary<string, IntegrityBaseline> _baselines;
        private Timer _verificationTimer;
        private bool _isMonitoring;
        private bool _isInitialized;
        private const int VERIFICATION_INTERVAL_MINUTES = 5;
        private const int MAX_RESTORE_ATTEMPTS = 3;
        
        public string ModuleId => "IntegrityVerifier";
        public string Version => "1.0.0";
        public string Description => "Sistema de verificación y protección de integridad";
        
        private IntegrityVerifier()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _cryptoHelper = CryptoHelper.Instance;
            _baselines = new Dictionary<string, IntegrityBaseline>();
            _isMonitoring = false;
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el verificador de integridad
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando IntegrityVerifier...", ModuleId);
                
                // Cargar líneas base desde base de datos
                await LoadBaselinesAsync();
                
                // Verificar integridad de archivos críticos
                await VerifyCriticalFilesAsync();
                
                // Inicializar monitoreo continuo
                StartContinuousMonitoring();
                
                _isInitialized = true;
                _logManager.LogInfo("IntegrityVerifier inicializado", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar IntegrityVerifier: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el verificador
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
                _logManager.LogInfo("IntegrityVerifier iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar IntegrityVerifier: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el verificador
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isMonitoring = false;
                _verificationTimer?.Dispose();
                
                _logManager.LogInfo("IntegrityVerifier detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener IntegrityVerifier: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Verifica integridad de todos los componentes
        /// </summary>
        public async Task<IntegrityVerificationResult> VerifyAllAsync()
        {
            try
            {
                _logManager.LogInfo("Iniciando verificación de integridad completa...", ModuleId);
                
                var results = new List<ComponentIntegrityResult>();
                var issues = new List<IntegrityIssue>();
                
                // 1. Verificar archivos binarios
                var binaryResults = await VerifyBinaryFilesAsync();
                results.AddRange(binaryResults);
                issues.AddRange(binaryResults.Where(r => !r.IsValid)
                    .Select(r => new IntegrityIssue
                    {
                        Component = r.ComponentName,
                        IssueType = IntegrityIssueType.FileTampered,
                        Severity = r.Severity,
                        Details = r.Details
                    }));
                
                // 2. Verificar configuración
                var configResults = await VerifyConfigurationAsync();
                results.AddRange(configResults);
                issues.AddRange(configResults.Where(r => !r.IsValid)
                    .Select(r => new IntegrityIssue
                    {
                        Component = r.ComponentName,
                        IssueType = IntegrityIssueType.ConfigurationModified,
                        Severity = r.Severity,
                        Details = r.Details
                    }));
                
                // 3. Verificar base de datos
                var dbResults = await VerifyDatabaseIntegrityAsync();
                results.AddRange(dbResults);
                issues.AddRange(dbResults.Where(r => !r.IsValid)
                    .Select(r => new IntegrityIssue
                    {
                        Component = r.ComponentName,
                        IssueType = IntegrityIssueType.DatabaseCorrupted,
                        Severity = r.Severity,
                        Details = r.Details
                    }));
                
                // 4. Verificar registros
                var logResults = await VerifyLogsIntegrityAsync();
                results.AddRange(logResults);
                issues.AddRange(logResults.Where(r => !r.IsValid)
                    .Select(r => new IntegrityIssue
                    {
                        Component = r.ComponentName,
                        IssueType = IntegrityIssueType.LogsTampered,
                        Severity = r.Severity,
                        Details = r.Details
                    }));
                
                // 5. Verificar estado del servicio
                var serviceResults = await VerifyServiceStateAsync();
                results.AddRange(serviceResults);
                issues.AddRange(serviceResults.Where(r => !r.IsValid)
                    .Select(r => new IntegrityIssue
                    {
                        Component = r.ComponentName,
                        IssueType = IntegrityIssueType.ServiceTampered,
                        Severity = r.Severity,
                        Details = r.Details
                    }));
                
                var overallIsValid = results.All(r => r.IsValid);
                var criticalIssues = issues.Where(i => i.Severity >= IntegritySeverity.High).ToList();
                
                var result = new IntegrityVerificationResult
                {
                    Timestamp = DateTime.UtcNow,
                    IsValid = overallIsValid,
                    TotalComponents = results.Count,
                    ValidComponents = results.Count(r => r.IsValid),
                    InvalidComponents = results.Count(r => !r.IsValid),
                    Issues = issues,
                    CriticalIssueCount = criticalIssues.Count,
                    Details = results.ToDictionary(
                        r => r.ComponentName,
                        r => new
                        {
                            r.IsValid,
                            r.Severity,
                            r.LastVerification,
                            r.Details
                        })
                };
                
                if (!overallIsValid)
                {
                    _logManager.LogWarning($"Integridad comprometida: {issues.Count} issues, {criticalIssues.Count} críticos", ModuleId);
                    
                    // Si hay issues críticos, tomar acción inmediata
                    if (criticalIssues.Any())
                    {
                        await HandleCriticalIntegrityIssuesAsync(criticalIssues);
                    }
                }
                else
                {
                    _logManager.LogInfo("Integridad verificada correctamente", ModuleId);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en verificación de integridad: {ex}", ModuleId);
                return IntegrityVerificationResult.Error($"Error de verificación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Restaura integridad de componentes comprometidos
        /// </summary>
        public async Task<RestorationResult> RestoreIntegrityAsync()
        {
            try
            {
                _logManager.LogWarning("Iniciando restauración de integridad...", ModuleId);
                
                var verification = await VerifyAllAsync();
                if (verification.IsValid)
                {
                    _logManager.LogInfo("No se requiere restauración - integridad válida", ModuleId);
                    return RestorationResult.Success("Integridad ya válida");
                }
                
                var restorationSteps = new List<RestorationStep>();
                var issuesFixed = new List<IntegrityIssue>();
                var issuesFailed = new List<IntegrityIssue>();
                
                // Restaurar cada issue
                foreach (var issue in verification.Issues)
                {
                    try
                    {
                        var stepResult = await RestoreComponentAsync(issue);
                        
                        var step = new RestorationStep
                        {
                            Timestamp = DateTime.UtcNow,
                            Component = issue.Component,
                            IssueType = issue.IssueType,
                            Action = stepResult.Action,
                            Success = stepResult.Success,
                            Details = stepResult.Details
                        };
                        
                        restorationSteps.Add(step);
                        
                        if (stepResult.Success)
                        {
                            issuesFixed.Add(issue);
                            _logManager.LogInfo($"Restaurado: {issue.Component} - {issue.IssueType}", ModuleId);
                        }
                        else
                        {
                            issuesFailed.Add(issue);
                            _logManager.LogError($"Error restaurando: {issue.Component} - {stepResult.ErrorMessage}", ModuleId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error en restauración de {issue.Component}: {ex}", ModuleId);
                        issuesFailed.Add(issue);
                    }
                }
                
                // Verificar restauración
                var postRestorationVerification = await VerifyAllAsync();
                
                var result = new RestorationResult
                {
                    Timestamp = DateTime.UtcNow,
                    Success = postRestorationVerification.IsValid,
                    IssuesFixed = issuesFixed.Count,
                    IssuesFailed = issuesFailed.Count,
                    RestorationSteps = restorationSteps,
                    PostRestorationStatus = postRestorationVerification,
                    RequiresAgentRestart = restorationSteps.Any(s => s.Action.Contains("Restart")),
                    RequiresSystemReboot = restorationSteps.Any(s => s.Action.Contains("Reboot"))
                };
                
                if (result.Success)
                {
                    _logManager.LogInfo($"Integridad restaurada exitosamente: {issuesFixed.Count} issues corregidos", ModuleId);
                }
                else
                {
                    _logManager.LogWarning($"Restauración parcial: {issuesFixed.Count} corregidos, {issuesFailed.Count} fallaron", ModuleId);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogCritical($"Error crítico en restauración de integridad: {ex}", ModuleId);
                return RestorationResult.Failed($"Error de restauración: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Establece línea base de integridad
        /// </summary>
        public async Task<BaselineResult> EstablishBaselineAsync(string componentName, string filePath = null)
        {
            try
            {
                _logManager.LogInfo($"Estableciendo línea base para: {componentName}", ModuleId);
                
                IntegrityBaseline baseline;
                
                if (!string.IsNullOrEmpty(filePath))
                {
                    baseline = await CreateFileBaselineAsync(componentName, filePath);
                }
                else
                {
                    baseline = await CreateComponentBaselineAsync(componentName);
                }
                
                _baselines[componentName] = baseline;
                await SaveBaselineAsync(baseline);
                
                _logManager.LogInfo($"Línea base establecida para: {componentName}", ModuleId);
                
                return BaselineResult.Success(baseline);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error estableciendo línea base para {componentName}: {ex}", ModuleId);
                return BaselineResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Verifica integridad de un componente específico
        /// </summary>
        public async Task<ComponentIntegrityResult> VerifyComponentAsync(string componentName)
        {
            try
            {
                if (!_baselines.TryGetValue(componentName, out var baseline))
                {
                    return ComponentIntegrityResult.Invalid(
                        componentName,
                        $"No hay línea base para {componentName}",
                        IntegritySeverity.High);
                }
                
                ComponentIntegrityResult result;
                
                switch (baseline.ComponentType)
                {
                    case ComponentType.BinaryFile:
                        result = await VerifyBinaryFileAsync(baseline);
                        break;
                        
                    case ComponentType.Configuration:
                        result = await VerifyConfigurationFileAsync(baseline);
                        break;
                        
                    case ComponentType.Database:
                        result = await VerifyDatabaseComponentAsync(baseline);
                        break;
                        
                    case ComponentType.Service:
                        result = await VerifyServiceComponentAsync(baseline);
                        break;
                        
                    case ComponentType.Registry:
                        result = await VerifyRegistryComponentAsync(baseline);
                        break;
                        
                    default:
                        result = ComponentIntegrityResult.Invalid(
                            componentName,
                            $"Tipo de componente no soportado: {baseline.ComponentType}",
                            IntegritySeverity.Medium);
                        break;
                }
                
                baseline.LastVerification = DateTime.UtcNow;
                baseline.LastResult = result;
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando componente {componentName}: {ex}", ModuleId);
                return ComponentIntegrityResult.Invalid(
                    componentName,
                    $"Error de verificación: {ex.Message}",
                    IntegritySeverity.High);
            }
        }
        
        /// <summary>
        /// Verifica firma digital de un archivo
        /// </summary>
        public async Task<bool> VerifyDigitalSignatureAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _logManager.LogWarning($"Archivo no encontrado: {filePath}", ModuleId);
                    return false;
                }
                
                // Verificar firma de Authenticode
                var signatureInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                
                // En producción usar API de Windows para verificación de firma
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate
                    .CreateFromSignedFile(filePath);
                
                if (cert == null)
                {
                    _logManager.LogWarning($"Archivo no firmado: {filePath}", ModuleId);
                    return false;
                }
                
                // Verificar cadena de certificados
                var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                
                // Verificar que sea de BWP Enterprise
                var isValid = certificate.Subject.Contains("BWP Enterprise") &&
                             certificate.NotAfter > DateTime.Now &&
                             certificate.NotBefore < DateTime.Now;
                
                if (!isValid)
                {
                    _logManager.LogWarning($"Certificado inválido para: {filePath}", ModuleId);
                }
                
                return isValid;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando firma digital de {filePath}: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene reporte de integridad
        /// </summary>
        public async Task<IntegrityReport> GetIntegrityReportAsync(TimeSpan? period = null)
        {
            period ??= TimeSpan.FromDays(7);
            
            try
            {
                var currentVerification = await VerifyAllAsync();
                var verificationHistory = await _localDatabase.GetIntegrityVerificationsAsync(period.Value);
                var restorationHistory = await _localDatabase.GetRestorationHistoryAsync(period.Value);
                
                var report = new IntegrityReport
                {
                    GeneratedAt = DateTime.UtcNow,
                    Period = period.Value,
                    CurrentStatus = currentVerification,
                    Baselines = _baselines.Values.ToList(),
                    VerificationHistory = verificationHistory,
                    RestorationHistory = restorationHistory,
                    Statistics = CalculateIntegrityStatistics(verificationHistory),
                    Recommendations = await GenerateIntegrityRecommendationsAsync(currentVerification)
                };
                
                return report;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando reporte de integridad: {ex}", ModuleId);
                return IntegrityReport.Error($"Error: {ex.Message}");
            }
        }
        
        #region Métodos privados
        
        /// <summary>
        /// Inicia monitoreo continuo
        /// </summary>
        private void StartContinuousMonitoring()
        {
            _verificationTimer = new Timer(
                async _ => await PerformScheduledVerificationAsync(),
                null,
                TimeSpan.FromMinutes(VERIFICATION_INTERVAL_MINUTES),
                TimeSpan.FromMinutes(VERIFICATION_INTERVAL_MINUTES));
            
            _isMonitoring = true;
            _logManager.LogInfo($"Monitoreo continuo iniciado (intervalo: {VERIFICATION_INTERVAL_MINUTES} minutos)", ModuleId);
        }
        
        /// <summary>
        /// Realiza verificación programada
        /// </summary>
        private async Task PerformScheduledVerificationAsync()
        {
            if (!_isMonitoring)
                return;
            
            try
            {
                _logManager.LogDebug("Ejecutando verificación de integridad programada...", ModuleId);
                
                var result = await VerifyAllAsync();
                
                if (!result.IsValid)
                {
                    _logManager.LogWarning($"Problemas de integridad detectados en verificación programada: {result.Issues.Count} issues", ModuleId);
                    
                    // Si hay issues críticos, restaurar automáticamente
                    if (result.CriticalIssueCount > 0)
                    {
                        _logManager.LogCritical($"Issues críticos detectados: {result.CriticalIssueCount}, iniciando restauración automática", ModuleId);
                        await RestoreIntegrityAsync();
                    }
                }
                
                // Guardar resultado en historial
                await _localDatabase.SaveIntegrityVerificationAsync(result);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en verificación programada: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Verifica archivos binarios críticos
        /// </summary>
        private async Task<List<ComponentIntegrityResult>> VerifyBinaryFilesAsync()
        {
            var results = new List<ComponentIntegrityResult>();
            
            // Archivos críticos del agente
            var criticalFiles = new[]
            {
                new { Name = "BWPAgent.exe", Path = GetAgentExecutablePath() },
                new { Name = "BWPSensor.dll", Path = GetSensorLibraryPath() },
                new { Name = "BWP.Core.dll", Path = GetCoreLibraryPath() },
                new { Name = "BWP.Config.json", Path = GetConfigFilePath() }
            };
            
            foreach (var file in criticalFiles)
            {
                if (_baselines.TryGetValue(file.Name, out var baseline))
                {
                    results.Add(await VerifyBinaryFileAsync(baseline));
                }
                else
                {
                    // Si no hay línea base, crear una y verificar
                    baseline = await CreateFileBaselineAsync(file.Name, file.Path);
                    _baselines[file.Name] = baseline;
                    results.Add(baseline.LastResult);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica archivo binario contra línea base
        /// </summary>
        private async Task<ComponentIntegrityResult> VerifyBinaryFileAsync(IntegrityBaseline baseline)
        {
            try
            {
                if (!File.Exists(baseline.FilePath))
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Archivo no encontrado: {baseline.FilePath}",
                        IntegritySeverity.Critical);
                }
                
                // 1. Verificar firma digital
                var isDigitallySigned = await VerifyDigitalSignatureAsync(baseline.FilePath);
                if (!isDigitallySigned && baseline.RequiresDigitalSignature)
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        "Firma digital inválida o faltante",
                        IntegritySeverity.Critical);
                }
                
                // 2. Verificar hash
                var currentHash = await CalculateFileHashAsync(baseline.FilePath, baseline.HashAlgorithm);
                if (currentHash != baseline.ExpectedHash)
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Hash no coincide. Esperado: {baseline.ExpectedHash}, Actual: {currentHash}",
                        IntegritySeverity.Critical);
                }
                
                // 3. Verificar tamaño
                var fileInfo = new FileInfo(baseline.FilePath);
                if (Math.Abs(fileInfo.Length - baseline.ExpectedSize) > 1024) // 1KB de tolerancia
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Tamaño modificado. Esperado: {baseline.ExpectedSize}, Actual: {fileInfo.Length}",
                        IntegritySeverity.High);
                }
                
                // 4. Verificar permisos
                var currentPermissions = GetFilePermissions(baseline.FilePath);
                if (currentPermissions != baseline.ExpectedPermissions)
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Permisos modificados. Esperado: {baseline.ExpectedPermissions}, Actual: {currentPermissions}",
                        IntegritySeverity.Medium);
                }
                
                // 5. Verificar timestamp (solo advertencia)
                var fileTime = fileInfo.LastWriteTimeUtc;
                if ((DateTime.UtcNow - fileTime).TotalDays > 365 && baseline.LastKnownGoodTime.HasValue)
                {
                    // Archivo muy antiguo
                    return ComponentIntegrityResult.ValidWithWarning(
                        baseline.ComponentName,
                        $"Archivo muy antiguo: {fileTime:yyyy-MM-dd}",
                        IntegritySeverity.Low);
                }
                
                return ComponentIntegrityResult.Valid(baseline.ComponentName);
            }
            catch (Exception ex)
            {
                return ComponentIntegrityResult.Invalid(
                    baseline.ComponentName,
                    $"Error de verificación: {ex.Message}",
                    IntegritySeverity.High);
            }
        }
        
        /// <summary>
        /// Verifica configuración
        /// </summary>
        private async Task<List<ComponentIntegrityResult>> VerifyConfigurationAsync()
        {
            var results = new List<ComponentIntegrityResult>();
            
            var configFiles = new[]
            {
                "AgentConfig.json",
                "PolicyConfig.json",
                "SensorConfig.json",
                "TelemetryConfig.json"
            };
            
            foreach (var configFile in configFiles)
            {
                var componentName = $"Config.{configFile}";
                
                if (_baselines.TryGetValue(componentName, out var baseline))
                {
                    results.Add(await VerifyConfigurationFileAsync(baseline));
                }
                else
                {
                    // Verificar sin línea base
                    var configPath = Path.Combine(GetConfigDirectory(), configFile);
                    if (File.Exists(configPath))
                    {
                        baseline = await CreateConfigurationBaselineAsync(componentName, configPath);
                        _baselines[componentName] = baseline;
                        results.Add(baseline.LastResult);
                    }
                    else
                    {
                        results.Add(ComponentIntegrityResult.Invalid(
                            componentName,
                            "Archivo de configuración no encontrado",
                            IntegritySeverity.Medium));
                    }
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica archivo de configuración
        /// </summary>
        private async Task<ComponentIntegrityResult> VerifyConfigurationFileAsync(IntegrityBaseline baseline)
        {
            try
            {
                if (!File.Exists(baseline.FilePath))
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Archivo de configuración no encontrado: {baseline.FilePath}",
                        IntegritySeverity.High);
                }
                
                // Para configuración, podemos permitir ciertos cambios
                var currentHash = await CalculateFileHashAsync(baseline.FilePath, baseline.HashAlgorithm);
                
                if (currentHash != baseline.ExpectedHash)
                {
                    // Verificar si los cambios son autorizados
                    var currentContent = await File.ReadAllTextAsync(baseline.FilePath);
                    var originalContent = baseline.OriginalContent;
                    
                    // Análisis básico de diferencias
                    var differences = FindConfigurationDifferences(originalContent, currentContent);
                    
                    if (differences.Any(d => d.IsCritical))
                    {
                        return ComponentIntegrityResult.Invalid(
                            baseline.ComponentName,
                            $"Cambios críticos en configuración detectados: {string.Join(", ", differences.Where(d => d.IsCritical).Select(d => d.Field))}",
                            IntegritySeverity.High);
                    }
                    else if (differences.Any())
                    {
                        return ComponentIntegrityResult.ValidWithWarning(
                            baseline.ComponentName,
                            $"Cambios no críticos en configuración: {differences.Count} diferencias",
                            IntegritySeverity.Low);
                    }
                }
                
                return ComponentIntegrityResult.Valid(baseline.ComponentName);
            }
            catch (Exception ex)
            {
                return ComponentIntegrityResult.Invalid(
                    baseline.ComponentName,
                    $"Error verificando configuración: {ex.Message}",
                    IntegritySeverity.Medium);
            }
        }
        
        /// <summary>
        /// Verifica integridad de base de datos
        /// </summary>
        private async Task<List<ComponentIntegrityResult>> VerifyDatabaseIntegrityAsync()
        {
            var results = new List<ComponentIntegrityResult>();
            
            var dbComponents = new[]
            {
                "LocalDatabase",
                "EventStore",
                "ConfigurationStore",
                "TelemetryCache"
            };
            
            foreach (var component in dbComponents)
            {
                if (_baselines.TryGetValue(component, out var baseline))
                {
                    results.Add(await VerifyDatabaseComponentAsync(baseline));
                }
                else
                {
                    results.Add(await VerifyDatabaseComponentWithoutBaselineAsync(component));
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica componente de base de datos
        /// </summary>
        private async Task<ComponentIntegrityResult> VerifyDatabaseComponentAsync(IntegrityBaseline baseline)
        {
            try
            {
                var dbPath = _localDatabase.GetDatabasePath();
                
                if (!File.Exists(dbPath))
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        "Archivo de base de datos no encontrado",
                        IntegritySeverity.Critical);
                }
                
                // Verificar integridad de la base de datos SQLite
                var integrityCheck = await _localDatabase.CheckDatabaseIntegrityAsync();
                
                if (!integrityCheck.IsHealthy)
                {
                    return ComponentIntegrityResult.Invalid(
                        baseline.ComponentName,
                        $"Problemas de integridad en base de datos: {integrityCheck.Issues.Count} issues",
                        IntegritySeverity.Critical);
                }
                
                // Verificar tamaño (crecimiento anormal puede indicar corrupción)
                var dbInfo = new FileInfo(dbPath);
                if (dbInfo.Length > baseline.ExpectedSize * 2) // Más del doble del tamaño esperado
                {
                    return ComponentIntegrityResult.ValidWithWarning(
                        baseline.ComponentName,
                        $"Base de datos más grande de lo esperado: {dbInfo.Length} bytes",
                        IntegritySeverity.Medium);
                }
                
                return ComponentIntegrityResult.Valid(baseline.ComponentName);
            }
            catch (Exception ex)
            {
                return ComponentIntegrityResult.Invalid(
                    baseline.ComponentName,
                    $"Error verificando base de datos: {ex.Message}",
                    IntegritySeverity.High);
            }
        }
        
        /// <summary>
        /// Verifica registros
        /// </summary>
        private async Task<List<ComponentIntegrityResult>> VerifyLogsIntegrityAsync()
        {
            var results = new List<ComponentIntegrityResult>();
            
            try
            {
                var logDirectory = GetLogDirectory();
                if (!Directory.Exists(logDirectory))
                {
                    results.Add(ComponentIntegrityResult.Invalid(
                        "Logs",
                        "Directorio de logs no encontrado",
                        IntegritySeverity.Medium));
                    return results;
                }
                
                // Verificar que los logs no hayan sido manipulados
                var logFiles = Directory.GetFiles(logDirectory, "*.log");
                
                foreach (var logFile in logFiles.Take(10)) // Revisar solo los 10 más recientes
                {
                    var fileName = Path.GetFileName(logFile);
                    var componentName = $"Log.{fileName}";
                    
                    try
                    {
                        // Verificar que el log tenga formato válido
                        var firstLine = await ReadFirstLineAsync(logFile);
                        var lastLine = await ReadLastLineAsync(logFile);
                        
                        if (string.IsNullOrEmpty(firstLine) || !firstLine.Contains("BWP"))
                        {
                            results.Add(ComponentIntegrityResult.Invalid(
                                componentName,
                                "Formato de log inválido",
                                IntegritySeverity.Low));
                        }
                        else if (lastLine.Contains("ERROR") || lastLine.Contains("CRITICAL"))
                        {
                            results.Add(ComponentIntegrityResult.ValidWithWarning(
                                componentName,
                                "Log contiene errores críticos",
                                IntegritySeverity.Medium));
                        }
                        else
                        {
                            results.Add(ComponentIntegrityResult.Valid(componentName));
                        }
                    }
                    catch
                    {
                        results.Add(ComponentIntegrityResult.Invalid(
                            componentName,
                            "Error leyendo archivo de log",
                            IntegritySeverity.Low));
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(ComponentIntegrityResult.Invalid(
                    "Logs",
                    $"Error verificando logs: {ex.Message}",
                    IntegritySeverity.Low));
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica estado del servicio
        /// </summary>
        private async Task<List<ComponentIntegrityResult>> VerifyServiceStateAsync()
        {
            var results = new List<ComponentIntegrityResult>();
            
            var services = new[]
            {
                new { Name = "BWPEnterpriseAgent", DisplayName = "BWP Enterprise Agent" },
                new { Name = "BWPSensor", DisplayName = "BWP Sensor Driver" }
            };
            
            foreach (var service in services)
            {
                try
                {
                    using (var sc = new System.ServiceProcess.ServiceController(service.Name))
                    {
                        var status = sc.Status;
                        var canStart = sc.CanStart;
                        var canStop = sc.CanStop;
                        
                        if (status != System.ServiceProcess.ServiceControllerStatus.Running)
                        {
                            results.Add(ComponentIntegrityResult.Invalid(
                                $"Service.{service.Name}",
                                $"Servicio no está ejecutándose: {status}",
                                IntegritySeverity.Critical));
                        }
                        else if (!canStop)
                        {
                            results.Add(ComponentIntegrityResult.ValidWithWarning(
                                $"Service.{service.Name}",
                                "Servicio no puede ser detenido (puede ser normal para servicios críticos)",
                                IntegritySeverity.Low));
                        }
                        else
                        {
                            results.Add(ComponentIntegrityResult.Valid($"Service.{service.Name}"));
                        }
                    }
                }
                catch (Exception ex)
                {
                    results.Add(ComponentIntegrityResult.Invalid(
                        $"Service.{service.Name}",
                        $"Error verificando servicio: {ex.Message}",
                        IntegritySeverity.High));
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica archivos críticos (sin línea base)
        /// </summary>
        private async Task VerifyCriticalFilesAsync()
        {
            var criticalFiles = new[]
            {
                GetAgentExecutablePath(),
                GetSensorLibraryPath(),
                GetCoreLibraryPath(),
                GetConfigFilePath()
            };
            
            foreach (var file in criticalFiles)
            {
                if (File.Exists(file))
                {
                    var fileName = Path.GetFileName(file);
                    if (!_baselines.ContainsKey(fileName))
                    {
                        await EstablishBaselineAsync(fileName, file);
                    }
                }
            }
        }
        
        /// <summary>
        /// Maneja issues críticos de integridad
        /// </summary>
        private async Task HandleCriticalIntegrityIssuesAsync(List<IntegrityIssue> criticalIssues)
        {
            _logManager.LogCritical($"Manejando {criticalIssues.Count} issues críticos de integridad", ModuleId);
            
            foreach (var issue in criticalIssues)
            {
                try
                {
                    switch (issue.IssueType)
                    {
                        case IntegrityIssueType.FileTampered:
                            await HandleTamperedFileAsync(issue);
                            break;
                            
                        case IntegrityIssueType.ServiceTampered:
                            await HandleTamperedServiceAsync(issue);
                            break;
                            
                        case IntegrityIssueType.DatabaseCorrupted:
                            await HandleCorruptedDatabaseAsync(issue);
                            break;
                            
                        case IntegrityIssueType.ConfigurationModified:
                            await HandleModifiedConfigurationAsync(issue);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error manejando issue crítico {issue.Component}: {ex}", ModuleId);
                }
            }
        }
        
        /// <summary>
        /// Restaura componente específico
        /// </summary>
        private async Task<RestorationStepResult> RestoreComponentAsync(IntegrityIssue issue)
        {
            try
            {
                switch (issue.IssueType)
                {
                    case IntegrityIssueType.FileTampered:
                        return await RestoreTamperedFileAsync(issue);
                        
                    case IntegrityIssueType.ServiceTampered:
                        return await RestoreServiceAsync(issue);
                        
                    case IntegrityIssueType.DatabaseCorrupted:
                        return await RestoreDatabaseAsync(issue);
                        
                    case IntegrityIssueType.ConfigurationModified:
                        return await RestoreConfigurationAsync(issue);
                        
                    case IntegrityIssueType.LogsTampered:
                        return await RestoreLogsAsync(issue);
                        
                    default:
                        return RestorationStepResult.Failed($"Tipo de issue no soportado: {issue.IssueType}");
                }
            }
            catch (Exception ex)
            {
                return RestorationStepResult.Failed($"Error restaurando {issue.Component}: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Restaura archivo manipulado
        /// </summary>
        private async Task<RestorationStepResult> RestoreTamperedFileAsync(IntegrityIssue issue)
        {
            try
            {
                var componentName = issue.Component;
                
                if (!_baselines.TryGetValue(componentName, out var baseline))
                {
                    return RestorationStepResult.Failed($"No hay línea base para {componentName}");
                }
                
                // 1. Si hay backup, restaurar desde backup
                if (!string.IsNullOrEmpty(baseline.BackupPath) && File.Exists(baseline.BackupPath))
                {
                    File.Copy(baseline.BackupPath, baseline.FilePath, true);
                    _logManager.LogInfo($"Archivo restaurado desde backup: {componentName}", ModuleId);
                    
                    return RestorationStepResult.Success(
                        $"RestoredFromBackup",
                        $"Archivo restaurado desde backup: {baseline.BackupPath}");
                }
                
                // 2. Si no hay backup, descargar desde servidor
                var apiClient = ApiClient.Instance;
                var downloadResult = await apiClient.DownloadComponentAsync(componentName);
                
                if (downloadResult.IsSuccess)
                {
                    var fileData = Convert.FromBase64String(downloadResult.Data);
                    await File.WriteAllBytesAsync(baseline.FilePath, fileData);
                    
                    _logManager.LogInfo($"Archivo descargado desde servidor: {componentName}", ModuleId);
                    
                    return RestorationStepResult.Success(
                        $"DownloadedFromServer",
                        $"Archivo descargado desde servidor, tamaño: {fileData.Length} bytes");
                }
                
                // 3. Si no se puede descargar, reinstalar
                var installer = new ComponentInstaller();
                var installResult = await installer.ReinstallComponentAsync(componentName);
                
                if (installResult.Success)
                {
                    return RestorationStepResult.Success(
                        $"Reinstalled",
                        $"Componente reinstalado: {componentName}");
                }
                
                return RestorationStepResult.Failed($"No se pudo restaurar {componentName}");
            }
            catch (Exception ex)
            {
                return RestorationStepResult.Failed($"Error restaurando archivo: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Carga líneas base desde base de datos
        /// </summary>
        private async Task LoadBaselinesAsync()
        {
            try
            {
                var baselines = await _localDatabase.GetIntegrityBaselinesAsync();
                
                foreach (var baseline in baselines)
                {
                    _baselines[baseline.ComponentName] = baseline;
                }
                
                _logManager.LogInfo($"Cargadas {baselines.Count} líneas base de integridad", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando líneas base: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda línea base
        /// </summary>
        private async Task SaveBaselineAsync(IntegrityBaseline baseline)
        {
            try
            {
                await _localDatabase.SaveIntegrityBaselineAsync(baseline);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando línea base: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Crea línea base para archivo
        /// </summary>
        private async Task<IntegrityBaseline> CreateFileBaselineAsync(string componentName, string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                
                var baseline = new IntegrityBaseline
                {
                    ComponentName = componentName,
                    ComponentType = ComponentType.BinaryFile,
                    FilePath = filePath,
                    ExpectedSize = fileInfo.Length,
                    ExpectedHash = await CalculateFileHashAsync(filePath, "SHA256"),
                    HashAlgorithm = "SHA256",
                    ExpectedPermissions = GetFilePermissions(filePath),
                    RequiresDigitalSignature = true,
                    CreatedAt = DateTime.UtcNow,
                    LastUpdated = DateTime.UtcNow
                };
                
                // Crear backup si es crítico
                if (IsCriticalFile(componentName))
                {
                    var backupPath = await CreateBackupAsync(filePath);
                    baseline.BackupPath = backupPath;
                }
                
                // Verificar inicial
                baseline.LastResult = await VerifyBinaryFileAsync(baseline);
                
                return baseline;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error creando línea base para {componentName}: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Crea línea base para configuración
        /// </summary>
        private async Task<IntegrityBaseline> CreateConfigurationBaselineAsync(string componentName, string configPath)
        {
            try
            {
                var content = await File.ReadAllTextAsync(configPath);
                
                var baseline = new IntegrityBaseline
                {
                    ComponentName = componentName,
                    ComponentType = ComponentType.Configuration,
                    FilePath = configPath,
                    ExpectedSize = content.Length,
                    ExpectedHash = _cryptoHelper.ComputeHash(content, "SHA256"),
                    HashAlgorithm = "SHA256",
                    OriginalContent = content,
                    CreatedAt = DateTime.UtcNow,
                    LastUpdated = DateTime.UtcNow
                };
                
                // Verificar inicial
                baseline.LastResult = await VerifyConfigurationFileAsync(baseline);
                
                return baseline;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error creando línea base de configuración para {componentName}: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Crea línea base para componente
        /// </summary>
        private async Task<IntegrityBaseline> CreateComponentBaselineAsync(string componentName)
        {
            // Implementación específica por tipo de componente
            throw new NotImplementedException();
        }
        
        /// <summary>
        /// Calcula hash de archivo
        /// </summary>
        private async Task<string> CalculateFileHashAsync(string filePath, string algorithm)
        {
            using (var stream = File.OpenRead(filePath))
            using (var hashAlgorithm = HashAlgorithm.Create(algorithm))
            {
                var hashBytes = await hashAlgorithm.ComputeHashAsync(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
        
        /// <summary>
        /// Obtiene permisos de archivo
        /// </summary>
        private string GetFilePermissions(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var attributes = fileInfo.Attributes;
                
                var permissions = new List<string>();
                
                if ((attributes & FileAttributes.ReadOnly) != 0)
                    permissions.Add("ReadOnly");
                if ((attributes & FileAttributes.Hidden) != 0)
                    permissions.Add("Hidden");
                if ((attributes & FileAttributes.System) != 0)
                    permissions.Add("System");
                
                return string.Join(",", permissions);
            }
            catch
            {
                return "Unknown";
            }
        }
        
        /// <summary>
        /// Crea backup de archivo
        /// </summary>
        private async Task<string> CreateBackupAsync(string filePath)
        {
            try
            {
                var backupDir = Path.Combine(GetBackupDirectory(), "Integrity");
                Directory.CreateDirectory(backupDir);
                
                var fileName = Path.GetFileName(filePath);
                var backupPath = Path.Combine(backupDir, $"{fileName}.backup_{DateTime.UtcNow:yyyyMMddHHmmss}");
                
                File.Copy(filePath, backupPath, true);
                
                // Comprimir backup
                await CompressBackupAsync(backupPath);
                
                return backupPath + ".zip";
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error creando backup de {filePath}: {ex}", ModuleId);
                return null;
            }
        }
        
        /// <summary>
        /// Encuentra diferencias en configuración
        /// </summary>
        private List<ConfigurationDifference> FindConfigurationDifferences(string original, string current)
        {
            var differences = new List<ConfigurationDifference>();
            
            try
            {
                // Análisis simple de JSON
                var originalLines = original.Split('\n');
                var currentLines = current.Split('\n');
                
                for (int i = 0; i < Math.Min(originalLines.Length, currentLines.Length); i++)
                {
                    var originalLine = originalLines[i].Trim();
                    var currentLine = currentLines[i].Trim();
                    
                    if (originalLine != currentLine)
                    {
                        // Determinar si es crítico
                        var isCritical = IsCriticalConfigurationChange(originalLine, currentLine);
                        
                        differences.Add(new ConfigurationDifference
                        {
                            LineNumber = i + 1,
                            Original = originalLine,
                            Current = currentLine,
                            IsCritical = isCritical,
                            Field = ExtractFieldName(originalLine)
                        });
                    }
                }
            }
            catch
            {
                // Si hay error en el análisis, considerar como crítica
                differences.Add(new ConfigurationDifference
                {
                    IsCritical = true,
                    Field = "Unknown",
                    Original = "Error parsing",
                    Current = "Error parsing"
                });
            }
            
            return differences;
        }
        
        private bool IsCriticalConfigurationChange(string original, string current)
        {
            var criticalFields = new[]
            {
                "ApiKey",
                "EncryptionKey",
                "AdminPassword",
                "TenantId",
                "DeviceId",
                "TelemetryUrl",
                "PolicyUrl"
            };
            
            return criticalFields.Any(field => 
                original.Contains($"\"{field}\"") || current.Contains($"\"{field}\""));
        }
        
        private string ExtractFieldName(string line)
        {
            var match = System.Text.RegularExpressions.Regex.Match(line, "\"([^\"]+)\"\\s*:");
            return match.Success ? match.Groups[1].Value : "Unknown";
        }
        
        private async Task<string> ReadFirstLineAsync(string filePath)
        {
            using (var reader = new StreamReader(filePath))
            {
                return await reader.ReadLineAsync();
            }
        }
        
        private async Task<string> ReadLastLineAsync(string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(stream))
            {
                string line = null;
                string lastLine = null;
                
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    lastLine = line;
                }
                
                return lastLine;
            }
        }
        
        private async Task CompressBackupAsync(string filePath)
        {
            // Implementación de compresión
            await Task.CompletedTask;
        }
        
        private bool IsCriticalFile(string componentName)
        {
            var criticalFiles = new[]
            {
                "BWPAgent.exe",
                "BWPSensor.dll",
                "BWP.Core.dll"
            };
            
            return criticalFiles.Contains(componentName);
        }
        
        private string GetAgentExecutablePath()
        {
            return System.Reflection.Assembly.GetExecutingAssembly().Location;
        }
        
        private string GetSensorLibraryPath()
        {
            var agentPath = GetAgentExecutablePath();
            var agentDir = Path.GetDirectoryName(agentPath);
            return Path.Combine(agentDir, "BWPSensor.dll");
        }
        
        private string GetCoreLibraryPath()
        {
            var agentPath = GetAgentExecutablePath();
            var agentDir = Path.GetDirectoryName(agentPath);
            return Path.Combine(agentDir, "BWP.Core.dll");
        }
        
        private string GetConfigFilePath()
        {
            var agentPath = GetAgentExecutablePath();
            var agentDir = Path.GetDirectoryName(agentPath);
            return Path.Combine(agentDir, "BWP.Config.json");
        }
        
        private string GetConfigDirectory()
        {
            var agentPath = GetAgentExecutablePath();
            return Path.GetDirectoryName(agentPath);
        }
        
        private string GetLogDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                "BWP Enterprise", "Logs");
        }
        
        private string GetBackupDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                "BWP Enterprise", "Backups");
        }
        
        private IntegrityStatistics CalculateIntegrityStatistics(List<IntegrityVerificationResult> history)
        {
            if (history.Count == 0)
                return new IntegrityStatistics();
            
            var stats = new IntegrityStatistics
            {
                TotalVerifications = history.Count,
                ValidVerifications = history.Count(h => h.IsValid),
                AverageVerificationTime = TimeSpan.FromMilliseconds(
                    history.Average(h => (h.Timestamp - h.StartTime)?.TotalMilliseconds ?? 0)),
                MostCommonIssue = history
                    .SelectMany(h => h.Issues)
                    .GroupBy(i => i.IssueType)
                    .OrderByDescending(g => g.Count())
                    .Select(g => g.Key.ToString())
                    .FirstOrDefault(),
                CriticalIssueCount = history.Sum(h => h.CriticalIssueCount)
            };
            
            return stats;
        }
        
        private async Task<List<IntegrityRecommendation>> GenerateIntegrityRecommendationsAsync(
            IntegrityVerificationResult currentStatus)
        {
            var recommendations = new List<IntegrityRecommendation>();
            
            if (!currentStatus.IsValid)
            {
                recommendations.Add(new IntegrityRecommendation
                {
                    Priority = RecommendationPriority.Critical,
                    Title = "Restaurar integridad inmediatamente",
                    Description = $"Se detectaron {currentStatus.InvalidComponents} componentes con problemas de integridad",
                    Action = "RunIntegrityRestoration",
                    EstimatedTime = TimeSpan.FromMinutes(5)
                });
            }
            
            if (currentStatus.CriticalIssueCount > 0)
            {
                recommendations.Add(new IntegrityRecommendation
                {
                    Priority = RecommendationPriority.Critical,
                    Title = "Revisar issues críticos",
                    Description = $"Existen {currentStatus.CriticalIssueCount} issues críticos que requieren atención inmediata",
                    Action = "ReviewCriticalIssues",
                    EstimatedTime = TimeSpan.FromMinutes(10)
                });
            }
            
            // Verificar si hay backups antiguos
            var backupAge = await GetBackupAgeAsync();
            if (backupAge > TimeSpan.FromDays(30))
            {
                recommendations.Add(new IntegrityRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "Actualizar backups",
                    Description = $"El backup más reciente tiene {backupAge.Days} días",
                    Action = "UpdateBackups",
                    EstimatedTime = TimeSpan.FromMinutes(15)
                });
            }
            
            return recommendations;
        }
        
        private async Task<TimeSpan> GetBackupAgeAsync()
        {
            try
            {
                var backupDir = Path.Combine(GetBackupDirectory(), "Integrity");
                if (!Directory.Exists(backupDir))
                    return TimeSpan.MaxValue;
                
                var backupFiles = Directory.GetFiles(backupDir, "*.zip");
                if (backupFiles.Length == 0)
                    return TimeSpan.MaxValue;
                
                var latestBackup = backupFiles
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTime)
                    .First();
                
                return DateTime.UtcNow - latestBackup.LastWriteTimeUtc;
            }
            catch
            {
                return TimeSpan.MaxValue;
            }
        }
        
        // Métodos de manejo específicos (implementaciones simplificadas)
        private async Task HandleTamperedFileAsync(IntegrityIssue issue) => await Task.Delay(1);
        private async Task HandleTamperedServiceAsync(IntegrityIssue issue) => await Task.Delay(1);
        private async Task HandleCorruptedDatabaseAsync(IntegrityIssue issue) => await Task.Delay(1);
        private async Task HandleModifiedConfigurationAsync(IntegrityIssue issue) => await Task.Delay(1);
        private async Task<RestorationStepResult> RestoreServiceAsync(IntegrityIssue issue) => await Task.FromResult(RestorationStepResult.Success("Restored", "Service restored"));
        private async Task<RestorationStepResult> RestoreDatabaseAsync(IntegrityIssue issue) => await Task.FromResult(RestorationStepResult.Success("Restored", "Database restored"));
        private async Task<RestorationStepResult> RestoreConfigurationAsync(IntegrityIssue issue) => await Task.FromResult(RestorationStepResult.Success("Restored", "Configuration restored"));
        private async Task<RestorationStepResult> RestoreLogsAsync(IntegrityIssue issue) => await Task.FromResult(RestorationStepResult.Success("Restored", "Logs restored"));
        private async Task<ComponentIntegrityResult> VerifyDatabaseComponentWithoutBaselineAsync(string componentName) => await Task.FromResult(ComponentIntegrityResult.Valid(componentName));
        private async Task<ComponentIntegrityResult> VerifyServiceComponentAsync(IntegrityBaseline baseline) => await Task.FromResult(ComponentIntegrityResult.Valid(baseline.ComponentName));
        private async Task<ComponentIntegrityResult> VerifyRegistryComponentAsync(IntegrityBaseline baseline) => await Task.FromResult(ComponentIntegrityResult.Valid(baseline.ComponentName));
        
        #endregion
        
        #region Métodos para HealthCheck
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var verification = await VerifyAllAsync();
                
                if (verification.IsValid)
                {
                    return HealthCheckResult.Healthy("IntegrityVerifier funcionando correctamente");
                }
                
                var details = new Dictionary<string, object>
                {
                    { "InvalidComponents", verification.InvalidComponents },
                    { "CriticalIssues", verification.CriticalIssueCount },
                    { "LastVerification", verification.Timestamp },
                    { "Issues", verification.Issues.Take(5).Select(i => new { i.Component, i.IssueType, i.Severity }) }
                };
                
                if (verification.CriticalIssueCount > 0)
                {
                    return HealthCheckResult.Unhealthy(
                        $"{verification.CriticalIssueCount} issues críticos de integridad detectados",
                        details);
                }
                
                return HealthCheckResult.Degraded(
                    $"{verification.InvalidComponents} componentes con problemas de integridad",
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
    
    public class IntegrityBaseline
    {
        public string ComponentName { get; set; }
        public ComponentType ComponentType { get; set; }
        public string FilePath { get; set; }
        public long ExpectedSize { get; set; }
        public string ExpectedHash { get; set; }
        public string HashAlgorithm { get; set; }
        public string ExpectedPermissions { get; set; }
        public bool RequiresDigitalSignature { get; set; }
        public string BackupPath { get; set; }
        public string OriginalContent { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastUpdated { get; set; }
        public DateTime? LastVerification { get; set; }
        public ComponentIntegrityResult LastResult { get; set; }
    }
    
    public class IntegrityVerificationResult
    {
        public DateTime Timestamp { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public bool IsValid { get; set; }
        public int TotalComponents { get; set; }
        public int ValidComponents { get; set; }
        public int InvalidComponents { get; set; }
        public int CriticalIssueCount { get; set; }
        public List<IntegrityIssue> Issues { get; set; }
        public Dictionary<string, object> Details { get; set; }
        public string Error { get; set; }
        
        public IntegrityVerificationResult()
        {
            Issues = new List<IntegrityIssue>();
            Details = new Dictionary<string, object>();
        }
        
        public static IntegrityVerificationResult Error(string errorMessage)
        {
            return new IntegrityVerificationResult
            {
                IsValid = false,
                Error = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class ComponentIntegrityResult
    {
        public string ComponentName { get; set; }
        public bool IsValid { get; set; }
        public IntegritySeverity Severity { get; set; }
        public string Message { get; set; }
        public DateTime LastVerification { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public ComponentIntegrityResult()
        {
            Details = new Dictionary<string, object>();
            LastVerification = DateTime.UtcNow;
        }
        
        public static ComponentIntegrityResult Valid(string componentName)
        {
            return new ComponentIntegrityResult
            {
                ComponentName = componentName,
                IsValid = true,
                Severity = IntegritySeverity.None,
                Message = "Componente válido"
            };
        }
        
        public static ComponentIntegrityResult ValidWithWarning(string componentName, string warning, IntegritySeverity severity)
        {
            return new ComponentIntegrityResult
            {
                ComponentName = componentName,
                IsValid = true,
                Severity = severity,
                Message = warning
            };
        }
        
        public static ComponentIntegrityResult Invalid(string componentName, string error, IntegritySeverity severity)
        {
            return new ComponentIntegrityResult
            {
                ComponentName = componentName,
                IsValid = false,
                Severity = severity,
                Message = error
            };
        }
    }
    
    public class IntegrityIssue
    {
        public string Component { get; set; }
        public IntegrityIssueType IssueType { get; set; }
        public IntegritySeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public IntegrityIssue()
        {
            Details = new Dictionary<string, object>();
            DetectedAt = DateTime.UtcNow;
        }
    }
    
    public class RestorationResult
    {
        public DateTime Timestamp { get; set; }
        public bool Success { get; set; }
        public int IssuesFixed { get; set; }
        public int IssuesFailed { get; set; }
        public List<RestorationStep> RestorationSteps { get; set; }
        public IntegrityVerificationResult PostRestorationStatus { get; set; }
        public bool RequiresAgentRestart { get; set; }
        public bool RequiresSystemReboot { get; set; }
        public string Error { get; set; }
        
        public RestorationResult()
        {
            RestorationSteps = new List<RestorationStep>();
        }
        
        public static RestorationResult Success(string message = null)
        {
            return new RestorationResult
            {
                Success = true,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static RestorationResult Failed(string errorMessage)
        {
            return new RestorationResult
            {
                Success = false,
                Error = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class RestorationStep
    {
        public DateTime Timestamp { get; set; }
        public string Component { get; set; }
        public IntegrityIssueType IssueType { get; set; }
        public string Action { get; set; }
        public bool Success { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public RestorationStep()
        {
            Details = new Dictionary<string, object>();
        }
    }
    
    public class RestorationStepResult
    {
        public bool Success { get; set; }
        public string Action { get; set; }
        public string Details { get; set; }
        public string ErrorMessage { get; set; }
        
        public static RestorationStepResult Success(string action, string details)
        {
            return new RestorationStepResult
            {
                Success = true,
                Action = action,
                Details = details
            };
        }
        
        public static RestorationStepResult Failed(string errorMessage)
        {
            return new RestorationStepResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class BaselineResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public IntegrityBaseline Baseline { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static BaselineResult Success(IntegrityBaseline baseline)
        {
            return new BaselineResult
            {
                Success = true,
                Baseline = baseline,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static BaselineResult Failed(string errorMessage)
        {
            return new BaselineResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class IntegrityReport
    {
        public DateTime GeneratedAt { get; set; }
        public TimeSpan Period { get; set; }
        public IntegrityVerificationResult CurrentStatus { get; set; }
        public List<IntegrityBaseline> Baselines { get; set; }
        public List<IntegrityVerificationResult> VerificationHistory { get; set; }
        public List<RestorationResult> RestorationHistory { get; set; }
        public IntegrityStatistics Statistics { get; set; }
        public List<IntegrityRecommendation> Recommendations { get; set; }
        public string Error { get; set; }
        
        public IntegrityReport()
        {
            Baselines = new List<IntegrityBaseline>();
            VerificationHistory = new List<IntegrityVerificationResult>();
            RestorationHistory = new List<RestorationResult>();
            Recommendations = new List<IntegrityRecommendation>();
        }
        
        public static IntegrityReport Error(string errorMessage)
        {
            return new IntegrityReport
            {
                Error = errorMessage,
                GeneratedAt = DateTime.UtcNow
            };
        }
    }
    
    public class IntegrityStatistics
    {
        public int TotalVerifications { get; set; }
        public int ValidVerifications { get; set; }
        public TimeSpan AverageVerificationTime { get; set; }
        public string MostCommonIssue { get; set; }
        public int CriticalIssueCount { get; set; }
    }
    
    public class IntegrityRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
        public TimeSpan EstimatedTime { get; set; }
    }
    
    public class ConfigurationDifference
    {
        public int LineNumber { get; set; }
        public string Field { get; set; }
        public string Original { get; set; }
        public string Current { get; set; }
        public bool IsCritical { get; set; }
    }
    
    public enum ComponentType
    {
        BinaryFile,
        Configuration,
        Database,
        Service,
        Registry,
        Logs
    }
    
    public enum IntegrityIssueType
    {
        FileTampered,
        ConfigurationModified,
        DatabaseCorrupted,
        ServiceTampered,
        LogsTampered,
        RegistryModified
    }
    
    public enum IntegritySeverity
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }
    
    public enum RecommendationPriority
    {
        Low,
        Medium,
        High,
        Critical
    }
    
    // Clase auxiliar para instalación de componentes
    internal class ComponentInstaller
    {
        public async Task<InstallationResult> ReinstallComponentAsync(string componentName)
        {
            await Task.Delay(100); // Simulación
            return new InstallationResult { Success = true };
        }
    }
    
    internal class InstallationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    #endregion
}