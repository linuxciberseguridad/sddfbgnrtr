using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Agent.Detection
{
    /// <summary>
    /// Mapeador de software a CVEs - Conecta vulnerabilidades con software instalado
    /// Genera alertas inteligentes basadas en severidad y contexto
    /// </summary>
    public sealed class SoftwareCveMapper : IAgentModule, ISoftwareVulnerabilityDetector
    {
        private static readonly Lazy<SoftwareCveMapper> _instance = 
            new Lazy<SoftwareCveMapper>(() => new SoftwareCveMapper());
        
        public static SoftwareCveMapper Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly IVulnerabilityStore _vulnerabilityStore;
        private readonly AlertManager _alertManager;
        private readonly TelemetryQueue _telemetryQueue;
        
        private readonly List<SoftwareDetectionRule> _detectionRules;
        private readonly Dictionary<string, DateTime> _lastAlertTimestamps;
        private readonly SemaphoreSlim _processingLock;
        
        private bool _isInitialized;
        private bool _isRunning;
        private Timer _scheduledScanTimer;
        
        private const int SCHEDULED_SCAN_INTERVAL_HOURS = 6;
        private const int ALERT_COOLDOWN_HOURS = 24;
        private const int MAX_CVES_PER_ALERT = 10;
        
        public string ModuleId => "SoftwareCveMapper";
        public string Version => "1.0.0";
        public string Description => "Detección de vulnerabilidades en software instalado";
        
        private SoftwareCveMapper()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _vulnerabilityStore = VulnerabilityStore.Instance;
            _alertManager = AlertManager.Instance;
            _telemetryQueue = TelemetryQueue.Instance;
            
            _detectionRules = new List<SoftwareDetectionRule>();
            _lastAlertTimestamps = new Dictionary<string, DateTime>();
            _processingLock = new SemaphoreSlim(1, 1);
            
            _isInitialized = false;
            _isRunning = false;
        }
        
        /// <summary>
        /// Inicializa el mapeador de software a CVEs
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando SoftwareCveMapper...", ModuleId);
                
                // 1. Cargar reglas de detección
                await LoadDetectionRulesAsync();
                
                // 2. Cargar historial de alertas previas
                await LoadAlertHistoryAsync();
                
                // 3. Inicializar store de vulnerabilidades
                await InitializeVulnerabilityStoreAsync();
                
                // 4. Programar escaneos periódicos
                SchedulePeriodicScans();
                
                _isInitialized = true;
                _logManager.LogInfo($"SoftwareCveMapper inicializado con {_detectionRules.Count} reglas", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar SoftwareCveMapper: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el mapeador
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
                _isRunning = true;
                
                // Ejecutar escaneo inicial
                _ = Task.Run(async () => await PerformInitialScanAsync());
                
                _logManager.LogInfo("SoftwareCveMapper iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar SoftwareCveMapper: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el mapeador
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isRunning = false;
                _scheduledScanTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                
                _logManager.LogInfo("SoftwareCveMapper detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener SoftwareCveMapper: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Pausa el mapeador
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("SoftwareCveMapper pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el mapeador
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("SoftwareCveMapper reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Analiza software instalado y detecta vulnerabilidades
        /// </summary>
        public async Task<List<SoftwareVulnerabilityDetection>> AnalyzeInstalledSoftwareAsync(
            List<InstalledSoftware> softwareList,
            CancellationToken cancellationToken = default)
        {
            if (softwareList == null || softwareList.Count == 0)
                return new List<SoftwareVulnerabilityDetection>();
            
            var results = new List<SoftwareVulnerabilityDetection>();
            
            try
            {
                await _processingLock.WaitAsync(cancellationToken);
                
                try
                {
                    _logManager.LogInfo($"Analizando {softwareList.Count} software instalados", ModuleId);
                    
                    // 1. Filtrar software relevante
                    var relevantSoftware = FilterRelevantSoftware(softwareList);
                    
                    if (!relevantSoftware.Any())
                    {
                        _logManager.LogInfo("No hay software relevante para analizar", ModuleId);
                        return results;
                    }
                    
                    // 2. Verificar vulnerabilidades por lote
                    var batchResults = await _vulnerabilityStore.BatchCheckVulnerabilitiesAsync(
                        relevantSoftware, cancellationToken);
                    
                    // 3. Procesar resultados
                    foreach (var result in batchResults)
                    {
                        if (result.IsVulnerable)
                        {
                            var detection = CreateVulnerabilityDetection(result);
                            results.Add(detection);
                            
                            // 4. Generar alertas si es necesario
                            await ProcessVulnerabilityForAlerts(detection, cancellationToken);
                        }
                    }
                    
                    // 5. Guardar resultados en base de datos
                    await SaveDetectionResultsAsync(results);
                    
                    // 6. Enviar telemetría
                    await SendTelemetryAsync(results);
                    
                    _logManager.LogInfo($"Detectadas {results.Count} vulnerabilidades en software", ModuleId);
                    
                    return results;
                }
                finally
                {
                    _processingLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error analizando software instalado: {ex}", ModuleId);
                return new List<SoftwareVulnerabilityDetection>();
            }
        }
        
        /// <summary>
        /// Escanea todo el sistema en busca de software vulnerable
        /// </summary>
        public async Task<SystemVulnerabilityScanResult> PerformFullSystemScanAsync(
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logManager.LogInfo("Iniciando escaneo completo del sistema", ModuleId);
                
                // 1. Enumerar software instalado
                var installedSoftware = await EnumerateInstalledSoftwareAsync(cancellationToken);
                
                if (!installedSoftware.Any())
                {
                    _logManager.LogWarning("No se pudo enumerar software instalado", ModuleId);
                    return new SystemVulnerabilityScanResult
                    {
                        ScanTimestamp = DateTime.UtcNow,
                        Status = ScanStatus.Failed,
                        Error = "No software found"
                    };
                }
                
                // 2. Analizar vulnerabilidades
                var detections = await AnalyzeInstalledSoftwareAsync(installedSoftware, cancellationToken);
                
                // 3. Calcular métricas de riesgo
                var metrics = CalculateSystemRiskMetrics(detections);
                
                // 4. Generar reporte
                var result = new SystemVulnerabilityScanResult
                {
                    ScanTimestamp = DateTime.UtcNow,
                    Status = ScanStatus.Completed,
                    TotalSoftwareScanned = installedSoftware.Count,
                    VulnerableSoftwareCount = detections.Count,
                    TotalVulnerabilities = detections.Sum(d => d.Vulnerabilities.Count),
                    RiskMetrics = metrics,
                    Detections = detections,
                    Recommendations = GenerateSystemRecommendations(detections, metrics)
                };
                
                // 5. Guardar resultado del escaneo
                await SaveSystemScanResultAsync(result);
                
                // 6. Generar alerta si el riesgo es alto
                if (metrics.OverallRiskScore >= 70) // Alto riesgo
                {
                    await GenerateSystemRiskAlertAsync(result, cancellationToken);
                }
                
                _logManager.LogInfo($"Escaneo completo completado: {result.VulnerableSoftwareCount}/{result.TotalSoftwareScanned} software vulnerable", 
                    ModuleId);
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en escaneo completo del sistema: {ex}", ModuleId);
                
                return new SystemVulnerabilityScanResult
                {
                    ScanTimestamp = DateTime.UtcNow,
                    Status = ScanStatus.Failed,
                    Error = ex.Message
                };
            }
        }
        
        /// <summary>
        /// Verifica vulnerabilidades críticas que requieren acción inmediata
        /// </summary>
        public async Task<List<CriticalSoftwareVulnerability>> GetCriticalVulnerabilitiesAsync(
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Obtener software instalado
                var installedSoftware = await EnumerateInstalledSoftwareAsync(cancellationToken);
                
                // 2. Obtener vulnerabilidades críticas
                var criticalVulns = await _vulnerabilityStore.GetCriticalVulnerabilitiesAsync(
                    installedSoftware, cancellationToken);
                
                // 3. Filtrar por reglas de detección
                var filteredVulns = ApplyDetectionRules(criticalVulns);
                
                // 4. Ordenar por criticidad
                return filteredVulns
                    .OrderByDescending(v => v.CvssScore)
                    .ThenByDescending(v => v.Severity == "CRITICAL")
                    .ThenByDescending(v => v.ExploitedInWild)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo vulnerabilidades críticas: {ex}", ModuleId);
                return new List<CriticalSoftwareVulnerability>();
            }
        }
        
        /// <summary>
        /// Agrega una regla de detección personalizada
        /// </summary>
        public void AddDetectionRule(SoftwareDetectionRule rule)
        {
            if (rule == null)
                throw new ArgumentNullException(nameof(rule));
            
            _detectionRules.Add(rule);
            
            // Guardar en base de datos
            _ = Task.Run(async () => 
            {
                await _localDatabase.SaveDetectionRuleAsync(rule);
            });
            
            _logManager.LogInfo($"Regla de detección agregada: {rule.Name}", ModuleId);
        }
        
        /// <summary>
        /// Elimina una regla de detección
        /// </summary>
        public bool RemoveDetectionRule(string ruleId)
        {
            var rule = _detectionRules.FirstOrDefault(r => r.Id == ruleId);
            if (rule != null)
            {
                _detectionRules.Remove(rule);
                
                // Eliminar de base de datos
                _ = Task.Run(async () => 
                {
                    await _localDatabase.DeleteDetectionRuleAsync(ruleId);
                });
                
                _logManager.LogInfo($"Regla de detección eliminada: {rule.Name}", ModuleId);
                return true;
            }
            
            return false;
        }
        
        /// <summary>
        /// Actualiza el estado de una vulnerabilidad (ej: marcada como falsa positiva)
        /// </summary>
        public async Task<bool> UpdateVulnerabilityStatusAsync(
            string detectionId, 
            VulnerabilityStatus newStatus,
            string notes = null)
        {
            try
            {
                await _localDatabase.UpdateVulnerabilityStatusAsync(detectionId, newStatus, notes);
                
                // Si se marca como falsa positiva, actualizar reglas para evitar futuras alertas
                if (newStatus == VulnerabilityStatus.FalsePositive)
                {
                    await UpdateFalsePositiveRulesAsync(detectionId);
                }
                
                _logManager.LogInfo($"Estado de vulnerabilidad actualizado: {detectionId} -> {newStatus}", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error actualizando estado de vulnerabilidad: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del mapeador
        /// </summary>
        public SoftwareCveMapperStats GetStats()
        {
            return new SoftwareCveMapperStats
            {
                Timestamp = DateTime.UtcNow,
                IsInitialized = _isInitialized,
                IsRunning = _isRunning,
                DetectionRulesCount = _detectionRules.Count,
                LastAlertTimestampsCount = _lastAlertTimestamps.Count,
                TotalScansPerformed = GetTotalScansCount()
            };
        }
        
        #region Métodos privados
        
        private async Task LoadDetectionRulesAsync()
        {
            try
            {
                // Cargar desde base de datos
                var rules = await _localDatabase.GetDetectionRulesAsync();
                _detectionRules.AddRange(rules);
                
                // Si no hay reglas, cargar por defecto
                if (!_detectionRules.Any())
                {
                    LoadDefaultDetectionRules();
                }
                
                _logManager.LogInfo($"Cargadas {_detectionRules.Count} reglas de detección", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando reglas de detección: {ex}", ModuleId);
                LoadDefaultDetectionRules();
            }
        }
        
        private void LoadDefaultDetectionRules()
        {
            // Reglas por defecto para software crítico
            
            // Regla 1: Software de sistema operativo
            AddDetectionRule(new SoftwareDetectionRule
            {
                Id = "SYS001",
                Name = "Critical OS Software",
                Description = "Software crítico del sistema operativo",
                SoftwarePatterns = new List<string> { "windows", "microsoft windows", "win" },
                SeverityThreshold = "MEDIUM",
                AlertEnabled = true,
                AutoRemediate = false,
                Created = DateTime.UtcNow,
                Updated = DateTime.UtcNow,
                IsEnabled = true
            });
            
            // Regla 2: Navegadores web
            AddDetectionRule(new SoftwareDetectionRule
            {
                Id = "BROWSER001",
                Name = "Web Browsers",
                Description = "Navegadores web populares",
                SoftwarePatterns = new List<string> { "chrome", "firefox", "edge", "safari", "opera" },
                SeverityThreshold = "HIGH",
                AlertEnabled = true,
                AutoRemediate = false,
                Created = DateTime.UtcNow,
                Updated = DateTime.UtcNow,
                IsEnabled = true
            });
            
            // Regla 3: Software de oficina
            AddDetectionRule(new SoftwareDetectionRule
            {
                Id = "OFFICE001",
                Name = "Office Software",
                Description = "Software de oficina y productividad",
                SoftwarePatterns = new List<string> { "office", "microsoft office", "excel", "word", "powerpoint" },
                SeverityThreshold = "HIGH",
                AlertEnabled = true,
                AutoRemediate = false,
                Created = DateTime.UtcNow,
                Updated = DateTime.UtcNow,
                IsEnabled = true
            });
            
            // Regla 4: Software de virtualización/remoto
            AddDetectionRule(new SoftwareDetectionRule
            {
                Id = "REMOTE001",
                Name = "Remote Access Software",
                Description = "Software de acceso remoto",
                SoftwarePatterns = new List<string> { "teamviewer", "anydesk", "vnc", "rdp", "remote desktop" },
                SeverityThreshold = "CRITICAL",
                AlertEnabled = true,
                AutoRemediate = true, // Remediar automáticamente software de acceso remoto vulnerable
                Created = DateTime.UtcNow,
                Updated = DateTime.UtcNow,
                IsEnabled = true
            });
            
            // Regla 5: Software de desarrollo
            AddDetectionRule(new SoftwareDetectionRule
            {
                Id = "DEV001",
                Name = "Development Tools",
                Description = "Herramientas de desarrollo",
                SoftwarePatterns = new List<string> { "java", "python", "node.js", "visual studio", "git" },
                SeverityThreshold = "HIGH",
                AlertEnabled = true,
                AutoRemediate = false,
                Created = DateTime.UtcNow,
                Updated = DateTime.UtcNow,
                IsEnabled = true
            });
        }
        
        private async Task LoadAlertHistoryAsync()
        {
            try
            {
                var alerts = await _localDatabase.GetRecentSoftwareAlertsAsync(TimeSpan.FromDays(30));
                
                foreach (var alert in alerts)
                {
                    var key = GenerateAlertKey(alert.SoftwareName, alert.CveId);
                    _lastAlertTimestamps[key] = alert.Timestamp;
                }
                
                _logManager.LogInfo($"Cargado historial de {alerts.Count} alertas", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando historial de alertas: {ex}", ModuleId);
            }
        }
        
        private async Task InitializeVulnerabilityStoreAsync()
        {
            try
            {
                // Inicializar store de vulnerabilidades
                // Esto podría cargar cache inicial de CVEs comunes
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando store de vulnerabilidades: {ex}", ModuleId);
            }
        }
        
        private void SchedulePeriodicScans()
        {
            _scheduledScanTimer = new Timer(async _ => 
            {
                if (_isRunning)
                {
                    await PerformScheduledScanAsync();
                }
            }, null, TimeSpan.FromHours(SCHEDULED_SCAN_INTERVAL_HOURS), 
               TimeSpan.FromHours(SCHEDULED_SCAN_INTERVAL_HOURS));
            
            _logManager.LogInfo($"Escaneos programados cada {SCHEDULED_SCAN_INTERVAL_HOURS} horas", ModuleId);
        }
        
        private async Task PerformInitialScanAsync()
        {
            try
            {
                _logManager.LogInfo("Ejecutando escaneo inicial de software", ModuleId);
                
                await PerformFullSystemScanAsync();
                
                _logManager.LogInfo("Escaneo inicial completado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en escaneo inicial: {ex}", ModuleId);
            }
        }
        
        private async Task PerformScheduledScanAsync()
        {
            try
            {
                if (!_isRunning)
                    return;
                
                _logManager.LogInfo("Ejecutando escaneo programado de software", ModuleId);
                
                await PerformFullSystemScanAsync();
                
                _logManager.LogInfo("Escaneo programado completado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en escaneo programado: {ex}", ModuleId);
            }
        }
        
        private List<InstalledSoftware> FilterRelevantSoftware(List<InstalledSoftware> softwareList)
        {
            var relevantSoftware = new List<InstalledSoftware>();
            
            foreach (var software in softwareList)
            {
                // Filtrar software de sistema no crítico
                if (IsSystemNoise(software))
                    continue;
                
                // Aplicar reglas de detección
                var matchingRules = _detectionRules.Where(r => 
                    r.IsEnabled && 
                    r.MatchesSoftware(software.Name)).ToList();
                
                if (matchingRules.Any())
                {
                    relevantSoftware.Add(software);
                }
            }
            
            return relevantSoftware;
        }
        
        private bool IsSystemNoise(InstalledSoftware software)
        {
            // Filtrar software de sistema que no es relevante para seguridad
            var noisePatterns = new[]
            {
                "microsoft visual c++",
                "microsoft .net",
                "windows update",
                "intel",
                "amd",
                "nvidia",
                "realtek",
                "broadcom",
                "qualcomm"
            };
            
            return noisePatterns.Any(pattern => 
                software.Name?.Contains(pattern, StringComparison.OrdinalIgnoreCase) == true);
        }
        
        private SoftwareVulnerabilityDetection CreateVulnerabilityDetection(VulnerabilityCheckResult result)
        {
            var detection = new SoftwareVulnerabilityDetection
            {
                DetectionId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                SoftwareName = result.SoftwareName,
                SoftwareVersion = result.SoftwareVersion,
                IsVulnerable = true,
                RiskLevel = result.RiskLevel,
                MaxCvssScore = result.MaxCvssScore,
                CriticalCount = result.CriticalCount,
                HighCount = result.HighCount,
                MediumCount = result.MediumCount,
                LowCount = result.LowCount,
                Vulnerabilities = result.Vulnerabilities?.Take(MAX_CVES_PER_ALERT).ToList() ?? new List<CveEntry>(),
                TotalVulnerabilityCount = result.Vulnerabilities?.Count ?? 0,
                ExploitedCount = result.ExploitedCount,
                PatchAvailableCount = result.PatchAvailableCount,
                Status = DetectionStatus.New,
                DetectionRules = GetMatchingRules(result.SoftwareName)
            };
            
            // Añadir recomendaciones
            detection.Recommendations = GenerateRecommendations(detection);
            
            return detection;
        }
        
        private async Task ProcessVulnerabilityForAlerts(
            SoftwareVulnerabilityDetection detection,
            CancellationToken cancellationToken)
        {
            try
            {
                // Verificar si ya alertamos recientemente
                if (ShouldSkipAlert(detection))
                {
                    _logManager.LogDebug($"Saltando alerta por cooldown para {detection.SoftwareName}", ModuleId);
                    return;
                }
                
                // Verificar umbral de severidad
                var matchingRules = detection.DetectionRules
                    .Where(r => r.SeverityThreshold != null && 
                           IsSeverityAboveThreshold(detection.RiskLevel, r.SeverityThreshold))
                    .ToList();
                
                if (!matchingRules.Any(r => r.AlertEnabled))
                {
                    _logManager.LogDebug($"Ninguna regla habilita alerta para {detection.SoftwareName}", ModuleId);
                    return;
                }
                
                // Crear alerta
                var alert = CreateSoftwareAlert(detection, matchingRules);
                
                // Enviar alerta
                await _alertManager.SendAlertAsync(alert, cancellationToken);
                
                // Registrar timestamp de alerta
                RegisterAlertTimestamp(detection);
                
                // Guardar alerta en base de datos
                await _localDatabase.SaveSoftwareAlertAsync(alert);
                
                _logManager.LogWarning($"Alerta de vulnerabilidad generada: {detection.SoftwareName} - {detection.RiskLevel}", 
                    ModuleId);
                
                // Remediar automáticamente si está configurado
                if (matchingRules.Any(r => r.AutoRemediate))
                {
                    await AttemptAutoRemediationAsync(detection, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error procesando vulnerabilidad para alertas: {ex}", ModuleId);
            }
        }
        
        private bool ShouldSkipAlert(SoftwareVulnerabilityDetection detection)
        {
            // Verificar cooldown por software
            var softwareKey = $"{detection.SoftwareName}:{detection.SoftwareVersion}";
            if (_lastAlertTimestamps.TryGetValue(softwareKey, out var lastAlert))
            {
                var timeSinceLastAlert = DateTime.UtcNow - lastAlert;
                if (timeSinceLastAlert.TotalHours < ALERT_COOLDOWN_HOURS)
                {
                    return true;
                }
            }
            
            // Verificar cooldown por CVE específico
            foreach (var cve in detection.Vulnerabilities.Take(3)) // Revisar primeros 3 CVEs
            {
                var cveKey = $"{detection.SoftwareName}:{cve.Id}";
                if (_lastAlertTimestamps.TryGetValue(cveKey, out lastAlert))
                {
                    var timeSinceLastAlert = DateTime.UtcNow - lastAlert;
                    if (timeSinceLastAlert.TotalHours < ALERT_COOLDOWN_HOURS)
                    {
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        private void RegisterAlertTimestamp(SoftwareVulnerabilityDetection detection)
        {
            var softwareKey = $"{detection.SoftwareName}:{detection.SoftwareVersion}";
            _lastAlertTimestamps[softwareKey] = DateTime.UtcNow;
            
            // También registrar por CVE críticos
            foreach (var cve in detection.Vulnerabilities.Where(v => 
                v.Severity == "CRITICAL" || v.Severity == "HIGH"))
            {
                var cveKey = $"{detection.SoftwareName}:{cve.Id}";
                _lastAlertTimestamps[cveKey] = DateTime.UtcNow;
            }
            
            // Limitar tamaño del diccionario
            if (_lastAlertTimestamps.Count > 1000)
            {
                var oldest = _lastAlertTimestamps.OrderBy(kv => kv.Value).First();
                _lastAlertTimestamps.Remove(oldest.Key);
            }
        }
        
        private bool IsSeverityAboveThreshold(string severity, string threshold)
        {
            var severityOrder = new[] { "LOW", "MEDIUM", "HIGH", "CRITICAL" };
            
            var severityIndex = Array.IndexOf(severityOrder, severity?.ToUpper() ?? "LOW");
            var thresholdIndex = Array.IndexOf(severityOrder, threshold?.ToUpper() ?? "LOW");
            
            return severityIndex >= thresholdIndex;
        }
        
        private SoftwareAlert CreateSoftwareAlert(
            SoftwareVulnerabilityDetection detection,
            List<SoftwareDetectionRule> matchingRules)
        {
            var alert = new SoftwareAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                SoftwareName = detection.SoftwareName,
                SoftwareVersion = detection.SoftwareVersion,
                Severity = MapToAlertSeverity(detection.RiskLevel),
                Title = $"Vulnerabilidad en {detection.SoftwareName} {detection.SoftwareVersion}",
                Description = GenerateAlertDescription(detection),
                Details = new Dictionary<string, object>
                {
                    { "RiskLevel", detection.RiskLevel },
                    { "MaxCvssScore", detection.MaxCvssScore },
                    { "CriticalCount", detection.CriticalCount },
                    { "HighCount", detection.HighCount },
                    { "TotalVulnerabilities", detection.TotalVulnerabilityCount },
                    { "TopCves", detection.Vulnerabilities.Take(3).Select(c => c.Id).ToList() },
                    { "MatchingRules", matchingRules.Select(r => r.Name).ToList() }
                },
                Recommendations = detection.Recommendations,
                Status = AlertStatus.Active,
                Source = ModuleId
            };
            
            return alert;
        }
        
        private string GenerateAlertDescription(SoftwareVulnerabilityDetection detection)
        {
            if (detection.Vulnerabilities.Count == 0)
                return $"Software {detection.SoftwareName} {detection.SoftwareVersion} es vulnerable";
            
            var topCve = detection.Vulnerabilities.OrderByDescending(c => 
                c.CvssMetrics?.Max(m => m.BaseScore) ?? 0).FirstOrDefault();
            
            if (topCve != null)
            {
                return $"{detection.SoftwareName} {detection.SoftwareVersion} tiene {detection.TotalVulnerabilityCount} vulnerabilidades, incluyendo {topCve.Id} ({topCve.Severity})";
            }
            
            return $"{detection.SoftwareName} {detection.SoftwareVersion} tiene {detection.TotalVulnerabilityCount} vulnerabilidades";
        }
        
        private AlertSeverity MapToAlertSeverity(string riskLevel)
        {
            return riskLevel?.ToUpper() switch
            {
                "CRITICAL" => AlertSeverity.Critical,
                "HIGH" => AlertSeverity.High,
                "MEDIUM" => AlertSeverity.Medium,
                "LOW" => AlertSeverity.Low,
                _ => AlertSeverity.Medium
            };
        }
        
        private List<SoftwareDetectionRule> GetMatchingRules(string softwareName)
        {
            return _detectionRules
                .Where(r => r.IsEnabled && r.MatchesSoftware(softwareName))
                .ToList();
        }
        
        private List<string> GenerateRecommendations(SoftwareVulnerabilityDetection detection)
        {
            var recommendations = new List<string>();
            
            if (detection.Vulnerabilities.Count > 0)
            {
                recommendations.Add($"Actualizar {detection.SoftwareName} a la versión más reciente");
                
                if (detection.PatchAvailableCount > 0)
                {
                    recommendations.Add($"Aplicar parches disponibles ({detection.PatchAvailableCount} parches identificados)");
                }
                
                if (detection.ExploitedCount > 0)
                {
                    recommendations.Add($"{detection.ExploitedCount} vulnerabilidades están siendo explotadas activamente - acción inmediata requerida");
                }
                
                if (detection.CriticalCount > 0)
                {
                    recommendations.Add($"{detection.CriticalCount} vulnerabilidades CRÍTICAS requieren atención prioritaria");
                }
            }
            
            return recommendations;
        }
        
        private async Task AttemptAutoRemediationAsync(
            SoftwareVulnerabilityDetection detection,
            CancellationToken cancellationToken)
        {
            try
            {
                // Solo remediar automáticamente si es crítico y tenemos reglas que lo permiten
                if (detection.RiskLevel != "CRITICAL")
                    return;
                
                _logManager.LogWarning($"Intentando remediación automática para {detection.SoftwareName}", ModuleId);
                
                // Implementar lógica de remediación específica
                // Por ahora solo log
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en remediación automática: {ex}", ModuleId);
            }
        }
        
        private async Task<List<InstalledSoftware>> EnumerateInstalledSoftwareAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                // Implementar enumeración real de software instalado
                // Por ahora retornar lista vacía
                
                await Task.CompletedTask;
                return new List<InstalledSoftware>();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error enumerando software instalado: {ex}", ModuleId);
                return new List<InstalledSoftware>();
            }
        }
        
        private RiskMetrics CalculateSystemRiskMetrics(List<SoftwareVulnerabilityDetection> detections)
        {
            var metrics = new RiskMetrics();
            
            if (!detections.Any())
                return metrics;
            
            metrics.TotalVulnerabilities = detections.Sum(d => d.TotalVulnerabilityCount);
            metrics.CriticalVulnerabilities = detections.Sum(d => d.CriticalCount);
            metrics.HighVulnerabilities = detections.Sum(d => d.HighCount);
            metrics.MediumVulnerabilities = detections.Sum(d => d.MediumCount);
            metrics.LowVulnerabilities = detections.Sum(d => d.LowCount);
            metrics.MaxCvssScore = detections.Max(d => d.MaxCvssScore);
            metrics.AverageCvssScore = detections.Average(d => d.MaxCvssScore);
            metrics.ExploitedVulnerabilities = detections.Sum(d => d.ExploitedCount);
            metrics.PatchedVulnerabilities = detections.Sum(d => d.PatchAvailableCount);
            metrics.RiskScore = CalculateOverallRiskScore(detections);
            
            return metrics;
        }
        
        private double CalculateOverallRiskScore(List<SoftwareVulnerabilityDetection> detections)
        {
            double score = 0;
            
            foreach (var detection in detections)
            {
                var weight = detection.RiskLevel switch
                {
                    "CRITICAL" => 1.0,
                    "HIGH" => 0.7,
                    "MEDIUM" => 0.4,
                    "LOW" => 0.1,
                    _ => 0
                };
                
                score += weight * detection.TotalVulnerabilityCount * (1 + (detection.MaxCvssScore / 10));
            }
            
            // Normalizar a escala 0-100
            return Math.Min(100, score * 5);
        }
        
        private List<string> GenerateSystemRecommendations(
            List<SoftwareVulnerabilityDetection> detections,
            RiskMetrics metrics)
        {
            var recommendations = new List<string>();
            
            if (detections.Count == 0)
            {
                recommendations.Add("No se encontraron vulnerabilidades en el sistema");
                return recommendations;
            }
            
            recommendations.Add($"Se encontraron {detections.Count} software con vulnerabilidades");
            
            if (metrics.CriticalVulnerabilities > 0)
            {
                recommendations.Add($"{metrics.CriticalVulnerabilities} vulnerabilidades CRÍTICAS requieren atención inmediata");
            }
            
            if (metrics.HighVulnerabilities > 0)
            {
                recommendations.Add($"{metrics.HighVulnerabilities} vulnerabilidades ALTAS deben ser priorizadas");
            }
            
            if (metrics.ExploitedVulnerabilities > 0)
            {
                recommendations.Add($"{metrics.ExploitedVulnerabilities} vulnerabilidades están siendo explotadas activamente");
            }
            
            // Recomendaciones específicas por software
            var criticalSoftware = detections.Where(d => d.RiskLevel == "CRITICAL").ToList();
            if (criticalSoftware.Any())
            {
                recommendations.Add("Software crítico que requiere actualización:");
                foreach (var software in criticalSoftware.Take(3))
                {
                    recommendations.Add($"  - {software.SoftwareName} {software.SoftwareVersion}");
                }
            }
            
            return recommendations;
        }
        
        private async Task SaveDetectionResultsAsync(List<SoftwareVulnerabilityDetection> detections)
        {
            try
            {
                await _localDatabase.SaveSoftwareDetectionsAsync(detections);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando resultados de detección: {ex}", ModuleId);
            }
        }
        
        private async Task SaveSystemScanResultAsync(SystemVulnerabilityScanResult result)
        {
            try
            {
                await _localDatabase.SaveSystemScanResultAsync(result);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando resultado de escaneo: {ex}", ModuleId);
            }
        }
        
        private async Task SendTelemetryAsync(List<SoftwareVulnerabilityDetection> detections)
        {
            try
            {
                foreach (var detection in detections)
                {
                    var telemetryEvent = new TelemetryEvent
                    {
                        EventId = detection.DetectionId,
                        Timestamp = detection.Timestamp,
                        EventType = "SoftwareVulnerabilityDetected",
                        Severity = detection.RiskLevel,
                        Data = new Dictionary<string, object>
                        {
                            { "softwareName", detection.SoftwareName },
                            { "softwareVersion", detection.SoftwareVersion },
                            { "riskLevel", detection.RiskLevel },
                            { "maxCvssScore", detection.MaxCvssScore },
                            { "criticalCount", detection.CriticalCount },
                            { "highCount", detection.HighCount },
                            { "totalVulnerabilities", detection.TotalVulnerabilityCount }
                        }
                    };
                    
                    await _telemetryQueue.EnqueueAsync(telemetryEvent);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error enviando telemetría: {ex}", ModuleId);
            }
        }
        
        private async Task GenerateSystemRiskAlertAsync(
            SystemVulnerabilityScanResult result,
            CancellationToken cancellationToken)
        {
            try
            {
                var alert = new SoftwareAlert
                {
                    AlertId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    SoftwareName = "System",
                    SoftwareVersion = "Multiple",
                    Severity = AlertSeverity.Critical,
                    Title = $"ALTO RIESGO DEL SISTEMA: Score {result.RiskMetrics.RiskScore:F1}/100",
                    Description = $"El sistema tiene {result.VulnerableSoftwareCount} software vulnerable con {result.TotalVulnerabilities} vulnerabilidades totales",
                    Details = new Dictionary<string, object>
                    {
                        { "RiskScore", result.RiskMetrics.RiskScore },
                        { "CriticalVulnerabilities", result.RiskMetrics.CriticalVulnerabilities },
                        { "HighVulnerabilities", result.RiskMetrics.HighVulnerabilities },
                        { "ExploitedVulnerabilities", result.RiskMetrics.ExploitedVulnerabilities }
                    },
                    Recommendations = result.Recommendations,
                    Status = AlertStatus.Active,
                    Source = ModuleId
                };
                
                await _alertManager.SendAlertAsync(alert, cancellationToken);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando alerta de riesgo del sistema: {ex}", ModuleId);
            }
        }
        
        private List<CriticalSoftwareVulnerability> ApplyDetectionRules(
            List<CriticalSoftwareVulnerability> vulnerabilities)
        {
            var filtered = new List<CriticalSoftwareVulnerability>();
            
            foreach (var vuln in vulnerabilities)
            {
                var matchingRules = _detectionRules.Where(r => 
                    r.IsEnabled && 
                    r.AlertEnabled &&
                    r.MatchesSoftware(vuln.SoftwareName) &&
                    IsSeverityAboveThreshold(vuln.Severity, r.SeverityThreshold))
                    .ToList();
                
                if (matchingRules.Any())
                {
                    // Añadir reglas coincidentes a los detalles
                    vuln.MitigationSteps.AddRange(matchingRules
                        .Where(r => r.AutoRemediate)
                        .Select(r => $"Auto-remediación habilitada por regla: {r.Name}"));
                    
                    filtered.Add(vuln);
                }
            }
            
            return filtered;
        }
        
        private async Task UpdateFalsePositiveRulesAsync(string detectionId)
        {
            try
            {
                // Obtener detección
                var detection = await _localDatabase.GetSoftwareDetectionAsync(detectionId);
                if (detection == null)
                    return;
                
                // Crear regla para evitar futuras alertas del mismo CVE en este software
                var rule = new SoftwareDetectionRule
                {
                    Id = $"FP_{detectionId.Substring(0, 8)}",
                    Name = $"False Positive: {detection.SoftwareName}",
                    Description = $"Marcado como falso positivo el {DateTime.UtcNow:yyyy-MM-dd}",
                    SoftwarePatterns = new List<string> { detection.SoftwareName },
                    CvePatterns = detection.Vulnerabilities.Select(c => c.Id).ToList(),
                    SeverityThreshold = "CRITICAL", // Solo ignorar si es crítico
                    AlertEnabled = false, // Deshabilitar alertas
                    AutoRemediate = false,
                    Created = DateTime.UtcNow,
                    Updated = DateTime.UtcNow,
                    IsEnabled = true,
                    IsFalsePositiveRule = true
                };
                
                AddDetectionRule(rule);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error actualizando reglas de falsos positivos: {ex}", ModuleId);
            }
        }
        
        private string GenerateAlertKey(string softwareName, string cveId)
        {
            return $"{softwareName}:{cveId}";
        }
        
        private long GetTotalScansCount()
        {
            // Implementar contador real
            return 0;
        }
        
        #endregion
    }
    
    #region Modelos de datos
    
    public interface ISoftwareVulnerabilityDetector
    {
        Task<List<SoftwareVulnerabilityDetection>> AnalyzeInstalledSoftwareAsync(
            List<InstalledSoftware> softwareList, CancellationToken cancellationToken = default);
        Task<SystemVulnerabilityScanResult> PerformFullSystemScanAsync(CancellationToken cancellationToken = default);
        Task<List<CriticalSoftwareVulnerability>> GetCriticalVulnerabilitiesAsync(CancellationToken cancellationToken = default);
    }
    
    public class SoftwareVulnerabilityDetection
    {
        public string DetectionId { get; set; }
        public DateTime Timestamp { get; set; }
        public string SoftwareName { get; set; }
        public string SoftwareVersion { get; set; }
        public bool IsVulnerable { get; set; }
        public string RiskLevel { get; set; }
        public double MaxCvssScore { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int TotalVulnerabilityCount { get; set; }
        public int ExploitedCount { get; set; }
        public int PatchAvailableCount { get; set; }
        public List<CveEntry> Vulnerabilities { get; set; }
        public List<SoftwareDetectionRule> DetectionRules { get; set; }
        public List<string> Recommendations { get; set; }
        public DetectionStatus Status { get; set; }
        
        public SoftwareVulnerabilityDetection()
        {
            Vulnerabilities = new List<CveEntry>();
            DetectionRules = new List<SoftwareDetectionRule>();
            Recommendations = new List<string>();
        }
    }
    
    public enum DetectionStatus
    {
        New,
        Investigating,
        Remediating,
        Resolved,
        FalsePositive,
        RiskAccepted
    }
    
    public class SoftwareDetectionRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<string> SoftwarePatterns { get; set; }
        public List<string> CvePatterns { get; set; }
        public string SeverityThreshold { get; set; } // CRITICAL, HIGH, MEDIUM, LOW
        public bool AlertEnabled { get; set; }
        public bool AutoRemediate { get; set; }
        public DateTime Created { get; set; }
        public DateTime Updated { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsFalsePositiveRule { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public SoftwareDetectionRule()
        {
            SoftwarePatterns = new List<string>();
            CvePatterns = new List<string>();
            Metadata = new Dictionary<string, object>();
        }
        
        public bool MatchesSoftware(string softwareName)
        {
            if (string.IsNullOrEmpty(softwareName) || !SoftwarePatterns.Any())
                return false;
            
            return SoftwarePatterns.Any(pattern => 
                softwareName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }
        
        public bool MatchesCve(string cveId)
        {
            if (string.IsNullOrEmpty(cveId) || !CvePatterns.Any())
                return false;
            
            return CvePatterns.Any(pattern => 
                cveId.Equals(pattern, StringComparison.OrdinalIgnoreCase));
        }
    }
    
    public class SystemVulnerabilityScanResult
    {
        public DateTime ScanTimestamp { get; set; }
        public ScanStatus Status { get; set; }
        public string Error { get; set; }
        public int TotalSoftwareScanned { get; set; }
        public int VulnerableSoftwareCount { get; set; }
        public int TotalVulnerabilities { get; set; }
        public RiskMetrics RiskMetrics { get; set; }
        public List<SoftwareVulnerabilityDetection> Detections { get; set; }
        public List<string> Recommendations { get; set; }
        
        public SystemVulnerabilityScanResult()
        {
            Detections = new List<SoftwareVulnerabilityDetection>();
            Recommendations = new List<string>();
        }
    }
    
    public enum ScanStatus
    {
        NotStarted,
        InProgress,
        Completed,
        Failed,
        Cancelled
    }
    
    public enum VulnerabilityStatus
    {
        New,
        Confirmed,
        Investigating,
        Remediating,
        Resolved,
        FalsePositive,
        RiskAccepted
    }
    
    public class CriticalSoftwareVulnerability
    {
        public string CveId { get; set; }
        public string SoftwareName { get; set; }
        public string SoftwareVersion { get; set; }
        public string Severity { get; set; }
        public double CvssScore { get; set; }
        public string Description { get; set; }
        public DateTime PublishedDate { get; set; }
        public bool ExploitedInWild { get; set; }
        public bool PatchAvailable { get; set; }
        public List<string> MitigationSteps { get; set; }
        
        public CriticalSoftwareVulnerability()
        {
            MitigationSteps = new List<string>();
        }
    }
    
    public class SoftwareCveMapperStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsInitialized { get; set; }
        public bool IsRunning { get; set; }
        public int DetectionRulesCount { get; set; }
        public int LastAlertTimestampsCount { get; set; }
        public long TotalScansPerformed { get; set; }
    }
    
    // Modelos de alerta (extendidos)
    public class SoftwareAlert
    {
        public string AlertId { get; set; }
        public DateTime Timestamp { get; set; }
        public string SoftwareName { get; set; }
        public string SoftwareVersion { get; set; }
        public AlertSeverity Severity { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public Dictionary<string, object> Details { get; set; }
        public List<string> Recommendations { get; set; }
        public AlertStatus Status { get; set; }
        public string Source { get; set; }
        
        public SoftwareAlert()
        {
            Details = new Dictionary<string, object>();
            Recommendations = new List<string>();
        }
    }
    
    public enum AlertSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }
    
    public enum AlertStatus
    {
        Active,
        Acknowledged,
        Investigating,
        Resolved,
        FalsePositive
    }
    
    #endregion
}