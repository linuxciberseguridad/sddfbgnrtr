using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Sensors;
using BWP.Enterprise.Agent.Storage;

namespace BWP.Enterprise.Agent.Detection
{
    /// <summary>
    /// Calculador de score de riesgo para endpoints
    /// Combina alertas y eventos para calcular riesgo global
    /// </summary>
    public sealed class RiskScoreCalculator : IAgentModule, IRiskCalculator
    {
        private static readonly Lazy<RiskScoreCalculator> _instance = 
            new Lazy<RiskScoreCalculator>(() => new RiskScoreCalculator());
        
        public static RiskScoreCalculator Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly ConcurrentDictionary<string, EndpointRiskProfile> _riskProfiles;
        private readonly RiskScoringModel _scoringModel;
        private readonly RiskHistoryManager _historyManager;
        private bool _isInitialized;
        private bool _isRunning;
        private Task _calculationTask;
        private CancellationTokenSource _cancellationTokenSource;
        private const int RISK_UPDATE_INTERVAL_MINUTES = 5;
        private const int MAX_HISTORY_DAYS = 30;
        private const double RISK_DECAY_RATE = 0.1; // 10% de reducción por hora sin incidentes
        
        public string ModuleId => "RiskScoreCalculator";
        public string Version => "1.0.0";
        public string Description => "Calculador de score de riesgo para endpoints";
        
        private RiskScoreCalculator()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _riskProfiles = new ConcurrentDictionary<string, EndpointRiskProfile>();
            _scoringModel = new RiskScoringModel();
            _historyManager = new RiskHistoryManager();
            _isInitialized = false;
            _isRunning = false;
            _cancellationTokenSource = new CancellationTokenSource();
        }
        
        /// <summary>
        /// Inicializa el calculador de riesgo
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando RiskScoreCalculator...", ModuleId);
                
                // Cargar perfiles de riesgo desde base de datos
                await LoadRiskProfilesAsync();
                
                // Inicializar modelo de scoring
                await InitializeScoringModelAsync();
                
                // Cargar historial de riesgo
                await LoadRiskHistoryAsync();
                
                _isInitialized = true;
                _logManager.LogInfo($"RiskScoreCalculator inicializado: {_riskProfiles.Count} perfiles cargados", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar RiskScoreCalculator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el cálculo de riesgo
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
                
                // Iniciar tarea de cálculo continuo
                _calculationTask = Task.Run(() => CalculateRiskContinuouslyAsync(_cancellationTokenSource.Token));
                
                _logManager.LogInfo("RiskScoreCalculator iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar RiskScoreCalculator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el calculador de riesgo
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isRunning = false;
                _cancellationTokenSource.Cancel();
                
                if (_calculationTask != null)
                {
                    await _calculationTask;
                }
                
                // Guardar perfiles antes de detener
                await SaveRiskProfilesAsync();
                await SaveRiskHistoryAsync();
                
                _logManager.LogInfo("RiskScoreCalculator detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener RiskScoreCalculator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Pausa el cálculo
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("RiskScoreCalculator pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el cálculo
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("RiskScoreCalculator reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Calcula score de riesgo para un endpoint
        /// </summary>
        public async Task<RiskAssessment> CalculateRiskAsync(string endpointId = null)
        {
            try
            {
                endpointId ??= GetCurrentEndpointId();
                
                // Obtener o crear perfil de riesgo
                var riskProfile = GetOrCreateRiskProfile(endpointId);
                
                // Recolectar datos para cálculo
                var riskData = await CollectRiskDataAsync(endpointId);
                
                // Calcular componentes del riesgo
                var components = await CalculateRiskComponentsAsync(riskData, riskProfile);
                
                // Calcular score total
                var totalScore = CalculateTotalRiskScore(components);
                
                // Actualizar perfil con nuevo cálculo
                UpdateRiskProfile(riskProfile, totalScore, components);
                
                // Crear assessment
                var assessment = CreateRiskAssessment(riskProfile, totalScore, components);
                
                // Guardar en historial
                await SaveRiskAssessmentAsync(assessment);
                
                _logManager.LogDebug($"Risk score calculado para {endpointId}: {totalScore}", ModuleId);
                
                return assessment;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al calcular riesgo: {ex}", ModuleId);
                return CreateErrorAssessment(ex);
            }
        }
        
        /// <summary>
        /// Calcula score de riesgo basado en resultado de correlación
        /// </summary>
        public async Task<int> CalculateRiskAsync(CorrelationResult correlationResult)
        {
            try
            {
                if (correlationResult == null)
                {
                    return 0;
                }
                
                // Factores de riesgo para correlación
                var baseScore = 50; // Score base para correlaciones
                
                // Ajustar por confianza
                var confidenceFactor = correlationResult.Confidence * 100;
                
                // Ajustar por severidad del patrón
                var severityFactor = GetPatternSeverityFactor(correlationResult.PatternType);
                
                // Ajustar por número de eventos correlacionados
                var eventCountFactor = Math.Min(correlationResult.RelatedEvents.Count / 10.0 * 20, 30);
                
                // Ajustar por timeframe (eventos más cercanos en tiempo = mayor riesgo)
                var timeFactor = CalculateTimeDensityFactor(correlationResult.RelatedEvents);
                
                // Calcular score total
                var totalScore = (int)(baseScore + confidenceFactor + severityFactor + eventCountFactor + timeFactor);
                
                // Limitar a 0-100
                totalScore = Math.Clamp(totalScore, 0, 100);
                
                _logManager.LogDebug($"Risk score para correlación {correlationResult.PatternName}: {totalScore}", ModuleId);
                
                return totalScore;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al calcular riesgo de correlación: {ex}", ModuleId);
                return 0;
            }
        }
        
        /// <summary>
        /// Calcula riesgo para múltiples endpoints
        /// </summary>
        public async Task<List<RiskAssessment>> CalculateRiskForAllEndpointsAsync()
        {
            var assessments = new ConcurrentBag<RiskAssessment>();
            
            try
            {
                // Calcular riesgo para cada perfil
                var tasks = _riskProfiles.Keys.Select(async endpointId =>
                {
                    try
                    {
                        var assessment = await CalculateRiskAsync(endpointId);
                        assessments.Add(assessment);
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error al calcular riesgo para {endpointId}: {ex}", ModuleId);
                    }
                });
                
                await Task.WhenAll(tasks);
                
                // Ordenar por score descendente
                return assessments.OrderByDescending(a => a.OverallScore).ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en CalculateRiskForAllEndpointsAsync: {ex}", ModuleId);
                return new List<RiskAssessment>();
            }
        }
        
        /// <summary>
        /// Obtiene el riesgo actual del endpoint
        /// </summary>
        public async Task<int> GetCurrentRiskScoreAsync()
        {
            var endpointId = GetCurrentEndpointId();
            
            if (_riskProfiles.TryGetValue(endpointId, out var profile))
            {
                // Aplicar decay si ha pasado tiempo desde última actualización
                var timeSinceLastUpdate = DateTime.UtcNow - profile.LastCalculation;
                var decayFactor = Math.Pow(1 - RISK_DECAY_RATE, timeSinceLastUpdate.TotalHours);
                
                return (int)(profile.CurrentScore * decayFactor);
            }
            
            return 0;
        }
        
        /// <summary>
        /// Obtiene tendencia de riesgo
        /// </summary>
        public async Task<RiskTrend> GetRiskTrendAsync(string endpointId = null, int days = 7)
        {
            endpointId ??= GetCurrentEndpointId();
            
            try
            {
                var history = await _historyManager.GetRiskHistoryAsync(endpointId, days);
                
                if (history.Count < 2)
                {
                    return new RiskTrend
                    {
                        EndpointId = endpointId,
                        Trend = TrendDirection.Stable,
                        Confidence = 0,
                        ChangeAmount = 0
                    };
                }
                
                // Calcular tendencia usando regresión lineal simple
                var recentScores = history.TakeLast(24).Select(h => h.Score).ToList();
                
                if (recentScores.Count < 2)
                {
                    return new RiskTrend
                    {
                        EndpointId = endpointId,
                        Trend = TrendDirection.Stable,
                        Confidence = 0,
                        ChangeAmount = 0
                    };
                }
                
                var (slope, confidence) = CalculateLinearTrend(recentScores);
                
                var trend = slope > 0.5 ? TrendDirection.Increasing :
                           slope < -0.5 ? TrendDirection.Decreasing :
                           TrendDirection.Stable;
                
                return new RiskTrend
                {
                    EndpointId = endpointId,
                    Trend = trend,
                    Confidence = confidence,
                    ChangeAmount = slope,
                    RecentScores = recentScores,
                    HistoricalAverage = history.Average(h => h.Score)
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al obtener tendencia de riesgo: {ex}", ModuleId);
                return new RiskTrend
                {
                    EndpointId = endpointId,
                    Trend = TrendDirection.Unknown,
                    Confidence = 0,
                    ChangeAmount = 0
                };
            }
        }
        
        /// <summary>
        /// Agrega evento de detección al cálculo de riesgo
        /// </summary>
        public async Task AddDetectionToRiskAsync(DetectionResult detection)
        {
            try
            {
                var endpointId = GetCurrentEndpointId();
                
                if (!_riskProfiles.TryGetValue(endpointId, out var profile))
                {
                    profile = CreateRiskProfile(endpointId);
                    _riskProfiles[endpointId] = profile;
                }
                
                // Actualizar contadores de detección
                profile.DetectionCount++;
                profile.LastDetection = DateTime.UtcNow;
                
                // Actualizar contadores por severidad
                switch (detection.Severity)
                {
                    case ThreatSeverity.Critical:
                        profile.CriticalDetections++;
                        break;
                    case ThreatSeverity.High:
                        profile.HighDetections++;
                        break;
                    case ThreatSeverity.Medium:
                        profile.MediumDetections++;
                        break;
                    case ThreatSeverity.Low:
                        profile.LowDetections++;
                        break;
                }
                
                // Actualizar contadores por tipo
                if (!profile.DetectionTypes.ContainsKey(detection.DetectionType))
                {
                    profile.DetectionTypes[detection.DetectionType] = 0;
                }
                profile.DetectionTypes[detection.DetectionType]++;
                
                // Actualizar perfil con evento específico
                UpdateProfileWithDetection(profile, detection);
                
                _logManager.LogDebug($"Detección agregada a riesgo: {detection.ThreatName} - Severidad: {detection.Severity}", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al agregar detección a riesgo: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Agrega alerta al cálculo de riesgo
        /// </summary>
        public async Task AddAlertToRiskAsync(SecurityAlert alert)
        {
            try
            {
                var endpointId = GetCurrentEndpointId();
                
                if (!_riskProfiles.TryGetValue(endpointId, out var profile))
                {
                    profile = CreateRiskProfile(endpointId);
                    _riskProfiles[endpointId] = profile;
                }
                
                // Actualizar contadores de alertas
                profile.AlertCount++;
                profile.LastAlert = DateTime.UtcNow;
                
                // Actualizar contadores por severidad
                switch (alert.Severity)
                {
                    case ThreatSeverity.Critical:
                        profile.CriticalAlerts++;
                        break;
                    case ThreatSeverity.High:
                        profile.HighAlerts++;
                        break;
                    case ThreatSeverity.Medium:
                        profile.MediumAlerts++;
                        break;
                    case ThreatSeverity.Low:
                        profile.LowAlerts++;
                        break;
                }
                
                // Actualizar perfil con alerta específica
                UpdateProfileWithAlert(profile, alert);
                
                _logManager.LogDebug($"Alerta agregada a riesgo: {alert.Title} - Severidad: {alert.Severity}", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al agregar alerta a riesgo: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene factores de riesgo principales
        /// </summary>
        public async Task<List<RiskFactor>> GetTopRiskFactorsAsync(string endpointId = null, int count = 5)
        {
            endpointId ??= GetCurrentEndpointId();
            
            try
            {
                if (!_riskProfiles.TryGetValue(endpointId, out var profile))
                {
                    return new List<RiskFactor>();
                }
                
                var factors = new List<RiskFactor>();
                
                // 1. Factor de detecciones recientes
                if (profile.DetectionCount > 0)
                {
                    var timeSinceLastDetection = DateTime.UtcNow - profile.LastDetection;
                    var detectionFactor = new RiskFactor
                    {
                        Name = "Recent Detections",
                        Description = $"Detecciones recientes: {profile.DetectionCount} total, última hace {timeSinceLastDetection.TotalMinutes:F0} minutos",
                        Score = CalculateDetectionFactorScore(profile),
                        Weight = 0.3,
                        Category = RiskCategory.ThreatActivity
                    };
                    factors.Add(detectionFactor);
                }
                
                // 2. Factor de alertas
                if (profile.AlertCount > 0)
                {
                    var alertFactor = new RiskFactor
                    {
                        Name = "Security Alerts",
                        Description = $"Alertas de seguridad: {profile.AlertCount} total, {profile.CriticalAlerts} críticas",
                        Score = CalculateAlertFactorScore(profile),
                        Weight = 0.25,
                        Category = RiskCategory.SecurityPosture
                    };
                    factors.Add(alertFactor);
                }
                
                // 3. Factor de actividad de red
                var networkFactor = new RiskFactor
                {
                    Name = "Network Activity",
                    Description = $"Actividad de red: {profile.NetworkConnections} conexiones",
                    Score = CalculateNetworkFactorScore(profile),
                    Weight = 0.2,
                    Category = RiskCategory.NetworkExposure
                };
                factors.Add(networkFactor);
                
                // 4. Factor de estado del sistema
                var systemFactor = new RiskFactor
                {
                    Name = "System Health",
                    Description = $"Estado del sistema: {profile.SystemHealthScore}/100",
                    Score = CalculateSystemHealthFactorScore(profile),
                    Weight = 0.15,
                    Category = RiskCategory.SystemHealth
                };
                factors.Add(systemFactor);
                
                // 5. Factor de exposición externa
                var exposureFactor = new RiskFactor
                {
                    Name = "External Exposure",
                    Description = $"Exposición externa: {profile.ExternalConnections} conexiones externas",
                    Score = CalculateExposureFactorScore(profile),
                    Weight = 0.1,
                    Category = RiskCategory.ExternalThreats
                };
                factors.Add(exposureFactor);
                
                // Ordenar por score ponderado
                return factors
                    .OrderByDescending(f => f.Score * f.Weight)
                    .Take(count)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al obtener factores de riesgo: {ex}", ModuleId);
                return new List<RiskFactor>();
            }
        }
        
        /// <summary>
        /// Obtiene recomendaciones para reducir riesgo
        /// </summary>
        public async Task<List<RiskRecommendation>> GetRiskRecommendationsAsync(string endpointId = null)
        {
            endpointId ??= GetCurrentEndpointId();
            
            try
            {
                var recommendations = new List<RiskRecommendation>();
                
                if (!_riskProfiles.TryGetValue(endpointId, out var profile))
                {
                    return recommendations;
                }
                
                var currentScore = await GetCurrentRiskScoreAsync();
                
                // Recomendaciones basadas en score
                if (currentScore >= 80)
                {
                    recommendations.Add(new RiskRecommendation
                    {
                        Priority = RecommendationPriority.Critical,
                        Title = "Aislamiento inmediato requerido",
                        Description = "El endpoint presenta riesgo crítico. Aislar de la red inmediatamente.",
                        Action = "IsolateEndpoint",
                        EstimatedRiskReduction = 40,
                        TimeToImplement = TimeSpan.FromMinutes(5)
                    });
                }
                else if (currentScore >= 60)
                {
                    recommendations.Add(new RiskRecommendation
                    {
                        Priority = RecommendationPriority.High,
                        Title = "Escaneo profundo requerido",
                        Description = "Realizar escaneo antimalware completo y análisis forense.",
                        Action = "DeepScanAndAnalysis",
                        EstimatedRiskReduction = 25,
                        TimeToImplement = TimeSpan.FromHours(1)
                    });
                }
                
                // Recomendaciones basadas en factores específicos
                if (profile.DetectionCount > 10)
                {
                    recommendations.Add(new RiskRecommendation
                    {
                        Priority = RecommendationPriority.High,
                        Title = "Limpiar detecciones acumuladas",
                        Description = $"Existen {profile.DetectionCount} detecciones pendientes. Investigar y remediar.",
                        Action = "InvestigateAndRemediateDetections",
                        EstimatedRiskReduction = 15,
                        TimeToImplement = TimeSpan.FromHours(2)
                    });
                }
                
                if (profile.CriticalAlerts > 0)
                {
                    recommendations.Add(new RiskRecommendation
                    {
                        Priority = RecommendationPriority.Critical,
                        Title = "Responder alertas críticas",
                        Description = $"Existen {profile.CriticalAlerts} alertas críticas sin resolver.",
                        Action = "RespondToCriticalAlerts",
                        EstimatedRiskReduction = 20,
                        TimeToImplement = TimeSpan.FromMinutes(30)
                    });
                }
                
                if (profile.SystemHealthScore < 70)
                {
                    recommendations.Add(new RiskRecommendation
                    {
                        Priority = RecommendationPriority.Medium,
                        Title = "Mejorar salud del sistema",
                        Description = "El sistema presenta problemas de salud. Actualizar y aplicar parches.",
                        Action = "UpdateAndPatchSystem",
                        EstimatedRiskReduction = 10,
                        TimeToImplement = TimeSpan.FromHours(4)
                    });
                }
                
                // Ordenar por prioridad y reducción de riesgo
                return recommendations
                    .OrderByDescending(r => (int)r.Priority)
                    .ThenByDescending(r => r.EstimatedRiskReduction)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al obtener recomendaciones: {ex}", ModuleId);
                return new List<RiskRecommendation>();
            }
        }
        
        /// <summary>
        /// Simula impacto de recomendación en score de riesgo
        /// </summary>
        public async Task<int> SimulateRecommendationImpactAsync(string endpointId, RiskRecommendation recommendation)
        {
            try
            {
                var currentScore = await GetCurrentRiskScoreAsync();
                var impact = recommendation.EstimatedRiskReduction;
                
                // Aplicar factor de efectividad basado en implementación
                var effectiveness = 1.0;
                
                if (recommendation.TimeToImplement > TimeSpan.FromHours(2))
                {
                    effectiveness = 0.8; // Implementaciones largas pueden ser menos efectivas
                }
                
                var newScore = currentScore - (impact * effectiveness);
                
                return Math.Max(0, (int)newScore);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en simulación de impacto: {ex}", ModuleId);
                return -1;
            }
        }
        
        /// <summary>
        /// Obtiene reporte de riesgo completo
        /// </summary>
        public async Task<RiskReport> GetRiskReportAsync(string endpointId = null, TimeSpan? period = null)
        {
            endpointId ??= GetCurrentEndpointId();
            period ??= TimeSpan.FromDays(7);
            
            try
            {
                var currentAssessment = await CalculateRiskAsync(endpointId);
                var trend = await GetRiskTrendAsync(endpointId, (int)period.Value.TotalDays);
                var factors = await GetTopRiskFactorsAsync(endpointId, 10);
                var recommendations = await GetRiskRecommendationsAsync(endpointId);
                var history = await _historyManager.GetRiskHistoryAsync(endpointId, (int)period.Value.TotalDays);
                
                return new RiskReport
                {
                    EndpointId = endpointId,
                    GeneratedAt = DateTime.UtcNow,
                    Period = period.Value,
                    CurrentRisk = currentAssessment,
                    RiskTrend = trend,
                    TopRiskFactors = factors,
                    Recommendations = recommendations,
                    RiskHistory = history,
                    Summary = GenerateRiskSummary(currentAssessment, trend, factors)
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al generar reporte de riesgo: {ex}", ModuleId);
                return CreateErrorReport(endpointId, ex);
            }
        }
        
        /// <summary>
        /// Exporta datos de riesgo
        /// </summary>
        public async Task<string> ExportRiskDataAsync(string endpointId = null, ExportFormat format = ExportFormat.Json)
        {
            endpointId ??= GetCurrentEndpointId();
            
            try
            {
                var report = await GetRiskReportAsync(endpointId);
                
                return format switch
                {
                    ExportFormat.Json => System.Text.Json.JsonSerializer.Serialize(report, 
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true }),
                    
                    ExportFormat.Xml => SerializeToXml(report),
                    
                    ExportFormat.Csv => SerializeToCsv(report),
                    
                    _ => throw new NotSupportedException($"Formato no soportado: {format}")
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al exportar datos de riesgo: {ex}", ModuleId);
                return $"{{ \"error\": \"{ex.Message}\" }}";
            }
        }
        
        /// <summary>
        /// Resetea score de riesgo para endpoint
        /// </summary>
        public async Task<bool> ResetRiskScoreAsync(string endpointId = null)
        {
            endpointId ??= GetCurrentEndpointId();
            
            try
            {
                if (_riskProfiles.TryRemove(endpointId, out _))
                {
                    await _historyManager.ClearHistoryAsync(endpointId);
                    _logManager.LogInfo($"Score de riesgo reseteado para {endpointId}", ModuleId);
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al resetear score de riesgo: {ex}", ModuleId);
                return false;
            }
        }
        
        #region Métodos privados
        
        /// <summary>
        /// Calcula riesgo continuamente
        /// </summary>
        private async Task CalculateRiskContinuouslyAsync(CancellationToken cancellationToken)
        {
            _logManager.LogInfo("Iniciando cálculo continuo de riesgo", ModuleId);
            
            while (!cancellationToken.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Calcular riesgo para endpoints activos
                    await CalculateRiskForAllEndpointsAsync();
                    
                    // Actualizar modelos de scoring periódicamente
                    if (DateTime.UtcNow.Hour % 6 == 0) // Cada 6 horas
                    {
                        await UpdateScoringModelAsync();
                    }
                    
                    // Limpiar historial antiguo
                    if (DateTime.UtcNow.DayOfWeek == DayOfWeek.Monday) // Cada lunes
                    {
                        await CleanupOldHistoryAsync();
                    }
                    
                    // Esperar antes de siguiente ciclo
                    await Task.Delay(TimeSpan.FromMinutes(RISK_UPDATE_INTERVAL_MINUTES), cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en cálculo continuo de riesgo: {ex}", ModuleId);
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
            
            _logManager.LogInfo("Cálculo continuo de riesgo detenido", ModuleId);
        }
        
        /// <summary>
        /// Obtiene o crea perfil de riesgo
        /// </summary>
        private EndpointRiskProfile GetOrCreateRiskProfile(string endpointId)
        {
            if (_riskProfiles.TryGetValue(endpointId, out var existingProfile))
            {
                return existingProfile;
            }
            
            var newProfile = CreateRiskProfile(endpointId);
            _riskProfiles[endpointId] = newProfile;
            
            return newProfile;
        }
        
        /// <summary>
        /// Crea nuevo perfil de riesgo
        /// </summary>
        private EndpointRiskProfile CreateRiskProfile(string endpointId)
        {
            return new EndpointRiskProfile
            {
                EndpointId = endpointId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                CurrentScore = 0,
                PeakScore = 0,
                DetectionCount = 0,
                AlertCount = 0,
                CriticalDetections = 0,
                HighDetections = 0,
                MediumDetections = 0,
                LowDetections = 0,
                CriticalAlerts = 0,
                HighAlerts = 0,
                MediumAlerts = 0,
                LowAlerts = 0,
                NetworkConnections = 0,
                ExternalConnections = 0,
                SystemHealthScore = 100,
                LastDetection = null,
                LastAlert = null,
                LastCalculation = DateTime.UtcNow,
                DetectionTypes = new Dictionary<DetectionType, int>(),
                RiskComponents = new Dictionary<string, double>()
            };
        }
        
        /// <summary>
        /// Recolecta datos para cálculo de riesgo
        /// </summary>
        private async Task<RiskData> CollectRiskDataAsync(string endpointId)
        {
            var data = new RiskData
            {
                EndpointId = endpointId,
                CollectionTime = DateTime.UtcNow
            };
            
            try
            {
                // Obtener detecciones recientes (últimas 24 horas)
                var recentDetections = await _localDatabase.GetRecentDetectionsAsync(endpointId, TimeSpan.FromHours(24));
                data.RecentDetections = recentDetections;
                data.DetectionCount = recentDetections.Count;
                data.CriticalDetectionCount = recentDetections.Count(d => d.Severity == ThreatSeverity.Critical);
                data.HighDetectionCount = recentDetections.Count(d => d.Severity == ThreatSeverity.High);
                
                // Obtener alertas recientes
                var recentAlerts = await _localDatabase.GetRecentAlertsAsync(endpointId, TimeSpan.FromHours(24));
                data.RecentAlerts = recentAlerts;
                data.AlertCount = recentAlerts.Count;
                data.CriticalAlertCount = recentAlerts.Count(a => a.Severity == ThreatSeverity.Critical);
                
                // Obtener eventos de red
                var networkEvents = await _localDatabase.GetRecentNetworkEventsAsync(endpointId, TimeSpan.FromHours(1));
                data.RecentNetworkEvents = networkEvents;
                data.NetworkEventCount = networkEvents.Count;
                data.ExternalConnectionCount = networkEvents.Count(e => 
                    !IsLocalOrPrivateIP(e.Data.RemoteAddress));
                
                // Obtener eventos de sistema
                var systemEvents = await _localDatabase.GetRecentSystemEventsAsync(endpointId, TimeSpan.FromHours(1));
                data.RecentSystemEvents = systemEvents;
                
                // Calcular métricas adicionales
                data.AverageDetectionConfidence = recentDetections.Any() ? 
                    recentDetections.Average(d => d.Confidence) : 0;
                
                data.DetectionFrequency = recentDetections.Count / 24.0; // Por hora
                
                data.LastDetectionTime = recentDetections.Any() ? 
                    recentDetections.Max(d => d.Timestamp) : (DateTime?)null;
                
                data.LastAlertTime = recentAlerts.Any() ? 
                    recentAlerts.Max(a => a.Timestamp) : (DateTime?)null;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al recolectar datos de riesgo: {ex}", ModuleId);
            }
            
            return data;
        }
        
        /// <summary>
        /// Calcula componentes de riesgo
        /// </summary>
        private async Task<Dictionary<RiskComponent, double>> CalculateRiskComponentsAsync(RiskData data, EndpointRiskProfile profile)
        {
            var components = new Dictionary<RiskComponent, double>();
            
            // 1. Componente de amenazas (detecciones)
            var threatComponent = CalculateThreatComponent(data, profile);
            components[RiskComponent.ThreatActivity] = threatComponent;
            
            // 2. Componente de alertas
            var alertComponent = CalculateAlertComponent(data, profile);
            components[RiskComponent.SecurityAlerts] = alertComponent;
            
            // 3. Componente de red
            var networkComponent = CalculateNetworkComponent(data, profile);
            components[RiskComponent.NetworkExposure] = networkComponent;
            
            // 4. Componente de sistema
            var systemComponent = CalculateSystemComponent(data, profile);
            components[RiskComponent.SystemHealth] = systemComponent;
            
            // 5. Componente temporal (decay)
            var temporalComponent = CalculateTemporalComponent(profile);
            components[RiskComponent.TemporalDecay] = temporalComponent;
            
            // 6. Componente de comportamiento (ML)
            var behaviorComponent = await CalculateBehaviorComponentAsync(data, profile);
            components[RiskComponent.BehaviorAnomalies] = behaviorComponent;
            
            return components;
        }
        
        /// <summary>
        /// Calcula componente de amenazas
        /// </summary>
        private double CalculateThreatComponent(RiskData data, EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            // Base por detecciones recientes
            score += data.CriticalDetectionCount * 15;
            score += data.HighDetectionCount * 10;
            score += (data.DetectionCount - data.CriticalDetectionCount - data.HighDetectionCount) * 5;
            
            // Ajustar por frecuencia
            if (data.DetectionFrequency > 1) // Más de 1 detección por hora
            {
                score += (data.DetectionFrequency - 1) * 5;
            }
            
            // Ajustar por confianza promedio
            score += data.AverageDetectionConfidence * 10;
            
            // Ajustar por tiempo desde última detección
            if (data.LastDetectionTime.HasValue)
            {
                var hoursSinceLastDetection = (DateTime.UtcNow - data.LastDetectionTime.Value).TotalHours;
                var recencyFactor = Math.Max(0, 1 - (hoursSinceLastDetection / 24));
                score *= recencyFactor;
            }
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula componente de alertas
        /// </summary>
        private double CalculateAlertComponent(RiskData data, EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            // Base por alertas recientes
            score += data.CriticalAlertCount * 20;
            score += (data.AlertCount - data.CriticalAlertCount) * 8;
            
            // Ajustar por tiempo desde última alerta
            if (data.LastAlertTime.HasValue)
            {
                var hoursSinceLastAlert = (DateTime.UtcNow - data.LastAlertTime.Value).TotalHours;
                var recencyFactor = Math.Max(0, 1 - (hoursSinceLastAlert / 24));
                score *= recencyFactor;
            }
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula componente de red
        /// </summary>
        private double CalculateNetworkComponent(RiskData data, EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            // Base por actividad de red
            score += Math.Min(data.NetworkEventCount / 10.0 * 15, 30);
            
            // Conexiones externas aumentan riesgo
            score += data.ExternalConnectionCount * 5;
            
            // Conexiones a puertos sospechosos
            var suspiciousPorts = data.RecentNetworkEvents.Count(e => 
                IsSuspiciousPort(e.Data.RemotePort ?? 0));
            score += suspiciousPorts * 10;
            
            // Conexiones a IPs de alto riesgo
            var highRiskConnections = data.RecentNetworkEvents.Count(e => 
                IsHighRiskIP(e.Data.RemoteAddress));
            score += highRiskConnections * 15;
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula componente de sistema
        /// </summary>
        private double CalculateSystemComponent(RiskData data, EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            // Salud del sistema base
            score += (100 - profile.SystemHealthScore) * 0.5;
            
            // Eventos de error del sistema
            var errorEvents = data.RecentSystemEvents.Count(e => 
                e.EventType == EventType.SystemError);
            score += errorEvents * 5;
            
            // Configuraciones de seguridad
            var securityConfigScore = EvaluateSecurityConfigurations();
            score += (100 - securityConfigScore) * 0.3;
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula componente temporal (decay)
        /// </summary>
        private double CalculateTemporalComponent(EndpointRiskProfile profile)
        {
            // Decay basado en tiempo sin incidentes
            var timeSinceLastIncident = DateTime.UtcNow - profile.LastCalculation;
            var decay = Math.Pow(1 - RISK_DECAY_RATE, timeSinceLastIncident.TotalHours);
            
            return 100 * (1 - decay); // Invertir para que decay reduzca score
        }
        
        /// <summary>
        /// Calcula componente de comportamiento
        /// </summary>
        private async Task<double> CalculateBehaviorComponentAsync(RiskData data, EndpointRiskProfile profile)
        {
            try
            {
                // Usar modelo de scoring para anomalías de comportamiento
                var behaviorScore = await _scoringModel.CalculateBehaviorRiskAsync(data);
                return behaviorScore;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al calcular componente de comportamiento: {ex}", ModuleId);
                return 0;
            }
        }
        
        /// <summary>
        /// Calcula score total de riesgo
        /// </summary>
        private int CalculateTotalRiskScore(Dictionary<RiskComponent, double> components)
        {
            var weights = new Dictionary<RiskComponent, double>
            {
                { RiskComponent.ThreatActivity, 0.35 },
                { RiskComponent.SecurityAlerts, 0.25 },
                { RiskComponent.NetworkExposure, 0.20 },
                { RiskComponent.SystemHealth, 0.10 },
                { RiskComponent.BehaviorAnomalies, 0.10 }
            };
            
            var totalScore = 0.0;
            
            foreach (var component in components)
            {
                if (weights.TryGetValue(component.Key, out var weight))
                {
                    totalScore += component.Value * weight;
                }
            }
            
            // Aplicar factor temporal (decay) como multiplicador
            if (components.TryGetValue(RiskComponent.TemporalDecay, out var temporalFactor))
            {
                totalScore *= (1 - temporalFactor / 100);
            }
            
            // Limitar a 0-100
            totalScore = Math.Clamp(totalScore, 0, 100);
            
            return (int)Math.Round(totalScore);
        }
        
        /// <summary>
        /// Actualiza perfil de riesgo
        /// </summary>
        private void UpdateRiskProfile(EndpointRiskProfile profile, int newScore, Dictionary<RiskComponent, double> components)
        {
            profile.CurrentScore = newScore;
            profile.PeakScore = Math.Max(profile.PeakScore, newScore);
            profile.LastCalculation = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;
            profile.RiskComponents = components.ToDictionary(
                kv => kv.Key.ToString(),
                kv => kv.Value);
            
            // Actualizar métricas acumuladas
            profile.DetectionCount = components.TryGetValue(RiskComponent.ThreatActivity, out var threatScore) ? 
                (int)(threatScore / 5) : profile.DetectionCount;
            
            profile.AlertCount = components.TryGetValue(RiskComponent.SecurityAlerts, out var alertScore) ? 
                (int)(alertScore / 8) : profile.AlertCount;
            
            profile.NetworkConnections = components.TryGetValue(RiskComponent.NetworkExposure, out var networkScore) ? 
                (int)(networkScore / 2) : profile.NetworkConnections;
            
            profile.SystemHealthScore = components.TryGetValue(RiskComponent.SystemHealth, out var systemScore) ? 
                100 - (int)systemScore : profile.SystemHealthScore;
        }
        
        /// <summary>
        /// Crea assessment de riesgo
        /// </summary>
        private RiskAssessment CreateRiskAssessment(EndpointRiskProfile profile, int score, Dictionary<RiskComponent, double> components)
        {
            var riskLevel = score >= 80 ? RiskLevel.Critical :
                           score >= 60 ? RiskLevel.High :
                           score >= 40 ? RiskLevel.Medium :
                           score >= 20 ? RiskLevel.Low :
                           RiskLevel.Minimal;
            
            return new RiskAssessment
            {
                AssessmentId = Guid.NewGuid().ToString(),
                EndpointId = profile.EndpointId,
                Timestamp = DateTime.UtcNow,
                OverallScore = score,
                RiskLevel = riskLevel,
                Components = components.ToDictionary(
                    kv => kv.Key.ToString(),
                    kv => new RiskComponentScore
                    {
                        Component = kv.Key,
                        Score = kv.Value,
                        Weight = GetComponentWeight(kv.Key)
                    }),
                ProfileSnapshot = profile,
                Confidence = CalculateAssessmentConfidence(components)
            };
        }
        
        /// <summary>
        /// Actualiza perfil con detección
        /// </summary>
        private void UpdateProfileWithDetection(EndpointRiskProfile profile, DetectionResult detection)
        {
            // Incrementar contadores específicos
            if (!profile.DetectionTypes.ContainsKey(detection.DetectionType))
            {
                profile.DetectionTypes[detection.DetectionType] = 0;
            }
            profile.DetectionTypes[detection.DetectionType]++;
            
            // Actualizar último evento
            profile.LastDetection = detection.Timestamp;
            
            // Actualizar métricas basadas en severidad
            switch (detection.Severity)
            {
                case ThreatSeverity.Critical:
                    profile.CriticalDetections++;
                    break;
                case ThreatSeverity.High:
                    profile.HighDetections++;
                    break;
                case ThreatSeverity.Medium:
                    profile.MediumDetections++;
                    break;
                case ThreatSeverity.Low:
                    profile.LowDetections++;
                    break;
            }
        }
        
        /// <summary>
        /// Actualiza perfil con alerta
        /// </summary>
        private void UpdateProfileWithAlert(EndpointRiskProfile profile, SecurityAlert alert)
        {
            // Actualizar último evento
            profile.LastAlert = alert.Timestamp;
            
            // Actualizar métricas basadas en severidad
            switch (alert.Severity)
            {
                case ThreatSeverity.Critical:
                    profile.CriticalAlerts++;
                    break;
                case ThreatSeverity.High:
                    profile.HighAlerts++;
                    break;
                case ThreatSeverity.Medium:
                    profile.MediumAlerts++;
                    break;
                case ThreatSeverity.Low:
                    profile.LowAlerts++;
                    break;
            }
        }
        
        /// <summary>
        /// Calcula factor de severidad de patrón
        /// </summary>
        private double GetPatternSeverityFactor(PatternType patternType)
        {
            return patternType switch
            {
                PatternType.Ransomware => 30,
                PatternType.DataExfiltration => 25,
                PatternType.C2Communication => 20,
                PatternType.LateralMovement => 18,
                PatternType.PrivilegeEscalation => 15,
                PatternType.Persistence => 12,
                PatternType.DefenseEvasion => 10,
                PatternType.Reconnaissance => 8,
                _ => 5
            };
        }
        
        /// <summary>
        /// Calcula factor de densidad temporal
        /// </summary>
        private double CalculateTimeDensityFactor(List<SensorEvent> events)
        {
            if (events.Count < 2)
                return 0;
            
            var timestamps = events.Select(e => e.Timestamp).OrderBy(t => t).ToList();
            var totalDuration = (timestamps.Last() - timestamps.First()).TotalSeconds;
            
            if (totalDuration == 0)
                return 0;
            
            // Eventos más cercanos en tiempo = mayor densidad = mayor riesgo
            var density = events.Count / totalDuration;
            
            return Math.Min(density * 10, 20);
        }
        
        /// <summary>
        /// Calcula factor de score de detecciones
        /// </summary>
        private double CalculateDetectionFactorScore(EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            score += profile.CriticalDetections * 20;
            score += profile.HighDetections * 15;
            score += profile.MediumDetections * 10;
            score += profile.LowDetections * 5;
            
            // Ajustar por recencia
            if (profile.LastDetection.HasValue)
            {
                var hoursSinceLastDetection = (DateTime.UtcNow - profile.LastDetection.Value).TotalHours;
                var recencyFactor = Math.Max(0, 1 - (hoursSinceLastDetection / 168)); // 1 semana
                score *= recencyFactor;
            }
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula factor de score de alertas
        /// </summary>
        private double CalculateAlertFactorScore(EndpointRiskProfile profile)
        {
            var score = 0.0;
            
            score += profile.CriticalAlerts * 25;
            score += profile.HighAlerts * 18;
            score += profile.MediumAlerts * 12;
            score += profile.LowAlerts * 6;
            
            // Ajustar por recencia
            if (profile.LastAlert.HasValue)
            {
                var hoursSinceLastAlert = (DateTime.UtcNow - profile.LastAlert.Value).TotalHours;
                var recencyFactor = Math.Max(0, 1 - (hoursSinceLastAlert / 168)); // 1 semana
                score *= recencyFactor;
            }
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula factor de score de red
        /// </summary>
        private double CalculateNetworkFactorScore(EndpointRiskProfile profile)
        {
            var score = Math.Min(profile.NetworkConnections * 0.5, 40);
            score += Math.Min(profile.ExternalConnections * 2, 30);
            
            return Math.Min(score, 100);
        }
        
        /// <summary>
        /// Calcula factor de salud del sistema
        /// </summary>
        private double CalculateSystemHealthFactorScore(EndpointRiskProfile profile)
        {
            return 100 - profile.SystemHealthScore;
        }
        
        /// <summary>
        /// Calcula factor de exposición
        /// </summary>
        private double CalculateExposureFactorScore(EndpointRiskProfile profile)
        {
            return Math.Min(profile.ExternalConnections * 3, 100);
        }
        
        /// <summary>
        /// Calcula tendencia lineal
        /// </summary>
        private (double slope, double confidence) CalculateLinearTrend(List<int> scores)
        {
            if (scores.Count < 2)
                return (0, 0);
            
            var n = scores.Count;
            var xValues = Enumerable.Range(0, n).Select(x => (double)x).ToArray();
            var yValues = scores.Select(s => (double)s).ToArray();
            
            // Calcular pendiente (m) usando mínimos cuadrados
            var sumX = xValues.Sum();
            var sumY = yValues.Sum();
            var sumXY = xValues.Zip(yValues, (x, y) => x * y).Sum();
            var sumX2 = xValues.Sum(x => x * x);
            
            var m = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
            
            // Calcular R² para confianza
            var yMean = sumY / n;
            var ssTotal = yValues.Sum(y => Math.Pow(y - yMean, 2));
            var ssResidual = yValues.Zip(xValues, (y, x) => 
                Math.Pow(y - (m * x + (sumY - m * sumX) / n), 2)).Sum();
            
            var r2 = 1 - (ssResidual / ssTotal);
            var confidence = Math.Max(0, Math.Min(1, r2));
            
            return (m, confidence);
        }
        
        /// <summary>
        /// Obtiene peso de componente
        /// </summary>
        private double GetComponentWeight(RiskComponent component)
        {
            return component switch
            {
                RiskComponent.ThreatActivity => 0.35,
                RiskComponent.SecurityAlerts => 0.25,
                RiskComponent.NetworkExposure => 0.20,
                RiskComponent.SystemHealth => 0.10,
                RiskComponent.BehaviorAnomalies => 0.10,
                _ => 0
            };
        }
        
        /// <summary>
        /// Calcula confianza del assessment
        /// </summary>
        private double CalculateAssessmentConfidence(Dictionary<RiskComponent, double> components)
        {
            // Confianza basada en cantidad y calidad de datos
            var dataPoints = components.Sum(c => c.Value > 0 ? 1 : 0);
            var maxDataPoints = components.Count;
            
            var coverage = (double)dataPoints / maxDataPoints;
            
            // Ajustar por variabilidad (más variabilidad = menor confianza)
            var avgScore = components.Average(c => c.Value);
            var variance = components.Sum(c => Math.Pow(c.Value - avgScore, 2)) / components.Count;
            var variability = Math.Min(variance / 100, 1);
            
            var confidence = coverage * (1 - variability * 0.5);
            
            return Math.Clamp(confidence, 0, 1);
        }
        
        /// <summary>
        /// Verifica si IP es local o privada
        /// </summary>
        private bool IsLocalOrPrivateIP(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;
            
            return ipAddress.StartsWith("127.") ||
                   ipAddress.StartsWith("10.") ||
                   ipAddress.StartsWith("192.168.") ||
                   (ipAddress.StartsWith("172.") && 
                    int.TryParse(ipAddress.Split('.')[1], out var secondOctet) &&
                    secondOctet >= 16 && secondOctet <= 31) ||
                   ipAddress == "::1" ||
                   ipAddress == "0:0:0:0:0:0:0:1";
        }
        
        /// <summary>
        /// Verifica si puerto es sospechoso
        /// </summary>
        private bool IsSuspiciousPort(int port)
        {
            var suspiciousPorts = new[] 
            { 
                4444, 5555, 6666, 6667, 6668, 6669, 
                31337, 12345, 12346, 20034, 27374 
            };
            
            return suspiciousPorts.Contains(port);
        }
        
        /// <summary>
        /// Verifica si IP es de alto riesgo
        /// </summary>
        private bool IsHighRiskIP(string ipAddress)
        {
            // Implementación simplificada
            // En producción usar lista de IPs maliciosas conocidas
            
            if (string.IsNullOrEmpty(ipAddress))
                return false;
            
            // Simulación: IPs que comienzan con ciertos patrones
            var highRiskPatterns = new[] { "5.", "46.", "93.", "185." };
            
            return highRiskPatterns.Any(pattern => ipAddress.StartsWith(pattern));
        }
        
        /// <summary>
        /// Evalúa configuraciones de seguridad
        /// </summary>
        private int EvaluateSecurityConfigurations()
        {
            // Implementación simplificada
            // En producción verificar configuraciones reales del sistema
            
            var score = 100;
            
            // Simular verificaciones
            if (!IsFirewallEnabled())
                score -= 20;
            
            if (!IsAntivirusEnabled())
                score -= 30;
            
            if (!IsAutoUpdateEnabled())
                score -= 15;
            
            if (!IsUACEnabled())
                score -= 10;
            
            return Math.Max(0, score);
        }
        
        private bool IsFirewallEnabled() => true;
        private bool IsAntivirusEnabled() => true;
        private bool IsAutoUpdateEnabled() => true;
        private bool IsUACEnabled() => true;
        
        /// <summary>
        /// Genera resumen de riesgo
        /// </summary>
        private string GenerateRiskSummary(RiskAssessment assessment, RiskTrend trend, List<RiskFactor> factors)
        {
            var summary = $"Riesgo {assessment.RiskLevel} ({assessment.OverallScore}/100). ";
            
            if (trend.Trend == TrendDirection.Increasing)
                summary += "Tendencia al alza. ";
            else if (trend.Trend == TrendDirection.Decreasing)
                summary += "Tendencia a la baja. ";
            else
                summary += "Tendencia estable. ";
            
            var topFactor = factors.FirstOrDefault();
            if (topFactor != null)
                summary += $"Factor principal: {topFactor.Name} ({topFactor.Score}/100).";
            
            return summary;
        }
        
        /// <summary>
        /// Obtiene ID del endpoint actual
        /// </summary>
        private string GetCurrentEndpointId()
        {
            return Environment.MachineName;
        }
        
        /// <summary>
        /// Carga perfiles de riesgo
        /// </summary>
        private async Task LoadRiskProfilesAsync()
        {
            try
            {
                var profiles = await _localDatabase.GetRiskProfilesAsync();
                
                foreach (var profile in profiles)
                {
                    _riskProfiles[profile.EndpointId] = profile;
                }
                
                _logManager.LogInfo($"Cargados {profiles.Count} perfiles de riesgo", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar perfiles de riesgo: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda perfiles de riesgo
        /// </summary>
        private async Task SaveRiskProfilesAsync()
        {
            try
            {
                var profiles = _riskProfiles.Values.ToList();
                await _localDatabase.SaveRiskProfilesAsync(profiles);
                
                _logManager.LogDebug($"Guardados {profiles.Count} perfiles de riesgo", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar perfiles: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Inicializa modelo de scoring
        /// </summary>
        private async Task InitializeScoringModelAsync()
        {
            try
            {
                await _scoringModel.InitializeAsync();
                _logManager.LogInfo("Modelo de scoring inicializado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar modelo de scoring: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Actualiza modelo de scoring
        /// </summary>
        private async Task UpdateScoringModelAsync()
        {
            try
            {
                await _scoringModel.UpdateAsync(_riskProfiles.Values.ToList());
                _logManager.LogDebug("Modelo de scoring actualizado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar modelo de scoring: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Carga historial de riesgo
        /// </summary>
        private async Task LoadRiskHistoryAsync()
        {
            try
            {
                await _historyManager.LoadHistoryAsync();
                _logManager.LogInfo("Historial de riesgo cargado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar historial de riesgo: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda historial de riesgo
        /// </summary>
        private async Task SaveRiskHistoryAsync()
        {
            try
            {
                await _historyManager.SaveHistoryAsync();
                _logManager.LogDebug("Historial de riesgo guardado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar historial: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Limpia historial antiguo
        /// </summary>
        private async Task CleanupOldHistoryAsync()
        {
            try
            {
                await _historyManager.CleanupOldRecordsAsync(MAX_HISTORY_DAYS);
                _logManager.LogDebug("Historial antiguo limpiado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al limpiar historial: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda assessment en historial
        /// </summary>
        private async Task SaveRiskAssessmentAsync(RiskAssessment assessment)
        {
            try
            {
                await _historyManager.AddAssessmentAsync(assessment);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar assessment: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Crea assessment de error
        /// </summary>
        private RiskAssessment CreateErrorAssessment(Exception ex)
        {
            return new RiskAssessment
            {
                AssessmentId = Guid.NewGuid().ToString(),
                EndpointId = GetCurrentEndpointId(),
                Timestamp = DateTime.UtcNow,
                OverallScore = -1,
                RiskLevel = RiskLevel.Unknown,
                Components = new Dictionary<string, RiskComponentScore>(),
                Confidence = 0,
                Error = ex.Message
            };
        }
        
        /// <summary>
        /// Crea reporte de error
        /// </summary>
        private RiskReport CreateErrorReport(string endpointId, Exception ex)
        {
            return new RiskReport
            {
                EndpointId = endpointId,
                GeneratedAt = DateTime.UtcNow,
                Period = TimeSpan.Zero,
                CurrentRisk = CreateErrorAssessment(ex),
                RiskTrend = new RiskTrend { EndpointId = endpointId, Trend = TrendDirection.Unknown },
                TopRiskFactors = new List<RiskFactor>(),
                Recommendations = new List<RiskRecommendation>(),
                RiskHistory = new List<RiskHistoryRecord>(),
                Summary = $"Error generando reporte: {ex.Message}",
                Error = ex.Message
            };
        }
        
        /// <summary>
        /// Serializa a XML
        /// </summary>
        private string SerializeToXml(RiskReport report)
        {
            // Implementación simplificada
            var xml = $"<RiskReport endpointId=\"{report.EndpointId}\" generatedAt=\"{report.GeneratedAt:o}\">";
            xml += $"<OverallScore>{report.CurrentRisk.OverallScore}</OverallScore>";
            xml += $"<RiskLevel>{report.CurrentRisk.RiskLevel}</RiskLevel>";
            xml += "</RiskReport>";
            return xml;
        }
        
        /// <summary>
        /// Serializa a CSV
        /// </summary>
        private string SerializeToCsv(RiskReport report)
        {
            var csv = "Timestamp,EndpointId,Score,RiskLevel,Factors\n";
            csv += $"{report.GeneratedAt:o},{report.EndpointId},{report.CurrentRisk.OverallScore},{report.CurrentRisk.RiskLevel},{report.TopRiskFactors.Count}\n";
            return csv;
        }
        
        #endregion
        
        #region Métodos para HealthCheck
        
        /// <summary>
        /// Verifica salud del calculador
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                
                // Verificar perfiles cargados
                if (_riskProfiles.Count == 0)
                    issues.Add("No hay perfiles de riesgo cargados");
                
                // Verificar modelo de scoring
                var modelHealth = await _scoringModel.CheckHealthAsync();
                if (!modelHealth.IsHealthy)
                    issues.Add($"Modelo de scoring: {modelHealth.Message}");
                
                // Verificar historial
                var historyHealth = await _historyManager.CheckHealthAsync();
                if (!historyHealth.IsHealthy)
                    issues.Add($"Historial: {historyHealth.Message}");
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("RiskScoreCalculator funcionando correctamente");
                }
                
                return HealthCheckResult.Degraded(
                    $"Problemas detectados: {string.Join(", ", issues)}",
                    new Dictionary<string, object>
                    {
                        { "ProfileCount", _riskProfiles.Count },
                        { "ModelHealth", modelHealth },
                        { "HistoryHealth", historyHealth }
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
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    /// <summary>
    /// Interfaz para calculadores de riesgo
    /// </summary>
    public interface IRiskCalculator
    {
        Task<RiskAssessment> CalculateRiskAsync(string endpointId = null);
        Task<int> CalculateRiskAsync(CorrelationResult correlationResult);
        Task<RiskTrend> GetRiskTrendAsync(string endpointId = null, int days = 7);
        Task<List<RiskFactor>> GetTopRiskFactorsAsync(string endpointId = null, int count = 5);
        Task<List<RiskRecommendation>> GetRiskRecommendationsAsync(string endpointId = null);
    }
    
    /// <summary>
    /// Perfil de riesgo de endpoint
    /// </summary>
    public class EndpointRiskProfile
    {
        public string EndpointId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public int CurrentScore { get; set; }
        public int PeakScore { get; set; }
        public int DetectionCount { get; set; }
        public int AlertCount { get; set; }
        public int CriticalDetections { get; set; }
        public int HighDetections { get; set; }
        public int MediumDetections { get; set; }
        public int LowDetections { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
        public int NetworkConnections { get; set; }
        public int ExternalConnections { get; set; }
        public int SystemHealthScore { get; set; }
        public DateTime? LastDetection { get; set; }
        public DateTime? LastAlert { get; set; }
        public DateTime LastCalculation { get; set; }
        public Dictionary<DetectionType, int> DetectionTypes { get; set; }
        public Dictionary<string, double> RiskComponents { get; set; }
        
        public EndpointRiskProfile()
        {
            DetectionTypes = new Dictionary<DetectionType, int>();
            RiskComponents = new Dictionary<string, double>();
        }
    }
    
    /// <summary>
    /// Datos para cálculo de riesgo
    /// </summary>
    public class RiskData
    {
        public string EndpointId { get; set; }
        public DateTime CollectionTime { get; set; }
        public List<DetectionResult> RecentDetections { get; set; }
        public List<SecurityAlert> RecentAlerts { get; set; }
        public List<SensorEvent> RecentNetworkEvents { get; set; }
        public List<SensorEvent> RecentSystemEvents { get; set; }
        public int DetectionCount { get; set; }
        public int CriticalDetectionCount { get; set; }
        public int HighDetectionCount { get; set; }
        public int AlertCount { get; set; }
        public int CriticalAlertCount { get; set; }
        public int NetworkEventCount { get; set; }
        public int ExternalConnectionCount { get; set; }
        public double AverageDetectionConfidence { get; set; }
        public double DetectionFrequency { get; set; }
        public DateTime? LastDetectionTime { get; set; }
        public DateTime? LastAlertTime { get; set; }
        
        public RiskData()
        {
            RecentDetections = new List<DetectionResult>();
            RecentAlerts = new List<SecurityAlert>();
            RecentNetworkEvents = new List<SensorEvent>();
            RecentSystemEvents = new List<SensorEvent>();
        }
    }
    
    /// <summary>
    /// Evaluación de riesgo
    /// </summary>
    public class RiskAssessment
    {
        public string AssessmentId { get; set; }
        public string EndpointId { get; set; }
        public DateTime Timestamp { get; set; }
        public int OverallScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public Dictionary<string, RiskComponentScore> Components { get; set; }
        public EndpointRiskProfile ProfileSnapshot { get; set; }
        public double Confidence { get; set; }
        public string Error { get; set; }
        
        public RiskAssessment()
        {
            Components = new Dictionary<string, RiskComponentScore>();
        }
    }
    
    /// <summary>
    /// Score de componente de riesgo
    /// </summary>
    public class RiskComponentScore
    {
        public RiskComponent Component { get; set; }
        public double Score { get; set; }
        public double Weight { get; set; }
    }
    
    /// <summary>
    /// Tendencias de riesgo
    /// </summary>
    public class RiskTrend
    {
        public string EndpointId { get; set; }
        public TrendDirection Trend { get; set; }
        public double Confidence { get; set; }
        public double ChangeAmount { get; set; }
        public List<int> RecentScores { get; set; }
        public double HistoricalAverage { get; set; }
        
        public RiskTrend()
        {
            RecentScores = new List<int>();
        }
    }
    
    /// <summary>
    /// Factor de riesgo
    /// </summary>
    public class RiskFactor
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public double Score { get; set; }
        public double Weight { get; set; }
        public RiskCategory Category { get; set; }
    }
    
    /// <summary>
    /// Recomendación para reducir riesgo
    /// </summary>
    public class RiskRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
        public int EstimatedRiskReduction { get; set; }
        public TimeSpan TimeToImplement { get; set; }
    }
    
    /// <summary>
    /// Reporte de riesgo completo
    /// </summary>
    public class RiskReport
    {
        public string EndpointId { get; set; }
        public DateTime GeneratedAt { get; set; }
        public TimeSpan Period { get; set; }
        public RiskAssessment CurrentRisk { get; set; }
        public RiskTrend RiskTrend { get; set; }
        public List<RiskFactor> TopRiskFactors { get; set; }
        public List<RiskRecommendation> Recommendations { get; set; }
        public List<RiskHistoryRecord> RiskHistory { get; set; }
        public string Summary { get; set; }
        public string Error { get; set; }
        
        public RiskReport()
        {
            TopRiskFactors = new List<RiskFactor>();
            Recommendations = new List<RiskRecommendation>();
            RiskHistory = new List<RiskHistoryRecord>();
        }
    }
    
    /// <summary>
    /// Registro de historial de riesgo
    /// </summary>
    public class RiskHistoryRecord
    {
        public string RecordId { get; set; }
        public string EndpointId { get; set; }
        public DateTime Timestamp { get; set; }
        public int Score { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public Dictionary<string, double> Components { get; set; }
        
        public RiskHistoryRecord()
        {
            Components = new Dictionary<string, double>();
        }
    }
    
    /// <summary>
    /// Componentes de riesgo
    /// </summary>
    public enum RiskComponent
    {
        ThreatActivity,
        SecurityAlerts,
        NetworkExposure,
        SystemHealth,
        BehaviorAnomalies,
        TemporalDecay
    }
    
    /// <summary>
    /// Niveles de riesgo
    /// </summary>
    public enum RiskLevel
    {
        Minimal,    // 0-19
        Low,        // 20-39
        Medium,     // 40-59
        High,       // 60-79
        Critical,   // 80-100
        Unknown     // Error
    }
    
    /// <summary>
    /// Categorías de riesgo
    /// </summary>
    public enum RiskCategory
    {
        ThreatActivity,
        SecurityPosture,
        NetworkExposure,
        SystemHealth,
        ExternalThreats,
        Behavioral
    }
    
    /// <summary>
    /// Direcciones de tendencia
    /// </summary>
    public enum TrendDirection
    {
        Increasing,
        Decreasing,
        Stable,
        Unknown
    }
    
    /// <summary>
    /// Prioridades de recomendación
    /// </summary>
    public enum RecommendationPriority
    {
        Critical,
        High,
        Medium,
        Low
    }
    
    /// <summary>
    /// Formatos de exportación
    /// </summary>
    public enum ExportFormat
    {
        Json,
        Xml,
        Csv
    }
    
    /// <summary>
    /// Modelo de scoring de riesgo
    /// </summary>
    internal class RiskScoringModel
    {
        private readonly MLContext _mlContext;
        private ITransformer _model;
        
        public RiskScoringModel()
        {
            _mlContext = new MLContext();
        }
        
        public async Task InitializeAsync()
        {
            await Task.CompletedTask; // Simulación
        }
        
        public async Task<double> CalculateBehaviorRiskAsync(RiskData data)
        {
            await Task.Delay(1); // Simulación
            
            // Lógica simplificada
            var score = 0.0;
            
            if (data.RecentDetections.Any())
                score += 30;
            
            if (data.RecentAlerts.Any(a => a.Severity == ThreatSeverity.Critical))
                score += 40;
            
            if (data.ExternalConnectionCount > 10)
                score += 20;
            
            return Math.Min(score, 100);
        }
        
        public async Task UpdateAsync(List<EndpointRiskProfile> profiles)
        {
            await Task.Delay(1); // Simulación
        }
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            await Task.Delay(1);
            return HealthCheckResult.Healthy("Modelo funcionando");
        }
    }
    
    /// <summary>
    /// Gestor de historial de riesgo
    /// </summary>
    internal class RiskHistoryManager
    {
        private readonly List<RiskHistoryRecord> _history;
        
        public RiskHistoryManager()
        {
            _history = new List<RiskHistoryRecord>();
        }
        
        public async Task LoadHistoryAsync()
        {
            await Task.Delay(1); // Simulación
        }
        
        public async Task SaveHistoryAsync()
        {
            await Task.Delay(1); // Simulación
        }
        
        public async Task<List<RiskHistoryRecord>> GetRiskHistoryAsync(string endpointId, int days)
        {
            await Task.Delay(1);
            
            // Simular datos de historial
            var records = new List<RiskHistoryRecord>();
            var now = DateTime.UtcNow;
            
            for (int i = 0; i < days; i++)
            {
                for (int h = 0; h < 24; h += 6) // Cada 6 horas
                {
                    records.Add(new RiskHistoryRecord
                    {
                        RecordId = Guid.NewGuid().ToString(),
                        EndpointId = endpointId,
                        Timestamp = now.AddDays(-i).AddHours(-h),
                        Score = Random.Shared.Next(20, 80),
                        RiskLevel = RiskLevel.Medium
                    });
                }
            }
            
            return records;
        }
        
        public async Task AddAssessmentAsync(RiskAssessment assessment)
        {
            await Task.Delay(1);
            
            var record = new RiskHistoryRecord
            {
                RecordId = Guid.NewGuid().ToString(),
                EndpointId = assessment.EndpointId,
                Timestamp = assessment.Timestamp,
                Score = assessment.OverallScore,
                RiskLevel = assessment.RiskLevel,
                Components = assessment.Components.ToDictionary(
                    kv => kv.Key,
                    kv => kv.Value.Score)
            };
            
            _history.Add(record);
        }
        
        public async Task ClearHistoryAsync(string endpointId)
        {
            await Task.Delay(1);
            _history.RemoveAll(r => r.EndpointId == endpointId);
        }
        
        public async Task CleanupOldRecordsAsync(int maxDays)
        {
            await Task.Delay(1);
            var cutoff = DateTime.UtcNow.AddDays(-maxDays);
            _history.RemoveAll(r => r.Timestamp < cutoff);
        }
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            await Task.Delay(1);
            return HealthCheckResult.Healthy($"Historial con {_history.Count} registros");
        }
    }
    
    #endregion
}