using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.Logging;
using BWP.Enterprise.Cloud.Storage;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BWP.Enterprise.Cloud.ThreatGraph
{
    /// <summary>
    /// Motor de cálculo de riesgo para amenazas y dispositivos
    /// Calcula scores de riesgo basado en múltiples factores con algoritmos avanzados
    /// </summary>
    public sealed class RiskScoringEngine : IRiskScoringEngine
    {
        private static readonly Lazy<RiskScoringEngine> _instance = 
            new Lazy<RiskScoringEngine>(() => new RiskScoringEngine());
        
        public static RiskScoringEngine Instance => _instance.Value;
        
        private readonly ILogger<RiskScoringEngine> _logger;
        private readonly ThreatGraphDatabase _graphDatabase;
        private readonly ConcurrentDictionary<string, DeviceRiskScore> _deviceRiskScores;
        private readonly ConcurrentDictionary<string, ThreatRiskScore> _threatRiskScores;
        private readonly ConcurrentDictionary<string, TenantRiskScore> _tenantRiskScores;
        private readonly List<RiskFactor> _riskFactors;
        private readonly Dictionary<RiskCategory, RiskWeight> _riskWeights;
        private readonly Dictionary<RiskEntityType, RiskThreshold> _riskThresholds;
        private readonly RiskScoringConfiguration _configuration;
        private bool _isInitialized;
        private DateTime _lastScoringUpdate;
        private readonly object _scoringLock = new object();
        
        public string EngineId => "RiskScoringEngine";
        public string Version => "1.0.0";
        public bool IsRunning => _isInitialized;
        
        public RiskScoringEngine()
        {
            _logger = LogManager.CreateLogger<RiskScoringEngine>();
            _graphDatabase = ThreatGraphDatabase.Instance;
            _deviceRiskScores = new ConcurrentDictionary<string, DeviceRiskScore>();
            _threatRiskScores = new ConcurrentDictionary<string, ThreatRiskScore>();
            _tenantRiskScores = new ConcurrentDictionary<string, TenantRiskScore>();
            _riskFactors = new List<RiskFactor>();
            _riskWeights = new Dictionary<RiskCategory, RiskWeight>();
            _riskThresholds = new Dictionary<RiskEntityType, RiskThreshold>();
            _configuration = new RiskScoringConfiguration();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el motor de cálculo de riesgo
        /// </summary>
        public async Task InitializeAsync(RiskScoringConfiguration configuration = null)
        {
            try
            {
                _logger.LogInformation("🚀 Inicializando RiskScoringEngine v{Version}...", Version);
                
                if (configuration != null)
                {
                    _configuration = configuration;
                }
                
                // 1. Validar configuración
                ValidateConfiguration();
                
                // 2. Cargar factores de riesgo desde configuración o por defecto
                await LoadRiskFactorsAsync();
                
                // 3. Cargar pesos de riesgo
                await LoadRiskWeightsAsync();
                
                // 4. Cargar umbrales de riesgo
                await LoadRiskThresholdsAsync();
                
                // 5. Verificar integridad de datos
                await VerifyDataIntegrityAsync();
                
                // 6. Cargar scores existentes desde persistencia
                await LoadExistingRiskScoresAsync();
                
                // 7. Inicializar algoritmos de scoring
                InitializeScoringAlgorithms();
                
                // 8. Programar tareas periódicas
                SchedulePeriodicTasks();
                
                _isInitialized = true;
                _lastScoringUpdate = DateTime.UtcNow;
                
                _logger.LogInformation("✅ RiskScoringEngine inicializado exitosamente");
                _logger.LogInformation("📊 Configuración: {FactorCount} factores, {WeightCount} pesos, {ThresholdCount} umbrales", 
                    _riskFactors.Count, _riskWeights.Count, _riskThresholds.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error al inicializar RiskScoringEngine");
                throw new RiskScoringException("Failed to initialize RiskScoringEngine", ex);
            }
        }
        
        /// <summary>
        /// Calcula score de riesgo para un dispositivo
        /// </summary>
        public async Task<DeviceRiskScore> CalculateDeviceRiskAsync(
            string deviceId, 
            DeviceContext context = null,
            bool forceRecalculation = false)
        {
            ValidateOperation();
            
            if (string.IsNullOrEmpty(deviceId))
                throw new ArgumentException("Device ID cannot be null or empty", nameof(deviceId));
            
            try
            {
                // Verificar cache y validez
                if (!forceRecalculation && TryGetCachedDeviceScore(deviceId, out var cachedScore))
                {
                    _logger.LogDebug("🔄 Usando score en caché para dispositivo {DeviceId} (válido por {Minutes} minutos)", 
                        deviceId, _configuration.CacheValidityMinutes);
                    return cachedScore;
                }
                
                _logger.LogDebug("🧮 Calculando score de riesgo para dispositivo {DeviceId}", deviceId);
                var startTime = DateTime.UtcNow;
                
                // 1. Obtener datos del dispositivo
                var deviceData = await GetDeviceDataAsync(deviceId, context);
                
                // 2. Calcular factores de riesgo individuales
                var factorScores = await CalculateRiskFactorsAsync(deviceData);
                
                // 3. Aplicar algoritmo de scoring principal
                var baseScore = CalculateBaseRiskScore(factorScores);
                
                // 4. Aplicar ajustes contextuales
                var contextualScore = ApplyContextualAdjustments(baseScore, deviceData, context);
                
                // 5. Aplicar pesos dinámicos
                var weightedScore = ApplyDynamicWeights(contextualScore, factorScores);
                
                // 6. Aplicar decaimiento temporal
                var finalScore = ApplyTimeDecay(weightedScore, deviceData.LastActivity);
                
                // 7. Determinar nivel de riesgo
                var riskLevel = DetermineRiskLevel(finalScore.TotalScore, RiskEntityType.Device);
                
                // 8. Calcular confianza del score
                var confidence = CalculateScoreConfidence(factorScores, deviceData);
                
                // 9. Generar recomendaciones
                var recommendations = GenerateRiskRecommendations(riskLevel, factorScores, deviceData);
                
                // 10. Crear objeto de resultado
                var riskScore = new DeviceRiskScore
                {
                    ScoreId = GenerateScoreId("DEV", deviceId),
                    DeviceId = deviceId,
                    TenantId = deviceData.TenantId,
                    Timestamp = DateTime.UtcNow,
                    TotalScore = finalScore.TotalScore,
                    RiskLevel = riskLevel,
                    Confidence = confidence,
                    FactorScores = factorScores,
                    BaseScore = baseScore.TotalScore,
                    WeightedScore = weightedScore.TotalScore,
                    FinalScore = finalScore.TotalScore,
                    LastCalculated = DateTime.UtcNow,
                    CalculationTime = DateTime.UtcNow - startTime,
                    Recommendations = recommendations,
                    Metadata = new Dictionary<string, object>
                    {
                        { "CalculationMethod", "AdvancedWeightedScoring" },
                        { "AlgorithmVersion", "2.1" },
                        { "FactorsConsidered", factorScores.Count },
                        { "ContextApplied", context != null }
                    }
                };
                
                // 11. Almacenar score
                await StoreRiskScoreAsync(riskScore);
                _deviceRiskScores[deviceId] = riskScore;
                
                // 12. Emitir eventos si es necesario
                if (riskLevel >= RiskLevel.High)
                {
                    await EmitRiskEventAsync(riskScore);
                }
                
                var processingTime = DateTime.UtcNow - startTime;
                _logger.LogInformation("📈 Score calculado para {DeviceId}: {Score:F2} ({Level}) en {Time}ms", 
                    deviceId, riskScore.TotalScore, riskLevel, processingTime.TotalMilliseconds);
                
                return riskScore;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error calculando score de riesgo para dispositivo {DeviceId}", deviceId);
                throw new RiskCalculationException($"Failed to calculate risk score for device {deviceId}", ex);
            }
        }
        
        /// <summary>
        /// Calcula score de riesgo para una amenaza específica
        /// </summary>
        public async Task<ThreatRiskScore> CalculateThreatRiskAsync(
            string threatId, 
            ThreatContext context,
            bool includePropagation = true)
        {
            ValidateOperation();
            
            if (string.IsNullOrEmpty(threatId))
                throw new ArgumentException("Threat ID cannot be null or empty", nameof(threatId));
            
            if (context == null)
                throw new ArgumentNullException(nameof(context), "Threat context is required");
            
            try
            {
                _logger.LogDebug("⚠️ Calculando score de riesgo para amenaza {ThreatId}: {ThreatName}", 
                    threatId, context.ThreatName);
                
                var startTime = DateTime.UtcNow;
                
                // 1. Calcular factores de amenaza
                var threatFactors = await CalculateThreatFactorsAsync(context);
                
                // 2. Calcular impacto potencial
                var impactScore = CalculateImpactScore(context);
                
                // 3. Calcular probabilidad
                var probabilityScore = CalculateProbabilityScore(context);
                
                // 4. Calcular severidad técnica
                var technicalSeverity = CalculateTechnicalSeverity(context);
                
                // 5. Calcular propagación si se solicita
                var propagationScore = includePropagation ? 
                    await CalculatePropagationScoreAsync(threatId, context) : 0;
                
                // 6. Calcular score compuesto
                var compositeScore = CalculateThreatCompositeScore(
                    impactScore, probabilityScore, technicalSeverity, propagationScore, threatFactors);
                
                // 7. Determinar nivel de amenaza
                var threatLevel = DetermineRiskLevel(compositeScore, RiskEntityType.Threat);
                
                // 8. Calcular confianza
                var confidence = CalculateThreatConfidence(context, threatFactors);
                
                // 9. Generar recomendaciones de mitigación
                var mitigations = GenerateThreatMitigations(threatLevel, context, threatFactors);
                
                // 10. Crear objeto de resultado
                var threatRiskScore = new ThreatRiskScore
                {
                    ScoreId = GenerateScoreId("THR", threatId),
                    ThreatId = threatId,
                    ThreatName = context.ThreatName,
                    ThreatType = context.ThreatType,
                    Timestamp = DateTime.UtcNow,
                    CompositeScore = compositeScore,
                    ThreatLevel = threatLevel,
                    Confidence = confidence,
                    ImpactScore = impactScore,
                    ProbabilityScore = probabilityScore,
                    TechnicalSeverity = technicalSeverity,
                    PropagationScore = propagationScore,
                    ThreatFactors = threatFactors,
                    AffectedDevices = context.AffectedDevices,
                    FirstDetected = context.FirstDetected,
                    LastDetected = context.LastDetected,
                    CalculationTime = DateTime.UtcNow - startTime,
                    MitigationRecommendations = mitigations,
                    IsActive = context.IsActive,
                    HasMitigations = context.MitigationsApplied?.Count > 0,
                    Metadata = new Dictionary<string, object>
                    {
                        { "ThreatCategory", context.ThreatCategory },
                        { "AttackVector", context.AttackVector },
                        { "Tactics", context.Tactics },
                        { "Techniques", context.Techniques },
                        { "Indicators", context.Indicators?.Count ?? 0 }
                    }
                };
                
                // 11. Almacenar score de amenaza
                await StoreThreatRiskScoreAsync(threatRiskScore);
                _threatRiskScores[threatId] = threatRiskScore;
                
                // 12. Emitir eventos si es crítico
                if (threatLevel >= RiskLevel.High)
                {
                    await EmitThreatEventAsync(threatRiskScore);
                }
                
                _logger.LogInformation("🎯 Score calculado para amenaza {ThreatId}: {Score:F2} ({Level})", 
                    threatId, compositeScore, threatLevel);
                
                return threatRiskScore;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error calculando score de riesgo para amenaza {ThreatId}", threatId);
                throw new RiskCalculationException($"Failed to calculate risk score for threat {threatId}", ex);
            }
        }
        
        /// <summary>
        /// Calcula score de riesgo agregado para un tenant
        /// </summary>
        public async Task<TenantRiskScore> CalculateTenantRiskAsync(
            string tenantId, 
            TenantContext context = null,
            bool includeDevices = true,
            bool includeThreats = true)
        {
            ValidateOperation();
            
            if (string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("Tenant ID cannot be null or empty", nameof(tenantId));
            
            try
            {
                _logger.LogDebug("🏢 Calculando score de riesgo para tenant {TenantId}", tenantId);
                var startTime = DateTime.UtcNow;
                
                // 1. Obtener contexto del tenant
                var tenantContext = context ?? await GetTenantContextAsync(tenantId);
                
                // 2. Calcular scores de dispositivos si se solicita
                var deviceScores = includeDevices ? 
                    await CalculateTenantDeviceScoresAsync(tenantId, tenantContext) : 
                    new List<DeviceRiskScore>();
                
                // 3. Calcular scores de amenazas si se solicita
                var threatScores = includeThreats ? 
                    await CalculateTenantThreatScoresAsync(tenantId, tenantContext) : 
                    new List<ThreatRiskScore>();
                
                // 4. Calcular factores del tenant
                var tenantFactors = await CalculateTenantFactorsAsync(tenantContext, deviceScores, threatScores);
                
                // 5. Calcular score agregado del tenant
                var tenantScore = CalculateAggregateTenantScore(tenantFactors, deviceScores, threatScores);
                
                // 6. Determinar nivel de riesgo del tenant
                var tenantRiskLevel = DetermineRiskLevel(tenantScore, RiskEntityType.Tenant);
                
                // 7. Calcular métricas de distribución
                var distributionMetrics = CalculateRiskDistributionMetrics(deviceScores, threatScores);
                
                // 8. Identificar puntos críticos
                var criticalPoints = IdentifyCriticalPoints(deviceScores, threatScores);
                
                // 9. Generar recomendaciones del tenant
                var recommendations = GenerateTenantRecommendations(tenantRiskLevel, deviceScores, threatScores, tenantContext);
                
                // 10. Crear objeto de resultado
                var tenantRiskScore = new TenantRiskScore
                {
                    ScoreId = GenerateScoreId("TEN", tenantId),
                    TenantId = tenantId,
                    TenantName = tenantContext.TenantName,
                    Timestamp = DateTime.UtcNow,
                    TotalScore = tenantScore,
                    RiskLevel = tenantRiskLevel,
                    TenantFactors = tenantFactors,
                    DeviceCount = deviceScores.Count,
                    ThreatCount = threatScores.Count,
                    DeviceScores = deviceScores,
                    ThreatScores = threatScores,
                    HighRiskDevices = deviceScores.Count(d => d.RiskLevel >= RiskLevel.High),
                    CriticalThreats = threatScores.Count(t => t.ThreatLevel >= RiskLevel.High),
                    DistributionMetrics = distributionMetrics,
                    CriticalPoints = criticalPoints,
                    CalculationTime = DateTime.UtcNow - startTime,
                    Recommendations = recommendations,
                    HistoricalTrend = await GetTenantHistoricalTrendAsync(tenantId),
                    ComparisonToPeers = await CompareToPeerTenantsAsync(tenantId, tenantScore),
                    Metadata = new Dictionary<string, object>
                    {
                        { "Industry", tenantContext.Industry },
                        { "EmployeeCount", tenantContext.EmployeeCount },
                        { "DeviceCount", tenantContext.DeviceCount },
                        { "SecurityMaturity", tenantContext.SecurityMaturity },
                        { "ComplianceRequirements", tenantContext.ComplianceRequirements }
                    }
                };
                
                // 11. Almacenar score del tenant
                await StoreTenantRiskScoreAsync(tenantRiskScore);
                _tenantRiskScores[tenantId] = tenantRiskScore;
                
                // 12. Emitir reporte si es necesario
                if (tenantRiskLevel >= RiskLevel.Medium)
                {
                    await EmitTenantReportAsync(tenantRiskScore);
                }
                
                _logger.LogInformation("📊 Score calculado para tenant {TenantId}: {Score:F2} ({Level}) - {HighRisk} dispositivos de alto riesgo", 
                    tenantId, tenantScore, tenantRiskLevel, tenantRiskScore.HighRiskDevices);
                
                return tenantRiskScore;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error calculando score de riesgo para tenant {TenantId}", tenantId);
                throw new RiskCalculationException($"Failed to calculate risk score for tenant {tenantId}", ex);
            }
        }
        
        /// <summary>
        /// Obtiene análisis de tendencia de riesgo
        /// </summary>
        public async Task<RiskTrendAnalysis> AnalyzeRiskTrendAsync(
            string entityId, 
            RiskEntityType entityType, 
            TimeSpan analysisPeriod,
            TrendAnalysisOptions options = null)
        {
            ValidateOperation();
            
            if (string.IsNullOrEmpty(entityId))
                throw new ArgumentException("Entity ID cannot be null or empty", nameof(entityId));
            
            try
            {
                _logger.LogDebug("📈 Analizando tendencia de riesgo para {EntityType} {EntityId} (período: {Period})", 
                    entityType, entityId, analysisPeriod);
                
                options ??= new TrendAnalysisOptions();
                
                // 1. Obtener scores históricos
                var historicalScores = await GetHistoricalRiskScoresAsync(entityId, entityType, analysisPeriod);
                
                if (historicalScores.Count < options.MinDataPoints)
                {
                    return new RiskTrendAnalysis
                    {
                        EntityId = entityId,
                        EntityType = entityType,
                        AnalysisPeriod = analysisPeriod,
                        HasEnoughData = false,
                        Message = $"Datos insuficientes para análisis de tendencia (mínimo {options.MinDataPoints} puntos requeridos, se tienen {historicalScores.Count})",
                        DataPointCount = historicalScores.Count
                    };
                }
                
                // 2. Calcular estadísticas descriptivas
                var statistics = CalculateTrendStatistics(historicalScores);
                
                // 3. Detectar tendencia principal
                var trend = DetectMainTrend(historicalScores, options);
                
                // 4. Identificar patrones estacionales
                var seasonality = DetectSeasonalityPatterns(historicalScores, options);
                
                // 5. Identificar puntos de cambio
                var changePoints = DetectChangePoints(historicalScores, options);
                
                // 6. Detectar anomalías
                var anomalies = DetectAnomalies(historicalScores, options);
                
                // 7. Identificar picos de riesgo
                var riskSpikes = IdentifyRiskSpikes(historicalScores, options);
                
                // 8. Predecir tendencia futura
                var futurePrediction = PredictFutureTrend(historicalScores, trend, options);
                
                // 9. Calcular métricas de calidad
                var qualityMetrics = CalculateTrendQualityMetrics(historicalScores, trend);
                
                // 10. Generar insights
                var insights = GenerateTrendInsights(trend, changePoints, anomalies, riskSpikes);
                
                // 11. Crear objeto de análisis
                var analysis = new RiskTrendAnalysis
                {
                    EntityId = entityId,
                    EntityType = entityType,
                    AnalysisPeriod = analysisPeriod,
                    Timestamp = DateTime.UtcNow,
                    HasEnoughData = true,
                    HistoricalScores = historicalScores,
                    Statistics = statistics,
                    Trend = trend,
                    SeasonalityPatterns = seasonality,
                    ChangePoints = changePoints,
                    Anomalies = anomalies,
                    RiskSpikes = riskSpikes,
                    FuturePrediction = futurePrediction,
                    QualityMetrics = qualityMetrics,
                    Insights = insights,
                    Recommendations = GenerateTrendRecommendations(trend, changePoints, anomalies),
                    Metadata = new Dictionary<string, object>
                    {
                        { "AnalysisMethod", options.AnalysisMethod },
                        { "ConfidenceInterval", options.ConfidenceLevel },
                        { "SmoothingApplied", options.ApplySmoothing },
                        { "OutlierDetection", options.DetectOutliers }
                    }
                };
                
                _logger.LogInformation("📊 Análisis de tendencia completado para {EntityType} {EntityId}: {TrendDirection} ({Confidence}% confianza)", 
                    entityType, entityId, trend.Direction, trend.Confidence * 100);
                
                return analysis;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error analizando tendencia de riesgo para {EntityType} {EntityId}", entityType, entityId);
                throw new RiskAnalysisException($"Failed to analyze risk trend for {entityType} {entityId}", ex);
            }
        }
        
        /// <summary>
        /// Obtiene dashboard de riesgo consolidado
        /// </summary>
        public async Task<RiskDashboard> GetRiskDashboardAsync(
            string tenantId = null, 
            DashboardOptions options = null)
        {
            ValidateOperation();
            
            try
            {
                _logger.LogDebug("🎛️ Generando dashboard de riesgo para tenant {TenantId}", tenantId ?? "global");
                var startTime = DateTime.UtcNow;
                
                options ??= new DashboardOptions();
                
                // 1. Obtener estadísticas generales
                var overallStats = await GetOverallRiskStatisticsAsync(tenantId);
                
                // 2. Obtener top dispositivos de alto riesgo
                var highRiskDevices = await GetHighRiskDevicesAsync(
                    options.TopDevicesCount, tenantId, options.MinRiskLevel);
                
                // 3. Obtener top amenazas críticas
                var criticalThreats = await GetCriticalThreatsAsync(
                    options.TopThreatsCount, tenantId, options.MinThreatLevel);
                
                // 4. Calcular distribución de riesgo
                var riskDistribution = await CalculateRiskDistributionAsync(tenantId);
                
                // 5. Obtener tendencias recientes
                var recentTrends = await GetRecentTrendsAsync(
                    options.TrendPeriod, tenantId, options.EntitiesToInclude);
                
                // 6. Obtener alertas de riesgo activas
                var activeRiskAlerts = await GetActiveRiskAlertsAsync(tenantId, options.AlertSeverity);
                
                // 7. Calcular métricas clave
                var riskMetrics = await CalculateRiskMetricsAsync(tenantId);
                
                // 8. Obtener insights predictivos
                var predictiveInsights = await GetPredictiveInsightsAsync(tenantId, options.PredictionHorizon);
                
                // 9. Obtener comparativas
                var comparisons = await GetRiskComparisonsAsync(tenantId, options.ComparisonGroups);
                
                // 10. Crear dashboard
                var dashboard = new RiskDashboard
                {
                    DashboardId = GenerateDashboardId(tenantId),
                    Timestamp = DateTime.UtcNow,
                    TenantId = tenantId,
                    TimeRange = options.TrendPeriod,
                    OverallRiskScore = overallStats.AverageScore,
                    OverallRiskLevel = overallStats.OverallLevel,
                    OverallConfidence = overallStats.Confidence,
                    DeviceCount = overallStats.DeviceCount,
                    ThreatCount = overallStats.ThreatCount,
                    HighRiskDeviceCount = overallStats.HighRiskDeviceCount,
                    CriticalThreatCount = overallStats.CriticalThreatCount,
                    HighRiskDevices = highRiskDevices,
                    CriticalThreats = criticalThreats,
                    RiskDistribution = riskDistribution,
                    RecentTrends = recentTrends,
                    ActiveRiskAlerts = activeRiskAlerts,
                    RiskMetrics = riskMetrics,
                    PredictiveInsights = predictiveInsights,
                    Comparisons = comparisons,
                    GenerationTime = DateTime.UtcNow - startTime,
                    LastDataUpdate = _lastScoringUpdate,
                    RefreshInterval = _configuration.DashboardRefreshInterval,
                    Metadata = new Dictionary<string, object>
                    {
                        { "DashboardVersion", "3.0" },
                        { "DataFreshness", (DateTime.UtcNow - _lastScoringUpdate).TotalMinutes },
                        { "ScoringEngine", EngineId },
                        { "IncludedEntities", options.EntitiesToInclude.Count }
                    }
                };
                
                _logger.LogInformation("📋 Dashboard generado para tenant {TenantId} en {Time}ms", 
                    tenantId ?? "global", (DateTime.UtcNow - startTime).TotalMilliseconds);
                
                return dashboard;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error generando dashboard de riesgo");
                throw new RiskDashboardException("Failed to generate risk dashboard", ex);
            }
        }
        
        /// <summary>
        /// Actualiza dinámicamente los factores de riesgo
        /// </summary>
        public async Task UpdateRiskFactorsAsync(List<RiskFactor> newFactors, bool merge = true)
        {
            ValidateOperation();
            
            if (newFactors == null || newFactors.Count == 0)
                throw new ArgumentException("Risk factors cannot be null or empty", nameof(newFactors));
            
            try
            {
                _logger.LogInformation("🔄 Actualizando factores de riesgo: {Count} nuevos factores", newFactors.Count);
                
                // Validar nuevos factores
                var validFactors = ValidateRiskFactors(newFactors);
                
                if (validFactors.Count == 0)
                {
                    _logger.LogWarning("⚠️ No hay factores válidos para actualizar");
                    return;
                }
                
                lock (_scoringLock)
                {
                    if (merge)
                    {
                        // Fusionar con factores existentes
                        foreach (var factor in validFactors)
                        {
                            var existingFactor = _riskFactors.FirstOrDefault(f => f.FactorId == factor.FactorId);
                            if (existingFactor != null)
                            {
                                _riskFactors.Remove(existingFactor);
                            }
                            _riskFactors.Add(factor);
                        }
                    }
                    else
                    {
                        // Reemplazar todos los factores
                        _riskFactors.Clear();
                        _riskFactors.AddRange(validFactors);
                    }
                    
                    // Ordenar por peso descendente
                    _riskFactors = _riskFactors.OrderByDescending(f => f.BaseWeight).ToList();
                }
                
                // Recalibrar pesos
                await RecalibrateRiskWeightsAsync();
                
                // Invalidar cache para forzar recálculo
                InvalidateCache();
                
                _logger.LogInformation("✅ Factores de riesgo actualizados: {Count} factores activos", _riskFactors.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error actualizando factores de riesgo");
                throw new RiskConfigurationException("Failed to update risk factors", ex);
            }
        }
        
        /// <summary>
        /// Optimiza los pesos de riesgo basado en datos históricos
        /// </summary>
        public async Task OptimizeRiskWeightsAsync(OptimizationOptions options = null)
        {
            ValidateOperation();
            
            try
            {
                _logger.LogInformation("⚙️ Optimizando pesos de riesgo...");
                
                options ??= new OptimizationOptions();
                
                // 1. Obtener datos históricos para entrenamiento
                var trainingData = await GetOptimizationTrainingDataAsync(options);
                
                if (trainingData.Count < options.MinTrainingSamples)
                {
                    _logger.LogWarning("⚠️ Datos insuficientes para optimización (mínimo {Min} muestras, se tienen {Actual})", 
                        options.MinTrainingSamples, trainingData.Count);
                    return;
                }
                
                // 2. Aplicar algoritmo de optimización
                var optimizedWeights = await OptimizeWeightsUsingAlgorithmAsync(trainingData, options);
                
                // 3. Validar pesos optimizados
                var validWeights = ValidateOptimizedWeights(optimizedWeights);
                
                if (validWeights.Count == 0)
                {
                    _logger.LogWarning("⚠️ No se generaron pesos válidos en la optimización");
                    return;
                }
                
                // 4. Aplicar pesos optimizados
                ApplyOptimizedWeights(validWeights, options.ApplyImmediately);
                
                // 5. Evaluar mejora
                var improvement = await EvaluateOptimizationImprovementAsync(trainingData, validWeights);
                
                _logger.LogInformation("✅ Optimización completada: {Improvement:F2}% de mejora en precisión", 
                    improvement * 100);
                
                // 6. Emitir evento de optimización
                await EmitOptimizationEventAsync(validWeights, improvement);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error optimizando pesos de riesgo");
                throw new RiskOptimizationException("Failed to optimize risk weights", ex);
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del motor de scoring
        /// </summary>
        public async Task<RiskScoringStats> GetStatisticsAsync()
        {
            try
            {
                var cacheStats = GetCacheStatistics();
                var scoringStats = GetScoringStatistics();
                var algorithmStats = GetAlgorithmStatistics();
                var performanceStats = GetPerformanceStatistics();
                
                var stats = new RiskScoringStats
                {
                    Timestamp = DateTime.UtcNow,
                    EngineId = EngineId,
                    Version = Version,
                    IsInitialized = _isInitialized,
                    IsRunning = _isInitialized,
                    LastScoringUpdate = _lastScoringUpdate,
                    
                    // Estadísticas de cache
                    DeviceScoresCached = cacheStats.DeviceScoresCached,
                    ThreatScoresCached = cacheStats.ThreatScoresCached,
                    TenantScoresCached = cacheStats.TenantScoresCached,
                    CacheHitRate = cacheStats.CacheHitRate,
                    CacheMemoryUsage = cacheStats.CacheMemoryUsage,
                    
                    // Estadísticas de scoring
                    TotalCalculations = scoringStats.TotalCalculations,
                    AverageCalculationTime = scoringStats.AverageCalculationTime,
                    FailedCalculations = scoringStats.FailedCalculations,
                    SuccessRate = scoringStats.SuccessRate,
                    
                    // Estadísticas de algoritmos
                    ActiveFactors = algorithmStats.ActiveFactors,
                    ActiveWeights = algorithmStats.ActiveWeights,
                    ActiveThresholds = algorithmStats.ActiveThresholds,
                    AlgorithmVersion = algorithmStats.AlgorithmVersion,
                    
                    // Estadísticas de rendimiento
                    MemoryUsage = performanceStats.MemoryUsage,
                    CpuUsage = performanceStats.CpuUsage,
                    QueueSize = performanceStats.QueueSize,
                    ActiveWorkers = performanceStats.ActiveWorkers,
                    
                    // Métricas de calidad
                    ScoreDistribution = await GetScoreDistributionAsync(),
                    ConfidenceLevels = await GetConfidenceLevelsAsync(),
                    TrendAccuracy = await GetTrendAccuracyAsync(),
                    
                    // Configuración
                    Configuration = _configuration,
                    HealthStatus = await CheckHealthAsync()
                };
                
                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error obteniendo estadísticas del motor de scoring");
                return new RiskScoringStats
                {
                    Timestamp = DateTime.UtcNow,
                    IsInitialized = _isInitialized,
                    HasError = true,
                    ErrorMessage = ex.Message
                };
            }
        }
        
        /// <summary>
        /// Verifica la salud del motor
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                var details = new Dictionary<string, object>();
                
                // 1. Verificar inicialización
                if (!_isInitialized)
                    issues.Add("Motor no inicializado");
                
                // 2. Verificar factores de riesgo
                if (_riskFactors.Count == 0)
                    issues.Add("No hay factores de riesgo configurados");
                
                // 3. Verificar pesos
                if (_riskWeights.Count == 0)
                    issues.Add("No hay pesos de riesgo configurados");
                
                // 4. Verificar umbrales
                if (_riskThresholds.Count == 0)
                    issues.Add("No hay umbrales de riesgo configurados");
                
                // 5. Verificar datos recientes
                var timeSinceUpdate = DateTime.UtcNow - _lastScoringUpdate;
                if (timeSinceUpdate > TimeSpan.FromHours(2))
                    issues.Add($"Sin actualizaciones recientes ({timeSinceUpdate.TotalHours:F1} horas)");
                
                // 6. Verificar cache
                if (_deviceRiskScores.Count == 0 && _threatRiskScores.Count == 0)
                    issues.Add("Cache de scores vacío");
                
                // 7. Verificar rendimiento
                var perfIssues = CheckPerformanceHealth();
                issues.AddRange(perfIssues);
                
                // 8. Verificar conectividad con base de datos
                var dbHealth = await CheckDatabaseHealthAsync();
                if (!dbHealth.IsHealthy)
                    issues.Add($"Problemas con base de datos: {dbHealth.Message}");
                
                details["DatabaseHealth"] = dbHealth;
                details["TimeSinceUpdate"] = timeSinceUpdate;
                details["CacheSize"] = _deviceRiskScores.Count + _threatRiskScores.Count + _tenantRiskScores.Count;
                details["ActiveFactors"] = _riskFactors.Count;
                details["MemoryUsage"] = GetMemoryUsageMB();
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("RiskScoringEngine funcionando correctamente", details);
                }
                
                var status = issues.Any(i => i.Contains("no inicializado") || i.Contains("vacío")) ? 
                    HealthStatus.Unhealthy : HealthStatus.Degraded;
                
                return new HealthCheckResult
                {
                    Status = status,
                    Message = string.Join("; ", issues),
                    Details = details,
                    Timestamp = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy($"Error en health check: {ex.Message}", new Dictionary<string, object>
                {
                    { "Exception", ex.ToString() },
                    { "StackTrace", ex.StackTrace }
                });
            }
        }
        
        /// <summary>
        /// Detiene el motor de scoring
        /// </summary>
        public async Task StopAsync()
        {
            try
            {
                _logger.LogInformation("🛑 Deteniendo RiskScoringEngine...");
                
                // 1. Detener tareas periódicas
                StopPeriodicTasks();
                
                // 2. Persistir datos en cache
                await PersistCacheDataAsync();
                
                // 3. Limpiar recursos
                CleanupResources();
                
                // 4. Cambiar estado
                _isInitialized = false;
                
                _logger.LogInformation("✅ RiskScoringEngine detenido correctamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error deteniendo RiskScoringEngine");
                throw;
            }
        }
        
        #region Métodos privados de inicialización
        
        private void ValidateConfiguration()
        {
            var errors = new List<string>();
            
            if (_configuration == null)
                errors.Add("Configuration is null");
            
            if (_configuration.CacheValidityMinutes <= 0)
                errors.Add("Cache validity must be positive");
            
            if (_configuration.MinimumDataPoints <= 0)
                errors.Add("Minimum data points must be positive");
            
            if (_configuration.ScoringInterval <= TimeSpan.Zero)
                errors.Add("Scoring interval must be positive");
            
            if (errors.Count > 0)
            {
                throw new RiskConfigurationException($"Invalid configuration: {string.Join("; ", errors)}");
            }
        }
        
        private async Task LoadRiskFactorsAsync()
        {
            try
            {
                // Intentar cargar desde configuración externa
                var externalFactors = await LoadExternalRiskFactorsAsync();
                if (externalFactors?.Count > 0)
                {
                    _riskFactors.AddRange(externalFactors);
                    _logger.LogInformation("📂 Cargados {Count} factores de riesgo desde configuración externa", externalFactors.Count);
                }
                else
                {
                    // Cargar factores predefinidos
                    await LoadDefaultRiskFactorsAsync();
                    _logger.LogInformation("📂 Cargados {Count} factores de riesgo predefinidos", _riskFactors.Count);
                }
                
                // Validar factores cargados
                var validFactors = ValidateRiskFactors(_riskFactors);
                if (validFactors.Count != _riskFactors.Count)
                {
                    _logger.LogWarning("⚠️ {InvalidCount} factores de riesgo inválidos filtrados", 
                        _riskFactors.Count - validFactors.Count);
                    _riskFactors.Clear();
                    _riskFactors.AddRange(validFactors);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error cargando factores de riesgo");
                throw;
            }
        }
        
        private async Task LoadDefaultRiskFactorsAsync()
        {
            // Factores de riesgo predefinidos con valores realistas
            _riskFactors.Add(new RiskFactor
            {
                FactorId = "NETWORK_SUSPICIOUS_ACTIVITY",
                Name = "Actividad de Red Sospechosa",
                Description = "Detección de conexiones anómalas, patrones de comunicación sospechosos y destinos de alto riesgo",
                Category = RiskCategory.Network,
                BaseWeight = 0.18,
                MaxScore = 100,
                CalculationMethod = "StatisticalAnalysis",
                SeverityMultiplier = 1.2,
                TimeSensitivity = 0.8,
                DataRequirements = new List<string> { "NetworkEvents", "DNSQueries", "FirewallLogs" },
                Thresholds = new Dictionary<RiskLevel, double>
                {
                    [RiskLevel.Info] = 10,
                    [RiskLevel.Low] = 25,
                    [RiskLevel.Medium] = 50,
                    [RiskLevel.High] = 75,
                    [RiskLevel.Critical] = 90
                },
                Indicators = new List<string>
                {
                    "Conexiones a destinos de alto riesgo",
                    "Comunicación con dominios recién registrados",
                    "Patrones de exfiltración de datos",
                    "Tráfico en horas no laborales",
                    "Volumen anómalo de tráfico"
                },
                IsEnabled = true,
                RequiresCalibration = true,
                LastCalibrated = DateTime.UtcNow,
                Confidence = 0.85
            });
            
            _riskFactors.Add(new RiskFactor
            {
                FactorId = "PROCESS_ANOMALOUS_BEHAVIOR",
                Name = "Comportamiento de Proceso Anómalo",
                Description = "Detección de procesos con comportamiento inusual, ejecución de código malicioso o técnicas de evasión",
                Category = RiskCategory.Process,
                BaseWeight = 0.22,
                MaxScore = 100,
                CalculationMethod = "BehavioralAnalysis",
                SeverityMultiplier = 1.5,
                TimeSensitivity = 0.9,
                DataRequirements = new List<string> { "ProcessEvents", "ThreadEvents", "ModuleLoads" },
                Thresholds = new Dictionary<RiskLevel, double>
                {
                    [RiskLevel.Info] = 15,
                    [RiskLevel.Low] = 30,
                    [RiskLevel.Medium] = 60,
                    [RiskLevel.High] = 85,
                    [RiskLevel.Critical] = 95
                },
                Indicators = new List<string>
                {
                    "Proceso inyectando código en otros procesos",
                    "Uso de técnicas de ofuscación",
                    "Ejecución desde ubicaciones atípicas",
                    "Comportamiento similar a malware conocido",
                    "Creación anómala de procesos hijos"
                },
                IsEnabled = true,
                RequiresCalibration = true,
                LastCalibrated = DateTime.UtcNow,
                Confidence = 0.88
            });
            
            _riskFactors.Add(new RiskFactor
            {
                FactorId = "FILE_SENSITIVE_ACCESS",
                Name = "Acceso a Archivos Sensitivos",
                Description = "Monitoreo de acceso no autorizado a archivos confidenciales o críticos para el negocio",
                Category = RiskCategory.FileSystem,
                BaseWeight = 0.16,
                MaxScore = 100,
                CalculationMethod = "AccessPatternAnalysis",
                SeverityMultiplier = 1.3,
                TimeSensitivity = 0.7,
                DataRequirements = new List<string> { "FileEvents", "AccessControlLogs" },
                Thresholds = new Dictionary<RiskLevel, double>
                {
                    [RiskLevel.Info] = 5,
                    [RiskLevel.Low] = 20,
                    [RiskLevel.Medium] = 40,
                    [RiskLevel.High] = 70,
                    [RiskLevel.Critical] = 85
                },
                Indicators = new List<string>
                {
                    "Acceso a archivos de contraseñas",
                    "Lectura de documentos confidenciales",
                    "Modificación de binarios del sistema",
                    "Patrones de copia masiva",
                    "Acceso fuera de horarios normales"
                },
                IsEnabled = true,
                RequiresCalibration = true,
                LastCalibrated = DateTime.UtcNow,
                Confidence = 0.82
            });
            
            // ... (continuaría con más factores predefinidos)
            
            await Task.CompletedTask;
        }
        
        private async Task LoadRiskWeightsAsync()
        {
            // Pesos predefinidos para diferentes categorías de riesgo
            _riskWeights[RiskCategory.Network] = new RiskWeight
            {
                Category = RiskCategory.Network,
                BaseWeight = 0.18,
                DynamicAdjustments = new Dictionary<string, double>
                {
                    ["CriticalSeverity"] = 1.5,
                    ["HighSeverity"] = 1.2,
                    ["MediumSeverity"] = 1.0,
                    ["LowSeverity"] = 0.8,
                    ["InfoSeverity"] = 0.5,
                    ["RecentActivity"] = 1.3,
                    ["HistoricalPattern"] = 0.9,
                    ["BusinessCritical"] = 1.4
                },
                TimeDecayFactor = 0.95,
                MaxWeight = 0.25,
                MinWeight = 0.05,
                LearningRate = 0.01,
                RequiresRecalibration = true,
                LastRecalibrated = DateTime.UtcNow,
                Confidence = 0.8
            };
            
            _riskWeights[RiskCategory.Process] = new RiskWeight
            {
                Category = RiskCategory.Process,
                BaseWeight = 0.22,
                DynamicAdjustments = new Dictionary<string, double>
                {
                    ["CriticalSeverity"] = 1.6,
                    ["HighSeverity"] = 1.3,
                    ["MediumSeverity"] = 1.0,
                    ["LowSeverity"] = 0.7,
                    ["InfoSeverity"] = 0.4,
                    ["MalwareMatch"] = 1.8,
                    ["SuspiciousBehavior"] = 1.5,
                    ["PrivilegeEscalation"] = 2.0
                },
                TimeDecayFactor = 0.90,
                MaxWeight = 0.30,
                MinWeight = 0.10,
                LearningRate = 0.015,
                RequiresRecalibration = true,
                LastRecalibrated = DateTime.UtcNow,
                Confidence = 0.85
            };
            
            // ... (continuaría con más pesos)
            
            await Task.CompletedTask;
        }
        
        private async Task LoadRiskThresholdsAsync()
        {
            // Umbrales predefinidos para diferentes tipos de entidades
            _riskThresholds[RiskEntityType.Device] = new RiskThreshold
            {
                EntityType = RiskEntityType.Device,
                Levels = new Dictionary<RiskLevel, ThresholdRange>
                {
                    [RiskLevel.None] = new ThresholdRange { Min = 0, Max = 5 },
                    [RiskLevel.Info] = new ThresholdRange { Min = 5, Max = 20 },
                    [RiskLevel.Low] = new ThresholdRange { Min = 20, Max = 40 },
                    [RiskLevel.Medium] = new ThresholdRange { Min = 40, Max = 65 },
                    [RiskLevel.High] = new ThresholdRange { Min = 65, Max = 85 },
                    [RiskLevel.Critical] = new ThresholdRange { Min = 85, Max = 100 }
                },
                Hysteresis = new Dictionary<RiskLevel, double>
                {
                    [RiskLevel.None] = 2,
                    [RiskLevel.Info] = 3,
                    [RiskLevel.Low] = 4,
                    [RiskLevel.Medium] = 5,
                    [RiskLevel.High] = 6,
                    [RiskLevel.Critical] = 8
                },
                RequiresCalibration = true,
                LastCalibrated = DateTime.UtcNow,
                CalibrationSamples = 1000,
                Confidence = 0.9
            };
            
            // ... (continuaría con más umbrales)
            
            await Task.CompletedTask;
        }
        
        private async Task VerifyDataIntegrityAsync()
        {
            try
            {
                _logger.LogDebug("🔍 Verificando integridad de datos de riesgo...");
                
                // Verificar que los pesos sumen aproximadamente 1
                var totalWeight = _riskWeights.Values.Sum(w => w.BaseWeight);
                if (Math.Abs(totalWeight - 1.0) > 0.1)
                {
                    _logger.LogWarning("⚠️ La suma de pesos base ({TotalWeight:F2}) no es cercana a 1.0", totalWeight);
                    await RecalibrateRiskWeightsAsync();
                }
                
                // Verificar que todos los factores tengan categorías válidas
                var invalidFactors = _riskFactors.Where(f => !_riskWeights.ContainsKey(f.Category)).ToList();
                if (invalidFactors.Count > 0)
                {
                    _logger.LogWarning("⚠️ {Count} factores con categorías sin pesos correspondientes", invalidFactors.Count);
                    // Podríamos crear pesos por defecto o eliminar factores
                }
                
                // Verificar umbrales superpuestos
                foreach (var threshold in _riskThresholds.Values)
                {
                    if (HasOverlappingThresholds(threshold))
                    {
                        _logger.LogWarning("⚠️ Umbrales superpuestos detectados para {EntityType}", threshold.EntityType);
                    }
                }
                
                _logger.LogDebug("✅ Integridad de datos verificada");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error verificando integridad de datos de riesgo");
                throw;
            }
        }
        
        private async Task LoadExistingRiskScoresAsync()
        {
            try
            {
                _logger.LogDebug("📂 Cargando scores de riesgo existentes...");
                
                var loadTasks = new List<Task>();
                var loadedCount = 0;
                
                // Cargar scores de dispositivos
                loadTasks.Add(Task.Run(async () =>
                {
                    var deviceScores = await _graphDatabase.GetRecentDeviceRiskScoresAsync(
                        TimeSpan.FromHours(_configuration.CacheValidityMinutes / 60.0));
                    
                    foreach (var score in deviceScores)
                    {
                        _deviceRiskScores[score.DeviceId] = score;
                        loadedCount++;
                    }
                    
                    _logger.LogDebug("📱 Cargados {Count} scores de dispositivo", deviceScores.Count);
                }));
                
                // Cargar scores de amenazas
                loadTasks.Add(Task.Run(async () =>
                {
                    var threatScores = await _graphDatabase.GetRecentThreatRiskScoresAsync(
                        TimeSpan.FromHours(_configuration.CacheValidityMinutes / 60.0));
                    
                    foreach (var score in threatScores)
                    {
                        _threatRiskScores[score.ThreatId] = score;
                        loadedCount++;
                    }
                    
                    _logger.LogDebug("⚠️ Cargados {Count} scores de amenaza", threatScores.Count);
                }));
                
                // Cargar scores de tenants
                loadTasks.Add(Task.Run(async () =>
                {
                    var tenantScores = await _graphDatabase.GetRecentTenantRiskScoresAsync(
                        TimeSpan.FromHours(_configuration.CacheValidityMinutes / 60.0 * 2)); // Doble tiempo para tenants
                    
                    foreach (var score in tenantScores)
                    {
                        _tenantRiskScores[score.TenantId] = score;
                        loadedCount++;
                    }
                    
                    _logger.LogDebug("🏢 Cargados {Count} scores de tenant", tenantScores.Count);
                }));
                
                await Task.WhenAll(loadTasks);
                
                _logger.LogInformation("✅ Cargados {TotalCount} scores de riesgo existentes", loadedCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error cargando scores de riesgo existentes, continuando con cache vacío");
            }
        }
        
        private void InitializeScoringAlgorithms()
        {
            try
            {
                _logger.LogDebug("🧠 Inicializando algoritmos de scoring...");
                
                // Inicializar algoritmos específicos
                InitializeWeightedAverageAlgorithm();
                InitializeMachineLearningAlgorithms();
                InitializeStatisticalAlgorithms();
                InitializeTrendAnalysisAlgorithms();
                
                _logger.LogDebug("✅ Algoritmos de scoring inicializados");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error inicializando algoritmos de scoring");
                throw;
            }
        }
        
        private void SchedulePeriodicTasks()
        {
            try
            {
                _logger.LogDebug("⏰ Programando tareas periódicas...");
                
                // Programar scoring periódico
                _ = Task.Run(async () =>
                {
                    while (_isInitialized)
                    {
                        await Task.Delay(_configuration.ScoringInterval);
                        try
                        {
                            await PerformPeriodicScoringAsync();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Error en scoring periódico");
                        }
                    }
                });
                
                // Programar limpieza de cache
                _ = Task.Run(async () =>
                {
                    while (_isInitialized)
                    {
                        await Task.Delay(TimeSpan.FromMinutes(30));
                        try
                        {
                            await CleanupExpiredCacheAsync();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Error limpiando cache");
                        }
                    }
                });
                
                // Programar recalibración
                _ = Task.Run(async () =>
                {
                    while (_isInitialized)
                    {
                        await Task.Delay(TimeSpan.FromHours(6));
                        try
                        {
                            await RecalibrateIfNeededAsync();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Error en recalibración");
                        }
                    }
                });
                
                _logger.LogDebug("✅ Tareas periódicas programadas");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error programando tareas periódicas");
                throw;
            }
        }
        
        #endregion
        
        #region Métodos privados de cálculo
        
        private bool TryGetCachedDeviceScore(string deviceId, out DeviceRiskScore score)
        {
            if (_deviceRiskScores.TryGetValue(deviceId, out score))
            {
                var cacheAge = DateTime.UtcNow - score.LastCalculated;
                if (cacheAge.TotalMinutes <= _configuration.CacheValidityMinutes)
                {
                    return true;
                }
                
                // Score expirado, remover del cache
                _deviceRiskScores.TryRemove(deviceId, out _);
            }
            
            score = null;
            return false;
        }
        
        private async Task<DeviceData> GetDeviceDataAsync(string deviceId, DeviceContext context)
        {
            try
            {
                var deviceData = new DeviceData
                {
                    DeviceId = deviceId,
                    Timestamp = DateTime.UtcNow
                };
                
                // Obtener datos del dispositivo desde múltiples fuentes
                if (context != null)
                {
                    // Usar contexto proporcionado
                    deviceData.TenantId = context.TenantId;
                    deviceData.DeviceType = context.DeviceType;
                    deviceData.OsVersion = context.OsVersion;
                    deviceData.LastActivity = context.LastActivity;
                    deviceData.RiskContext = context.RiskContext;
                }
                else
                {
                    // Obtener desde base de datos
                    deviceData = await _graphDatabase.GetDeviceDataAsync(deviceId);
                }
                
                // Enriquecer con datos adicionales
                deviceData.NetworkEvents = await _graphDatabase.GetDeviceNetworkEventsAsync(deviceId, TimeSpan.FromHours(24));
                deviceData.ProcessEvents = await _graphDatabase.GetDeviceProcessEventsAsync(deviceId, TimeSpan.FromHours(24));
                deviceData.FileEvents = await _graphDatabase.GetDeviceFileEventsAsync(deviceId, TimeSpan.FromHours(24));
                deviceData.Vulnerabilities = await _graphDatabase.GetDeviceVulnerabilitiesAsync(deviceId);
                deviceData.ThreatEvents = await _graphDatabase.GetDeviceThreatEventsAsync(deviceId, TimeSpan.FromHours(24));
                
                return deviceData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error obteniendo datos del dispositivo {DeviceId}", deviceId);
                throw new RiskDataException($"Failed to get device data for {deviceId}", ex);
            }
        }
        
        private async Task<List<RiskFactorScore>> CalculateRiskFactorsAsync(DeviceData deviceData)
        {
            var factorScores = new List<RiskFactorScore>();
            var calculationTasks = new List<Task<RiskFactorScore>>();
            
            // Calcular factores en paralelo cuando sea posible
            foreach (var factor in _riskFactors.Where(f => f.IsEnabled))
            {
                calculationTasks.Add(Task.Run(() => CalculateSingleRiskFactorAsync(factor, deviceData)));
            }
            
            // Esperar todos los cálculos
            var results = await Task.WhenAll(calculationTasks);
            factorScores.AddRange(results.Where(r => r != null));
            
            // Ordenar por score descendente
            return factorScores.OrderByDescending(f => f.Score).ToList();
        }
        
        private async Task<RiskFactorScore> CalculateSingleRiskFactorAsync(RiskFactor factor, DeviceData deviceData)
        {
            try
            {
                var calculationStart = DateTime.UtcNow;
                double score = 0;
                var indicators = new List<string>();
                var evidence = new List<RiskEvidence>();
                var confidence = 0.0;
                
                // Seleccionar método de cálculo basado en la categoría y disponibilidad de datos
                switch (factor.Category)
                {
                    case RiskCategory.Network:
                        (score, indicators, evidence, confidence) = await CalculateNetworkRiskFactorAsync(factor, deviceData);
                        break;
                        
                    case RiskCategory.Process:
                        (score, indicators, evidence, confidence) = await CalculateProcessRiskFactorAsync(factor, deviceData);
                        break;
                        
                    case RiskCategory.FileSystem:
                        (score, indicators, evidence, confidence) = await CalculateFileSystemRiskFactorAsync(factor, deviceData);
                        break;
                        
                    case RiskCategory.Registry:
                        (score, indicators, evidence, confidence) = await CalculateRegistryRiskFactorAsync(factor, deviceData);
                        break;
                        
                    case RiskCategory.Vulnerability:
                        (score, indicators, evidence, confidence) = await CalculateVulnerabilityRiskFactorAsync(factor, deviceData);
                        break;
                        
                    case RiskCategory.User:
                        (score, indicators, evidence, confidence) = await CalculateUserRiskFactorAsync(factor, deviceData);
                        break;
                        
                    default:
                        (score, indicators, evidence, confidence) = await CalculateGenericRiskFactorAsync(factor, deviceData);
                        break;
                }
                
                // Aplicar límites y ajustes
                score = Math.Min(Math.Max(score, 0), factor.MaxScore);
                
                // Aplicar multiplicador de severidad
                score *= factor.SeverityMultiplier;
                
                // Crear objeto de resultado
                return new RiskFactorScore
                {
                    FactorId = factor.FactorId,
                    FactorName = factor.Name,
                    Category = factor.Category,
                    Score = score,
                    Weight = factor.BaseWeight,
                    Confidence = confidence,
                    Indicators = indicators,
                    Evidence = evidence,
                    Timestamp = DateTime.UtcNow,
                    CalculationTime = DateTime.UtcNow - calculationStart,
                    Metadata = new Dictionary<string, object>
                    {
                        { "CalculationMethod", factor.CalculationMethod },
                        { "SeverityMultiplier", factor.SeverityMultiplier },
                        { "TimeSensitivity", factor.TimeSensitivity },
                        { "EvidenceCount", evidence.Count },
                        { "IndicatorCount", indicators.Count }
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error calculando factor {FactorId} para dispositivo {DeviceId}", 
                    factor.FactorId, deviceData.DeviceId);
                
                // Devolver factor con score 0 en caso de error
                return new RiskFactorScore
                {
                    FactorId = factor.FactorId,
                    FactorName = factor.Name,
                    Category = factor.Category,
                    Score = 0,
                    Weight = factor.BaseWeight,
                    Confidence = 0.1,
                    Indicators = new List<string> { $"Error en cálculo: {ex.Message}" },
                    Evidence = new List<RiskEvidence>(),
                    Timestamp = DateTime.UtcNow,
                    CalculationTime = TimeSpan.Zero,
                    Metadata = new Dictionary<string, object>
                    {
                        { "CalculationError", ex.Message },
                        { "HasError", true }
                    }
                };
            }
        }
        
        private async Task<(double Score, List<string> Indicators, List<RiskEvidence> Evidence, double Confidence)> 
            CalculateNetworkRiskFactorAsync(RiskFactor factor, DeviceData deviceData)
        {
            double score = 0;
            var indicators = new List<string>();
            var evidence = new List<RiskEvidence>();
            double confidence = 0.7; // Confianza base
            
            try
            {
                // 1. Analizar eventos de red sospechosos
                if (deviceData.NetworkEvents?.Count > 0)
                {
                    var suspiciousConnections = deviceData.NetworkEvents
                        .Where(e => IsSuspiciousNetworkEvent(e))
                        .ToList();
                    
                    if (suspiciousConnections.Count > 0)
                    {
                        score += suspiciousConnections.Count * 5;
                        indicators.Add($"Conexiones sospechosas detectadas: {suspiciousConnections.Count}");
                        
                        evidence.Add(new RiskEvidence
                        {
                            EvidenceType = "NetworkConnections",
                            Description = $"Se detectaron {suspiciousConnections.Count} conexiones de red sospechosas",
                            Value = suspiciousConnections.Count,
                            Severity = suspiciousConnections.Count > 10 ? RiskLevel.High : RiskLevel.Medium,
                            Timestamp = DateTime.UtcNow
                        });
                        
                        // Ejemplos específicos
                        foreach (var conn in suspiciousConnections.Take(3))
                        {
                            indicators.Add($"- Conexión a {conn.RemoteAddress}:{conn.RemotePort} ({conn.Protocol})");
                        }
                    }
                    
                    // 2. Detectar patrones de exfiltración
                    var exfiltrationPatterns = DetectDataExfiltrationPatterns(deviceData.NetworkEvents);
                    if (exfiltrationPatterns.Count > 0)
                    {
                        score += exfiltrationPatterns.Count * 15;
                        indicators.Add($"Patrones de exfiltración detectados: {exfiltrationPatterns.Count}");
                        confidence = 0.85;
                    }
                    
                    // 3. Analizar destinos de alto riesgo
                    var highRiskDestinations = AnalyzeHighRiskDestinations(deviceData.NetworkEvents);
                    if (highRiskDestinations.Count > 0)
                    {
                        score += highRiskDestinations.Count * 10;
                        indicators.Add($"Destinos de alto riesgo contactados: {highRiskDestinations.Count}");
                        confidence = Math.Max(confidence, 0.8);
                    }
                    
                    // 4. Verificar tráfico en horas no laborales
                    var offHoursTraffic = AnalyzeOffHoursTraffic(deviceData.NetworkEvents);
                    if (offHoursTraffic.Volume > 0)
                    {
                        score += offHoursTraffic.Score;
                        indicators.Add($"Tráfico significativo fuera de horario: {offHoursTraffic.Volume} bytes");
                    }
                }
                
                // 5. Considerar DNS queries sospechosas
                if (deviceData.DnsQueries?.Count > 0)
                {
                    var suspiciousQueries = deviceData.DnsQueries
                        .Where(q => IsSuspiciousDnsQuery(q))
                        .ToList();
                    
                    if (suspiciousQueries.Count > 0)
                    {
                        score += suspiciousQueries.Count * 3;
                        indicators.Add($"Consultas DNS sospechosas: {suspiciousQueries.Count}");
                    }
                }
                
                // Limitar score máximo
                score = Math.Min(score, factor.MaxScore);
                
                // Ajustar confianza basada en cantidad y calidad de datos
                confidence = AdjustConfidenceBasedOnData(confidence, deviceData.NetworkEvents?.Count ?? 0);
                
                return (score, indicators, evidence, confidence);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error en cálculo de factor de red");
                return (0, new List<string> { "Error en análisis de red" }, new List<RiskEvidence>(), 0.1);
            }
        }
        
        // ... (continuar con otros métodos de cálculo de factores)
        
        private RiskScoreResult CalculateBaseRiskScore(List<RiskFactorScore> factorScores)
        {
            var result = new RiskScoreResult();
            
            if (factorScores.Count == 0)
                return result;
            
            try
            {
                // 1. Filtrar factores con suficiente confianza
                var validFactors = factorScores
                    .Where(f => f.Confidence >= _configuration.MinimumConfidence)
                    .ToList();
                
                if (validFactors.Count == 0)
                {
                    _logger.LogWarning("⚠️ Ningún factor con confianza suficiente (mínimo {MinConfidence})", 
                        _configuration.MinimumConfidence);
                    return result;
                }
                
                // 2. Calcular score base como promedio ponderado
                double totalWeightedScore = 0;
                double totalEffectiveWeight = 0;
                
                foreach (var factor in validFactors)
                {
                    var effectiveWeight = factor.Weight * factor.Confidence;
                    totalWeightedScore += factor.Score * effectiveWeight;
                    totalEffectiveWeight += effectiveWeight;
                }
                
                // 3. Normalizar score
                result.TotalScore = totalEffectiveWeight > 0 ? 
                    totalWeightedScore / totalEffectiveWeight : 0;
                
                // 4. Aplicar ajuste por cantidad de factores
                var factorCountAdjustment = CalculateFactorCountAdjustment(validFactors.Count);
                result.TotalScore *= factorCountAdjustment;
                
                // 5. Limitar rango
                result.TotalScore = Math.Min(Math.Max(result.TotalScore, 0), 100);
                
                // 6. Guardar factores
                result.FactorScores = validFactors;
                result.CalculationDetails = $"Factores válidos: {validFactors.Count}, Peso efectivo: {totalEffectiveWeight:F2}";
                result.Confidence = CalculateOverallConfidence(validFactors);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error calculando score base de riesgo");
                return result;
            }
        }
        
        private RiskScoreResult ApplyContextualAdjustments(RiskScoreResult baseScore, DeviceData deviceData, DeviceContext context)
        {
            var result = new RiskScoreResult
            {
                FactorScores = baseScore.FactorScores,
                TotalScore = baseScore.TotalScore,
                Confidence = baseScore.Confidence
            };
            
            if (deviceData == null)
                return result;
            
            try
            {
                var adjustments = new List<string>();
                var adjustmentFactor = 1.0;
                
                // 1. Ajuste por criticidad del dispositivo
                if (!string.IsNullOrEmpty(deviceData.DeviceType))
                {
                    var criticalityAdjustment = GetDeviceCriticalityAdjustment(deviceData.DeviceType);
                    if (Math.Abs(criticalityAdjustment - 1.0) > 0.01)
                    {
                        adjustmentFactor *= criticalityAdjustment;
                        adjustments.Add($"Criticidad del dispositivo: x{criticalityAdjustment:F2}");
                    }
                }
                
                // 2. Ajuste por contexto de riesgo
                if (context?.RiskContext != null)
                {
                    var contextAdjustment = ApplyRiskContextAdjustment(context.RiskContext);
                    adjustmentFactor *= contextAdjustment;
                    adjustments.Add($"Contexto de riesgo: x{contextAdjustment:F2}");
                }
                
                // 3. Ajuste por vulnerabilidades conocidas
                if (deviceData.Vulnerabilities?.Count > 0)
                {
                    var vulnAdjustment = CalculateVulnerabilityAdjustment(deviceData.Vulnerabilities);
                    adjustmentFactor *= vulnAdjustment;
                    adjustments.Add($"Vulnerabilidades: x{vulnAdjustment:F2}");
                }
                
                // 4. Aplicar ajustes
                result.TotalScore *= adjustmentFactor;
                result.TotalScore = Math.Min(Math.Max(result.TotalScore, 0), 100);
                
                // 5. Guardar detalles
                if (adjustments.Count > 0)
                {
                    result.CalculationDetails = $"{baseScore.CalculationDetails}. Ajustes: {string.Join(", ", adjustments)}";
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error aplicando ajustes contextuales");
                return result;
            }
        }
        
        private RiskScoreResult ApplyDynamicWeights(RiskScoreResult contextualScore, List<RiskFactorScore> factorScores)
        {
            var result = new RiskScoreResult
            {
                FactorScores = factorScores,
                TotalScore = contextualScore.TotalScore,
                Confidence = contextualScore.Confidence
            };
            
            if (factorScores.Count == 0)
                return result;
            
            try
            {
                // 1. Calcular pesos dinámicos basados en factores dominantes
                var dynamicWeights = CalculateDynamicWeights(factorScores);
                
                // 2. Recalcular score con pesos dinámicos
                double totalDynamicScore = 0;
                double totalDynamicWeight = 0;
                
                for (int i = 0; i < factorScores.Count; i++)
                {
                    var factor = factorScores[i];
                    var dynamicWeight = dynamicWeights[i];
                    
                    totalDynamicScore += factor.Score * dynamicWeight;
                    totalDynamicWeight += dynamicWeight;
                    
                    // Guardar peso dinámico
                    factor.DynamicWeight = dynamicWeight;
                }
                
                // 3. Calcular score ponderado dinámicamente
                var dynamicScore = totalDynamicWeight > 0 ? 
                    totalDynamicScore / totalDynamicWeight : 0;
                
                // 4. Combinar con score contextual (promedio ponderado)
                var dynamicWeight = 0.7; // Peso del cálculo dinámico
                var contextualWeight = 0.3; // Peso del cálculo contextual
                
                result.TotalScore = (dynamicScore * dynamicWeight) + (contextualScore.TotalScore * contextualWeight);
                result.TotalScore = Math.Min(Math.Max(result.TotalScore, 0), 100);
                
                // 5. Actualizar confianza
                result.Confidence = CalculateDynamicConfidence(factorScores, dynamicWeights);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error aplicando pesos dinámicos");
                return result;
            }
        }
        
        private RiskScoreResult ApplyTimeDecay(RiskScoreResult weightedScore, DateTime? lastActivity)
        {
            var result = new RiskScoreResult
            {
                FactorScores = weightedScore.FactorScores,
                TotalScore = weightedScore.TotalScore,
                Confidence = weightedScore.Confidence,
                CalculationDetails = weightedScore.CalculationDetails
            };
            
            if (!lastActivity.HasValue)
                return result;
            
            try
            {
                var hoursInactive = (DateTime.UtcNow - lastActivity.Value).TotalHours;
                
                if (hoursInactive > _configuration.TimeDecayThresholdHours)
                {
                    // Decaimiento exponencial basado en inactividad
                    var decayFactor = Math.Pow(_configuration.TimeDecayFactor, hoursInactive);
                    result.TotalScore *= decayFactor;
                    
                    // También aplicar decaimiento a factores individuales
                    foreach (var factor in result.FactorScores)
                    {
                        factor.Score *= decayFactor;
                    }
                    
                    result.CalculationDetails += $". Decaimiento aplicado: x{decayFactor:F2} ({hoursInactive:F1} horas inactivo)";
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error aplicando decaimiento temporal");
                return result;
            }
        }
        
        private RiskLevel DetermineRiskLevel(double score, RiskEntityType entityType)
        {
            if (!_riskThresholds.TryGetValue(entityType, out var threshold))
            {
                _logger.LogWarning("⚠️ No hay umbrales definidos para {EntityType}, usando valores por defecto", entityType);
                return GetDefaultRiskLevel(score);
            }
            
            try
            {
                // Encontrar nivel basado en umbrales con histéresis
                var currentLevel = FindRiskLevelWithHysteresis(score, threshold);
                
                // Validar que el nivel sea consistente
                if (!IsRiskLevelConsistent(currentLevel, score, threshold))
                {
                    _logger.LogDebug("📊 Nivel de riesgo inconsistente detectado, ajustando...");
                    currentLevel = AdjustRiskLevel(currentLevel, score, threshold);
                }
                
                return currentLevel;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error determinando nivel de riesgo, usando valor por defecto");
                return GetDefaultRiskLevel(score);
            }
        }
        
        private double CalculateScoreConfidence(List<RiskFactorScore> factorScores, DeviceData deviceData)
        {
            try
            {
                // 1. Confianza basada en factores
                var factorConfidence = factorScores.Any() ? 
                    factorScores.Average(f => f.Confidence) : 0;
                
                // 2. Confianza basada en cantidad de datos
                var dataConfidence = CalculateDataConfidence(deviceData);
                
                // 3. Confianza basada en consistencia
                var consistencyConfidence = CalculateConsistencyConfidence(factorScores);
                
                // 4. Combinar confianzas (promedio ponderado)
                var weights = new Dictionary<string, double>
                {
                    ["Factor"] = 0.4,
                    ["Data"] = 0.3,
                    ["Consistency"] = 0.3
                };
                
                var totalConfidence = (factorConfidence * weights["Factor"]) +
                                     (dataConfidence * weights["Data"]) +
                                     (consistencyConfidence * weights["Consistency"]);
                
                // 5. Aplicar límites
                totalConfidence = Math.Min(Math.Max(totalConfidence, 0), 1);
                
                return totalConfidence;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error calculando confianza del score");
                return 0.5; // Confianza por defecto
            }
        }
        
        private List<RiskRecommendation> GenerateRiskRecommendations(
            RiskLevel riskLevel, 
            List<RiskFactorScore> factorScores,
            DeviceData deviceData)
        {
            var recommendations = new List<RiskRecommendation>();
            
            try
            {
                // 1. Recomendaciones basadas en nivel de riesgo
                recommendations.AddRange(GetRiskLevelRecommendations(riskLevel));
                
                // 2. Recomendaciones basadas en factores dominantes
                var topFactors = factorScores
                    .OrderByDescending(f => f.Score * f.Weight)
                    .Take(3)
                    .ToList();
                
                foreach (var factor in topFactors)
                {
                    if (factor.Score > 30) // Solo si el factor es significativo
                    {
                        recommendations.AddRange(GetFactorSpecificRecommendations(factor));
                    }
                }
                
                // 3. Recomendaciones basadas en datos del dispositivo
                if (deviceData != null)
                {
                    recommendations.AddRange(GetDeviceSpecificRecommendations(deviceData));
                }
                
                // 4. Priorizar y eliminar duplicados
                recommendations = recommendations
                    .GroupBy(r => r.Action)
                    .Select(g => g.OrderByDescending(r => r.Priority).First())
                    .OrderBy(r => r.Priority)
                    .Take(10) // Limitar a 10 recomendaciones principales
                    .ToList();
                
                return recommendations;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error generando recomendaciones de riesgo");
                return new List<RiskRecommendation>
                {
                    new RiskRecommendation
                    {
                        Priority = 1,
                        Action = "ReviewRiskScore",
                        Description = "Revisar el score de riesgo manualmente debido a errores en la generación de recomendaciones",
                        Reason = "Error técnico en el sistema de recomendaciones",
                        ExpectedImpact = "Medium",
                        TimeToImplement = TimeSpan.FromHours(1)
                    }
                };
            }
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        private void ValidateOperation()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("RiskScoringEngine no está inicializado. Llame a InitializeAsync primero.");
        }
        
        private string GenerateScoreId(string prefix, string entityId)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var random = new Random().Next(1000, 9999);
            return $"{prefix}_{entityId}_{timestamp}_{random}";
        }
        
        private string GenerateDashboardId(string tenantId)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmm");
            return $"DASH_{tenantId ?? "GLOBAL"}_{timestamp}";
        }
        
        private double GetMemoryUsageMB()
        {
            try
            {
                var process = System.Diagnostics.Process.GetCurrentProcess();
                return process.WorkingSet64 / (1024.0 * 1024.0);
            }
            catch
            {
                return 0;
            }
        }
        
        private async Task PerformPeriodicScoringAsync()
        {
            try
            {
                _logger.LogDebug("🔄 Ejecutando scoring periódico...");
                var startTime = DateTime.UtcNow;
                
                // 1. Obtener dispositivos que necesitan recalcular
                var devicesToScore = await GetDevicesNeedingRescoringAsync();
                
                if (devicesToScore.Count == 0)
                {
                    _logger.LogDebug("📭 No hay dispositivos que necesiten rescoring en este momento");
                    return;
                }
                
                // 2. Recalcular scores en paralelo (con limitación)
                var batchSize = Math.Min(devicesToScore.Count, _configuration.MaxConcurrentScoring);
                var processedCount = 0;
                
                foreach (var batch in devicesToScore.Chunk(batchSize))
                {
                    var scoringTasks = batch.Select(deviceId => 
                        CalculateDeviceRiskAsync(deviceId, forceRecalculation: true));
                    
                    await Task.WhenAll(scoringTasks);
                    processedCount += batch.Length;
                    
                    _logger.LogDebug("📊 Procesado lote de {BatchSize} dispositivos ({Processed}/{Total})", 
                        batch.Length, processedCount, devicesToScore.Count);
                    
                    // Pequeña pausa para no sobrecargar
                    await Task.Delay(100);
                }
                
                _lastScoringUpdate = DateTime.UtcNow;
                
                var processingTime = DateTime.UtcNow - startTime;
                _logger.LogInformation("✅ Scoring periódico completado: {Count} dispositivos en {Time}ms", 
                    processedCount, processingTime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error en scoring periódico");
            }
        }
        
        private async Task CleanupExpiredCacheAsync()
        {
            try
            {
                var cutoffTime = DateTime.UtcNow.AddMinutes(-_configuration.CacheValidityMinutes);
                var removedCount = 0;
                
                // Limpiar scores de dispositivos expirados
                var expiredDevices = _deviceRiskScores
                    .Where(kvp => kvp.Value.LastCalculated < cutoffTime)
                    .Select(kvp => kvp.Key)
                    .ToList();
                
                foreach (var deviceId in expiredDevices)
                {
                    if (_deviceRiskScores.TryRemove(deviceId, out _))
                        removedCount++;
                }
                
                // Limpiar scores de amenazas expiradas
                var expiredThreats = _threatRiskScores
                    .Where(kvp => kvp.Value.Timestamp < cutoffTime)
                    .Select(kvp => kvp.Key)
                    .ToList();
                
                foreach (var threatId in expiredThreats)
                {
                    if (_threatRiskScores.TryRemove(threatId, out _))
                        removedCount++;
                }
                
                if (removedCount > 0)
                {
                    _logger.LogDebug("🧹 Limpiados {Count} scores expirados del cache", removedCount);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error limpiando cache expirado");
            }
        }
        
        private async Task RecalibrateIfNeededAsync()
        {
            try
            {
                var needsRecalibration = false;
                
                // Verificar factores que necesitan recalibración
                var factorsNeedingCalibration = _riskFactors
                    .Where(f => f.RequiresCalibration && 
                               (DateTime.UtcNow - f.LastCalibrated).TotalDays > 7)
                    .ToList();
                
                if (factorsNeedingCalibration.Count > 0)
                {
                    needsRecalibration = true;
                    _logger.LogDebug("⚙️ {Count} factores necesitan recalibración", factorsNeedingCalibration.Count);
                }
                
                // Verificar pesos que necesitan recalibración
                var weightsNeedingCalibration = _riskWeights.Values
                    .Where(w => w.RequiresRecalibration && 
                               (DateTime.UtcNow - w.LastRecalibrated).TotalDays > 14)
                    .ToList();
                
                if (weightsNeedingCalibration.Count > 0)
                {
                    needsRecalibration = true;
                    _logger.LogDebug("⚖️ {Count} pesos necesitan recalibración", weightsNeedingCalibration.Count);
                }
                
                if (needsRecalibration)
                {
                    await RecalibrateRiskWeightsAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error verificando necesidad de recalibración");
            }
        }
        
        private async Task RecalibrateRiskWeightsAsync()
        {
            try
            {
                _logger.LogInformation("⚙️ Recalibrando pesos de riesgo...");
                
                // 1. Obtener datos históricos para recalibración
                var calibrationData = await GetCalibrationDataAsync();
                
                if (calibrationData.Count < _configuration.MinimumDataPoints)
                {
                    _logger.LogWarning("⚠️ Datos insuficientes para recalibración (mínimo {Min} puntos, se tienen {Actual})", 
                        _configuration.MinimumDataPoints, calibrationData.Count);
                    return;
                }
                
                // 2. Aplicar algoritmo de recalibración
                var recalibratedWeights = await RecalibrateWeightsAsync(calibrationData);
                
                // 3. Aplicar nuevos pesos
                ApplyRecalibratedWeights(recalibratedWeights);
                
                // 4. Actualizar marcas de tiempo
                UpdateCalibrationTimestamps();
                
                _logger.LogInformation("✅ Pesos de riesgo recalibrados exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error recalibrando pesos de riesgo");
            }
        }
        
        private void InvalidateCache()
        {
            _deviceRiskScores.Clear();
            _threatRiskScores.Clear();
            _tenantRiskScores.Clear();
            _logger.LogDebug("🗑️ Cache de scores invalidado");
        }
        
        private async Task PersistCacheDataAsync()
        {
            try
            {
                _logger.LogDebug("💾 Persistiendo datos del cache...");
                
                // Persistir scores de dispositivos
                foreach (var score in _deviceRiskScores.Values)
                {
                    await _graphDatabase.StoreDeviceRiskScoreAsync(score);
                }
                
                // Persistir scores de amenazas
                foreach (var score in _threatRiskScores.Values)
                {
                    await _graphDatabase.StoreThreatRiskScoreAsync(score);
                }
                
                // Persistir scores de tenants
                foreach (var score in _tenantRiskScores.Values)
                {
                    await _graphDatabase.StoreTenantRiskScoreAsync(score);
                }
                
                _logger.LogDebug("✅ Datos del cache persistidos");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error persistiendo datos del cache");
            }
        }
        
        private void CleanupResources()
        {
            try
            {
                // Limpiar diccionarios
                _deviceRiskScores.Clear();
                _threatRiskScores.Clear();
                _tenantRiskScores.Clear();
                _riskFactors.Clear();
                _riskWeights.Clear();
                _riskThresholds.Clear();
                
                // Forzar recolección de basura
                GC.Collect();
                GC.WaitForPendingFinalizers();
                
                _logger.LogDebug("🧹 Recursos del RiskScoringEngine liberados");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Error limpiando recursos");
            }
        }
        
        private void StopPeriodicTasks()
        {
            // En una implementación real, aquí se cancelarían los timers/tasks periódicos
            _logger.LogDebug("⏹️ Tareas periódicas detenidas");
        }
        
        #endregion
        
        #region Métodos de ayuda (stubs para completitud)
        
        // Estos métodos serían implementados completamente en producción
        private bool IsSuspiciousNetworkEvent(NetworkEvent networkEvent) => 
            networkEvent?.RemoteAddress?.Contains("malicious") == true;
        
        private List<string> DetectDataExfiltrationPatterns(List<NetworkEvent> networkEvents) => 
            new List<string>();
        
        private List<string> AnalyzeHighRiskDestinations(List<NetworkEvent> networkEvents) => 
            new List<string>();
        
        private (double Score, long Volume) AnalyzeOffHoursTraffic(List<NetworkEvent> networkEvents) => 
            (0, 0);
        
        private bool IsSuspiciousDnsQuery(DnsQuery query) => false;
        
        private double CalculateFactorCountAdjustment(int factorCount) => 1.0;
        
        private double CalculateOverallConfidence(List<RiskFactorScore> factorScores) => 0.8;
        
        private double GetDeviceCriticalityAdjustment(string deviceType) => 1.0;
        
        private double ApplyRiskContextAdjustment(RiskContext riskContext) => 1.0;
        
        private double CalculateVulnerabilityAdjustment(List<Vulnerability> vulnerabilities) => 1.0;
        
        private List<double> CalculateDynamicWeights(List<RiskFactorScore> factorScores) => 
            factorScores.Select(f => f.Weight).ToList();
        
        private double CalculateDynamicConfidence(List<RiskFactorScore> factorScores, List<double> dynamicWeights) => 0.8;
        
        private RiskLevel FindRiskLevelWithHysteresis(double score, RiskThreshold threshold) => RiskLevel.Medium;
        
        private bool IsRiskLevelConsistent(RiskLevel level, double score, RiskThreshold threshold) => true;
        
        private RiskLevel AdjustRiskLevel(RiskLevel currentLevel, double score, RiskThreshold threshold) => currentLevel;
        
        private RiskLevel GetDefaultRiskLevel(double score)
        {
            if (score >= 85) return RiskLevel.Critical;
            if (score >= 70) return RiskLevel.High;
            if (score >= 50) return RiskLevel.Medium;
            if (score >= 30) return RiskLevel.Low;
            if (score >= 10) return RiskLevel.Info;
            return RiskLevel.None;
        }
        
        private double CalculateDataConfidence(DeviceData deviceData) => 0.7;
        
        private double CalculateConsistencyConfidence(List<RiskFactorScore> factorScores) => 0.8;
        
        private List<RiskRecommendation> GetRiskLevelRecommendations(RiskLevel riskLevel) => 
            new List<RiskRecommendation>();
        
        private List<RiskRecommendation> GetFactorSpecificRecommendations(RiskFactorScore factor) => 
            new List<RiskRecommendation>();
        
        private List<RiskRecommendation> GetDeviceSpecificRecommendations(DeviceData deviceData) => 
            new List<RiskRecommendation>();
        
        private async Task<List<string>> GetDevicesNeedingRescoringAsync() => 
            new List<string>();
        
        private async Task<List<CalibrationData>> GetCalibrationDataAsync() => 
            new List<CalibrationData>();
        
        private async Task<Dictionary<RiskCategory, double>> RecalibrateWeightsAsync(List<CalibrationData> calibrationData) => 
            new Dictionary<RiskCategory, double>();
        
        private void ApplyRecalibratedWeights(Dictionary<RiskCategory, double> recalibratedWeights)
        {
            // Implementación real actualizaría _riskWeights
        }
        
        private void UpdateCalibrationTimestamps()
        {
            // Implementación real actualizaría marcas de tiempo
        }
        
        private async Task<List<RiskFactor>> LoadExternalRiskFactorsAsync() => null;
        
        private List<RiskFactor> ValidateRiskFactors(List<RiskFactor> factors) => 
            factors.Where(f => !string.IsNullOrEmpty(f.FactorId)).ToList();
        
        private bool HasOverlappingThresholds(RiskThreshold threshold) => false;
        
        private void InitializeWeightedAverageAlgorithm() { }
        private void InitializeMachineLearningAlgorithms() { }
        private void InitializeStatisticalAlgorithms() { }
        private void InitializeTrendAnalysisAlgorithms() { }
        
        private CacheStatistics GetCacheStatistics() => new CacheStatistics();
        private ScoringStatistics GetScoringStatistics() => new ScoringStatistics();
        private AlgorithmStatistics GetAlgorithmStatistics() => new AlgorithmStatistics();
        private PerformanceStatistics GetPerformanceStatistics() => new PerformanceStatistics();
        
        private List<string> CheckPerformanceHealth() => new List<string>();
        private async Task<HealthCheckResult> CheckDatabaseHealthAsync() => 
            HealthCheckResult.Healthy("Database OK");
        
        private async Task<DeviceRiskScore> StoreRiskScoreAsync(DeviceRiskScore score) => score;
        private async Task<ThreatRiskScore> StoreThreatRiskScoreAsync(ThreatRiskScore score) => score;
        private async Task<TenantRiskScore> StoreTenantRiskScoreAsync(TenantRiskScore score) => score;
        
        private async Task EmitRiskEventAsync(DeviceRiskScore score) { }
        private async Task EmitThreatEventAsync(ThreatRiskScore score) { }
        private async Task EmitTenantReportAsync(TenantRiskScore score) { }
        private async Task EmitOptimizationEventAsync(Dictionary<RiskCategory, double> weights, double improvement) { }
        
        #endregion
    }
    
    #region Clases de datos y estructuras
    
    public interface IRiskScoringEngine
    {
        Task InitializeAsync(RiskScoringConfiguration configuration = null);
        Task<DeviceRiskScore> CalculateDeviceRiskAsync(string deviceId, DeviceContext context = null, bool forceRecalculation = false);
        Task<ThreatRiskScore> CalculateThreatRiskAsync(string threatId, ThreatContext context, bool includePropagation = true);
        Task<TenantRiskScore> CalculateTenantRiskAsync(string tenantId, TenantContext context = null, bool includeDevices = true, bool includeThreats = true);
        Task<RiskTrendAnalysis> AnalyzeRiskTrendAsync(string entityId, RiskEntityType entityType, TimeSpan analysisPeriod, TrendAnalysisOptions options = null);
        Task<RiskDashboard> GetRiskDashboardAsync(string tenantId = null, DashboardOptions options = null);
        Task UpdateRiskFactorsAsync(List<RiskFactor> newFactors, bool merge = true);
        Task OptimizeRiskWeightsAsync(OptimizationOptions options = null);
        Task<RiskScoringStats> GetStatisticsAsync();
        Task<HealthCheckResult> CheckHealthAsync();
        Task StopAsync();
    }
    
    public class RiskScoringConfiguration
    {
        public int CacheValidityMinutes { get; set; } = 60;
        public int MinimumDataPoints { get; set; } = 100;
        public double MinimumConfidence { get; set; } = 0.6;
        public TimeSpan ScoringInterval { get; set; } = TimeSpan.FromMinutes(5);
        public int MaxConcurrentScoring { get; set; } = 10;
        public double TimeDecayFactor { get; set; } = 0.95;
        public double TimeDecayThresholdHours { get; set; } = 1.0;
        public TimeSpan DashboardRefreshInterval { get; set; } = TimeSpan.FromMinutes(15);
        public Dictionary<string, object> AdvancedSettings { get; set; } = new Dictionary<string, object>();
    }
    
    public class DeviceRiskScore
    {
        public string ScoreId { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public DateTime Timestamp { get; set; }
        public double TotalScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public double Confidence { get; set; }
        public List<RiskFactorScore> FactorScores { get; set; } = new List<RiskFactorScore>();
        public double BaseScore { get; set; }
        public double WeightedScore { get; set; }
        public double FinalScore { get; set; }
        public DateTime LastCalculated { get; set; }
        public TimeSpan CalculationTime { get; set; }
        public List<RiskRecommendation> Recommendations { get; set; } = new List<RiskRecommendation>();
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }
    
    public class ThreatRiskScore
    {
        public string ScoreId { get; set; }
        public string ThreatId { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public DateTime Timestamp { get; set; }
        public double CompositeScore { get; set; }
        public RiskLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public double ImpactScore { get; set; }
        public double ProbabilityScore { get; set; }
        public double TechnicalSeverity { get; set; }
        public double PropagationScore { get; set; }
        public List<RiskFactorScore> ThreatFactors { get; set; } = new List<RiskFactorScore>();
        public List<string> AffectedDevices { get; set; } = new List<string>();
        public DateTime FirstDetected { get; set; }
        public DateTime LastDetected { get; set; }
        public TimeSpan CalculationTime { get; set; }
        public List<RiskRecommendation> MitigationRecommendations { get; set; } = new List<RiskRecommendation>();
        public bool IsActive { get; set; }
        public bool HasMitigations { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }
    
    public class TenantRiskScore
    {
        public string ScoreId { get; set; }
        public string TenantId { get; set; }
        public string TenantName { get; set; }
        public DateTime Timestamp { get; set; }
        public double TotalScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public List<RiskFactorScore> TenantFactors { get; set; } = new List<RiskFactorScore>();
        public int DeviceCount { get; set; }
        public int ThreatCount { get; set; }
        public List<DeviceRiskScore> DeviceScores { get; set; } = new List<DeviceRiskScore>();
        public List<ThreatRiskScore> ThreatScores { get; set; } = new List<ThreatRiskScore>();
        public int HighRiskDevices { get; set; }
        public int CriticalThreats { get; set; }
        public RiskDistributionMetrics DistributionMetrics { get; set; }
        public List<CriticalPoint> CriticalPoints { get; set; } = new List<CriticalPoint>();
        public TimeSpan CalculationTime { get; set; }
        public List<RiskRecommendation> Recommendations { get; set; } = new List<RiskRecommendation>();
        public RiskTrend HistoricalTrend { get; set; }
        public PeerComparison ComparisonToPeers { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }
    
    public class RiskFactor
    {
        public string FactorId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public RiskCategory Category { get; set; }
        public double BaseWeight { get; set; }
        public double MaxScore { get; set; }
        public string CalculationMethod { get; set; }
        public double SeverityMultiplier { get; set; } = 1.0;
        public double TimeSensitivity { get; set; } = 1.0;
        public List<string> DataRequirements { get; set; } = new List<string>();
        public Dictionary<RiskLevel, double> Thresholds { get; set; } = new Dictionary<RiskLevel, double>();
        public List<string> Indicators { get; set; } = new List<string>();
        public bool IsEnabled { get; set; } = true;
        public bool RequiresCalibration { get; set; }
        public DateTime LastCalibrated { get; set; }
        public double Confidence { get; set; } = 0.8;
    }
    
    public class RiskFactorScore
    {
        public string FactorId { get; set; }
        public string FactorName { get; set; }
        public RiskCategory Category { get; set; }
        public double Score { get; set; }
        public double Weight { get; set; }
        public double? DynamicWeight { get; set; }
        public double Confidence { get; set; }
        public List<string> Indicators { get; set; } = new List<string>();
        public List<RiskEvidence> Evidence { get; set; } = new List<RiskEvidence>();
        public DateTime Timestamp { get; set; }
        public TimeSpan CalculationTime { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }
    
    public class RiskWeight
    {
        public RiskCategory Category { get; set; }
        public double BaseWeight { get; set; }
        public Dictionary<string, double> DynamicAdjustments { get; set; } = new Dictionary<string, double>();
        public double TimeDecayFactor { get; set; }
        public double MaxWeight { get; set; }
        public double MinWeight { get; set; }
        public double LearningRate { get; set; }
        public bool RequiresRecalibration { get; set; }
        public DateTime LastRecalibrated { get; set; }
        public double Confidence { get; set; }
    }
    
    public class RiskThreshold
    {
        public RiskEntityType EntityType { get; set; }
        public Dictionary<RiskLevel, ThresholdRange> Levels { get; set; } = new Dictionary<RiskLevel, ThresholdRange>();
        public Dictionary<RiskLevel, double> Hysteresis { get; set; } = new Dictionary<RiskLevel, double>();
        public bool RequiresCalibration { get; set; }
        public DateTime LastCalibrated { get; set; }
        public int CalibrationSamples { get; set; }
        public double Confidence { get; set; }
    }
    
    public class ThresholdRange
    {
        public double Min { get; set; }
        public double Max { get; set; }
    }
    
    public class RiskScoreResult
    {
        public double TotalScore { get; set; }
        public List<RiskFactorScore> FactorScores { get; set; } = new List<RiskFactorScore>();
        public double Confidence { get; set; }
        public string CalculationDetails { get; set; }
    }
    
    public class DeviceData
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string DeviceType { get; set; }
        public string OsVersion { get; set; }
        public DateTime? LastActivity { get; set; }
        public RiskContext RiskContext { get; set; }
        public List<NetworkEvent> NetworkEvents { get; set; }
        public List<ProcessEvent> ProcessEvents { get; set; }
        public List<FileEvent> FileEvents { get; set; }
        public List<DnsQuery> DnsQueries { get; set; }
        public List<Vulnerability> Vulnerabilities { get; set; }
        public List<ThreatEvent> ThreatEvents { get; set; }
        public DateTime Timestamp { get; set; }
    }
    
    public class DeviceContext
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string DeviceType { get; set; }
        public string OsVersion { get; set; }
        public DateTime? LastActivity { get; set; }
        public RiskContext RiskContext { get; set; }
    }
    
    public class ThreatContext
    {
        public string ThreatId { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string ThreatCategory { get; set; }
        public string AttackVector { get; set; }
        public List<string> Tactics { get; set; } = new List<string>();
        public List<string> Techniques { get; set; } = new List<string>();
        public List<string> Indicators { get; set; } = new List<string>();
        public List<string> AffectedDevices { get; set; } = new List<string>();
        public DateTime FirstDetected { get; set; }
        public DateTime LastDetected { get; set; }
        public DateTime? InitialInfection { get; set; }
        public List<string> PersistenceMechanisms { get; set; } = new List<string>();
        public List<string> SpreadMethods { get; set; } = new List<string>();
        public double? SpreadRate { get; set; }
        public List<string> ImpactTypes { get; set; } = new List<string>();
        public List<string> AdvancedTechniques { get; set; } = new List<string>();
        public List<string> EvasionTechniques { get; set; } = new List<string>();
        public string ThreatActorLevel { get; set; }
        public List<string> HidingTechniques { get; set; } = new List<string>();
        public string DetectionDifficulty { get; set; }
        public List<string> MitigationsApplied { get; set; } = new List<string>();
        public bool IsActive { get; set; }
    }
    
    public class TenantContext
    {
        public string TenantId { get; set; }
        public string TenantName { get; set; }
        public string Industry { get; set; }
        public int EmployeeCount { get; set; }
        public int DeviceCount { get; set; }
        public string SecurityMaturity { get; set; }
        public List<string> ComplianceRequirements { get; set; } = new List<string>();
        public Dictionary<string, object> BusinessCriticalSystems { get; set; } = new Dictionary<string, object>();
    }
    
    public class RiskTrendAnalysis
    {
        public string EntityId { get; set; }
        public RiskEntityType EntityType { get; set; }
        public TimeSpan AnalysisPeriod { get; set; }
        public DateTime Timestamp { get; set; }
        public bool HasEnoughData { get; set; }
        public string Message { get; set; }
        public int DataPointCount { get; set; }
        public List<HistoricalScore> HistoricalScores { get; set; } = new List<HistoricalScore>();
        public TrendStatistics Statistics { get; set; }
        public RiskTrend Trend { get; set; }
        public List<SeasonalityPattern> SeasonalityPatterns { get; set; } = new List<SeasonalityPattern>();
        public List<ChangePoint> ChangePoints { get; set; } = new List<ChangePoint>();
        public List<Anomaly> Anomalies { get; set; } = new List<Anomaly>();
        public List<RiskSpike> RiskSpikes { get; set; } = new List<RiskSpike>();
        public FuturePrediction FuturePrediction { get; set; }
        public TrendQualityMetrics QualityMetrics { get; set; }
        public List<TrendInsight> Insights { get; set; } = new List<TrendInsight>();
        public List<RiskRecommendation> Recommendations { get; set; } = new List<RiskRecommendation>();
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
        
        public static RiskTrendAnalysis Empty(string entityId, RiskEntityType entityType)
        {
            return new RiskTrendAnalysis
            {
                EntityId = entityId,
                EntityType = entityType,
                HasEnoughData = false,
                Message = "Análisis no disponible"
            };
        }
        
        public static RiskTrendAnalysis Error(string entityId, RiskEntityType entityType, string errorMessage)
        {
            return new RiskTrendAnalysis
            {
                EntityId = entityId,
                EntityType = entityType,
                HasEnoughData = false,
                Message = $"Error en análisis: {errorMessage}",
                Metadata = new Dictionary<string, object> { { "HasError", true } }
            };
        }
    }
    
    public class RiskDashboard
    {
        public string DashboardId { get; set; }
        public DateTime Timestamp { get; set; }
        public string TenantId { get; set; }
        public TimeSpan TimeRange { get; set; }
        public double OverallRiskScore { get; set; }
        public RiskLevel OverallRiskLevel { get; set; }
        public double OverallConfidence { get; set; }
        public int DeviceCount { get; set; }
        public int ThreatCount { get; set; }
        public int HighRiskDeviceCount { get; set; }
        public int CriticalThreatCount { get; set; }
        public List<DeviceRiskScore> HighRiskDevices { get; set; } = new List<DeviceRiskScore>();
        public List<ThreatRiskScore> CriticalThreats { get; set; } = new List<ThreatRiskScore>();
        public RiskDistribution RiskDistribution { get; set; }
        public List<RiskTrend> RecentTrends { get; set; } = new List<RiskTrend>();
        public List<RiskAlert> ActiveRiskAlerts { get; set; } = new List<RiskAlert>();
        public RiskMetrics RiskMetrics { get; set; }
        public List<PredictiveInsight> PredictiveInsights { get; set; } = new List<PredictiveInsight>();
        public List<RiskComparison> Comparisons { get; set; } = new List<RiskComparison>();
        public TimeSpan GenerationTime { get; set; }
        public DateTime LastDataUpdate { get; set; }
        public TimeSpan RefreshInterval { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
        
        public static RiskDashboard Empty()
        {
            return new RiskDashboard
            {
                DashboardId = "EMPTY",
                Timestamp = DateTime.UtcNow,
                Message = "Dashboard no disponible"
            };
        }
        
        public static RiskDashboard Error(string errorMessage)
        {
            return new RiskDashboard
            {
                DashboardId = "ERROR",
                Timestamp = DateTime.UtcNow,
                Message = $"Error generando dashboard: {errorMessage}",
                Metadata = new Dictionary<string, object> { { "HasError", true } }
            };
        }
        
        public string Message { get; set; }
    }
    
    public class RiskScoringStats
    {
        public DateTime Timestamp { get; set; }
        public string EngineId { get; set; }
        public string Version { get; set; }
        public bool IsInitialized { get; set; }
        public bool IsRunning { get; set; }
        public DateTime LastScoringUpdate { get; set; }
        
        // Cache
        public int DeviceScoresCached { get; set; }
        public int ThreatScoresCached { get; set; }
        public int TenantScoresCached { get; set; }
        public double CacheHitRate { get; set; }
        public long CacheMemoryUsage { get; set; }
        
        // Scoring
        public long TotalCalculations { get; set; }
        public TimeSpan AverageCalculationTime { get; set; }
        public long FailedCalculations { get; set; }
        public double SuccessRate { get; set; }
        
        // Algorithms
        public int ActiveFactors { get; set; }
        public int ActiveWeights { get; set; }
        public int ActiveThresholds { get; set; }
        public string AlgorithmVersion { get; set; }
        
        // Performance
        public double MemoryUsage { get; set; } // MB
        public double CpuUsage { get; set; } // Percentage
        public int QueueSize { get; set; }
        public int ActiveWorkers { get; set; }
        
        // Quality Metrics
        public ScoreDistribution ScoreDistribution { get; set; }
        public ConfidenceLevels ConfidenceLevels { get; set; }
        public TrendAccuracy TrendAccuracy { get; set; }
        
        // Configuration
        public RiskScoringConfiguration Configuration { get; set; }
        public HealthCheckResult HealthStatus { get; set; }
        
        // Error handling
        public bool HasError { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class RiskScoringException : Exception
    {
        public RiskScoringException(string message) : base(message) { }
        public RiskScoringException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskCalculationException : RiskScoringException
    {
        public RiskCalculationException(string message) : base(message) { }
        public RiskCalculationException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskAnalysisException : RiskScoringException
    {
        public RiskAnalysisException(string message) : base(message) { }
        public RiskAnalysisException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskConfigurationException : RiskScoringException
    {
        public RiskConfigurationException(string message) : base(message) { }
        public RiskConfigurationException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskOptimizationException : RiskScoringException
    {
        public RiskOptimizationException(string message) : base(message) { }
        public RiskOptimizationException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskDashboardException : RiskScoringException
    {
        public RiskDashboardException(string message) : base(message) { }
        public RiskDashboardException(string message, Exception inner) : base(message, inner) { }
    }
    
    public class RiskDataException : RiskScoringException
    {
        public RiskDataException(string message) : base(message) { }
        public RiskDataException(string message, Exception inner) : base(message, inner) { }
    }
    
    public enum RiskLevel
    {
        None = 0,
        Info = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Critical = 5,
        Unknown = 99
    }
    
    public enum RiskCategory
    {
        Network,
        Process,
        FileSystem,
        Registry,
        Vulnerability,
        User,
        Threat,
        Compliance,
        Business,
        Technical
    }
    
    public enum RiskEntityType
    {
        Device,
        Threat,
        Tenant,
        User,
        Application,
        Network
    }
    
    #endregion
}