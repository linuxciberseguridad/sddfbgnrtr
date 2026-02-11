using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Cloud.SOAR;
using BWP.Enterprise.Cloud.ThreatGraph;
using BWP.Enterprise.Cloud.TenantManagement;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.SOAR
{
    /// <summary>
    /// Sistema de retroalimentación que aprende de las acciones tomadas
    /// para mejorar automáticamente los playbooks y decisiones futuras
    /// </summary>
    public sealed class FeedbackLoop : IFeedbackLoop
    {
        private readonly ILogger<FeedbackLoop> _logger;
        private readonly ConcurrentDictionary<string, FeedbackData> _feedbackStore;
        private readonly IThreatGraphService _threatGraphService;
        private readonly ITenantManager _tenantManager;
        private readonly PlaybookDefinitionEngine _playbookEngine;
        private readonly List<FeedbackRule> _rules;
        private bool _isInitialized;
        private const int MAX_FEEDBACK_HISTORY = 10000;

        public FeedbackLoop(
            ILogger<FeedbackLoop> logger,
            IThreatGraphService threatGraphService,
            ITenantManager tenantManager,
            PlaybookDefinitionEngine playbookEngine)
        {
            _logger = logger;
            _feedbackStore = new ConcurrentDictionary<string, FeedbackData>();
            _threatGraphService = threatGraphService;
            _tenantManager = tenantManager;
            _playbookEngine = playbookEngine;
            _rules = new List<FeedbackRule>();
            _isInitialized = false;
        }

        /// <summary>
        /// Inicializa el sistema de retroalimentación
        /// </summary>
        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;

            try
            {
                // Cargar reglas de retroalimentación
                await LoadFeedbackRulesAsync();

                // Inicializar análisis de datos históricos
                await AnalyzeHistoricalDataAsync();

                _isInitialized = true;
                _logger.LogInformation("FeedbackLoop inicializado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inicializando FeedbackLoop");
                throw;
            }
        }

        /// <summary>
        /// Registra retroalimentación de una acción SOAR
        /// </summary>
        public async Task<FeedbackResult> RecordFeedbackAsync(FeedbackRequest request)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("FeedbackLoop no inicializado");

            try
            {
                var feedbackId = Guid.NewGuid().ToString();
                var timestamp = DateTime.UtcNow;

                // Validar retroalimentación
                var validationResult = await ValidateFeedbackAsync(request);
                if (!validationResult.IsValid)
                {
                    return FeedbackResult.Invalid(validationResult.Errors);
                }

                // Procesar retroalimentación
                var feedbackData = new FeedbackData
                {
                    FeedbackId = feedbackId,
                    Timestamp = timestamp,
                    TenantId = request.TenantId,
                    IncidentId = request.IncidentId,
                    PlaybookId = request.PlaybookId,
                    ActionId = request.ActionId,
                    FeedbackType = request.FeedbackType,
                    EffectivenessScore = request.EffectivenessScore,
                    Comments = request.Comments,
                    AnalystId = request.AnalystId,
                    Metadata = request.Metadata
                };

                // Almacenar retroalimentación
                _feedbackStore[feedbackId] = feedbackData;

                // Procesar reglas de retroalimentación
                var ruleResults = await ProcessFeedbackRulesAsync(feedbackData);

                // Actualizar playbooks si es necesario
                var playbookUpdates = await UpdatePlaybooksBasedOnFeedbackAsync(feedbackData);

                // Aprender de la retroalimentación
                var learningResults = await LearnFromFeedbackAsync(feedbackData);

                // Generar reporte de retroalimentación
                var report = GenerateFeedbackReport(feedbackData, ruleResults, playbookUpdates, learningResults);

                _logger.LogInformation("Retroalimentación registrada: {FeedbackId} para acción {ActionId}", 
                    feedbackId, request.ActionId);

                return FeedbackResult.Success(feedbackId, report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando retroalimentación");
                return FeedbackResult.Error($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Obtiene retroalimentación por ID de incidente
        /// </summary>
        public async Task<List<FeedbackData>> GetFeedbackByIncidentAsync(string tenantId, string incidentId)
        {
            var feedbacks = _feedbackStore.Values
                .Where(f => f.TenantId == tenantId && f.IncidentId == incidentId)
                .OrderByDescending(f => f.Timestamp)
                .ToList();

            // Enriquecer con datos del threat graph
            foreach (var feedback in feedbacks)
            {
                await EnrichFeedbackWithThreatDataAsync(feedback);
            }

            return feedbacks;
        }

        /// <summary>
        /// Obtiene estadísticas de efectividad por playbook
        /// </summary>
        public async Task<PlaybookEffectivenessStats> GetPlaybookEffectivenessStatsAsync(
            string tenantId, 
            string playbookId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null)
        {
            var relevantFeedbacks = _feedbackStore.Values
                .Where(f => f.TenantId == tenantId && 
                           f.PlaybookId == playbookId &&
                           (!fromDate.HasValue || f.Timestamp >= fromDate) &&
                           (!toDate.HasValue || f.Timestamp <= toDate))
                .ToList();

            if (!relevantFeedbacks.Any())
                return new PlaybookEffectivenessStats { PlaybookId = playbookId };

            var stats = new PlaybookEffectivenessStats
            {
                PlaybookId = playbookId,
                TotalExecutions = relevantFeedbacks.Count,
                AverageEffectiveness = relevantFeedbacks.Average(f => f.EffectivenessScore),
                PositiveFeedbackCount = relevantFeedbacks.Count(f => f.EffectivenessScore >= 7),
                NegativeFeedbackCount = relevantFeedbacks.Count(f => f.EffectivenessScore <= 3),
                FeedbackTypes = relevantFeedbacks
                    .GroupBy(f => f.FeedbackType)
                    .ToDictionary(g => g.Key, g => g.Count()),
                RecentImprovements = await GetRecentImprovementsAsync(relevantFeedbacks)
            };

            // Calcular tendencia
            stats.EffectivenessTrend = CalculateEffectivenessTrend(relevantFeedbacks);

            return stats;
        }

        /// <summary>
        /// Sugiere mejoras para un playbook basado en retroalimentación
        /// </summary>
        public async Task<List<PlaybookImprovement>> SuggestPlaybookImprovementsAsync(
            string tenantId, 
            string playbookId)
        {
            var improvements = new List<PlaybookImprovement>();
            var feedbacks = _feedbackStore.Values
                .Where(f => f.TenantId == tenantId && f.PlaybookId == playbookId)
                .ToList();

            if (!feedbacks.Any())
                return improvements;

            // Analizar patrones comunes en retroalimentación negativa
            var negativeFeedbacks = feedbacks.Where(f => f.EffectivenessScore <= 3).ToList();
            
            if (negativeFeedbacks.Any())
            {
                // Patrón 1: Acciones ineficaces
                var ineffectiveActions = AnalyzeIneffectiveActions(negativeFeedbacks);
                improvements.AddRange(ineffectiveActions);

                // Patrón 2: Timing inadecuado
                var timingIssues = AnalyzeTimingIssues(negativeFeedbacks);
                improvements.AddRange(timingIssues);

                // Patrón 3: Orden incorrecto de acciones
                var orderingIssues = AnalyzeActionOrdering(negativeFeedbacks);
                improvements.AddRange(orderingIssues);
            }

            // Aplicar machine learning para sugerencias adicionales
            var mlSuggestions = await GenerateMLSuggestionsAsync(feedbacks);
            improvements.AddRange(mlSuggestions);

            // Priorizar mejoras
            improvements = improvements
                .OrderByDescending(i => i.ImpactScore * i.Confidence)
                .Take(10)
                .ToList();

            return improvements;
        }

        /// <summary>
        /// Aprende automáticamente de la retroalimentación y actualiza reglas
        /// </summary>
        public async Task<LearningResult> AutoLearnAsync()
        {
            try
            {
                _logger.LogInformation("Iniciando aprendizaje automático desde retroalimentación");

                // 1. Analizar patrones en retroalimentación exitosa
                var successfulPatterns = await AnalyzeSuccessfulPatternsAsync();

                // 2. Identificar patrones en retroalimentación fallida
                var failurePatterns = await AnalyzeFailurePatternsAsync();

                // 3. Descubrir nuevas reglas
                var newRules = await DiscoverNewRulesAsync(successfulPatterns, failurePatterns);

                // 4. Actualizar reglas existentes
                var updatedRules = await UpdateExistingRulesAsync(newRules);

                // 5. Optimizar parámetros de playbooks
                var optimizationResults = await OptimizePlaybookParametersAsync();

                // 6. Generar reporte de aprendizaje
                var learningReport = new LearningResult
                {
                    Timestamp = DateTime.UtcNow,
                    NewRulesDiscovered = newRules.Count,
                    ExistingRulesUpdated = updatedRules.Count,
                    OptimizationResults = optimizationResults,
                    Insights = await GenerateInsightsAsync()
                };

                _logger.LogInformation("Aprendizaje automático completado: {NewRules} nuevas reglas", 
                    newRules.Count);

                return learningReport;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en aprendizaje automático");
                throw;
            }
        }

        /// <summary>
        /// Obtiene métricas de retroalimentación
        /// </summary>
        public async Task<FeedbackMetrics> GetMetricsAsync(string tenantId, DateTimeRange range)
        {
            var feedbacks = _feedbackStore.Values
                .Where(f => f.TenantId == tenantId && 
                           f.Timestamp >= range.Start && 
                           f.Timestamp <= range.End)
                .ToList();

            var metrics = new FeedbackMetrics
            {
                TenantId = tenantId,
                TimeRange = range,
                TotalFeedbacks = feedbacks.Count,
                AverageResponseTime = await CalculateAverageResponseTimeAsync(feedbacks),
                FeedbackDistribution = feedbacks
                    .GroupBy(f => f.FeedbackType)
                    .ToDictionary(g => g.Key, g => g.Count()),
                EffectivenessOverTime = CalculateEffectivenessOverTime(feedbacks),
                TopAnalysts = GetTopAnalysts(feedbacks),
                CommonIssues = await IdentifyCommonIssuesAsync(feedbacks),
                ImprovementRate = CalculateImprovementRate(feedbacks)
            };

            return metrics;
        }

        #region Métodos Privados

        private async Task LoadFeedbackRulesAsync()
        {
            // Reglas predefinidas
            _rules.AddRange(new[]
            {
                new FeedbackRule
                {
                    RuleId = "RULE_001",
                    Name = "Baja efectividad repetida",
                    Description = "Playbook con efectividad menor a 3 en múltiples ejecuciones",
                    Condition = feedbacks => feedbacks.Count(f => f.EffectivenessScore <= 3) >= 3,
                    Action = async feedbacks => await FlagPlaybookForReviewAsync(feedbacks.First().PlaybookId),
                    Priority = RulePriority.High
                },
                new FeedbackRule
                {
                    RuleId = "RULE_002",
                    Name = "Retroalimentación positiva consistente",
                    Description = "Playbook con efectividad mayor a 7 en múltiples ejecuciones",
                    Condition = feedbacks => feedbacks.Count(f => f.EffectivenessScore >= 7) >= 5,
                    Action = async feedbacks => await MarkPlaybookAsEffectiveAsync(feedbacks.First().PlaybookId),
                    Priority = RulePriority.Medium
                },
                new FeedbackRule
                {
                    RuleId = "RULE_003",
                    Name = "Comentarios sobre falsos positivos",
                    Description = "Múltiples comentarios sobre falsos positivos",
                    Condition = feedbacks => feedbacks.Count(f => 
                        f.Comments?.ToLower().Contains("false positive") == true) >= 2,
                    Action = async feedbacks => await AdjustAlertThresholdsAsync(feedbacks),
                    Priority = RulePriority.High
                }
            });

            // Cargar reglas personalizadas del tenant
            var customRules = await _tenantManager.GetCustomFeedbackRulesAsync();
            _rules.AddRange(customRules);

            _logger.LogInformation("Cargadas {RuleCount} reglas de retroalimentación", _rules.Count);
        }

        private async Task AnalyzeHistoricalDataAsync()
        {
            // Analizar datos históricos para identificar patrones iniciales
            var historicalData = await _threatGraphService.GetHistoricalFeedbackDataAsync();
            
            if (historicalData.Any())
            {
                var patterns = await IdentifyInitialPatternsAsync(historicalData);
                _logger.LogInformation("Identificados {PatternCount} patrones iniciales", patterns.Count);
            }
        }

        private async Task<ValidationResult> ValidateFeedbackAsync(FeedbackRequest request)
        {
            var errors = new List<string>();

            // Validar tenant
            var tenant = await _tenantManager.GetTenantAsync(request.TenantId);
            if (tenant == null)
                errors.Add($"Tenant no encontrado: {request.TenantId}");

            // Validar playbook
            if (!string.IsNullOrEmpty(request.PlaybookId))
            {
                var playbook = await _playbookEngine.GetPlaybookAsync(request.TenantId, request.PlaybookId);
                if (playbook == null)
                    errors.Add($"Playbook no encontrado: {request.PlaybookId}");
            }

            // Validar puntuación
            if (request.EffectivenessScore < 1 || request.EffectivenessScore > 10)
                errors.Add("Puntuación de efectividad debe estar entre 1 y 10");

            // Validar comentarios (si existen)
            if (!string.IsNullOrEmpty(request.Comments) && request.Comments.Length > 1000)
                errors.Add("Comentarios no pueden exceder 1000 caracteres");

            return new ValidationResult
            {
                IsValid = !errors.Any(),
                Errors = errors
            };
        }

        private async Task<List<RuleExecutionResult>> ProcessFeedbackRulesAsync(FeedbackData feedback)
        {
            var results = new List<RuleExecutionResult>();
            var relevantFeedbacks = _feedbackStore.Values
                .Where(f => f.TenantId == feedback.TenantId && 
                           f.PlaybookId == feedback.PlaybookId)
                .Take(100) // Limitar para performance
                .ToList();

            foreach (var rule in _rules)
            {
                try
                {
                    if (rule.Condition(relevantFeedbacks))
                    {
                        var result = await rule.Action(relevantFeedbacks);
                        results.Add(new RuleExecutionResult
                        {
                            RuleId = rule.RuleId,
                            RuleName = rule.Name,
                            Triggered = true,
                            Result = result,
                            Timestamp = DateTime.UtcNow
                        });

                        _logger.LogInformation("Regla de retroalimentación activada: {RuleName}", rule.Name);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error ejecutando regla {RuleId}", rule.RuleId);
                    results.Add(new RuleExecutionResult
                    {
                        RuleId = rule.RuleId,
                        RuleName = rule.Name,
                        Triggered = false,
                        Error = ex.Message,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            return results;
        }

        private async Task<List<PlaybookUpdate>> UpdatePlaybooksBasedOnFeedbackAsync(FeedbackData feedback)
        {
            var updates = new List<PlaybookUpdate>();

            // Solo actualizar si la retroalimentación es significativa
            if (feedback.EffectivenessScore <= 3 || feedback.EffectivenessScore >= 8)
            {
                var playbook = await _playbookEngine.GetPlaybookAsync(feedback.TenantId, feedback.PlaybookId);
                if (playbook != null)
                {
                    // Sugerir actualizaciones basadas en retroalimentación
                    var suggestions = await SuggestPlaybookImprovementsAsync(feedback.TenantId, feedback.PlaybookId);
                    
                    foreach (var suggestion in suggestions.Where(s => s.Confidence >= 0.7))
                    {
                        var update = await _playbookEngine.ApplyImprovementAsync(
                            feedback.TenantId, 
                            feedback.PlaybookId, 
                            suggestion);

                        if (update.Success)
                        {
                            updates.Add(update);
                            _logger.LogInformation("Playbook {PlaybookId} actualizado con mejora: {Improvement}", 
                                feedback.PlaybookId, suggestion.Description);
                        }
                    }
                }
            }

            return updates;
        }

        private async Task<LearningOutcome> LearnFromFeedbackAsync(FeedbackData feedback)
        {
            var outcome = new LearningOutcome
            {
                FeedbackId = feedback.FeedbackId,
                Timestamp = DateTime.UtcNow,
                Insights = new List<string>()
            };

            // Aprendizaje 1: Efectividad de acciones específicas
            if (!string.IsNullOrEmpty(feedback.ActionId))
            {
                var actionEffectiveness = await AnalyzeActionEffectivenessAsync(feedback);
                outcome.Insights.AddRange(actionEffectiveness);
            }

            // Aprendizaje 2: Timing óptimo
            var timingInsights = await AnalyzeOptimalTimingAsync(feedback);
            outcome.Insights.AddRange(timingInsights);

            // Aprendizaje 3: Contexto de amenaza
            var contextInsights = await AnalyzeThreatContextAsync(feedback);
            outcome.Insights.AddRange(contextInsights);

            // Aprendizaje 4: Preferencias del analista
            if (!string.IsNullOrEmpty(feedback.AnalystId))
            {
                var analystInsights = await AnalyzeAnalystPreferencesAsync(feedback);
                outcome.Insights.AddRange(analystInsights);
            }

            outcome.Success = outcome.Insights.Any();
            return outcome;
        }

        private async Task<List<string>> AnalyzeActionEffectivenessAsync(FeedbackData feedback)
        {
            var insights = new List<string>();
            
            // Analizar efectividad de la acción en diferentes contextos
            var similarFeedbacks = _feedbackStore.Values
                .Where(f => f.ActionId == feedback.ActionId && 
                           f.TenantId == feedback.TenantId)
                .ToList();

            if (similarFeedbacks.Count >= 3)
            {
                var avgScore = similarFeedbacks.Average(f => f.EffectivenessScore);
                var stdDev = CalculateStandardDeviation(similarFeedbacks.Select(f => f.EffectivenessScore));

                if (stdDev < 2) // Baja variación = consistencia
                {
                    insights.Add($"Acción {feedback.ActionId} muestra consistencia en efectividad: {avgScore:F1}/10");
                    
                    if (avgScore >= 7)
                    {
                        insights.Add($"Acción {feedback.ActionId} es altamente efectiva");
                    }
                    else if (avgScore <= 3)
                    {
                        insights.Add($"Acción {feedback.ActionId} requiere revisión");
                    }
                }
            }

            return insights;
        }

        private async Task EnrichFeedbackWithThreatDataAsync(FeedbackData feedback)
        {
            try
            {
                // Obtener datos del threat graph para el incidente
                var threatData = await _threatGraphService.GetIncidentDataAsync(
                    feedback.TenantId, 
                    feedback.IncidentId);

                if (threatData != null)
                {
                    feedback.Metadata["threat_severity"] = threatData.Severity;
                    feedback.Metadata["threat_category"] = threatData.Category;
                    feedback.Metadata["indicators_count"] = threatData.Indicators.Count;
                    feedback.Metadata["affected_assets"] = threatData.AffectedAssets.Count;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "No se pudieron enriquecer datos de threat para feedback {FeedbackId}", 
                    feedback.FeedbackId);
            }
        }

        private async Task<List<PlaybookImprovement>> AnalyzeIneffectiveActions(List<FeedbackData> negativeFeedbacks)
        {
            var improvements = new List<PlaybookImprovement>();

            // Agrupar por acción y comentarios comunes
            var actionGroups = negativeFeedbacks
                .Where(f => !string.IsNullOrEmpty(f.ActionId))
                .GroupBy(f => f.ActionId)
                .Where(g => g.Count() >= 2);

            foreach (var group in actionGroups)
            {
                var commonWords = ExtractCommonWords(group.Select(f => f.Comments).ToList());
                
                if (commonWords.Any())
                {
                    improvements.Add(new PlaybookImprovement
                    {
                        PlaybookId = group.First().PlaybookId,
                        ActionId = group.Key,
                        Description = $"Acción '{group.Key}' frecuentemente reportada como inefectiva. Palabras clave: {string.Join(", ", commonWords.Take(3))}",
                        SuggestedChange = "Considerar reemplazar o modificar esta acción",
                        ImpactScore = CalculateImpactScore(group.Count(), negativeFeedbacks.Count),
                        Confidence = CalculateConfidence(group.Count()),
                        Category = ImprovementCategory.ActionEffectiveness
                    });
                }
            }

            return improvements;
        }

        private async Task<List<PlaybookImprovement>> AnalyzeTimingIssues(List<FeedbackData> negativeFeedbacks)
        {
            var improvements = new List<PlaybookImprovement>();

            // Buscar patrones de timing en comentarios
            var timingKeywords = new[] { "lento", "tardío", "demorado", "retraso", "timing", "temprano" };
            var timingFeedbacks = negativeFeedbacks
                .Where(f => timingKeywords.Any(kw => 
                    f.Comments?.ToLower().Contains(kw) == true))
                .ToList();

            if (timingFeedbacks.Any())
            {
                improvements.Add(new PlaybookImprovement
                {
                    PlaybookId = timingFeedbacks.First().PlaybookId,
                    Description = "Múltiples reportes de problemas de timing en la ejecución",
                    SuggestedChange = "Revisar tiempos de ejecución y dependencias entre acciones",
                    ImpactScore = CalculateImpactScore(timingFeedbacks.Count, negativeFeedbacks.Count),
                    Confidence = 0.8,
                    Category = ImprovementCategory.ExecutionTiming
                });
            }

            return improvements;
        }

        private async Task<List<PlaybookImprovement>> GenerateMLSuggestionsAsync(List<FeedbackData> feedbacks)
        {
            var suggestions = new List<PlaybookImprovement>();

            // Implementación simplificada - en producción usar ML real
            if (feedbacks.Any())
            {
                // Sugerencia 1: Optimizar orden basado en efectividad secuencial
                var sequentialEffectiveness = await AnalyzeSequentialEffectivenessAsync(feedbacks);
                if (sequentialEffectiveness.Any())
                {
                    suggestions.Add(new PlaybookImprovement
                    {
                        Description = "Patrón detectado: Mejor efectividad cuando ciertas acciones se ejecutan en orden específico",
                        SuggestedChange = "Reordenar acciones según patrón óptimo detectado",
                        ImpactScore = 0.7,
                        Confidence = 0.75,
                        Category = ImprovementCategory.ActionOrdering
                    });
                }

                // Sugerencia 2: Ajustar parámetros basado en contexto
                var contextAnalysis = await AnalyzeContextualEffectivenessAsync(feedbacks);
                if (contextAnalysis.Any())
                {
                    suggestions.Add(new PlaybookImprovement
                    {
                        Description = "La efectividad varía según el contexto de la amenaza",
                        SuggestedChange = "Implementar reglas condicionales basadas en contexto",
                        ImpactScore = 0.6,
                        Confidence = 0.7,
                        Category = ImprovementCategory.ConditionalLogic
                    });
                }
            }

            return suggestions;
        }

        private FeedbackReport GenerateFeedbackReport(
            FeedbackData feedback, 
            List<RuleExecutionResult> ruleResults,
            List<PlaybookUpdate> playbookUpdates,
            LearningOutcome learningOutcome)
        {
            return new FeedbackReport
            {
                FeedbackId = feedback.FeedbackId,
                Timestamp = DateTime.UtcNow,
                Summary = $"Retroalimentación registrada para acción {feedback.ActionId}",
                EffectivenessScore = feedback.EffectivenessScore,
                FeedbackType = feedback.FeedbackType,
                RulesTriggered = ruleResults.Where(r => r.Triggered).Select(r => r.RuleName).ToList(),
                PlaybooksUpdated = playbookUpdates.Select(u => u.PlaybookId).Distinct().ToList(),
                LearningOutcomes = learningOutcome.Insights,
                Recommendations = GenerateRecommendations(feedback, ruleResults)
            };
        }

        private List<string> GenerateRecommendations(FeedbackData feedback, List<RuleExecutionResult> ruleResults)
        {
            var recommendations = new List<string>();

            if (feedback.EffectivenessScore <= 3)
            {
                recommendations.Add("Revisar playbook asociado para posibles mejoras");
                recommendations.Add("Considerar entrenamiento adicional para analistas");
            }
            else if (feedback.EffectivenessScore >= 8)
            {
                recommendations.Add("Documentar mejores prácticas de esta ejecución");
                recommendations.Add("Considerar replicar este enfoque en playbooks similares");
            }

            // Recomendaciones basadas en reglas activadas
            foreach (var rule in ruleResults.Where(r => r.Triggered))
            {
                recommendations.Add($"Regla '{rule.RuleName}' activada - {rule.Result}");
            }

            return recommendations;
        }

        #endregion

        #region Clases y estructuras de datos

        public interface IFeedbackLoop
        {
            Task InitializeAsync();
            Task<FeedbackResult> RecordFeedbackAsync(FeedbackRequest request);
            Task<List<FeedbackData>> GetFeedbackByIncidentAsync(string tenantId, string incidentId);
            Task<PlaybookEffectivenessStats> GetPlaybookEffectivenessStatsAsync(
                string tenantId, string playbookId, DateTime? fromDate, DateTime? toDate);
            Task<List<PlaybookImprovement>> SuggestPlaybookImprovementsAsync(
                string tenantId, string playbookId);
            Task<LearningResult> AutoLearnAsync();
            Task<FeedbackMetrics> GetMetricsAsync(string tenantId, DateTimeRange range);
        }

        public class FeedbackRequest
        {
            public string TenantId { get; set; }
            public string IncidentId { get; set; }
            public string PlaybookId { get; set; }
            public string ActionId { get; set; }
            public string FeedbackType { get; set; }
            public int EffectivenessScore { get; set; }
            public string Comments { get; set; }
            public string AnalystId { get; set; }
            public Dictionary<string, object> Metadata { get; set; }
        }

        public class FeedbackData
        {
            public string FeedbackId { get; set; }
            public DateTime Timestamp { get; set; }
            public string TenantId { get; set; }
            public string IncidentId { get; set; }
            public string PlaybookId { get; set; }
            public string ActionId { get; set; }
            public string FeedbackType { get; set; }
            public int EffectivenessScore { get; set; }
            public string Comments { get; set; }
            public string AnalystId { get; set; }
            public Dictionary<string, object> Metadata { get; set; }
        }

        public class FeedbackResult
        {
            public bool Success { get; set; }
            public string FeedbackId { get; set; }
            public FeedbackReport Report { get; set; }
            public List<string> Errors { get; set; }

            public static FeedbackResult Success(string feedbackId, FeedbackReport report)
            {
                return new FeedbackResult
                {
                    Success = true,
                    FeedbackId = feedbackId,
                    Report = report,
                    Errors = new List<string>()
                };
            }

            public static FeedbackResult Invalid(List<string> errors)
            {
                return new FeedbackResult
                {
                    Success = false,
                    Errors = errors
                };
            }

            public static FeedbackResult Error(string error)
            {
                return new FeedbackResult
                {
                    Success = false,
                    Errors = new List<string> { error }
                };
            }
        }

        public class FeedbackRule
        {
            public string RuleId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public Func<List<FeedbackData>, bool> Condition { get; set; }
            public Func<List<FeedbackData>, Task<string>> Action { get; set; }
            public RulePriority Priority { get; set; }
        }

        public enum RulePriority
        {
            Low,
            Medium,
            High,
            Critical
        }

        public class PlaybookEffectivenessStats
        {
            public string PlaybookId { get; set; }
            public int TotalExecutions { get; set; }
            public double AverageEffectiveness { get; set; }
            public int PositiveFeedbackCount { get; set; }
            public int NegativeFeedbackCount { get; set; }
            public Dictionary<string, int> FeedbackTypes { get; set; }
            public List<string> RecentImprovements { get; set; }
            public double EffectivenessTrend { get; set; }
        }

        public class PlaybookImprovement
        {
            public string PlaybookId { get; set; }
            public string ActionId { get; set; }
            public string Description { get; set; }
            public string SuggestedChange { get; set; }
            public double ImpactScore { get; set; }
            public double Confidence { get; set; }
            public ImprovementCategory Category { get; set; }
        }

        public enum ImprovementCategory
        {
            ActionEffectiveness,
            ExecutionTiming,
            ActionOrdering,
            ConditionalLogic,
            ParameterTuning,
            Integration
        }

        public class LearningResult
        {
            public DateTime Timestamp { get; set; }
            public int NewRulesDiscovered { get; set; }
            public int ExistingRulesUpdated { get; set; }
            public Dictionary<string, object> OptimizationResults { get; set; }
            public List<string> Insights { get; set; }
        }

        public class FeedbackMetrics
        {
            public string TenantId { get; set; }
            public DateTimeRange TimeRange { get; set; }
            public int TotalFeedbacks { get; set; }
            public TimeSpan AverageResponseTime { get; set; }
            public Dictionary<string, int> FeedbackDistribution { get; set; }
            public Dictionary<DateTime, double> EffectivenessOverTime { get; set; }
            public Dictionary<string, int> TopAnalysts { get; set; }
            public List<string> CommonIssues { get; set; }
            public double ImprovementRate { get; set; }
        }

        // Métodos helper privados (implementaciones simplificadas)
        private async Task<string> FlagPlaybookForReviewAsync(string playbookId)
        {
            return $"Playbook {playbookId} marcado para revisión";
        }

        private async Task<string> MarkPlaybookAsEffectiveAsync(string playbookId)
        {
            return $"Playbook {playbookId} marcado como efectivo";
        }

        private async Task<string> AdjustAlertThresholdsAsync(List<FeedbackData> feedbacks)
        {
            return "Umbrales de alerta ajustados para reducir falsos positivos";
        }

        private List<string> ExtractCommonWords(List<string> texts)
        {
            // Implementación simplificada
            return new List<string>();
        }

        private double CalculateImpactScore(int issueCount, int totalCount)
        {
            return totalCount > 0 ? (double)issueCount / totalCount : 0;
        }

        private double CalculateConfidence(int sampleSize)
        {
            return Math.Min(1.0, sampleSize / 10.0);
        }

        private double CalculateStandardDeviation(IEnumerable<int> values)
        {
            var avg = values.Average();
            var sumOfSquares = values.Sum(v => Math.Pow(v - avg, 2));
            return Math.Sqrt(sumOfSquares / values.Count());
        }

        #endregion
    }
}