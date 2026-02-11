using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Cloud.DeviceRegistry;
using BWP.Enterprise.Cloud.Logging;
using BWP.Enterprise.Cloud.Storage;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.ThreatGraph
{
    /// <summary>
    /// Motor de correlación de amenazas basado en grafos
    /// Detecta patrones complejos y ataques multi-etapa
    /// </summary>
    public sealed class GraphCorrelationEngine
    {
        private static readonly Lazy<GraphCorrelationEngine> _instance = 
            new Lazy<GraphCorrelationEngine>(() => new GraphCorrelationEngine());
        
        public static GraphCorrelationEngine Instance => _instance.Value;
        
        private readonly ILogger<GraphCorrelationEngine> _logger;
        private readonly ThreatGraphDatabase _graphDatabase;
        private readonly ConcurrentDictionary<string, GraphPattern> _activePatterns;
        private readonly ConcurrentDictionary<string, ThreatCluster> _activeClusters;
        private readonly List<CorrelationRule> _correlationRules;
        private readonly List<DetectionPattern> _detectionPatterns;
        private bool _isInitialized;
        private DateTime _lastGraphUpdate;
        private const int MAX_GRAPH_NODES = 100000;
        private const int MAX_GRAPH_EDGES = 500000;
        private const double SIMILARITY_THRESHOLD = 0.85;
        
        public GraphCorrelationEngine()
        {
            _logger = LogManager.CreateLogger<GraphCorrelationEngine>();
            _graphDatabase = new ThreatGraphDatabase();
            _activePatterns = new ConcurrentDictionary<string, GraphPattern>();
            _activeClusters = new ConcurrentDictionary<string, ThreatCluster>();
            _correlationRules = new List<CorrelationRule>();
            _detectionPatterns = new List<DetectionPattern>();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el motor de correlación
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Inicializando GraphCorrelationEngine...");
                
                // 1. Inicializar base de datos de grafos
                await _graphDatabase.InitializeAsync();
                
                // 2. Cargar patrones de detección predefinidos
                await LoadDetectionPatternsAsync();
                
                // 3. Cargar reglas de correlación
                await LoadCorrelationRulesAsync();
                
                // 4. Inicializar clusters activos
                await InitializeThreatClustersAsync();
                
                // 5. Programar mantenimiento periódico
                ScheduleMaintenance();
                
                _isInitialized = true;
                _lastGraphUpdate = DateTime.UtcNow;
                
                _logger.LogInformation("GraphCorrelationEngine inicializado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al inicializar GraphCorrelationEngine");
                throw;
            }
        }
        
        /// <summary>
        /// Procesa eventos de telemetría para correlación
        /// </summary>
        public async Task<CorrelationResult> ProcessEventsAsync(TelemetryEventBatch batch)
        {
            if (!_isInitialized || batch?.Events == null || batch.Events.Count == 0)
                return CorrelationResult.Empty();
            
            try
            {
                var startTime = DateTime.UtcNow;
                var correlationId = Guid.NewGuid().ToString();
                
                _logger.LogDebug($"Procesando batch {batch.BatchId} con {batch.Events.Count} eventos");
                
                // 1. Ingresar eventos al grafo
                var graphEvents = await IngestEventsToGraphAsync(batch);
                
                // 2. Buscar patrones en el grafo
                var detectedPatterns = await DetectPatternsAsync(graphEvents);
                
                // 3. Correlacionar eventos
                var correlationResults = await CorrelateEventsAsync(graphEvents, detectedPatterns);
                
                // 4. Actualizar clusters de amenazas
                var updatedClusters = await UpdateThreatClustersAsync(correlationResults);
                
                // 5. Generar resultados consolidados
                var result = new CorrelationResult
                {
                    CorrelationId = correlationId,
                    Timestamp = DateTime.UtcNow,
                    DeviceId = batch.DeviceId,
                    TotalEvents = batch.Events.Count,
                    DetectedPatterns = detectedPatterns,
                    CorrelationScore = CalculateCorrelationScore(detectedPatterns),
                    ThreatClusters = updatedClusters,
                    ProcessingTime = DateTime.UtcNow - startTime,
                    Recommendations = GenerateRecommendations(detectedPatterns, updatedClusters)
                };
                
                // 6. Almacenar resultados para análisis posterior
                await StoreCorrelationResultAsync(result);
                
                _logger.LogInformation($"Correlación completada: {detectedPatterns.Count} patrones detectados");
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error procesando eventos del dispositivo {batch.DeviceId}");
                return CorrelationResult.Error($"Error de correlación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Correlaciona alertas de seguridad
        /// </summary>
        public async Task<List<CorrelatedAlert>> CorrelateAlertsAsync(List<SecurityAlert> alerts)
        {
            var correlatedAlerts = new List<CorrelatedAlert>();
            
            if (!_isInitialized || alerts == null || alerts.Count == 0)
                return correlatedAlerts;
            
            try
            {
                // Agrupar alertas por dispositivo y tipo
                var deviceGroups = alerts.GroupBy(a => a.DeviceId);
                
                foreach (var deviceGroup in deviceGroups)
                {
                    var deviceId = deviceGroup.Key;
                    var deviceAlerts = deviceGroup.ToList();
                    
                    // Correlacionar alertas del mismo dispositivo
                    var deviceCorrelation = await CorrelateDeviceAlertsAsync(deviceId, deviceAlerts);
                    correlatedAlerts.AddRange(deviceCorrelation);
                    
                    // Correlacionar entre dispositivos (ataques laterales)
                    if (deviceAlerts.Count >= 3) // Mínimo 3 alertas para correlación lateral
                    {
                        var lateralCorrelation = await CorrelateLateralMovementAsync(deviceId, deviceAlerts);
                        correlatedAlerts.AddRange(lateralCorrelation);
                    }
                }
                
                // Detectar patrones de campaña
                var campaignPatterns = await DetectCampaignPatternsAsync(correlatedAlerts);
                
                // Consolidar alertas correlacionadas
                var consolidatedAlerts = await ConsolidateAlertsAsync(correlatedAlerts, campaignPatterns);
                
                return consolidatedAlerts;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error correlacionando alertas");
                return new List<CorrelatedAlert>();
            }
        }
        
        /// <summary>
        /// Busca amenazas en el grafo histórico
        /// </summary>
        public async Task<List<ThreatDetection>> SearchThreatsAsync(ThreatSearchQuery query)
        {
            var threats = new List<ThreatDetection>();
            
            if (!_isInitialized || query == null)
                return threats;
            
            try
            {
                // 1. Buscar en nodos del grafo
                var graphResults = await _graphDatabase.SearchAsync(query);
                
                // 2. Aplicar filtros temporales
                var filteredResults = ApplyTimeFilters(graphResults, query.TimeRange);
                
                // 3. Calcular scores de amenaza
                var scoredResults = await CalculateThreatScoresAsync(filteredResults);
                
                // 4. Agrupar resultados similares
                var groupedResults = GroupSimilarThreats(scoredResults);
                
                // 5. Ordenar por severidad y score
                threats = groupedResults
                    .OrderByDescending(t => t.SeverityScore)
                    .ThenByDescending(t => t.Confidence)
                    .ToList();
                
                _logger.LogDebug($"Búsqueda completada: {threats.Count} amenazas encontradas");
                
                return threats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error buscando amenazas");
                return threats;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del motor de correlación
        /// </summary>
        public async Task<GraphCorrelationStats> GetStatisticsAsync()
        {
            try
            {
                var graphStats = await _graphDatabase.GetStatisticsAsync();
                
                return new GraphCorrelationStats
                {
                    Timestamp = DateTime.UtcNow,
                    IsInitialized = _isInitialized,
                    TotalNodes = graphStats.TotalNodes,
                    TotalEdges = graphStats.TotalEdges,
                    ActivePatterns = _activePatterns.Count,
                    ActiveClusters = _activeClusters.Count,
                    CorrelationRules = _correlationRules.Count,
                    DetectionPatterns = _detectionPatterns.Count,
                    LastGraphUpdate = _lastGraphUpdate,
                    MemoryUsage = GetMemoryUsage(),
                    ProcessingQueue = GetQueueStatistics()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo estadísticas");
                return new GraphCorrelationStats { IsInitialized = false };
            }
        }
        
        /// <summary>
        /// Actualiza reglas de correlación dinámicamente
        /// </summary>
        public async Task<bool> UpdateCorrelationRulesAsync(List<CorrelationRule> newRules)
        {
            try
            {
                if (newRules == null || newRules.Count == 0)
                    return false;
                
                // Validar nuevas reglas
                var validRules = newRules.Where(r => ValidateCorrelationRule(r)).ToList();
                
                if (validRules.Count == 0)
                {
                    _logger.LogWarning("No hay reglas válidas para actualizar");
                    return false;
                }
                
                // Actualizar reglas existentes
                foreach (var rule in validRules)
                {
                    var existingRule = _correlationRules.FirstOrDefault(r => r.RuleId == rule.RuleId);
                    if (existingRule != null)
                    {
                        _correlationRules.Remove(existingRule);
                    }
                    _correlationRules.Add(rule);
                }
                
                // Re-indexar patrones
                await ReindexDetectionPatternsAsync();
                
                _logger.LogInformation($"Actualizadas {validRules.Count} reglas de correlación");
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando reglas de correlación");
                return false;
            }
        }
        
        /// <summary>
        /// Visualiza el grafo de amenazas
        /// </summary>
        public async Task<ThreatGraphVisualization> VisualizeThreatGraphAsync(
            string deviceId = null, 
            TimeSpan? timeRange = null, 
            int maxNodes = 1000)
        {
            try
            {
                var visualization = new ThreatGraphVisualization
                {
                    Timestamp = DateTime.UtcNow,
                    Nodes = new List<GraphNode>(),
                    Edges = new List<GraphEdge>(),
                    Clusters = new List<ThreatClusterVisualization>()
                };
                
                // Obtener datos del grafo
                var graphData = await _graphDatabase.GetVisualizationDataAsync(
                    deviceId, timeRange, maxNodes);
                
                // Construir visualización
                visualization.Nodes = graphData.Nodes.Select(n => new GraphNode
                {
                    Id = n.Id,
                    Label = n.Label,
                    Type = n.Type,
                    Properties = n.Properties,
                    Size = CalculateNodeSize(n),
                    Color = GetNodeColor(n.Type)
                }).ToList();
                
                visualization.Edges = graphData.Edges.Select(e => new GraphEdge
                {
                    Id = e.Id,
                    Source = e.Source,
                    Target = e.Target,
                    Label = e.Label,
                    Type = e.Type,
                    Weight = e.Weight,
                    Properties = e.Properties
                }).ToList();
                
                // Agrupar en clusters
                visualization.Clusters = await IdentifyVisualClustersAsync(
                    visualization.Nodes, visualization.Edges);
                
                // Calcular layout
                visualization.Layout = await CalculateGraphLayoutAsync(
                    visualization.Nodes, visualization.Edges);
                
                return visualization;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error visualizando grafo de amenazas");
                return new ThreatGraphVisualization();
            }
        }
        
        #region Métodos privados
        
        private async Task LoadDetectionPatternsAsync()
        {
            // Patrones predefinidos de amenazas
            _detectionPatterns.Add(new DetectionPattern
            {
                PatternId = "APT_LATERAL_MOVEMENT",
                Name = "Movimiento Lateral APT",
                Description = "Patrón de movimiento lateral en red interna",
                Indicators = new List<string>
                {
                    "MultipleSMBConnections",
                    "PsExecUsage",
                    "WMIExecution",
                    "PassTheHash"
                },
                Threshold = 3,
                Severity = ThreatSeverity.Critical,
                Confidence = 0.9
            });
            
            _detectionPatterns.Add(new DetectionPattern
            {
                PatternId = "DATA_EXFILTRATION",
                Name = "Exfiltración de Datos",
                Description = "Transferencia masiva de datos a destinos externos",
                Indicators = new List<string>
                {
                    "LargeOutboundTransfer",
                    "CompressedData",
                    "OffHoursActivity",
                    "EncryptedTrafficToUnknown"
                },
                Threshold = 2,
                Severity = ThreatSeverity.High,
                Confidence = 0.85
            });
            
            _detectionPatterns.Add(new DetectionPattern
            {
                PatternId = "RANSOMWARE_BEHAVIOR",
                Name = "Comportamiento de Ransomware",
                Description = "Patrón típico de cifrado de archivos",
                Indicators = new List<string>
                {
                    "MassFileEncryption",
                    "RansomNoteCreation",
                    "ShadowCopyDeletion",
                    "RegistryModification"
                },
                Threshold = 3,
                Severity = ThreatSeverity.Critical,
                Confidence = 0.95
            });
            
            await Task.CompletedTask;
        }
        
        private async Task LoadCorrelationRulesAsync()
        {
            // Reglas de correlación predefinidas
            _correlationRules.Add(new CorrelationRule
            {
                RuleId = "CORR_001",
                Name = "Correlación Temporal",
                Description = "Correlaciona eventos que ocurren en ventana temporal corta",
                Conditions = new List<CorrelationCondition>
                {
                    new CorrelationCondition
                    {
                        Field = "Timestamp",
                        Operator = "Within",
                        Value = "300" // 5 minutos
                    }
                },
                Weight = 0.7,
                Enabled = true
            });
            
            _correlationRules.Add(new CorrelationRule
            {
                RuleId = "CORR_002",
                Name = "Correlación de Proceso",
                Description = "Correlaciona eventos del mismo proceso",
                Conditions = new List<CorrelationCondition>
                {
                    new CorrelationCondition
                    {
                        Field = "ProcessId",
                        Operator = "Equals",
                        Value = ""
                    }
                },
                Weight = 0.8,
                Enabled = true
            });
            
            _correlationRules.Add(new CorrelationRule
            {
                RuleId = "CORR_003",
                Name = "Correlación de Usuario",
                Description = "Correlaciona eventos del mismo usuario",
                Conditions = new List<CorrelationCondition>
                {
                    new CorrelationCondition
                    {
                        Field = "UserId",
                        Operator = "Equals",
                        Value = ""
                    }
                },
                Weight = 0.6,
                Enabled = true
            });
            
            await Task.CompletedTask;
        }
        
        private async Task InitializeThreatClustersAsync()
        {
            // Inicializar clusters vacíos
            _activeClusters["MALWARE"] = new ThreatCluster
            {
                ClusterId = "MALWARE",
                Name = "Actividad Malware",
                Description = "Cluster de actividad maliciosa",
                Severity = ThreatSeverity.High,
                CreatedAt = DateTime.UtcNow,
                LastUpdated = DateTime.UtcNow,
                MemberCount = 0,
                ThreatScore = 0
            };
            
            _activeClusters["INSIDER_THREAT"] = new ThreatCluster
            {
                ClusterId = "INSIDER_THREAT",
                Name = "Amenaza Interna",
                Description = "Actividad sospechosa de usuario interno",
                Severity = ThreatSeverity.Medium,
                CreatedAt = DateTime.UtcNow,
                LastUpdated = DateTime.UtcNow,
                MemberCount = 0,
                ThreatScore = 0
            };
            
            _activeClusters["DATA_EXFIL"] = new ThreatCluster
            {
                ClusterId = "DATA_EXFIL",
                Name = "Exfiltración de Datos",
                Description = "Cluster de exfiltración de datos",
                Severity = ThreatSeverity.Critical,
                CreatedAt = DateTime.UtcNow,
                LastUpdated = DateTime.UtcNow,
                MemberCount = 0,
                ThreatScore = 0
            };
            
            await Task.CompletedTask;
        }
        
        private async Task<List<GraphEvent>> IngestEventsToGraphAsync(TelemetryEventBatch batch)
        {
            var graphEvents = new List<GraphEvent>();
            
            foreach (var telemetryEvent in batch.Events)
            {
                var graphEvent = ConvertToGraphEvent(telemetryEvent, batch.DeviceId);
                
                // Agregar al grafo
                await _graphDatabase.AddNodeAsync(graphEvent.Node);
                
                // Conectar con eventos relacionados
                await ConnectRelatedEventsAsync(graphEvent);
                
                graphEvents.Add(graphEvent);
            }
            
            return graphEvents;
        }
        
        private async Task<List<DetectedPattern>> DetectPatternsAsync(List<GraphEvent> graphEvents)
        {
            var detectedPatterns = new List<DetectedPattern>();
            
            foreach (var pattern in _detectionPatterns)
            {
                var matchCount = await CountPatternMatchesAsync(graphEvents, pattern);
                
                if (matchCount >= pattern.Threshold)
                {
                    detectedPatterns.Add(new DetectedPattern
                    {
                        PatternId = pattern.PatternId,
                        PatternName = pattern.Name,
                        MatchCount = matchCount,
                        Confidence = pattern.Confidence,
                        Severity = pattern.Severity,
                        MatchedEvents = graphEvents.Where(e => 
                            MatchesPattern(e, pattern)).ToList(),
                        FirstDetected = DateTime.UtcNow
                    });
                }
            }
            
            return detectedPatterns;
        }
        
        private async Task<List<EventCorrelation>> CorrelateEventsAsync(
            List<GraphEvent> graphEvents, 
            List<DetectedPattern> patterns)
        {
            var correlations = new List<EventCorrelation>();
            
            // Aplicar reglas de correlación
            foreach (var rule in _correlationRules.Where(r => r.Enabled))
            {
                var ruleCorrelations = await ApplyCorrelationRuleAsync(graphEvents, rule);
                correlations.AddRange(ruleCorrelations);
            }
            
            // Correlacionar basado en patrones
            foreach (var pattern in patterns)
            {
                var patternCorrelations = CorrelateByPattern(graphEvents, pattern);
                correlations.AddRange(patternCorrelations);
            }
            
            // Eliminar duplicados y consolidar
            var consolidatedCorrelations = ConsolidateCorrelations(correlations);
            
            return consolidatedCorrelations;
        }
        
        private async Task<List<ThreatCluster>> UpdateThreatClustersAsync(
            List<EventCorrelation> correlations)
        {
            var updatedClusters = new List<ThreatCluster>();
            
            foreach (var correlation in correlations)
            {
                // Determinar cluster apropiado
                var clusterId = DetermineThreatCluster(correlation);
                
                if (_activeClusters.TryGetValue(clusterId, out var cluster))
                {
                    // Actualizar cluster existente
                    cluster.MemberCount++;
                    cluster.ThreatScore = CalculateClusterScore(cluster, correlation);
                    cluster.LastUpdated = DateTime.UtcNow;
                    cluster.RelatedCorrelations.Add(correlation.CorrelationId);
                    
                    _activeClusters[clusterId] = cluster;
                    updatedClusters.Add(cluster);
                }
            }
            
            return updatedClusters;
        }
        
        private GraphEvent ConvertToGraphEvent(TelemetryEvent telemetryEvent, string deviceId)
        {
            return new GraphEvent
            {
                EventId = telemetryEvent.EventId,
                DeviceId = deviceId,
                Timestamp = telemetryEvent.Timestamp,
                EventType = telemetryEvent.EventType,
                Node = new GraphNode
                {
                    Id = $"event_{telemetryEvent.EventId}",
                    Label = telemetryEvent.EventType,
                    Type = GetNodeType(telemetryEvent.EventType),
                    Properties = telemetryEvent.Data ?? new Dictionary<string, object>()
                },
                Metadata = telemetryEvent.Metadata ?? new Dictionary<string, object>()
            };
        }
        
        private string GetNodeType(string eventType)
        {
            if (eventType.Contains("Process")) return "PROCESS";
            if (eventType.Contains("File")) return "FILE";
            if (eventType.Contains("Network")) return "NETWORK";
            if (eventType.Contains("Registry")) return "REGISTRY";
            return "EVENT";
        }
        
        private double CalculateCorrelationScore(List<DetectedPattern> patterns)
        {
            if (patterns.Count == 0) return 0;
            
            var totalScore = patterns.Sum(p => p.Confidence * GetSeverityWeight(p.Severity));
            var maxScore = patterns.Count * GetSeverityWeight(ThreatSeverity.Critical);
            
            return totalScore / maxScore;
        }
        
        private double GetSeverityWeight(ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Critical => 1.0,
                ThreatSeverity.High => 0.8,
                ThreatSeverity.Medium => 0.5,
                ThreatSeverity.Low => 0.3,
                ThreatSeverity.Info => 0.1,
                _ => 0.1
            };
        }
        
        private List<string> GenerateRecommendations(
            List<DetectedPattern> patterns, 
            List<ThreatCluster> clusters)
        {
            var recommendations = new List<string>();
            
            if (patterns.Any(p => p.Severity >= ThreatSeverity.High))
            {
                recommendations.Add("Investigar inmediatamente");
                recommendations.Add("Aislar dispositivo afectado");
                recommendations.Add("Notificar al equipo SOC");
            }
            
            if (clusters.Any(c => c.ThreatScore > 70))
            {
                recommendations.Add("Actualizar reglas de correlación");
                recommendations.Add("Revisar políticas de seguridad");
                recommendations.Add("Realizar análisis forense");
            }
            
            if (patterns.Count >= 3)
            {
                recommendations.Add("Buscar actividad relacionada en otros dispositivos");
                recommendations.Add("Revisar logs de autenticación");
                recommendations.Add("Verificar integridad de sistemas");
            }
            
            return recommendations.Distinct().ToList();
        }
        
        private async Task StoreCorrelationResultAsync(CorrelationResult result)
        {
            try
            {
                await _graphDatabase.StoreCorrelationResultAsync(result);
                
                // Mantener límite de resultados almacenados
                await CleanupOldResultsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error almacenando resultado de correlación");
            }
        }
        
        private async Task CleanupOldResultsAsync()
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-30);
                await _graphDatabase.DeleteOldResultsAsync(cutoffDate);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error limpiando resultados antiguos");
            }
        }
        
        private void ScheduleMaintenance()
        {
            // Programar mantenimiento cada 6 horas
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromHours(6));
                    await PerformMaintenanceAsync();
                }
            });
        }
        
        private async Task PerformMaintenanceAsync()
        {
            try
            {
                _logger.LogInformation("Iniciando mantenimiento del grafo...");
                
                // 1. Optimizar índices
                await _graphDatabase.OptimizeIndicesAsync();
                
                // 2. Limpiar nodos desconectados
                await _graphDatabase.CleanupDisconnectedNodesAsync();
                
                // 3. Compactar base de datos
                await _graphDatabase.CompactAsync();
                
                // 4. Actualizar estadísticas
                _lastGraphUpdate = DateTime.UtcNow;
                
                _logger.LogInformation("Mantenimiento del grafo completado");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en mantenimiento del grafo");
            }
        }
        
        private GraphMemoryUsage GetMemoryUsage()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            
            return new GraphMemoryUsage
            {
                WorkingSet = process.WorkingSet64,
                PrivateBytes = process.PrivateMemorySize64,
                VirtualMemory = process.VirtualMemorySize64,
                GraphNodesInMemory = _graphDatabase.GetInMemoryNodeCount(),
                GraphEdgesInMemory = _graphDatabase.GetInMemoryEdgeCount()
            };
        }
        
        private QueueStatistics GetQueueStatistics()
        {
            return new QueueStatistics
            {
                ProcessingQueueSize = 0, // Implementar si se usa cola
                AverageProcessingTime = TimeSpan.Zero,
                MaxQueueSize = 1000,
                CurrentLoad = 0.5 // Ejemplo
            };
        }
        
        private bool ValidateCorrelationRule(CorrelationRule rule)
        {
            if (string.IsNullOrEmpty(rule.RuleId) || 
                string.IsNullOrEmpty(rule.Name) || 
                rule.Conditions == null || 
                rule.Conditions.Count == 0)
            {
                return false;
            }
            
            // Validar condiciones
            foreach (var condition in rule.Conditions)
            {
                if (string.IsNullOrEmpty(condition.Field) || 
                    string.IsNullOrEmpty(condition.Operator))
                {
                    return false;
                }
            }
            
            return true;
        }
        
        private async Task ReindexDetectionPatternsAsync()
        {
            try
            {
                _logger.LogInformation("Re-indexando patrones de detección...");
                
                // Recalcular índices para búsqueda más rápida
                await _graphDatabase.ReindexPatternsAsync(_detectionPatterns);
                
                _logger.LogInformation("Patrones re-indexados exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error re-indexando patrones");
            }
        }
        
        #endregion
        
        #region Métodos auxiliares para visualización
        
        private double CalculateNodeSize(GraphNode node)
        {
            // Tamaño basado en importancia del nodo
            var baseSize = 20.0;
            
            if (node.Type == "PROCESS") return baseSize * 1.5;
            if (node.Type == "FILE") return baseSize * 1.2;
            if (node.Type == "NETWORK") return baseSize * 1.3;
            
            return baseSize;
        }
        
        private string GetNodeColor(string nodeType)
        {
            return nodeType switch
            {
                "PROCESS" => "#FF6B6B", // Rojo
                "FILE" => "#4ECDC4",    // Turquesa
                "NETWORK" => "#45B7D1", // Azul
                "REGISTRY" => "#96CEB4", // Verde
                _ => "#FFEAA7"          // Amarillo
            };
        }
        
        private async Task<List<ThreatClusterVisualization>> IdentifyVisualClustersAsync(
            List<GraphNode> nodes, List<GraphEdge> edges)
        {
            var clusters = new List<ThreatClusterVisualization>();
            
            // Algoritmo simple de detección de comunidades
            var visited = new HashSet<string>();
            
            foreach (var node in nodes)
            {
                if (!visited.Contains(node.Id))
                {
                    var clusterNodes = new List<GraphNode>();
                    var clusterEdges = new List<GraphEdge>();
                    
                    // BFS para encontrar componentes conectados
                    await FindConnectedComponentAsync(node, nodes, edges, 
                        visited, clusterNodes, clusterEdges);
                    
                    if (clusterNodes.Count >= 3) // Mínimo 3 nodos para cluster
                    {
                        clusters.Add(new ThreatClusterVisualization
                        {
                            ClusterId = $"cluster_{clusters.Count + 1}",
                            Nodes = clusterNodes,
                            Edges = clusterEdges,
                            Center = CalculateClusterCenter(clusterNodes),
                            Radius = CalculateClusterRadius(clusterNodes),
                            ThreatLevel = CalculateClusterThreatLevel(clusterNodes)
                        });
                    }
                }
            }
            
            return clusters;
        }
        
        private async Task FindConnectedComponentAsync(
            GraphNode startNode,
            List<GraphNode> allNodes,
            List<GraphEdge> allEdges,
            HashSet<string> visited,
            List<GraphNode> componentNodes,
            List<GraphEdge> componentEdges)
        {
            var queue = new Queue<GraphNode>();
            queue.Enqueue(startNode);
            visited.Add(startNode.Id);
            
            while (queue.Count > 0)
            {
                var currentNode = queue.Dequeue();
                componentNodes.Add(currentNode);
                
                // Encontrar aristas conectadas
                var connectedEdges = allEdges
                    .Where(e => e.Source == currentNode.Id || e.Target == currentNode.Id)
                    .ToList();
                
                componentEdges.AddRange(connectedEdges);
                
                // Encontrar nodos vecinos
                foreach (var edge in connectedEdges)
                {
                    var neighborId = edge.Source == currentNode.Id ? edge.Target : edge.Source;
                    var neighbor = allNodes.FirstOrDefault(n => n.Id == neighborId);
                    
                    if (neighbor != null && !visited.Contains(neighbor.Id))
                    {
                        visited.Add(neighbor.Id);
                        queue.Enqueue(neighbor);
                    }
                }
            }
        }
        
        private (double X, double Y) CalculateClusterCenter(List<GraphNode> nodes)
        {
            if (nodes.Count == 0) return (0, 0);
            
            var sumX = nodes.Sum(n => n.Properties.ContainsKey("X") ? 
                Convert.ToDouble(n.Properties["X"]) : 0);
            var sumY = nodes.Sum(n => n.Properties.ContainsKey("Y") ? 
                Convert.ToDouble(n.Properties["Y"]) : 0);
            
            return (sumX / nodes.Count, sumY / nodes.Count);
        }
        
        private double CalculateClusterRadius(List<GraphNode> nodes)
        {
            if (nodes.Count <= 1) return 0;
            
            var center = CalculateClusterCenter(nodes);
            var maxDistance = 0.0;
            
            foreach (var node in nodes)
            {
                var nodeX = node.Properties.ContainsKey("X") ? 
                    Convert.ToDouble(node.Properties["X"]) : 0;
                var nodeY = node.Properties.ContainsKey("Y") ? 
                    Convert.ToDouble(node.Properties["Y"]) : 0;
                
                var distance = Math.Sqrt(
                    Math.Pow(nodeX - center.X, 2) + 
                    Math.Pow(nodeY - center.Y, 2));
                
                maxDistance = Math.Max(maxDistance, distance);
            }
            
            return maxDistance * 1.2; // 20% de margen
        }
        
        private double CalculateClusterThreatLevel(List<GraphNode> nodes)
        {
            var threatCount = nodes.Count(n => 
                n.Properties.ContainsKey("ThreatScore") && 
                Convert.ToDouble(n.Properties["ThreatScore"]) > 0.5);
            
            return (double)threatCount / nodes.Count;
        }
        
        private async Task<GraphLayout> CalculateGraphLayoutAsync(
            List<GraphNode> nodes, List<GraphEdge> edges)
        {
            // Implementación simple de layout de fuerza dirigida
            var layout = new GraphLayout
            {
                Type = "ForceDirected",
                Iterations = 100,
                RepulsionStrength = 200,
                AttractionStrength = 0.1
            };
            
            // Asignar posiciones iniciales aleatorias
            var random = new Random();
            foreach (var node in nodes)
            {
                if (!node.Properties.ContainsKey("X"))
                {
                    node.Properties["X"] = random.NextDouble() * 800;
                }
                if (!node.Properties.ContainsKey("Y"))
                {
                    node.Properties["Y"] = random.NextDouble() * 600;
                }
            }
            
            // Aplicar algoritmo de fuerza dirigida (simplificado)
            await ApplyForceDirectedLayoutAsync(nodes, edges, layout);
            
            return layout;
        }
        
        private async Task ApplyForceDirectedLayoutAsync(
            List<GraphNode> nodes, 
            List<GraphEdge> edges, 
            GraphLayout layout)
        {
            // Implementación simplificada
            // En producción usar biblioteca especializada como GraphViz, Gephi, etc.
            
            for (int i = 0; i < layout.Iterations; i++)
            {
                await Task.Delay(1); // Simular procesamiento asíncrono
                
                // Calcular fuerzas de repulsión
                foreach (var node1 in nodes)
                {
                    foreach (var node2 in nodes)
                    {
                        if (node1.Id != node2.Id)
                        {
                            // Fuerza de repulsión
                            ApplyRepulsionForce(node1, node2, layout.RepulsionStrength);
                        }
                    }
                }
                
                // Calcular fuerzas de atracción
                foreach (var edge in edges)
                {
                    var sourceNode = nodes.FirstOrDefault(n => n.Id == edge.Source);
                    var targetNode = nodes.FirstOrDefault(n => n.Id == edge.Target);
                    
                    if (sourceNode != null && targetNode != null)
                    {
                        ApplyAttractionForce(sourceNode, targetNode, 
                            layout.AttractionStrength * edge.Weight);
                    }
                }
                
                // Aplicar desplazamientos
                ApplyDisplacements(nodes);
            }
        }
        
        private void ApplyRepulsionForce(GraphNode node1, GraphNode node2, double strength)
        {
            var x1 = Convert.ToDouble(node1.Properties["X"]);
            var y1 = Convert.ToDouble(node1.Properties["Y"]);
            var x2 = Convert.ToDouble(node2.Properties["X"]);
            var y2 = Convert.ToDouble(node2.Properties["Y"]);
            
            var dx = x2 - x1;
            var dy = y2 - y1;
            var distance = Math.Sqrt(dx * dx + dy * dy);
            
            if (distance > 0)
            {
                var force = strength / (distance * distance);
                
                if (!node1.Properties.ContainsKey("dx"))
                    node1.Properties["dx"] = 0.0;
                if (!node1.Properties.ContainsKey("dy"))
                    node1.Properties["dy"] = 0.0;
                
                node1.Properties["dx"] = Convert.ToDouble(node1.Properties["dx"]) - (dx / distance) * force;
                node1.Properties["dy"] = Convert.ToDouble(node1.Properties["dy"]) - (dy / distance) * force;
                
                if (!node2.Properties.ContainsKey("dx"))
                    node2.Properties["dx"] = 0.0;
                if (!node2.Properties.ContainsKey("dy"))
                    node2.Properties["dy"] = 0.0;
                
                node2.Properties["dx"] = Convert.ToDouble(node2.Properties["dx"]) + (dx / distance) * force;
                node2.Properties["dy"] = Convert.ToDouble(node2.Properties["dy"]) + (dy / distance) * force;
            }
        }
        
        private void ApplyAttractionForce(GraphNode source, GraphNode target, double strength)
        {
            var x1 = Convert.ToDouble(source.Properties["X"]);
            var y1 = Convert.ToDouble(source.Properties["Y"]);
            var x2 = Convert.ToDouble(target.Properties["X"]);
            var y2 = Convert.ToDouble(target.Properties["Y"]);
            
            var dx = x2 - x1;
            var dy = y2 - y1;
            var distance = Math.Sqrt(dx * dx + dy * dy);
            
            if (distance > 0)
            {
                var force = strength * distance;
                
                if (!source.Properties.ContainsKey("dx"))
                    source.Properties["dx"] = 0.0;
                if (!source.Properties.ContainsKey("dy"))
                    source.Properties["dy"] = 0.0;
                
                source.Properties["dx"] = Convert.ToDouble(source.Properties["dx"]) + (dx / distance) * force;
                source.Properties["dy"] = Convert.ToDouble(source.Properties["dy"]) + (dy / distance) * force;
                
                if (!target.Properties.ContainsKey("dx"))
                    target.Properties["dx"] = 0.0;
                if (!target.Properties.ContainsKey("dy"))
                    target.Properties["dy"] = 0.0;
                
                target.Properties["dx"] = Convert.ToDouble(target.Properties["dx"]) - (dx / distance) * force;
                target.Properties["dy"] = Convert.ToDouble(target.Properties["dy"]) - (dy / distance) * force;
            }
        }
        
        private void ApplyDisplacements(List<GraphNode> nodes)
        {
            foreach (var node in nodes)
            {
                if (node.Properties.ContainsKey("dx") && node.Properties.ContainsKey("dy"))
                {
                    var dx = Convert.ToDouble(node.Properties["dx"]);
                    var dy = Convert.ToDouble(node.Properties["dy"]);
                    
                    // Limitar desplazamiento máximo
                    var displacement = Math.Sqrt(dx * dx + dy * dy);
                    if (displacement > 10)
                    {
                        dx = (dx / displacement) * 10;
                        dy = (dy / displacement) * 10;
                    }
                    
                    // Aplicar desplazamiento
                    node.Properties["X"] = Convert.ToDouble(node.Properties["X"]) + dx;
                    node.Properties["Y"] = Convert.ToDouble(node.Properties["Y"]) + dy;
                    
                    // Resetear fuerzas
                    node.Properties["dx"] = 0.0;
                    node.Properties["dy"] = 0.0;
                }
            }
        }
        
        #endregion
    }
    
    #region Clases de datos para Graph Correlation
    
    public class CorrelationResult
    {
        public string CorrelationId { get; set; }
        public DateTime Timestamp { get; set; }
        public string DeviceId { get; set; }
        public int TotalEvents { get; set; }
        public List<DetectedPattern> DetectedPatterns { get; set; }
        public double CorrelationScore { get; set; }
        public List<ThreatCluster> ThreatClusters { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public List<string> Recommendations { get; set; }
        public string ErrorMessage { get; set; }
        
        public CorrelationResult()
        {
            DetectedPatterns = new List<DetectedPattern>();
            ThreatClusters = new List<ThreatCluster>();
            Recommendations = new List<string>();
        }
        
        public static CorrelationResult Empty()
        {
            return new CorrelationResult();
        }
        
        public static CorrelationResult Error(string errorMessage)
        {
            return new CorrelationResult
            {
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class DetectedPattern
    {
        public string PatternId { get; set; }
        public string PatternName { get; set; }
        public int MatchCount { get; set; }
        public double Confidence { get; set; }
        public ThreatSeverity Severity { get; set; }
        public List<GraphEvent> MatchedEvents { get; set; }
        public DateTime FirstDetected { get; set; }
        public DateTime LastDetected { get; set; }
        
        public DetectedPattern()
        {
            MatchedEvents = new List<GraphEvent>();
            LastDetected = DateTime.UtcNow;
        }
    }
    
    public class GraphEvent
    {
        public string EventId { get; set; }
        public string DeviceId { get; set; }
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
        public GraphNode Node { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public GraphEvent()
        {
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class GraphNode
    {
        public string Id { get; set; }
        public string Label { get; set; }
        public string Type { get; set; }
        public Dictionary<string, object> Properties { get; set; }
        
        public GraphNode()
        {
            Properties = new Dictionary<string, object>();
        }
    }
    
    public class GraphEdge
    {
        public string Id { get; set; }
        public string Source { get; set; }
        public string Target { get; set; }
        public string Label { get; set; }
        public string Type { get; set; }
        public double Weight { get; set; }
        public Dictionary<string, object> Properties { get; set; }
        
        public GraphEdge()
        {
            Properties = new Dictionary<string, object>();
        }
    }
    
    public class ThreatCluster
    {
        public string ClusterId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastUpdated { get; set; }
        public int MemberCount { get; set; }
        public double ThreatScore { get; set; }
        public List<string> RelatedCorrelations { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public ThreatCluster()
        {
            RelatedCorrelations = new List<string>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class CorrelationRule
    {
        public string RuleId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<CorrelationCondition> Conditions { get; set; }
        public double Weight { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        
        public CorrelationRule()
        {
            Conditions = new List<CorrelationCondition>();
            CreatedAt = DateTime.UtcNow;
            LastModified = DateTime.UtcNow;
        }
    }
    
    public class CorrelationCondition
    {
        public string Field { get; set; }
        public string Operator { get; set; }
        public string Value { get; set; }
    }
    
    public class DetectionPattern
    {
        public string PatternId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<string> Indicators { get; set; }
        public int Threshold { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        
        public DetectionPattern()
        {
            Indicators = new List<string>();
        }
    }
    
    public class EventCorrelation
    {
        public string CorrelationId { get; set; }
        public List<string> EventIds { get; set; }
        public string RuleId { get; set; }
        public double CorrelationScore { get; set; }
        public string PatternId { get; set; }
        public DateTime DetectedAt { get; set; }
        
        public EventCorrelation()
        {
            EventIds = new List<string>();
        }
    }
    
    public class CorrelatedAlert
    {
        public string AlertId { get; set; }
        public string CorrelationId { get; set; }
        public List<string> SourceAlertIds { get; set; }
        public string ThreatType { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public List<string> AffectedDevices { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        
        public CorrelatedAlert()
        {
            SourceAlertIds = new List<string>();
            AffectedDevices = new List<string>();
        }
    }
    
    public class ThreatDetection
    {
        public string DetectionId { get; set; }
        public string ThreatName { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public double SeverityScore { get; set; }
        public List<string> AffectedDevices { get; set; }
        public List<string> Indicators { get; set; }
        public DateTime FirstDetected { get; set; }
        public DateTime LastDetected { get; set; }
        
        public ThreatDetection()
        {
            AffectedDevices = new List<string>();
            Indicators = new List<string>();
        }
    }
    
    public class ThreatSearchQuery
    {
        public string DeviceId { get; set; }
        public TimeSpan? TimeRange { get; set; }
        public ThreatSeverity? MinSeverity { get; set; }
        public double? MinConfidence { get; set; }
        public List<string> ThreatTypes { get; set; }
        public List<string> Indicators { get; set; }
        public string PatternId { get; set; }
        public int? MaxResults { get; set; }
        
        public ThreatSearchQuery()
        {
            ThreatTypes = new List<string>();
            Indicators = new List<string>();
        }
    }
    
    public class GraphCorrelationStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsInitialized { get; set; }
        public long TotalNodes { get; set; }
        public long TotalEdges { get; set; }
        public int ActivePatterns { get; set; }
        public int ActiveClusters { get; set; }
        public int CorrelationRules { get; set; }
        public int DetectionPatterns { get; set; }
        public DateTime LastGraphUpdate { get; set; }
        public GraphMemoryUsage MemoryUsage { get; set; }
        public QueueStatistics ProcessingQueue { get; set; }
    }
    
    public class GraphMemoryUsage
    {
        public long WorkingSet { get; set; } // bytes
        public long PrivateBytes { get; set; } // bytes
        public long VirtualMemory { get; set; } // bytes
        public int GraphNodesInMemory { get; set; }
        public int GraphEdgesInMemory { get; set; }
    }
    
    public class QueueStatistics
    {
        public int ProcessingQueueSize { get; set; }
        public TimeSpan AverageProcessingTime { get; set; }
        public int MaxQueueSize { get; set; }
        public double CurrentLoad { get; set; } // 0.0 a 1.0
    }
    
    public class ThreatGraphVisualization
    {
        public DateTime Timestamp { get; set; }
        public List<GraphNode> Nodes { get; set; }
        public List<GraphEdge> Edges { get; set; }
        public List<ThreatClusterVisualization> Clusters { get; set; }
        public GraphLayout Layout { get; set; }
        
        public ThreatGraphVisualization()
        {
            Nodes = new List<GraphNode>();
            Edges = new List<GraphEdge>();
            Clusters = new List<ThreatClusterVisualization>();
        }
    }
    
    public class ThreatClusterVisualization
    {
        public string ClusterId { get; set; }
        public List<GraphNode> Nodes { get; set; }
        public List<GraphEdge> Edges { get; set; }
        public (double X, double Y) Center { get; set; }
        public double Radius { get; set; }
        public double ThreatLevel { get; set; }
        
        public ThreatClusterVisualization()
        {
            Nodes = new List<GraphNode>();
            Edges = new List<GraphEdge>();
        }
    }
    
    public class GraphLayout
    {
        public string Type { get; set; }
        public int Iterations { get; set; }
        public double RepulsionStrength { get; set; }
        public double AttractionStrength { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        
        public GraphLayout()
        {
            Parameters = new Dictionary<string, object>();
        }
    }
    
    public enum ThreatSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
    
    #endregion
}