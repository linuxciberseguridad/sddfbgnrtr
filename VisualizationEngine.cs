using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using QuickGraph;
using QuickGraph.Graphviz;
using QuickGraph.Graphviz.Dot;

namespace BWP.Enterprise.Cloud.ThreatGraph
{
    /// <summary>
    /// Motor de visualización de grafos de amenazas en tiempo real
    /// Genera representaciones visuales interactivas de relaciones entre entidades maliciosas
    /// Soporta múltiples formatos: DOT, JSON, PNG, SVG, y streaming WebSocket
    /// </summary>
    public sealed class VisualizationEngine : IDisposable
    {
        private static readonly Lazy<VisualizationEngine> _instance = 
            new Lazy<VisualizationEngine>(() => new VisualizationEngine());
        
        public static VisualizationEngine Instance => _instance.Value;

        // Cache de grafos renderizados
        private readonly IMemoryCache _graphCache;
        private readonly ConcurrentDictionary<string, ThreatGraphSession> _activeSessions;
        private readonly ConcurrentDictionary<string, GraphLayout> _layoutCache;
        private readonly ILogger<VisualizationEngine> _logger;
        
        // Configuración de renderizado
        private readonly VisualizationConfig _config;
        private readonly Timer _cleanupTimer;
        private readonly SemaphoreSlim _renderSemaphore;
        private readonly Random _random;
        
        // Estadísticas
        private long _totalGraphsRendered;
        private long _totalLayoutsComputed;
        private long _totalCacheHits;
        private long _totalCacheMisses;

        private VisualizationEngine()
        {
            _graphCache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = 1024 * 1024 * 512, // 512MB
                ExpirationScanFrequency = TimeSpan.FromMinutes(5),
                CompactionPercentage = 0.25
            });

            _activeSessions = new ConcurrentDictionary<string, ThreatGraphSession>();
            _layoutCache = new ConcurrentDictionary<string, GraphLayout>();
            _renderSemaphore = new SemaphoreSlim(Environment.ProcessorCount, Environment.ProcessorCount);
            _random = new Random(Guid.NewGuid().GetHashCode());
            
            _config = LoadConfiguration();
            
            // Timer de limpieza cada 5 minutos
            _cleanupTimer = new Timer(CleanupCallback, null, 
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
            
            // Inicializar logger
            _logger = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.AddEventLog();
                builder.AddJsonConsole();
            }).CreateLogger<VisualizationEngine>();
            
            _logger.LogInformation("VisualizationEngine initialized with {MaxDegree} parallelism", 
                Environment.ProcessorCount);
        }

        /// <summary>
        /// Genera un grafo de amenazas completo para un tenant
        /// </summary>
        public async Task<ThreatGraphResult> GenerateTenantGraphAsync(
            string tenantId,
            GraphGenerationOptions options,
            CancellationToken cancellationToken = default)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var cacheKey = $"tenant_graph_{tenantId}_{options.TimeRange}_{options.MaxNodes}_{options.IncludeIsolated}";

            // Intentar obtener del cache
            if (options.UseCache && _graphCache.TryGetValue(cacheKey, out ThreatGraphResult cached))
            {
                Interlocked.Increment(ref _totalCacheHits);
                _logger.LogDebug("Cache hit for tenant graph: {TenantId}", tenantId);
                return cached;
            }

            Interlocked.Increment(ref _totalCacheMisses);
            
            await _renderSemaphore.WaitAsync(cancellationToken);
            try
            {
                // 1. Obtener datos del ThreatGraphIngestionEngine
                var threatGraph = ThreatGraphIngestionEngine.Instance;
                
                // 2. Construir grafo dirigido
                var graph = new BidirectionalGraph<GraphNode, GraphEdge>();
                
                // 3. Obtener todos los nodos del tenant
                var tenantNodes = await threatGraph.GetTenantNodesAsync(tenantId, options.TimeRange);
                
                // 4. Filtrar y limitar nodos
                var filteredNodes = tenantNodes
                    .Where(n => options.IncludeIsolated || n.EdgeCount > 0)
                    .OrderByDescending(n => n.RiskScore)
                    .Take(options.MaxNodes)
                    .ToList();

                foreach (var node in filteredNodes)
                {
                    graph.AddVertex(node);
                }

                // 5. Obtener y agregar aristas
                foreach (var node in filteredNodes)
                {
                    var edges = await threatGraph.GetNodeEdgesAsync(node.Id, options.TimeRange);
                    foreach (var edge in edges.Where(e => 
                        filteredNodes.Any(n => n.Id == e.SourceId) && 
                        filteredNodes.Any(n => n.Id == e.TargetId)))
                    {
                        if (!graph.ContainsEdge(edge.SourceId, edge.TargetId))
                        {
                            graph.AddEdge(edge);
                        }
                    }
                }

                // 6. Calcular layout
                var layout = await ComputeLayoutAsync(graph, options.LayoutAlgorithm, cancellationToken);
                
                // 7. Generar representaciones
                var dotRepresentation = GenerateDotGraph(graph, layout, options);
                var jsonRepresentation = GenerateJsonGraph(graph, layout);
                var svgRepresentation = options.GenerateSvg ? 
                    await ConvertDotToSvgAsync(dotRepresentation) : null;
                
                // 8. Enriquecer con metadata
                var result = new ThreatGraphResult
                {
                    TenantId = tenantId,
                    GeneratedAt = DateTime.UtcNow,
                    Graph = graph,
                    Layout = layout,
                    DotGraph = dotRepresentation,
                    JsonGraph = jsonRepresentation,
                    SvgGraph = svgRepresentation,
                    Statistics = new GraphStatistics
                    {
                        NodeCount = graph.VertexCount,
                        EdgeCount = graph.EdgeCount,
                        IsolatedNodes = graph.Vertices.Count(v => v.EdgeCount == 0),
                        HighRiskNodes = graph.Vertices.Count(v => v.RiskScore >= 80),
                        MediumRiskNodes = graph.Vertices.Count(v => v.RiskScore >= 50 && v.RiskScore < 80),
                        LowRiskNodes = graph.Vertices.Count(v => v.RiskScore < 50),
                        AverageDegree = graph.EdgeCount / (double)Math.Max(1, graph.VertexCount),
                        GenerationTimeMs = sw.ElapsedMilliseconds,
                        CacheKey = cacheKey
                    }
                };

                // 9. Cachear resultado
                if (options.CacheDuration > TimeSpan.Zero)
                {
                    var cacheEntryOptions = new MemoryCacheEntryOptions()
                        .SetSize(EstimateGraphSize(result))
                        .SetAbsoluteExpiration(options.CacheDuration)
                        .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                        .RegisterPostEvictionCallback((key, value, reason, state) =>
                        {
                            _logger.LogDebug("Graph evicted from cache: {Key}, Reason: {Reason}", 
                                key, reason);
                        });

                    _graphCache.Set(cacheKey, result, cacheEntryOptions);
                }

                Interlocked.Increment(ref _totalGraphsRendered);
                
                _logger.LogInformation(
                    "Tenant graph generated for {TenantId} in {ElapsedMs}ms. " +
                    "Nodes: {Nodes}, Edges: {Edges}, Cache: {CacheKey}", 
                    tenantId, sw.ElapsedMilliseconds, graph.VertexCount, graph.EdgeCount, cacheKey);

                return result;
            }
            finally
            {
                _renderSemaphore.Release();
            }
        }

        /// <summary>
        /// Genera grafo de ataque específico para un incidente
        /// </summary>
        public async Task<AttackGraphResult> GenerateAttackGraphAsync(
            string incidentId,
            AttackGraphOptions options,
            CancellationToken cancellationToken = default)
        {
            var incidentManager = IncidentManager.Instance;
            var incident = await incidentManager.GetIncidentAsync(incidentId);
            
            if (incident == null)
                throw new ArgumentException($"Incident not found: {incidentId}");

            // Construir grafo de ataque (árbol)
            var attackGraph = new AttackGraph
            {
                IncidentId = incidentId,
                RootNode = new AttackNode
                {
                    Id = incidentId,
                    Type = AttackNodeType.Incident,
                    Label = incident.Title,
                    Severity = incident.Severity,
                    Timestamp = incident.DetectedAt,
                    RiskScore = incident.RiskScore,
                    IsRoot = true
                }
            };

            // Agregar técnicas MITRE ATT&CK
            foreach (var technique in incident.MitreTechniques)
            {
                var techniqueNode = new AttackNode
                {
                    Id = technique.Id,
                    Type = AttackNodeType.Technique,
                    Label = technique.Name,
                    Tactic = technique.Tactic,
                    Platform = technique.Platform,
                    ParentId = incidentId
                };
                
                attackGraph.AddNode(techniqueNode);
                attackGraph.AddEdge(incidentId, technique.Id, 
                    new AttackEdge { Type = EdgeType.Uses });
            }

            // Agregar indicadores de compromiso (IOCs)
            foreach (var indicator in incident.IOCs)
            {
                var indicatorNode = new AttackNode
                {
                    Id = indicator.Id,
                    Type = AttackNodeType.Indicator,
                    Label = indicator.Value,
                    IndicatorType = indicator.Type,
                    Confidence = indicator.Confidence,
                    ParentId = incidentId
                };
                
                attackGraph.AddNode(indicatorNode);
                attackGraph.AddEdge(incidentId, indicator.Id, 
                    new AttackEdge { Type = EdgeType.Indicates });
            }

            // Agregar dispositivos afectados
            foreach (var device in incident.AffectedDevices)
            {
                var deviceNode = new AttackNode
                {
                    Id = device.DeviceId,
                    Type = AttackNodeType.Device,
                    Label = device.Hostname,
                    IpAddress = device.IpAddress,
                    OsVersion = device.OsVersion,
                    CompromisedAt = device.FirstSeen,
                    ParentId = incidentId
                };
                
                attackGraph.AddNode(deviceNode);
                attackGraph.AddEdge(incidentId, device.DeviceId, 
                    new AttackEdge { Type = EdgeType.Affects });
                
                // Agregar procesos maliciosos en el dispositivo
                foreach (var process in device.MaliciousProcesses)
                {
                    var processNode = new AttackNode
                    {
                        Id = process.ProcessId,
                        Type = AttackNodeType.Process,
                        Label = process.Name,
                        Path = process.ImagePath,
                        CommandLine = process.CommandLine,
                        User = process.UserName,
                        ParentId = device.DeviceId
                    };
                    
                    attackGraph.AddNode(processNode);
                    attackGraph.AddEdge(device.DeviceId, process.ProcessId, 
                        new AttackEdge { Type = EdgeType.Executes });
                }
            }

            // Calcular layout jerárquico
            var layout = await ComputeHierarchicalLayoutAsync(attackGraph, cancellationToken);
            
            return new AttackGraphResult
            {
                IncidentId = incidentId,
                GeneratedAt = DateTime.UtcNow,
                Graph = attackGraph,
                Layout = layout,
                DotGraph = GenerateAttackGraphDot(attackGraph, layout),
                JsonGraph = GenerateAttackGraphJson(attackGraph, layout)
            };
        }

        /// <summary>
        /// Calcula layout óptimo para visualización de grafos
        /// </summary>
        private async Task<GraphLayout> ComputeLayoutAsync<TVertex, TEdge>(
            IBidirectionalGraph<TVertex, TEdge> graph,
            LayoutAlgorithm algorithm,
            CancellationToken cancellationToken)
            where TVertex : GraphNode
            where TEdge : GraphEdge
        {
            var cacheKey = $"layout_{algorithm}_{graph.VertexCount}_{graph.EdgeCount}_{graph.GetHashCode()}";
            
            if (_layoutCache.TryGetValue(cacheKey, out GraphLayout cachedLayout))
            {
                Interlocked.Increment(ref _totalCacheHits);
                return cachedLayout;
            }

            return await Task.Run(() =>
            {
                var layout = new GraphLayout();
                
                switch (algorithm)
                {
                    case LayoutAlgorithm.KamadaKawai:
                        layout = ComputeKamadaKawaiLayout(graph);
                        break;
                        
                    case LayoutAlgorithm.FruchtermanReingold:
                        layout = ComputeFruchtermanReingoldLayout(graph);
                        break;
                        
                    case LayoutAlgorithm.Sugiyama:
                        layout = ComputeSugiyamaLayout(graph);
                        break;
                        
                    case LayoutAlgorithm.Circular:
                        layout = ComputeCircularLayout(graph);
                        break;
                        
                    case LayoutAlgorithm.Tree:
                        layout = ComputeTreeLayout(graph);
                        break;
                        
                    case LayoutAlgorithm.ForceDirected3D:
                        layout = ComputeForceDirected3DLayout(graph);
                        break;
                        
                    default:
                        layout = ComputeFruchtermanReingoldLayout(graph);
                        break;
                }

                // Cachear layout por 1 hora
                _layoutCache.TryAdd(cacheKey, layout, TimeSpan.FromHours(1));
                Interlocked.Increment(ref _totalLayoutsComputed);
                
                return layout;
            }, cancellationToken);
        }

        /// <summary>
        /// Algoritmo Force-Directed 3D para visualización inmersiva
        /// </summary>
        private GraphLayout ComputeForceDirected3DLayout<TVertex, TEdge>(
            IBidirectionalGraph<TVertex, TEdge> graph)
            where TVertex : GraphNode
            where TEdge : GraphEdge
        {
            var layout = new GraphLayout { Algorithm = "ForceDirected3D" };
            var positions = new ConcurrentDictionary<string, Point3D>();
            var velocities = new ConcurrentDictionary<string, Vector3D>();
            
            // Parámetros físicos
            const float k = 2.0f; // Constante de resorte
            const float repulsion = 1000.0f;
            const float attraction = 0.1f;
            const float damping = 0.85f;
            const int iterations = 100;
            
            // Inicializar posiciones aleatorias en esfera
            foreach (var vertex in graph.Vertices)
            {
                var theta = 2 * Math.PI * _random.NextDouble();
                var phi = Math.Acos(2 * _random.NextDouble() - 1);
                var r = 10 * _random.NextDouble();
                
                positions[vertex.Id] = new Point3D
                {
                    X = (float)(r * Math.Sin(phi) * Math.Cos(theta)),
                    Y = (float)(r * Math.Sin(phi) * Math.Sin(theta)),
                    Z = (float)(r * Math.Cos(phi))
                };
                
                velocities[vertex.Id] = new Vector3D();
            }

            // Iteraciones de relajación
            for (int iter = 0; iter < iterations; iter++)
            {
                Parallel.ForEach(graph.Vertices, vertex =>
                {
                    var pos = positions[vertex.Id];
                    var force = new Vector3D();

                    // Repulsión entre todos los nodos
                    foreach (var other in graph.Vertices)
                    {
                        if (other.Id == vertex.Id) continue;
                        
                        var otherPos = positions[other.Id];
                        var delta = new Vector3D
                        {
                            X = pos.X - otherPos.X,
                            Y = pos.Y - otherPos.Y,
                            Z = pos.Z - otherPos.Z
                        };

                        var distance = (float)Math.Sqrt(
                            delta.X * delta.X + 
                            delta.Y * delta.Y + 
                            delta.Z * delta.Z);
                        
                        if (distance > 0)
                        {
                            var repulsionForce = repulsion / (distance * distance);
                            force.X += delta.X / distance * repulsionForce;
                            force.Y += delta.Y / distance * repulsionForce;
                            force.Z += delta.Z / distance * repulsionForce;
                        }
                    }

                    // Atracción para aristas
                    foreach (var edge in graph.OutEdges(vertex))
                    {
                        var targetPos = positions[edge.TargetId];
                        var delta = new Vector3D
                        {
                            X = targetPos.X - pos.X,
                            Y = targetPos.Y - pos.Y,
                            Z = targetPos.Z - pos.Z
                        };

                        var distance = (float)Math.Sqrt(
                            delta.X * delta.X + 
                            delta.Y * delta.Y + 
                            delta.Z * delta.Z);

                        if (distance > 0)
                        {
                            var attractionForce = distance / k * attraction;
                            force.X += delta.X / distance * attractionForce;
                            force.Y += delta.Y / distance * attractionForce;
                            force.Z += delta.Z / distance * attractionForce;
                        }
                    }

                    foreach (var edge in graph.InEdges(vertex))
                    {
                        var sourcePos = positions[edge.SourceId];
                        var delta = new Vector3D
                        {
                            X = sourcePos.X - pos.X,
                            Y = sourcePos.Y - pos.Y,
                            Z = sourcePos.Z - pos.Z
                        };

                        var distance = (float)Math.Sqrt(
                            delta.X * delta.X + 
                            delta.Y * delta.Y + 
                            delta.Z * delta.Z);

                        if (distance > 0)
                        {
                            var attractionForce = distance / k * attraction;
                            force.X += delta.X / distance * attractionForce;
                            force.Y += delta.Y / distance * attractionForce;
                            force.Z += delta.Z / distance * attractionForce;
                        }
                    }

                    // Actualizar velocidad y posición
                    var vel = velocities[vertex.Id];
                    vel.X = (vel.X + force.X) * damping;
                    vel.Y = (vel.Y + force.Y) * damping;
                    vel.Z = (vel.Z + force.Z) * damping;
                    
                    velocities[vertex.Id] = vel;
                    
                    pos.X += vel.X;
                    pos.Y += vel.Y;
                    pos.Z += vel.Z;
                    
                    positions[vertex.Id] = pos;
                });
            }

            // Normalizar posiciones y construir resultado
            float minX = positions.Values.Min(p => p.X);
            float maxX = positions.Values.Max(p => p.X);
            float minY = positions.Values.Min(p => p.Y);
            float maxY = positions.Values.Max(p => p.Y);
            float minZ = positions.Values.Min(p => p.Z);
            float maxZ = positions.Values.Max(p => p.Z);

            foreach (var kvp in positions)
            {
                layout.Positions[kvp.Key] = new Point3D
                {
                    X = (kvp.Value.X - minX) / (maxX - minX) * 1000 - 500,
                    Y = (kvp.Value.Y - minY) / (maxY - minY) * 1000 - 500,
                    Z = (kvp.Value.Z - minZ) / (maxZ - minZ) * 1000 - 500
                };
            }

            return layout;
        }

        /// <summary>
        /// Genera representación DOT para Graphviz
        /// </summary>
        private string GenerateDotGraph<TVertex, TEdge>(
            IBidirectionalGraph<TVertex, TEdge> graph,
            GraphLayout layout,
            GraphGenerationOptions options)
            where TVertex : GraphNode
            where TEdge : GraphEdge
        {
            var dot = new StringBuilder();
            
            dot.AppendLine("digraph ThreatGraph {");
            dot.AppendLine("  graph [");
            dot.AppendLine("    splines=polyline,");
            dot.AppendLine("    overlap=false,");
            dot.AppendLine("    rankdir=TB,");
            dot.AppendLine("    fontname=\"Segoe UI\",");
            dot.AppendLine($"    label=\"Threat Graph - {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\",");
            dot.AppendLine("    labelloc=t,");
            dot.AppendLine("    fontsize=16");
            dot.AppendLine("  ];");
            
            dot.AppendLine("  node [");
            dot.AppendLine("    shape=box,");
            dot.AppendLine("    style=\"rounded,filled\",");
            dot.AppendLine("    fontname=\"Segoe UI\",");
            dot.AppendLine("    fontsize=10");
            dot.AppendLine("  ];");
            
            dot.AppendLine("  edge [");
            dot.AppendLine("    fontname=\"Segoe UI\",");
            dot.AppendLine("    fontsize=8,");
            dot.AppendLine("    arrowsize=0.7");
            dot.AppendLine("  ];");

            // Agregar nodos
            foreach (var vertex in graph.Vertices)
            {
                string color = vertex.RiskScore switch
                {
                    >= 80 => "crimson",
                    >= 50 => "goldenrod1",
                    >= 20 => "palegreen3",
                    _ => "lightsteelblue1"
                };

                string shape = vertex.Type switch
                {
                    NodeType.Device => "box3d",
                    NodeType.Process => "ellipse",
                    NodeType.File => "note",
                    NodeType.Network => "cylinder",
                    NodeType.Registry => "component",
                    NodeType.User => "house",
                    _ => "box"
                };

                dot.AppendLine($"  \"{EscapeDotString(vertex.Id)}\" [");
                dot.AppendLine($"    label=\"{EscapeDotString(vertex.Label)}\",");
                
                if (layout.Positions.TryGetValue(vertex.Id, out var pos))
                {
                    dot.AppendLine($"    pos=\"{pos.X},{pos.Y}!\",");
                }
                
                dot.AppendLine($"    fillcolor=\"{color}\",");
                dot.AppendLine($"    shape={shape},");
                dot.AppendLine($"    tooltip=\"{EscapeDotString(vertex.Description)}\"");
                dot.AppendLine("  ];");
            }

            // Agregar aristas
            foreach (var edge in graph.Edges)
            {
                string color = edge.RiskScore switch
                {
                    >= 80 => "crimson",
                    >= 50 => "darkorange",
                    _ => "gray40"
                };

                string style = edge.IsAnomalous ? "bold" : "solid";
                
                dot.AppendLine($"  \"{EscapeDotString(edge.SourceId)}\" -> \"{EscapeDotString(edge.TargetId)}\" [");
                dot.AppendLine($"    color=\"{color}\",");
                dot.AppendLine($"    style={style},");
                dot.AppendLine($"    penwidth={Math.Max(1, edge.Weight / 10)},");
                dot.AppendLine($"    label=\"{EscapeDotString(edge.Label)}\",");
                dot.AppendLine($"    tooltip=\"{EscapeDotString(edge.Description)}\"");
                dot.AppendLine("  ];");
            }

            dot.AppendLine("}");
            
            return dot.ToString();
        }

        /// <summary>
        /// Genera representación JSON para clientes web
        /// </summary>
        private string GenerateJsonGraph<TVertex, TEdge>(
            IBidirectionalGraph<TVertex, TEdge> graph,
            GraphLayout layout)
            where TVertex : GraphNode
            where TEdge : GraphEdge
        {
            var nodes = graph.Vertices.Select(v => new
            {
                id = v.Id,
                label = v.Label,
                type = v.Type.ToString(),
                riskScore = v.RiskScore,
                severity = v.Severity.ToString(),
                timestamp = v.Timestamp,
                description = v.Description,
                position = layout.Positions.TryGetValue(v.Id, out var pos) 
                    ? new { x = pos.X, y = pos.Y, z = pos.Z } 
                    : null,
                metadata = v.Metadata
            });

            var edges = graph.Edges.Select(e => new
            {
                source = e.SourceId,
                target = e.TargetId,
                type = e.Type.ToString(),
                label = e.Label,
                riskScore = e.RiskScore,
                weight = e.Weight,
                isAnomalous = e.IsAnomalous,
                timestamp = e.Timestamp,
                metadata = e.Metadata
            });

            var result = new
            {
                version = "2.0",
                generatedAt = DateTime.UtcNow,
                stats = new
                {
                    nodeCount = graph.VertexCount,
                    edgeCount = graph.EdgeCount,
                    minRisk = graph.Vertices.Min(v => v.RiskScore),
                    maxRisk = graph.Vertices.Max(v => v.RiskScore),
                    avgRisk = graph.Vertices.Average(v => v.RiskScore)
                },
                layout = new
                {
                    algorithm = layout.Algorithm,
                    bounds = new
                    {
                        minX = layout.Positions.Values.Min(p => p.X),
                        maxX = layout.Positions.Values.Max(p => p.X),
                        minY = layout.Positions.Values.Min(p => p.Y),
                        maxY = layout.Positions.Values.Max(p => p.Y),
                        minZ = layout.Positions.Values.Min(p => p.Z),
                        maxZ = layout.Positions.Values.Max(p => p.Z)
                    }
                },
                nodes = nodes,
                edges = edges
            };

            return JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
        }

        /// <summary>
        /// Convierte DOT a SVG usando Graphviz
        /// </summary>
        private async Task<string> ConvertDotToSvgAsync(string dotGraph)
        {
            // En producción, usar Graphviz nativo o biblioteca como Graphviz.NET
            // Este es un wrapper simplificado
            var tempFile = Path.GetTempFileName();
            var svgFile = Path.ChangeExtension(tempFile, "svg");
            
            try
            {
                await File.WriteAllTextAsync(tempFile, dotGraph, Encoding.UTF8);
                
                // Llamar a dot.exe (Graphviz)
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "dot",
                        Arguments = $"-Tsvg -O \"{tempFile}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    _logger.LogError("Graphviz error: {Error}", error);
                    return GenerateFallbackSvg(dotGraph);
                }

                if (File.Exists(svgFile))
                {
                    return await File.ReadAllTextAsync(svgFile);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to convert DOT to SVG");
                return GenerateFallbackSvg(dotGraph);
            }
            finally
            {
                try
                {
                    File.Delete(tempFile);
                    if (File.Exists(svgFile)) File.Delete(svgFile);
                }
                catch { }
            }

            return GenerateFallbackSvg(dotGraph);
        }

        /// <summary>
        /// Genera SVG de respaldo cuando Graphviz no está disponible
        /// </summary>
        private string GenerateFallbackSvg(string dotGraph)
        {
            // Generar SVG minimalista con el grafo en texto
            var svg = new StringBuilder();
            
            svg.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            svg.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\"");
            svg.AppendLine("     width=\"800\" height=\"600\"");
            svg.AppendLine("     viewBox=\"0 0 800 600\">");
            
            svg.AppendLine("  <rect width=\"800\" height=\"600\" fill=\"#f5f5f5\"/>");
            svg.AppendLine("  <text x=\"50\" y=\"50\" font-family=\"Segoe UI\" font-size=\"16\" fill=\"#333\">");
            svg.AppendLine("    Graph visualization requires Graphviz");
            svg.AppendLine("  </text>");
            svg.AppendLine("  <text x=\"50\" y=\"80\" font-family=\"Segoe UI\" font-size=\"14\" fill=\"#666\">");
            svg.AppendLine("    Install Graphviz from: https://graphviz.org/download/");
            svg.AppendLine("  </text>");
            svg.AppendLine("  <text x=\"50\" y=\"120\" font-family=\"Segoe UI\" font-size=\"12\" fill=\"#999\">");
            svg.AppendLine($"    DOT representation ({dotGraph.Length} bytes) is available in the JSON output");
            svg.AppendLine("  </text>");
            
            svg.AppendLine("</svg>");
            
            return svg.ToString();
        }

        /// <summary>
        /// Transmite actualizaciones de grafo en tiempo real vía WebSocket
        /// </summary>
        public async Task StreamGraphUpdatesAsync(
            string tenantId,
            string sessionId,
            System.Net.WebSockets.WebSocket webSocket,
            CancellationToken cancellationToken)
        {
            var session = new ThreatGraphSession
            {
                SessionId = sessionId,
                TenantId = tenantId,
                WebSocket = webSocket,
                CreatedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                SubscriptionFilters = new GraphSubscriptionFilters()
            };

            _activeSessions[sessionId] = session;

            try
            {
                var ingestionEngine = ThreatGraphIngestionEngine.Instance;
                var buffer = new byte[4096];
                
                // Suscribirse a actualizaciones en tiempo real
                using var subscription = ingestionEngine.SubscribeToUpdates(async update =>
                {
                    if (update.TenantId == tenantId)
                    {
                        var graphUpdate = new
                        {
                            type = "graph_update",
                            timestamp = DateTime.UtcNow,
                            data = update
                        };

                        var json = JsonSerializer.Serialize(graphUpdate);
                        var bytes = Encoding.UTF8.GetBytes(json);
                        
                        if (webSocket.State == System.Net.WebSockets.WebSocketState.Open)
                        {
                            try
                            {
                                await webSocket.SendAsync(
                                    new ArraySegment<byte>(bytes),
                                    System.Net.WebSockets.WebSocketMessageType.Text,
                                    true,
                                    cancellationToken);
                                
                                session.LastActivity = DateTime.UtcNow;
                                Interlocked.Increment(ref session.MessagesSent);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error sending WebSocket message");
                            }
                        }
                    }
                });

                // Mantener sesión activa
                while (webSocket.State == System.Net.WebSockets.WebSocketState.Open && 
                       !cancellationToken.IsCancellationRequested)
                {
                    var result = await webSocket.ReceiveAsync(
                        new ArraySegment<byte>(buffer), 
                        cancellationToken);

                    if (result.MessageType == System.Net.WebSockets.WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(
                            System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,
                            "Session ended",
                            cancellationToken);
                        break;
                    }

                    // Procesar mensajes del cliente (filtros, navegación, etc.)
                    if (result.Count > 0)
                    {
                        var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        ProcessClientMessage(session, message);
                    }

                    session.LastActivity = DateTime.UtcNow;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in graph stream session {SessionId}", sessionId);
            }
            finally
            {
                _activeSessions.TryRemove(sessionId, out _);
                _logger.LogInformation("Graph stream session {SessionId} ended", sessionId);
            }
        }

        /// <summary>
        /// Exporta grafo a formato compatible con herramientas externas
        /// </summary>
        public async Task<byte[]> ExportGraphAsync(
            ThreatGraphResult graph,
            ExportFormat format,
            CancellationToken cancellationToken)
        {
            return format switch
            {
                ExportFormat.PNG => await ExportToPngAsync(graph.DotGraph, cancellationToken),
                ExportFormat.SVG => Encoding.UTF8.GetBytes(graph.SvgGraph ?? graph.DotGraph),
                ExportFormat.JSON => Encoding.UTF8.GetBytes(graph.JsonGraph),
                ExportFormat.GraphML => await ExportToGraphMLAsync(graph, cancellationToken),
                ExportFormat.CSV => await ExportToCsvAsync(graph, cancellationToken),
                ExportFormat.PDF => await ExportToPdfAsync(graph, cancellationToken),
                _ => Encoding.UTF8.GetBytes(graph.DotGraph)
            };
        }

        /// <summary>
        /// Limpieza periódica de sesiones inactivas
        /// </summary>
        private void CleanupCallback(object state)
        {
            var timeout = TimeSpan.FromMinutes(30);
            var expiredSessions = _activeSessions
                .Where(s => DateTime.UtcNow - s.Value.LastActivity > timeout)
                .Select(s => s.Key)
                .ToList();

            foreach (var sessionId in expiredSessions)
            {
                if (_activeSessions.TryRemove(sessionId, out var session))
                {
                    try
                    {
                        session.WebSocket?.CloseAsync(
                            System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,
                            "Session timeout",
                            CancellationToken.None).Wait(1000);
                    }
                    catch { }
                    
                    _logger.LogInformation("Session {SessionId} cleaned up due to inactivity", sessionId);
                }
            }

            // Limpiar cache de layouts antiguos
            var expiredLayouts = _layoutCache.Keys
                .Where(k => !_graphCache.TryGetValue(k, out _))
                .ToList();

            foreach (var key in expiredLayouts)
            {
                _layoutCache.TryRemove(key, out _);
            }

            _logger.LogDebug(
                "Cleanup completed. Active sessions: {ActiveSessions}, Layout cache: {LayoutCacheSize}", 
                _activeSessions.Count, 
                _layoutCache.Count);
        }

        /// <summary>
        /// Obtiene estadísticas del motor
        /// </summary>
        public VisualizationStats GetStatistics()
        {
            return new VisualizationStats
            {
                TotalGraphsRendered = Interlocked.Read(ref _totalGraphsRendered),
                TotalLayoutsComputed = Interlocked.Read(ref _totalLayoutsComputed),
                TotalCacheHits = Interlocked.Read(ref _totalCacheHits),
                TotalCacheMisses = Interlocked.Read(ref _totalCacheMisses),
                CacheHitRatio = _totalCacheHits / (double)Math.Max(1, _totalCacheHits + _totalCacheMisses),
                ActiveSessions = _activeSessions.Count,
                GraphCacheSize = _graphCache.Count,
                LayoutCacheSize = _layoutCache.Count,
                MemoryUsageMB = Environment.WorkingSet / 1024 / 1024,
                CacheMemoryMB = _graphCache.GetCurrentStatistics()?.CurrentEstimatedSize ?? 0,
                Uptime = DateTime.UtcNow - _startTime
            };
        }

        private string EscapeDotString(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            return input
                .Replace("\"", "\\\"")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t");
        }

        private int EstimateGraphSize(ThreatGraphResult graph)
        {
            // Estimación aproximada del tamaño en bytes
            return graph.JsonGraph.Length + 
                   (graph.SvgGraph?.Length ?? 0) + 
                   graph.DotGraph.Length;
        }

        private VisualizationConfig LoadConfiguration()
        {
            var configPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, 
                "configs", 
                "visualization.yaml");

            try
            {
                if (File.Exists(configPath))
                {
                    var yaml = File.ReadAllText(configPath);
                    return YamlConverter.Deserialize<VisualizationConfig>(yaml);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load visualization config, using defaults");
            }

            return new VisualizationConfig
            {
                DefaultLayout = LayoutAlgorithm.ForceDirected3D,
                DefaultTimeRange = TimeSpan.FromHours(24),
                MaxNodesPerGraph = 1000,
                Enable3DVisualization = true,
                EnableRealTimeUpdates = true,
                CacheDuration = TimeSpan.FromHours(1),
                GraphvizPath = "dot"
            };
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
            _graphCache?.Dispose();
            _renderSemaphore?.Dispose();
            
            // Cerrar sesiones activas
            foreach (var session in _activeSessions.Values)
            {
                try
                {
                    session.WebSocket?.CloseAsync(
                        System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,
                        "Engine disposing",
                        CancellationToken.None).Wait(1000);
                }
                catch { }
            }
            
            _activeSessions.Clear();
            _layoutCache.Clear();
        }

        private static readonly DateTime _startTime = DateTime.UtcNow;
    }

    #region Clases de Soporte

    public class ThreatGraphResult
    {
        public string TenantId { get; set; }
        public DateTime GeneratedAt { get; set; }
        public BidirectionalGraph<GraphNode, GraphEdge> Graph { get; set; }
        public GraphLayout Layout { get; set; }
        public string DotGraph { get; set; }
        public string JsonGraph { get; set; }
        public string SvgGraph { get; set; }
        public GraphStatistics Statistics { get; set; }
    }

    public class AttackGraphResult
    {
        public string IncidentId { get; set; }
        public DateTime GeneratedAt { get; set; }
        public AttackGraph Graph { get; set; }
        public GraphLayout Layout { get; set; }
        public string DotGraph { get; set; }
        public string JsonGraph { get; set; }
    }

    public class GraphNode
    {
        public string Id { get; set; }
        public string Label { get; set; }
        public NodeType Type { get; set; }
        public double RiskScore { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; }
        public string Description { get; set; }
        public int EdgeCount { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class GraphEdge
    {
        public string Id { get; set; }
        public string SourceId { get; set; }
        public string TargetId { get; set; }
        public EdgeType Type { get; set; }
        public string Label { get; set; }
        public double RiskScore { get; set; }
        public double Weight { get; set; }
        public bool IsAnomalous { get; set; }
        public DateTime Timestamp { get; set; }
        public string Description { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class AttackGraph
    {
        public string IncidentId { get; set; }
        public AttackNode RootNode { get; set; }
        public Dictionary<string, AttackNode> Nodes { get; set; } = new();
        public List<AttackEdge> Edges { get; set; } = new();

        public void AddNode(AttackNode node)
        {
            Nodes[node.Id] = node;
        }

        public void AddEdge(string sourceId, string targetId, AttackEdge edge)
        {
            edge.SourceId = sourceId;
            edge.TargetId = targetId;
            Edges.Add(edge);
        }
    }

    public class AttackNode
    {
        public string Id { get; set; }
        public AttackNodeType Type { get; set; }
        public string Label { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; }
        public double RiskScore { get; set; }
        public bool IsRoot { get; set; }
        public string ParentId { get; set; }
        
        // MITRE ATT&CK
        public string Tactic { get; set; }
        public string Technique { get; set; }
        public string Platform { get; set; }
        
        // IOCs
        public IOCType IndicatorType { get; set; }
        public double Confidence { get; set; }
        public string Value { get; set; }
        
        // Device
        public string Hostname { get; set; }
        public string IpAddress { get; set; }
        public string OsVersion { get; set; }
        public DateTime CompromisedAt { get; set; }
        
        // Process
        public string Path { get; set; }
        public string CommandLine { get; set; }
        public string User { get; set; }
        
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class AttackEdge
    {
        public string SourceId { get; set; }
        public string TargetId { get; set; }
        public EdgeType Type { get; set; }
        public double Confidence { get; set; } = 1.0;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class GraphLayout
    {
        public string Algorithm { get; set; } = "ForceDirected";
        public Dictionary<string, Point3D> Positions { get; set; } = new();
    }

    public struct Point3D
    {
        public float X { get; set; }
        public float Y { get; set; }
        public float Z { get; set; }
    }

    public struct Vector3D
    {
        public float X { get; set; }
        public float Y { get; set; }
        public float Z { get; set; }
    }

    public class GraphGenerationOptions
    {
        public TimeSpan TimeRange { get; set; } = TimeSpan.FromHours(24);
        public int MaxNodes { get; set; } = 500;
        public bool IncludeIsolated { get; set; } = false;
        public LayoutAlgorithm LayoutAlgorithm { get; set; } = LayoutAlgorithm.ForceDirected3D;
        public bool UseCache { get; set; } = true;
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(15);
        public bool GenerateSvg { get; set; } = true;
        public bool GenerateJson { get; set; } = true;
    }

    public class AttackGraphOptions
    {
        public bool IncludeDevices { get; set; } = true;
        public bool IncludeProcesses { get; set; } = true;
        public bool IncludeIOCs { get; set; } = true;
        public bool IncludeMitreTechniques { get; set; } = true;
        public LayoutAlgorithm LayoutAlgorithm { get; set; } = LayoutAlgorithm.Tree;
    }

    public class GraphStatistics
    {
        public int NodeCount { get; set; }
        public int EdgeCount { get; set; }
        public int IsolatedNodes { get; set; }
        public int HighRiskNodes { get; set; }
        public int MediumRiskNodes { get; set; }
        public int LowRiskNodes { get; set; }
        public double AverageDegree { get; set; }
        public long GenerationTimeMs { get; set; }
        public string CacheKey { get; set; }
    }

    public class VisualizationStats
    {
        public long TotalGraphsRendered { get; set; }
        public long TotalLayoutsComputed { get; set; }
        public long TotalCacheHits { get; set; }
        public long TotalCacheMisses { get; set; }
        public double CacheHitRatio { get; set; }
        public int ActiveSessions { get; set; }
        public int GraphCacheSize { get; set; }
        public int LayoutCacheSize { get; set; }
        public long MemoryUsageMB { get; set; }
        public long CacheMemoryMB { get; set; }
        public TimeSpan Uptime { get; set; }
    }

    public class ThreatGraphSession
    {
        public string SessionId { get; set; }
        public string TenantId { get; set; }
        public System.Net.WebSockets.WebSocket WebSocket { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public long MessagesSent { get; set; }
        public GraphSubscriptionFilters SubscriptionFilters { get; set; }
    }

    public class GraphSubscriptionFilters
    {
        public double? MinRiskScore { get; set; }
        public List<NodeType> NodeTypes { get; set; } = new();
        public List<string> DeviceGroups { get; set; } = new();
        public TimeSpan? TimeWindow { get; set; }
    }

    public class VisualizationConfig
    {
        public LayoutAlgorithm DefaultLayout { get; set; }
        public TimeSpan DefaultTimeRange { get; set; }
        public int MaxNodesPerGraph { get; set; }
        public bool Enable3DVisualization { get; set; }
        public bool EnableRealTimeUpdates { get; set; }
        public TimeSpan CacheDuration { get; set; }
        public string GraphvizPath { get; set; }
    }

    public enum NodeType
    {
        Device,
        Process,
        File,
        Network,
        Registry,
        User,
        Incident,
        Indicator,
        Technique
    }

    public enum EdgeType
    {
        Communicates,
        Executes,
        Creates,
        Modifies,
        Deletes,
        Accesses,
        Authenticates,
        Uses,
        Indicates,
        Affects,
        Correlated
    }

    public enum AttackNodeType
    {
        Incident,
        Technique,
        Indicator,
        Device,
        Process,
        File,
        Network,
        Registry
    }

    public enum LayoutAlgorithm
    {
        FruchtermanReingold,
        KamadaKawai,
        Sugiyama,
        Circular,
        Tree,
        ForceDirected3D
    }

    public enum ExportFormat
    {
        DOT,
        PNG,
        SVG,
        JSON,
        GraphML,
        CSV,
        PDF
    }

    public enum IOCType
    {
        SHA256,
        MD5,
        IPAddress,
        Domain,
        URL,
        Email,
        RegistryPath,
        FilePath
    }

    #endregion
}