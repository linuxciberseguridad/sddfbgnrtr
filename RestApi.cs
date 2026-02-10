using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.DeviceRegistry;
using BWP.Enterprise.Cloud.TenantManagement;
using BWP.Enterprise.Cloud.SOAR;
using BWP.Enterprise.Cloud.ThreatGraph;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Cloud.Api
{
    /// <summary>
    /// API REST para comunicación con agentes y panel de control
    /// Proporciona endpoints seguros para telemetría, configuración y administración
    /// </summary>
    public class RestApi : IApiServer
    {
        private static readonly LogManager _logManager = LogManager.Instance;
        
        private readonly IConfiguration _configuration;
        private readonly DeviceRegistry _deviceRegistry;
        private readonly TenantManager _tenantManager;
        private readonly ActionOrchestrator _actionOrchestrator;
        private readonly GraphCorrelationEngine _correlationEngine;
        private readonly ILogger<RestApi> _logger;
        
        private WebHost _webHost;
        private bool _isRunning;
        private readonly Dictionary<string, DateTime> _rateLimitCache;
        private readonly object _lockObject = new object();
        private const int RATE_LIMIT_WINDOW_MINUTES = 1;
        private const int MAX_REQUESTS_PER_WINDOW = 100;
        
        public RestApi(
            IConfiguration configuration,
            DeviceRegistry deviceRegistry,
            TenantManager tenantManager,
            ActionOrchestrator actionOrchestrator,
            GraphCorrelationEngine correlationEngine,
            ILogger<RestApi> logger)
        {
            _configuration = configuration;
            _deviceRegistry = deviceRegistry;
            _tenantManager = tenantManager;
            _actionOrchestrator = actionOrchestrator;
            _correlationEngine = correlationEngine;
            _logger = logger;
            _rateLimitCache = new Dictionary<string, DateTime>();
        }
        
        /// <summary>
        /// Inicia el servidor API
        /// </summary>
        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_isRunning)
            {
                _logger.LogWarning("API ya está en ejecución");
                return;
            }
            
            try
            {
                var hostBuilder = WebHost.CreateDefaultBuilder()
                    .ConfigureAppConfiguration((context, config) =>
                    {
                        config.AddJsonFile("appsettings.json", optional: true);
                        config.AddEnvironmentVariables();
                    })
                    .ConfigureServices((context, services) =>
                    {
                        ConfigureServices(services);
                    })
                    .Configure((context, app) =>
                    {
                        ConfigureMiddleware(app);
                        ConfigureEndpoints(app);
                    })
                    .UseUrls(GetApiUrls());
                
                _webHost = (WebHost)hostBuilder.Build();
                
                await _webHost.StartAsync(cancellationToken);
                
                _isRunning = true;
                _logger.LogInformation($"API REST iniciada en: {string.Join(", ", GetApiUrls())}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al iniciar API REST");
                throw;
            }
        }
        
        /// <summary>
        /// Detiene el servidor API
        /// </summary>
        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            if (!_isRunning || _webHost == null)
                return;
            
            try
            {
                await _webHost.StopAsync(cancellationToken);
                _webHost.Dispose();
                _webHost = null;
                _isRunning = false;
                
                _logger.LogInformation("API REST detenida");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al detener API REST");
                throw;
            }
        }
        
        /// <summary>
        /// Configura servicios DI
        /// </summary>
        private void ConfigureServices(IServiceCollection services)
        {
            // Configurar CORS
            services.AddCors(options =>
            {
                options.AddPolicy("BWPEnterprisePolicy", policy =>
                {
                    policy.WithOrigins(
                            "https://*.bwpenterprise.com",
                            "http://localhost:3000",
                            "http://localhost:8080")
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials()
                        .SetPreflightMaxAge(TimeSpan.FromHours(1));
                });
            });
            
            // Configurar autenticación
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";
            })
            .AddJwtBearer("Bearer", options =>
            {
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidAudience = _configuration["Jwt:Audience"],
                    IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]))
                };
            });
            
            // Configurar autorización
            services.AddAuthorization(options =>
            {
                options.AddPolicy("DeviceAccess", policy =>
                    policy.RequireClaim("device_id"));
                
                options.AddPolicy("AdminAccess", policy =>
                    policy.RequireRole("admin", "superadmin"));
                
                options.AddPolicy("TenantAccess", policy =>
                    policy.RequireClaim("tenant_id"));
            });
            
            // Configurar controladores
            services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                    options.JsonSerializerOptions.WriteIndented = true;
                });
            
            // Configurar Swagger/OpenAPI
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
                {
                    Title = "BWP Enterprise API",
                    Version = "v1",
                    Description = "API para gestión de seguridad empresarial"
                });
                
                // Configurar autenticación JWT en Swagger
                c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header usando el esquema Bearer",
                    Name = "Authorization",
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                    Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT"
                });
                
                c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
                {
                    {
                        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                        {
                            Reference = new Microsoft.OpenApi.Models.OpenApiReference
                            {
                                Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new List<string>()
                    }
                });
            });
            
            // Registrar servicios
            services.AddSingleton(_deviceRegistry);
            services.AddSingleton(_tenantManager);
            services.AddSingleton(_actionOrchestrator);
            services.AddSingleton(_correlationEngine);
            services.AddSingleton<IApiServer>(this);
        }
        
        /// <summary>
        /// Configura middleware
        /// </summary>
        private void ConfigureMiddleware(IApplicationBuilder app)
        {
            // Middleware de manejo de excepciones
            app.UseExceptionHandler("/error");
            
            // Middleware de logging
            app.Use(async (context, next) =>
            {
                var startTime = DateTime.UtcNow;
                await next();
                var duration = DateTime.UtcNow - startTime;
                
                _logger.LogInformation(
                    "Request {Method} {Path} responded {StatusCode} in {Duration}ms",
                    context.Request.Method,
                    context.Request.Path,
                    context.Response.StatusCode,
                    duration.TotalMilliseconds);
            });
            
            // Middleware de rate limiting
            app.Use(async (context, next) =>
            {
                if (!await CheckRateLimit(context))
                {
                    context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    await context.Response.WriteAsync("Rate limit exceeded");
                    return;
                }
                await next();
            });
            
            // Middleware de CORS
            app.UseCors("BWPEnterprisePolicy");
            
            // Middleware de autenticación
            app.UseAuthentication();
            app.UseAuthorization();
            
            // Swagger UI
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "BWP Enterprise API v1");
                c.RoutePrefix = "api-docs";
            });
            
            // Middleware de tenant
            app.UseMiddleware<TenantMiddleware>();
        }
        
        /// <summary>
        /// Configura endpoints
        /// </summary>
        private void ConfigureEndpoints(IApplicationBuilder app)
        {
            app.UseRouting();
            
            app.UseEndpoints(endpoints =>
            {
                // Grupo de endpoints de dispositivos
                endpoints.MapGroup("/api/v1/devices")
                    .MapDeviceEndpoints()
                    .RequireAuthorization("DeviceAccess");
                
                // Grupo de endpoints de telemetría
                endpoints.MapGroup("/api/v1/telemetry")
                    .MapTelemetryEndpoints()
                    .RequireAuthorization();
                
                // Grupo de endpoints de administración
                endpoints.MapGroup("/api/v1/admin")
                    .MapAdminEndpoints()
                    .RequireAuthorization("AdminAccess");
                
                // Grupo de endpoints de tenant
                endpoints.MapGroup("/api/v1/tenant")
                    .MapTenantEndpoints()
                    .RequireAuthorization("TenantAccess");
                
                // Grupo de endpoints de políticas
                endpoints.MapGroup("/api/v1/policies")
                    .MapPolicyEndpoints()
                    .RequireAuthorization();
                
                // Grupo de endpoints de SOAR
                endpoints.MapGroup("/api/v1/soar")
                    .MapSoarEndpoints()
                    .RequireAuthorization("AdminAccess");
                
                // Health check
                endpoints.MapGet("/health", async context =>
                {
                    var healthStatus = await GetHealthStatusAsync();
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(healthStatus));
                });
                
                // Error endpoint
                endpoints.Map("/error", async context =>
                {
                    var exception = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
                    
                    var errorResponse = new
                    {
                        Error = exception?.Message ?? "Error desconocido",
                        Timestamp = DateTime.UtcNow,
                        RequestId = context.TraceIdentifier
                    };
                    
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse));
                });
            });
        }
        
        /// <summary>
        /// Verifica rate limiting
        /// </summary>
        private async Task<bool> CheckRateLimit(HttpContext context)
        {
            var clientIp = context.Connection.RemoteIpAddress?.ToString();
            var endpoint = context.Request.Path;
            
            if (string.IsNullOrEmpty(clientIp))
                return true;
            
            var key = $"{clientIp}:{endpoint}";
            var now = DateTime.UtcNow;
            
            lock (_lockObject)
            {
                // Limpiar entradas antiguas
                var oldKeys = _rateLimitCache
                    .Where(kv => (now - kv.Value).TotalMinutes > RATE_LIMIT_WINDOW_MINUTES)
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var oldKey in oldKeys)
                {
                    _rateLimitCache.Remove(oldKey);
                }
                
                // Contar solicitudes en la ventana actual
                var requestCount = _rateLimitCache
                    .Count(kv => kv.Key.StartsWith(clientIp) && 
                                (now - kv.Value).TotalMinutes <= RATE_LIMIT_WINDOW_MINUTES);
                
                if (requestCount >= MAX_REQUESTS_PER_WINDOW)
                {
                    return false;
                }
                
                _rateLimitCache[key] = now;
                return true;
            }
        }
        
        /// <summary>
        /// Obtiene URLs de la API
        /// </summary>
        private string[] GetApiUrls()
        {
            var urls = new List<string>();
            
            var httpPort = _configuration.GetValue<int>("Api:HttpPort", 8080);
            var httpsPort = _configuration.GetValue<int>("Api:HttpsPort", 8443);
            
            urls.Add($"http://*:{httpPort}");
            urls.Add($"https://*:{httpsPort}");
            
            return urls.ToArray();
        }
        
        /// <summary>
        /// Obtiene estado de salud de la API
        /// </summary>
        private async Task<ApiHealthStatus> GetHealthStatusAsync()
        {
            var status = new ApiHealthStatus
            {
                Timestamp = DateTime.UtcNow,
                IsRunning = _isRunning,
                Uptime = GetUptime(),
                ActiveConnections = GetActiveConnections(),
                ComponentStatus = new Dictionary<string, ComponentHealth>()
            };
            
            // Verificar estado de componentes
            status.ComponentStatus["DeviceRegistry"] = await CheckComponentHealthAsync(_deviceRegistry);
            status.ComponentStatus["TenantManager"] = await CheckComponentHealthAsync(_tenantManager);
            status.ComponentStatus["ActionOrchestrator"] = await CheckComponentHealthAsync(_actionOrchestrator);
            status.ComponentStatus["CorrelationEngine"] = await CheckComponentHealthAsync(_correlationEngine);
            
            // Determinar estado general
            status.OverallStatus = status.ComponentStatus.Values.All(c => c.IsHealthy) ? 
                HealthStatus.Healthy : HealthStatus.Degraded;
            
            if (!_isRunning)
            {
                status.OverallStatus = HealthStatus.Unhealthy;
                status.Issues.Add("API no está en ejecución");
            }
            
            return status;
        }
        
        private TimeSpan GetUptime()
        {
            // Implementar cálculo de uptime
            return TimeSpan.Zero;
        }
        
        private int GetActiveConnections()
        {
            // Implementar conteo de conexiones activas
            return 0;
        }
        
        private async Task<ComponentHealth> CheckComponentHealthAsync(object component)
        {
            try
            {
                // Verificar métodos de health check en el componente
                var healthMethod = component.GetType().GetMethod("CheckHealthAsync");
                if (healthMethod != null)
                {
                    var result = await (Task<dynamic>)healthMethod.Invoke(component, null);
                    return new ComponentHealth
                    {
                        IsHealthy = result?.Status == "Healthy",
                        Message = result?.Message,
                        LastChecked = DateTime.UtcNow
                    };
                }
                
                return new ComponentHealth
                {
                    IsHealthy = true,
                    Message = "Componente sin health check específico",
                    LastChecked = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                return new ComponentHealth
                {
                    IsHealthy = false,
                    Message = $"Error verificando salud: {ex.Message}",
                    LastChecked = DateTime.UtcNow
                };
            }
        }
        
        #region Métodos de extensión para endpoints
        
        /// <summary>
        /// Mapea endpoints de dispositivos
        /// </summary>
        private static IEndpointRouteBuilder MapDeviceEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapPost("/register", async (DeviceRegistrationRequest request, DeviceRegistry registry) =>
            {
                var result = await registry.RegisterDeviceAsync(request);
                return Results.Json(result);
            });
            
            endpoints.MapGet("/{deviceId}", async (string deviceId, DeviceRegistry registry) =>
            {
                var device = await registry.GetDeviceAsync(deviceId);
                return device != null ? Results.Json(device) : Results.NotFound();
            });
            
            endpoints.MapPost("/{deviceId}/heartbeat", async (string deviceId, DeviceRegistry registry) =>
            {
                var result = await registry.UpdateHeartbeatAsync(deviceId);
                return Results.Json(result);
            });
            
            endpoints.MapGet("/{deviceId}/status", async (string deviceId, DeviceRegistry registry) =>
            {
                var status = await registry.GetDeviceStatusAsync(deviceId);
                return Results.Json(status);
            });
            
            endpoints.MapPost("/{deviceId}/update", async (string deviceId, DeviceUpdateRequest request, DeviceRegistry registry) =>
            {
                var result = await registry.UpdateDeviceAsync(deviceId, request);
                return Results.Json(result);
            });
            
            return endpoints;
        }
        
        /// <summary>
        /// Mapea endpoints de telemetría
        /// </summary>
        private static IEndpointRouteBuilder MapTelemetryEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapPost("/events", async (TelemetryEventBatch batch, GraphCorrelationEngine engine) =>
            {
                var result = await engine.ProcessEventsAsync(batch);
                return Results.Json(result);
            });
            
            endpoints.MapPost("/alerts", async (SecurityAlert alert, ActionOrchestrator orchestrator) =>
            {
                var result = await orchestrator.ProcessAlertAsync(alert);
                return Results.Json(result);
            });
            
            endpoints.MapGet("/stats", async (GraphCorrelationEngine engine) =>
            {
                var stats = await engine.GetStatisticsAsync();
                return Results.Json(stats);
            });
            
            return endpoints;
        }
        
        /// <summary>
        /// Mapea endpoints de administración
        /// </summary>
        private static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/system-status", async (IApiServer api) =>
            {
                var status = await api.GetStatusAsync();
                return Results.Json(status);
            });
            
            endpoints.MapPost("/system/restart", async (IApiServer api) =>
            {
                await api.RestartAsync();
                return Results.Ok(new { Message = "Sistema reiniciando" });
            });
            
            endpoints.MapGet("/logs", async (HttpContext context, ILogger<RestApi> logger) =>
            {
                var logLevel = context.Request.Query["level"].ToString();
                var since = DateTime.TryParse(context.Request.Query["since"], out var sinceDate) ? 
                    sinceDate : DateTime.UtcNow.AddHours(-1);
                
                var logs = await GetLogsAsync(logLevel, since);
                return Results.Json(logs);
            });
            
            return endpoints;
        }
        
        /// <summary>
        /// Mapea endpoints de tenant
        /// </summary>
        private static IEndpointRouteBuilder MapTenantEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/info", async (TenantManager manager) =>
            {
                var tenantInfo = await manager.GetCurrentTenantInfoAsync();
                return Results.Json(tenantInfo);
            });
            
            endpoints.MapGet("/devices", async (TenantManager manager) =>
            {
                var devices = await manager.GetTenantDevicesAsync();
                return Results.Json(devices);
            });
            
            endpoints.MapGet("/policies", async (TenantManager manager) =>
            {
                var policies = await manager.GetTenantPoliciesAsync();
                return Results.Json(policies);
            });
            
            endpoints.MapGet("/reports", async (TenantManager manager) =>
            {
                var reports = await manager.GetTenantReportsAsync();
                return Results.Json(reports);
            });
            
            return endpoints;
        }
        
        /// <summary>
        /// Mapea endpoints de políticas
        /// </summary>
        private static IEndpointRouteBuilder MapPolicyEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/", async (TenantManager manager) =>
            {
                var policies = await manager.GetTenantPoliciesAsync();
                return Results.Json(policies);
            });
            
            endpoints.MapPost("/deploy", async (PolicyDeploymentRequest request, TenantManager manager) =>
            {
                var result = await manager.DeployPolicyAsync(request);
                return Results.Json(result);
            });
            
            endpoints.MapGet("/{policyId}/status", async (string policyId, TenantManager manager) =>
            {
                var status = await manager.GetPolicyStatusAsync(policyId);
                return Results.Json(status);
            });
            
            endpoints.MapPost("/{policyId}/enforce", async (string policyId, TenantManager manager) =>
            {
                var result = await manager.EnforcePolicyAsync(policyId);
                return Results.Json(result);
            });
            
            return endpoints;
        }
        
        /// <summary>
        /// Mapea endpoints de SOAR
        /// </summary>
        private static IEndpointRouteBuilder MapSoarEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/playbooks", async (ActionOrchestrator orchestrator) =>
            {
                var playbooks = await orchestrator.GetPlaybooksAsync();
                return Results.Json(playbooks);
            });
            
            endpoints.MapPost("/playbooks/execute", async (PlaybookExecutionRequest request, ActionOrchestrator orchestrator) =>
            {
                var result = await orchestrator.ExecutePlaybookAsync(request);
                return Results.Json(result);
            });
            
            endpoints.MapGet("/incidents", async (ActionOrchestrator orchestrator) =>
            {
                var incidents = await orchestrator.GetActiveIncidentsAsync();
                return Results.Json(incidents);
            });
            
            endpoints.MapPost("/incidents/{incidentId}/resolve", async (string incidentId, ActionOrchestrator orchestrator) =>
            {
                var result = await orchestrator.ResolveIncidentAsync(incidentId);
                return Results.Json(result);
            });
            
            return endpoints;
        }
        
        private static async Task<List<LogEntry>> GetLogsAsync(string logLevel, DateTime since)
        {
            // Implementar obtención de logs
            await Task.Delay(1);
            return new List<LogEntry>();
        }
        
        #endregion
        
        #region Implementación IApiServer
        
        public async Task<ApiStatus> GetStatusAsync()
        {
            var healthStatus = await GetHealthStatusAsync();
            
            return new ApiStatus
            {
                IsRunning = _isRunning,
                HealthStatus = healthStatus,
                StartTime = GetStartTime(),
                RequestCount = GetRequestCount(),
                ActiveSessions = GetActiveSessions(),
                MemoryUsage = GetMemoryUsage(),
                Configuration = GetApiConfiguration()
            };
        }
        
        public async Task RestartAsync()
        {
            _logger.LogInformation("Reiniciando API...");
            
            var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            
            await StopAsync(cancellationTokenSource.Token);
            await Task.Delay(TimeSpan.FromSeconds(2));
            await StartAsync(cancellationTokenSource.Token);
            
            _logger.LogInformation("API reiniciada exitosamente");
        }
        
        public async Task<ApiStatistics> GetStatisticsAsync(TimeSpan period)
        {
            return new ApiStatistics
            {
                Period = period,
                Timestamp = DateTime.UtcNow,
                TotalRequests = GetTotalRequests(period),
                SuccessfulRequests = GetSuccessfulRequests(period),
                FailedRequests = GetFailedRequests(period),
                AverageResponseTime = GetAverageResponseTime(period),
                EndpointStatistics = GetEndpointStatistics(period),
                ClientStatistics = GetClientStatistics(period)
            };
        }
        
        private DateTime GetStartTime()
        {
            // Implementar obtención de tiempo de inicio
            return DateTime.UtcNow.AddHours(-1);
        }
        
        private long GetRequestCount()
        {
            // Implementar conteo de solicitudes
            return 0;
        }
        
        private int GetActiveSessions()
        {
            // Implementar conteo de sesiones activas
            return 0;
        }
        
        private MemoryUsage GetMemoryUsage()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            
            return new MemoryUsage
            {
                TotalMemory = GC.GetTotalMemory(false),
                WorkingSet = process.WorkingSet64,
                PrivateMemory = process.PrivateMemorySize64,
                VirtualMemory = process.VirtualMemorySize64
            };
        }
        
        private ApiConfiguration GetApiConfiguration()
        {
            return new ApiConfiguration
            {
                HttpPort = _configuration.GetValue<int>("Api:HttpPort", 8080),
                HttpsPort = _configuration.GetValue<int>("Api:HttpsPort", 8443),
                EnableSwagger = _configuration.GetValue<bool>("Api:EnableSwagger", true),
                EnableCors = _configuration.GetValue<bool>("Api:EnableCors", true),
                RateLimitEnabled = _configuration.GetValue<bool>("Api:RateLimitEnabled", true),
                MaxRequestsPerMinute = _configuration.GetValue<int>("Api:MaxRequestsPerMinute", 100)
            };
        }
        
        private long GetTotalRequests(TimeSpan period)
        {
            // Implementar
            return 0;
        }
        
        private long GetSuccessfulRequests(TimeSpan period)
        {
            // Implementar
            return 0;
        }
        
        private long GetFailedRequests(TimeSpan period)
        {
            // Implementar
            return 0;
        }
        
        private TimeSpan GetAverageResponseTime(TimeSpan period)
        {
            // Implementar
            return TimeSpan.Zero;
        }
        
        private Dictionary<string, EndpointStats> GetEndpointStatistics(TimeSpan period)
        {
            // Implementar
            return new Dictionary<string, EndpointStats>();
        }
        
        private Dictionary<string, ClientStats> GetClientStatistics(TimeSpan period)
        {
            // Implementar
            return new Dictionary<string, ClientStats>();
        }
        
        #endregion
        
        #region Métodos para comunicación HTTP segura
        
        /// <summary>
        /// Envía una solicitud HTTP segura
        /// </summary>
        public static async Task<HttpResponseMessage> SendSecureRequestAsync(
            HttpMethod method,
            string url,
            object content = null,
            Dictionary<string, string> headers = null,
            string jwtToken = null,
            TimeSpan? timeout = null)
        {
            using (var client = CreateHttpClient(jwtToken, timeout))
            {
                var request = new HttpRequestMessage(method, url);
                
                if (content != null)
                {
                    var jsonContent = JsonSerializer.Serialize(content);
                    request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                }
                
                if (headers != null)
                {
                    foreach (var header in headers)
                    {
                        request.Headers.Add(header.Key, header.Value);
                    }
                }
                
                var response = await client.SendAsync(request);
                return response;
            }
        }
        
        /// <summary>
        /// Crea un HttpClient configurado
        /// </summary>
        public static HttpClient CreateHttpClient(string jwtToken = null, TimeSpan? timeout = null)
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                {
                    // Validación personalizada de certificado
                    if (errors == System.Net.Security.SslPolicyErrors.None)
                        return true;
                    
                    // Aquí se puede agregar lógica adicional de validación
                    return false;
                },
                UseProxy = false,
                AllowAutoRedirect = false
            };
            
            var client = new HttpClient(handler)
            {
                Timeout = timeout ?? TimeSpan.FromSeconds(30)
            };
            
            // Configurar headers por defecto
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            
            client.DefaultRequestHeaders.UserAgent.ParseAdd(
                "BWP-Enterprise-API/1.0");
            
            // Agregar token JWT si se proporciona
            if (!string.IsNullOrEmpty(jwtToken))
            {
                client.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Bearer", jwtToken);
            }
            
            return client;
        }
        
        /// <summary>
        /// Valida firma de solicitud
        /// </summary>
        public static bool ValidateRequestSignature(
            HttpRequest request,
            string secretKey,
            string signatureHeader = "X-Signature")
        {
            if (!request.Headers.TryGetValue(signatureHeader, out var signature))
                return false;
            
            // Obtener cuerpo de la solicitud
            var body = string.Empty;
            if (request.Method != "GET" && request.Method != "HEAD")
            {
                // En un entorno real, necesitaríamos leer el cuerpo
                // Esto es simplificado
            }
            
            // Calcular HMAC
            var computedSignature = CalculateHmac(request, body, secretKey);
            
            return string.Equals(signature, computedSignature, StringComparison.OrdinalIgnoreCase);
        }
        
        private static string CalculateHmac(HttpRequest request, string body, string secretKey)
        {
            var dataToSign = $"{request.Method}\n{request.Path}\n{body}";
            
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
                return Convert.ToBase64String(hash);
            }
        }
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public interface IApiServer
    {
        Task StartAsync(CancellationToken cancellationToken = default);
        Task StopAsync(CancellationToken cancellationToken = default);
        Task<ApiStatus> GetStatusAsync();
        Task RestartAsync();
        Task<ApiStatistics> GetStatisticsAsync(TimeSpan period);
    }
    
    public class ApiHealthStatus
    {
        public DateTime Timestamp { get; set; }
        public bool IsRunning { get; set; }
        public TimeSpan Uptime { get; set; }
        public int ActiveConnections { get; set; }
        public HealthStatus OverallStatus { get; set; }
        public Dictionary<string, ComponentHealth> ComponentStatus { get; set; }
        public List<string> Issues { get; set; }
        
        public ApiHealthStatus()
        {
            ComponentStatus = new Dictionary<string, ComponentHealth>();
            Issues = new List<string>();
        }
    }
    
    public class ComponentHealth
    {
        public bool IsHealthy { get; set; }
        public string Message { get; set; }
        public DateTime LastChecked { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public ComponentHealth()
        {
            Details = new Dictionary<string, object>();
        }
    }
    
    public class ApiStatus
    {
        public bool IsRunning { get; set; }
        public ApiHealthStatus HealthStatus { get; set; }
        public DateTime StartTime { get; set; }
        public long RequestCount { get; set; }
        public int ActiveSessions { get; set; }
        public MemoryUsage MemoryUsage { get; set; }
        public ApiConfiguration Configuration { get; set; }
    }
    
    public class MemoryUsage
    {
        public long TotalMemory { get; set; } // bytes
        public long WorkingSet { get; set; } // bytes
        public long PrivateMemory { get; set; } // bytes
        public long VirtualMemory { get; set; } // bytes
    }
    
    public class ApiConfiguration
    {
        public int HttpPort { get; set; }
        public int HttpsPort { get; set; }
        public bool EnableSwagger { get; set; }
        public bool EnableCors { get; set; }
        public bool RateLimitEnabled { get; set; }
        public int MaxRequestsPerMinute { get; set; }
    }
    
    public class ApiStatistics
    {
        public TimeSpan Period { get; set; }
        public DateTime Timestamp { get; set; }
        public long TotalRequests { get; set; }
        public long SuccessfulRequests { get; set; }
        public long FailedRequests { get; set; }
        public TimeSpan AverageResponseTime { get; set; }
        public Dictionary<string, EndpointStats> EndpointStatistics { get; set; }
        public Dictionary<string, ClientStats> ClientStatistics { get; set; }
        
        public ApiStatistics()
        {
            EndpointStatistics = new Dictionary<string, EndpointStats>();
            ClientStatistics = new Dictionary<string, ClientStats>();
        }
    }
    
    public class EndpointStats
    {
        public string Endpoint { get; set; }
        public string Method { get; set; }
        public long RequestCount { get; set; }
        public long SuccessCount { get; set; }
        public long ErrorCount { get; set; }
        public TimeSpan AverageResponseTime { get; set; }
        public TimeSpan MaxResponseTime { get; set; }
        public TimeSpan MinResponseTime { get; set; }
    }
    
    public class ClientStats
    {
        public string ClientId { get; set; }
        public string IpAddress { get; set; }
        public long RequestCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public List<string> UserAgents { get; set; }
        
        public ClientStats()
        {
            UserAgents = new List<string>();
        }
    }
    
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Level { get; set; }
        public string Message { get; set; }
        public string Logger { get; set; }
        public Dictionary<string, object> Properties { get; set; }
        
        public LogEntry()
        {
            Properties = new Dictionary<string, object>();
        }
    }
    
    // Clases de request/response
    public class DeviceRegistrationRequest
    {
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string OsVersion { get; set; }
        public string AgentVersion { get; set; }
        public Dictionary<string, string> Metadata { get; set; }
        
        public DeviceRegistrationRequest()
        {
            Metadata = new Dictionary<string, string>();
        }
    }
    
    public class DeviceUpdateRequest
    {
        public string DeviceName { get; set; }
        public Dictionary<string, string> Metadata { get; set; }
        public DeviceStatus Status { get; set; }
        
        public DeviceUpdateRequest()
        {
            Metadata = new Dictionary<string, string>();
        }
    }
    
    public class TelemetryEventBatch
    {
        public string DeviceId { get; set; }
        public List<TelemetryEvent> Events { get; set; }
        public DateTime Timestamp { get; set; }
        public string BatchId { get; set; }
        
        public TelemetryEventBatch()
        {
            Events = new List<TelemetryEvent>();
        }
    }
    
    public class PolicyDeploymentRequest
    {
        public string PolicyId { get; set; }
        public string PolicyContent { get; set; }
        public List<string> DeviceIds { get; set; }
        public DateTime? EffectiveFrom { get; set; }
        public DateTime? EffectiveTo { get; set; }
        
        public PolicyDeploymentRequest()
        {
            DeviceIds = new List<string>();
        }
    }
    
    public class PlaybookExecutionRequest
    {
        public string PlaybookId { get; set; }
        public string IncidentId { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        public bool ExecuteAsync { get; set; }
        
        public PlaybookExecutionRequest()
        {
            Parameters = new Dictionary<string, object>();
        }
    }
    
    public enum HealthStatus
    {
        Healthy,
        Degraded,
        Unhealthy,
        Unknown
    }
    
    public enum DeviceStatus
    {
        Online,
        Offline,
        Degraded,
        Updating,
        Quarantined
    }
    
    #endregion
}
