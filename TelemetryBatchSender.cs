using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.Telemetry
{
    /// <summary>
    /// Enviador de lotes de telemetría con reconexión inteligente, compresión y cifrado
    /// Implementa circuit breaker, backoff exponencial y múltiples endpoints de fallback
    /// </summary>
    public sealed class TelemetryBatchSender : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<TelemetryBatchSender> _instance = 
            new Lazy<TelemetryBatchSender>(() => new TelemetryBatchSender());
        
        public static TelemetryBatchSender Instance => _instance.Value;
        
        private readonly TelemetryQueue _telemetryQueue;
        private readonly LogManager _logManager;
        private readonly CryptoHelper _cryptoHelper;
        private readonly HttpClient _httpClient;
        private readonly Timer _sendTimer;
        private readonly List<string> _endpoints;
        private readonly SemaphoreSlim _sendLock;
        
        private bool _isInitialized;
        private bool _isRunning;
        private int _currentEndpointIndex;
        private CircuitBreakerState _circuitBreakerState;
        private DateTime _circuitBreakerOpenedTime;
        private long _totalBatchesSent;
        private long _totalEventsSent;
        private long _totalBatchesFailed;
        private long _consecutiveFailures;
        private DateTime _startTime;
        private string _deviceId;
        private string _tenantId;
        private string _authToken;
        
        private const int SEND_INTERVAL_MS = 5000; // 5 segundos
        private const int BATCH_SIZE = 100;
        private const int MAX_BATCH_SIZE = 1000;
        private const int MAX_RETRY_COUNT = 3;
        private const int CIRCUIT_BREAKER_THRESHOLD = 5;
        private const int CIRCUIT_BREAKER_TIMEOUT_SECONDS = 30;
        private const int REQUEST_TIMEOUT_SECONDS = 30;
        private const int BACKOFF_BASE_MS = 1000;
        private const int BACKOFF_MAX_MS = 60000;
        private const int COMPRESSION_THRESHOLD = 1024; // 1KB
        
        public string ModuleId => "TelemetryBatchSender";
        public string Version => "1.0.0";
        public string Description => "Enviador de lotes de telemetría con reconexión inteligente";
        
        private TelemetryBatchSender()
        {
            _telemetryQueue = TelemetryQueue.Instance;
            _logManager = LogManager.Instance;
            _cryptoHelper = new CryptoHelper();
            
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(REQUEST_TIMEOUT_SECONDS)
            };
            
            // Configurar headers por defecto
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BWP-Agent/1.0");
            
            _sendTimer = new Timer(SendCallback, null, Timeout.Infinite, Timeout.Infinite);
            _endpoints = new List<string>();
            _sendLock = new SemaphoreSlim(1, 1);
            
            _isInitialized = false;
            _isRunning = false;
            _circuitBreakerState = CircuitBreakerState.Closed;
            _currentEndpointIndex = 0;
        }
        
        /// <summary>
        /// Inicializa el enviador de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                if (_isInitialized)
                    return ModuleOperationResult.SuccessResult();
                
                // Cargar configuración
                await LoadConfiguration();
                
                // Validar endpoints
                if (_endpoints.Count == 0)
                {
                    throw new InvalidOperationException("No hay endpoints configurados");
                }
                
                // Iniciar timer
                _sendTimer.Change(TimeSpan.Zero, TimeSpan.FromMilliseconds(SEND_INTERVAL_MS));
                
                _startTime = DateTime.UtcNow;
                _isInitialized = true;
                _isRunning = true;
                
                _logManager.LogInfo("TelemetryBatchSender inicializado", ModuleId, new Dictionary<string, object>
                {
                    { "endpoints", _endpoints },
                    { "batchSize", BATCH_SIZE },
                    { "maxRetryCount", MAX_RETRY_COUNT },
                    { "circuitBreakerThreshold", CIRCUIT_BREAKER_THRESHOLD }
                });
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando TelemetryBatchSender: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el enviador de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            _isRunning = true;
            _logManager.LogInfo("TelemetryBatchSender iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene el enviador de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            _isRunning = false;
            
            // Enviar batch final
            await SendBatchAsync();
            
            _logManager.LogInfo("TelemetryBatchSender detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Pausa el enviador de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("TelemetryBatchSender pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el enviador de telemetría
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("TelemetryBatchSender reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Envía un lote de telemetría
        /// </summary>
        public async Task<bool> SendBatchAsync()
        {
            if (!_isInitialized || !_isRunning)
                return false;
            
            // Verificar circuit breaker
            if (_circuitBreakerState == CircuitBreakerState.Open)
            {
                var timeSinceOpen = DateTime.UtcNow - _circuitBreakerOpenedTime;
                if (timeSinceOpen.TotalSeconds < CIRCUIT_BREAKER_TIMEOUT_SECONDS)
                {
                    _logManager.LogWarning($"Circuit breaker abierto, reintento en {CIRCUIT_BREAKER_TIMEOUT_SECONDS - timeSinceOpen.TotalSeconds:F0}s", 
                        ModuleId);
                    return false;
                }
                
                // Intentar resetear circuit breaker
                _circuitBreakerState = CircuitBreakerState.HalfOpen;
                _logManager.LogInfo("Circuit breaker en modo half-open", ModuleId);
            }
            
            try
            {
                await _sendLock.WaitAsync();
                
                // Obtener batch de eventos
                var batch = await _telemetryQueue.GetNextBatchAsync(BATCH_SIZE);
                if (batch.Count == 0)
                {
                    return true; // No hay eventos para enviar
                }
                
                // Preparar payload
                var payload = PreparePayload(batch);
                
                // Intentar enviar con reintentos
                var success = await SendWithRetryAsync(payload, batch);
                
                if (success)
                {
                    // Marcar como enviados
                    var eventIds = batch.Select(e => e.EventId).ToList();
                    await _telemetryQueue.MarkAsSentAsync(eventIds);
                    
                    // Resetear circuit breaker si estaba en half-open
                    if (_circuitBreakerState == CircuitBreakerState.HalfOpen)
                    {
                        _circuitBreakerState = CircuitBreakerState.Closed;
                        _consecutiveFailures = 0;
                        _logManager.LogInfo("Circuit breaker cerrado (half-open success)", ModuleId);
                    }
                    
                    // Actualizar estadísticas
                    Interlocked.Increment(ref _totalBatchesSent);
                    Interlocked.Add(ref _totalEventsSent, batch.Count);
                    _consecutiveFailures = 0;
                    
                    // Log periódico
                    if (_totalBatchesSent % 10 == 0)
                    {
                        _logManager.LogInfo($"Batch enviado: {batch.Count} eventos, total: {_totalEventsSent}", 
                            ModuleId, new Dictionary<string, object>
                            {
                                { "batchSize", batch.Count },
                                { "totalEvents", _totalEventsSent },
                                { "totalBatches", _totalBatchesSent }
                            });
                    }
                    
                    return true;
                }
                else
                {
                    // Marcar como fallidos
                    await _telemetryQueue.MarkAsFailedAsync(batch);
                    
                    // Actualizar circuit breaker
                    Interlocked.Increment(ref _consecutiveFailures);
                    Interlocked.Increment(ref _totalBatchesFailed);
                    
                    if (_consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD)
                    {
                        _circuitBreakerState = CircuitBreakerState.Open;
                        _circuitBreakerOpenedTime = DateTime.UtcNow;
                        
                        _logManager.LogError($"Circuit breaker abierto después de {_consecutiveFailures} fallos consecutivos", 
                            ModuleId, new Dictionary<string, object>
                            {
                                { "failures", _consecutiveFailures },
                                { "threshold", CIRCUIT_BREAKER_THRESHOLD },
                                { "timeoutSeconds", CIRCUIT_BREAKER_TIMEOUT_SECONDS }
                            });
                    }
                    
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error enviando batch: {ex}", ModuleId);
                Interlocked.Increment(ref _totalBatchesFailed);
                return false;
            }
            finally
            {
                _sendLock.Release();
            }
        }
        
        /// <summary>
        /// Envía un batch de eventos específico (para casos especiales)
        /// </summary>
        public async Task<bool> SendSpecificBatchAsync(List<TelemetryEvent> events, bool markAsSent = true)
        {
            if (!_isInitialized || !_isRunning || events == null || events.Count == 0)
                return false;
            
            try
            {
                await _sendLock.WaitAsync();
                
                // Preparar payload
                var payload = PreparePayload(events);
                
                // Enviar
                var success = await SendPayloadAsync(payload, GetCurrentEndpoint());
                
                if (success && markAsSent)
                {
                    var eventIds = events.Select(e => e.EventId).ToList();
                    await _telemetryQueue.MarkAsSentAsync(eventIds);
                    
                    Interlocked.Increment(ref _totalBatchesSent);
                    Interlocked.Add(ref _totalEventsSent, events.Count);
                }
                
                return success;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error enviando batch específico: {ex}", ModuleId);
                return false;
            }
            finally
            {
                _sendLock.Release();
            }
        }
        
        /// <summary>
        /// Verifica conectividad con el servidor de telemetría
        /// </summary>
        public async Task<ConnectivityCheckResult> CheckConnectivityAsync()
        {
            var results = new List<EndpointConnectivity>();
            
            foreach (var endpoint in _endpoints)
            {
                try
                {
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    
                    // Enviar ping de prueba
                    var pingPayload = new
                    {
                        type = "ping",
                        timestamp = DateTime.UtcNow,
                        deviceId = _deviceId,
                        agentVersion = Version
                    };
                    
                    var content = new StringContent(
                        JsonSerializer.Serialize(pingPayload),
                        Encoding.UTF8,
                        "application/json");
                    
                    AddAuthHeaders(content.Headers);
                    
                    var response = await _httpClient.PostAsync(
                        $"{endpoint}/api/v1/telemetry/ping",
                        content);
                    
                    stopwatch.Stop();
                    
                    results.Add(new EndpointConnectivity
                    {
                        Endpoint = endpoint,
                        IsReachable = response.IsSuccessStatusCode,
                        ResponseTimeMs = stopwatch.ElapsedMilliseconds,
                        StatusCode = (int)response.StatusCode,
                        Error = response.IsSuccessStatusCode ? null : $"HTTP {response.StatusCode}"
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new EndpointConnectivity
                    {
                        Endpoint = endpoint,
                        IsReachable = false,
                        ResponseTimeMs = 0,
                        StatusCode = 0,
                        Error = ex.Message
                    });
                }
            }
            
            var primaryResult = results.FirstOrDefault(r => r.Endpoint == GetCurrentEndpoint());
            var anyReachable = results.Any(r => r.IsReachable);
            
            return new ConnectivityCheckResult
            {
                Timestamp = DateTime.UtcNow,
                PrimaryEndpoint = GetCurrentEndpoint(),
                PrimaryReachable = primaryResult?.IsReachable ?? false,
                AnyEndpointReachable = anyReachable,
                EndpointResults = results,
                CircuitBreakerState = _circuitBreakerState,
                ConsecutiveFailures = _consecutiveFailures
            };
        }
        
        /// <summary>
        /// Verifica salud del enviador
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                var stats = GetStats();
                
                // Verificar si está corriendo
                if (!_isRunning)
                {
                    issues.Add("Sender no está corriendo");
                }
                
                // Verificar circuit breaker
                if (_circuitBreakerState == CircuitBreakerState.Open)
                {
                    issues.Add("Circuit breaker abierto");
                }
                
                // Verificar tasa de fallos
                if (stats.TotalBatchesSent > 0)
                {
                    var failureRate = (double)stats.TotalBatchesFailed / stats.TotalBatchesSent;
                    if (failureRate > 0.3) // Más del 30% de fallos
                    {
                        issues.Add($"Alta tasa de fallos: {failureRate:P2}");
                    }
                }
                
                // Verificar conectividad
                var connectivity = await CheckConnectivityAsync();
                if (!connectivity.PrimaryReachable)
                {
                    issues.Add($"Endpoint primario no accesible: {connectivity.PrimaryEndpoint}");
                }
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy(
                        $"Sender saludable: {stats.TotalEventsSent} eventos enviados",
                        new Dictionary<string, object>
                        {
                            { "stats", stats },
                            { "connectivity", connectivity }
                        });
                }
                else
                {
                    return HealthCheckResult.Degraded(
                        $"Sender con problemas: {string.Join(", ", issues)}",
                        new Dictionary<string, object>
                        {
                            { "issues", issues },
                            { "stats", stats },
                            { "connectivity", connectivity }
                        });
                }
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error verificando salud de sender: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "exception", ex.ToString() }
                    });
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del enviador
        /// </summary>
        public TelemetrySenderStats GetStats()
        {
            var now = DateTime.UtcNow;
            
            return new TelemetrySenderStats
            {
                Timestamp = now,
                IsRunning = _isRunning,
                IsInitialized = _isInitialized,
                Uptime = now - _startTime,
                
                TotalBatchesSent = Interlocked.Read(ref _totalBatchesSent),
                TotalEventsSent = Interlocked.Read(ref _totalEventsSent),
                TotalBatchesFailed = Interlocked.Read(ref _totalBatchesFailed),
                ConsecutiveFailures = Interlocked.Read(ref _consecutiveFailures),
                
                CircuitBreakerState = _circuitBreakerState,
                CircuitBreakerOpenedTime = _circuitBreakerOpenedTime,
                CurrentEndpoint = GetCurrentEndpoint(),
                EndpointCount = _endpoints.Count,
                
                BatchSendRate = CalculateRate(_totalBatchesSent, _startTime),
                EventSendRate = CalculateRate(_totalEventsSent, _startTime),
                
                BatchSize = BATCH_SIZE,
                MaxRetryCount = MAX_RETRY_COUNT
            };
        }
        
        /// <summary>
        /// Cambia al siguiente endpoint (para fallback)
        /// </summary>
        public void RotateEndpoint()
        {
            _currentEndpointIndex = (_currentEndpointIndex + 1) % _endpoints.Count;
            _logManager.LogInfo($"Endpoint rotado a: {GetCurrentEndpoint()}", ModuleId);
        }
        
        /// <summary>
        /// Reinicia el circuit breaker
        /// </summary>
        public void ResetCircuitBreaker()
        {
            _circuitBreakerState = CircuitBreakerState.Closed;
            _consecutiveFailures = 0;
            _logManager.LogInfo("Circuit breaker reiniciado", ModuleId);
        }
        
        /// <summary>
        /// Establece credenciales de autenticación
        /// </summary>
        public void SetCredentials(string deviceId, string tenantId, string authToken)
        {
            _deviceId = deviceId;
            _tenantId = tenantId;
            _authToken = authToken;
            
            _logManager.LogInfo("Credenciales actualizadas", ModuleId, new Dictionary<string, object>
            {
                { "deviceId", CryptoHelper.MaskSensitiveData(deviceId) },
                { "tenantId", CryptoHelper.MaskSensitiveData(tenantId) }
            });
        }
        
        /// <summary>
        /// Agrega un nuevo endpoint
        /// </summary>
        public void AddEndpoint(string endpoint)
        {
            if (!string.IsNullOrEmpty(endpoint) && !_endpoints.Contains(endpoint))
            {
                _endpoints.Add(endpoint);
                _logManager.LogInfo($"Endpoint agregado: {endpoint}", ModuleId);
            }
        }
        
        /// <summary>
        /// Configura timeout de HTTP client
        /// </summary>
        public void SetHttpTimeout(TimeSpan timeout)
        {
            _httpClient.Timeout = timeout;
            _logManager.LogInfo($"HTTP timeout configurado a {timeout.TotalSeconds}s", ModuleId);
        }
        
        #region Métodos Privados
        
        private async Task LoadConfiguration()
        {
            try
            {
                // Cargar desde configuración o registro
                // Por ahora, valores por defecto
                _endpoints.Clear();
                _endpoints.Add("https://telemetry.bwp-enterprise.com");
                _endpoints.Add("https://telemetry-backup.bwp-enterprise.com");
                
                // Cargar credenciales
                _deviceId = Environment.MachineName;
                _tenantId = "default";
                _authToken = "initial-token"; // En producción, cargar desde almacén seguro
                
                _logManager.LogInfo("Configuración cargada", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando configuración: {ex}", ModuleId);
                throw;
            }
        }
        
        private async void SendCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                await SendBatchAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en SendCallback: {ex}", ModuleId);
            }
        }
        
        private async Task<bool> SendWithRetryAsync(string payload, List<TelemetryEvent> events)
        {
            var retryCount = 0;
            var delay = BACKOFF_BASE_MS;
            
            while (true)
            {
                try
                {
                    var endpoint = GetCurrentEndpoint();
                    var success = await SendPayloadAsync(payload, endpoint);
                    
                    if (success)
                        return true;
                    
                    retryCount++;
                    
                    if (retryCount >= MAX_RETRY_COUNT)
                    {
                        // Rotar endpoint después de fallar todos los reintentos
                        RotateEndpoint();
                        return false;
                    }
                    
                    // Backoff exponencial
                    await Task.Delay(delay);
                    delay = Math.Min(delay * 2, BACKOFF_MAX_MS);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en reintento {retryCount}: {ex}", ModuleId);
                    
                    retryCount++;
                    if (retryCount >= MAX_RETRY_COUNT)
                        return false;
                    
                    await Task.Delay(delay);
                    delay = Math.Min(delay * 2, BACKOFF_MAX_MS);
                }
            }
        }
        
        private async Task<bool> SendPayloadAsync(string payload, string endpoint)
        {
            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                // Determinar si comprimir
                var shouldCompress = payload.Length > COMPRESSION_THRESHOLD;
                HttpContent content;
                
                if (shouldCompress)
                {
                    var compressed = CryptoHelper.ToCompressedJson(payload);
                    content = new ByteArrayContent(compressed);
                    content.Headers.ContentEncoding.Add("gzip");
                }
                else
                {
                    content = new StringContent(payload, Encoding.UTF8, "application/json");
                }
                
                AddAuthHeaders(content.Headers);
                
                var response = await _httpClient.PostAsync(
                    $"{endpoint}/api/v1/telemetry/batch",
                    content);
                
                stopwatch.Stop();
                
                var responseContent = await response.Content.ReadAsStringAsync();
                
                if (response.IsSuccessStatusCode)
                {
                    _logManager.LogDebug($"Batch enviado exitosamente en {stopwatch.ElapsedMilliseconds}ms", 
                        ModuleId, new Dictionary<string, object>
                        {
                            { "endpoint", endpoint },
                            { "responseTimeMs", stopwatch.ElapsedMilliseconds },
                            { "compressed", shouldCompress },
                            { "response", responseContent }
                        });
                    
                    return true;
                }
                else
                {
                    _logManager.LogError($"Error enviando batch: HTTP {response.StatusCode}", 
                        ModuleId, new Dictionary<string, object>
                        {
                            { "endpoint", endpoint },
                            { "statusCode", (int)response.StatusCode },
                            { "response", responseContent },
                            { "responseTimeMs", stopwatch.ElapsedMilliseconds }
                        });
                    
                    return false;
                }
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                _logManager.LogError($"Timeout enviando batch a {endpoint}", ModuleId);
                return false;
            }
            catch (HttpRequestException ex)
            {
                _logManager.LogError($"Error de red enviando batch a {endpoint}: {ex.Message}", ModuleId);
                return false;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inesperado enviando batch: {ex}", ModuleId);
                return false;
            }
        }
        
        private string PreparePayload(List<TelemetryEvent> events)
        {
            var payload = new
            {
                batchId = Guid.NewGuid().ToString(),
                timestamp = DateTime.UtcNow,
                deviceId = _deviceId,
                tenantId = _tenantId,
                agentVersion = Version,
                events = events.Select(e => new
                {
                    e.EventId,
                    e.Timestamp,
                    e.EventType,
                    e.Severity,
                    Data = e.Data,
                    Metadata = e.Metadata
                }).ToList()
            };
            
            return JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        }
        
        private string GetCurrentEndpoint()
        {
            if (_endpoints.Count == 0)
                return string.Empty;
            
            return _endpoints[_currentEndpointIndex];
        }
        
        private void AddAuthHeaders(HttpContentHeaders headers)
        {
            if (!string.IsNullOrEmpty(_authToken))
            {
                headers.Add("Authorization", $"Bearer {_authToken}");
            }
            
            headers.Add("X-Device-Id", _deviceId);
            headers.Add("X-Tenant-Id", _tenantId);
            headers.Add("X-Agent-Version", Version);
            headers.Add("X-Request-Id", Guid.NewGuid().ToString());
        }
        
        private double CalculateRate(long count, DateTime startTime)
        {
            var elapsed = DateTime.UtcNow - startTime;
            if (elapsed.TotalSeconds == 0)
                return 0;
            
            return count / elapsed.TotalSeconds;
        }
        
        #endregion
        
        #region Clases y Enums de Soporte
        
        private enum CircuitBreakerState
        {
            Closed,
            HalfOpen,
            Open
        }
        
        public class TelemetrySenderStats
        {
            public DateTime Timestamp { get; set; }
            public bool IsRunning { get; set; }
            public bool IsInitialized { get; set; }
            public TimeSpan Uptime { get; set; }
            
            public long TotalBatchesSent { get; set; }
            public long TotalEventsSent { get; set; }
            public long TotalBatchesFailed { get; set; }
            public long ConsecutiveFailures { get; set; }
            
            public CircuitBreakerState CircuitBreakerState { get; set; }
            public DateTime CircuitBreakerOpenedTime { get; set; }
            public string CurrentEndpoint { get; set; }
            public int EndpointCount { get; set; }
            
            public double BatchSendRate { get; set; }
            public double EventSendRate { get; set; }
            
            public int BatchSize { get; set; }
            public int MaxRetryCount { get; set; }
        }
        
        public class ConnectivityCheckResult
        {
            public DateTime Timestamp { get; set; }
            public string PrimaryEndpoint { get; set; }
            public bool PrimaryReachable { get; set; }
            public bool AnyEndpointReachable { get; set; }
            public List<EndpointConnectivity> EndpointResults { get; set; }
            public CircuitBreakerState CircuitBreakerState { get; set; }
            public long ConsecutiveFailures { get; set; }
        }
        
        public class EndpointConnectivity
        {
            public string Endpoint { get; set; }
            public bool IsReachable { get; set; }
            public long ResponseTimeMs { get; set; }
            public int StatusCode { get; set; }
            public string Error { get; set; }
        }
        
        #endregion
    }
}