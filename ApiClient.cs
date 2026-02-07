using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.Communication
{
    /// <summary>
    /// Cliente HTTP/WebSocket para comunicación con cloud BWP-Enterprise
    /// Implementa autenticación, reconexión automática, circuit breaker y cifrado
    /// </summary>
    public sealed class ApiClient : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<ApiClient> _instance = 
            new Lazy<ApiClient>(() => new ApiClient());
        
        public static ApiClient Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly HttpClient _httpClient;
        private readonly HttpClient _longPollingClient;
        private ClientWebSocket _webSocket;
        private readonly SemaphoreSlim _wsLock;
        private readonly SemaphoreSlim _httpLock;
        private readonly Timer _reconnectTimer;
        private readonly Timer _heartbeatTimer;
        private readonly Dictionary<string, string> _endpoints;
        private readonly Dictionary<string, Func<string, Task>> _messageHandlers;
        private readonly Dictionary<string, TaskCompletionSource<string>> _pendingRequests;
        
        private bool _isInitialized;
        private bool _isConnected;
        private bool _isWebSocketConnected;
        private string _baseUrl;
        private string _deviceId;
        private string _tenantId;
        private string _authToken;
        private string _sessionId;
        private DateTime _lastHeartbeat;
        private DateTime _lastSuccessfulRequest;
        private long _totalRequests;
        private long _totalFailures;
        private long _consecutiveFailures;
        private int _reconnectAttempt;
        private CancellationTokenSource _wsCancellationToken;
        private readonly object _statsLock = new object();
        
        private const int RECONNECT_INTERVAL_MS = 5000;
        private const int HEARTBEAT_INTERVAL_MS = 30000;
        private const int REQUEST_TIMEOUT_SECONDS = 30;
        private const int WEB_SOCKET_TIMEOUT_SECONDS = 60;
        private const int MAX_RECONNECT_ATTEMPTS = 10;
        private const int MAX_CONSECUTIVE_FAILURES = 5;
        private const int BUFFER_SIZE = 8192;
        private const string USER_AGENT = "BWP-Agent/1.0";
        
        public string ModuleId => "ApiClient";
        public string Version => "1.0.0";
        public string Description => "Cliente HTTP/WebSocket para comunicación con cloud";
        
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;
        public event EventHandler<ConnectionStatusChangedEventArgs> ConnectionStatusChanged;
        
        private ApiClient()
        {
            _logManager = LogManager.Instance;
            
            // Configurar HttpClient para requests normales
            _httpClient = new HttpClient(new HttpClientHandler
            {
                UseDefaultCredentials = false,
                MaxConnectionsPerServer = 100
            })
            {
                Timeout = TimeSpan.FromSeconds(REQUEST_TIMEOUT_SECONDS),
                DefaultRequestHeaders =
                {
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                    UserAgent = { new ProductInfoHeaderValue("BWP-Agent", "1.0") }
                }
            };
            
            // Configurar HttpClient para long-polling (sin timeout)
            _longPollingClient = new HttpClient(new HttpClientHandler
            {
                UseDefaultCredentials = false,
                MaxConnectionsPerServer = 10
            })
            {
                DefaultRequestHeaders =
                {
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                    UserAgent = { new ProductInfoHeaderValue("BWP-Agent", "1.0") }
                }
            };
            
            _wsLock = new SemaphoreSlim(1, 1);
            _httpLock = new SemaphoreSlim(10, 10); // Limitar concurrencia HTTP
            
            _reconnectTimer = new Timer(ReconnectCallback, null, Timeout.Infinite, Timeout.Infinite);
            _heartbeatTimer = new Timer(HeartbeatCallback, null, Timeout.Infinite, Timeout.Infinite);
            
            _endpoints = new Dictionary<string, string>();
            _messageHandlers = new Dictionary<string, Func<string, Task>>();
            _pendingRequests = new Dictionary<string, TaskCompletionSource<string>>();
            
            _isInitialized = false;
            _isConnected = false;
            _isWebSocketConnected = false;
            _reconnectAttempt = 0;
            _wsCancellationToken = new CancellationTokenSource();
        }
        
        /// <summary>
        /// Inicializa el cliente API
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                if (_isInitialized)
                    return ModuleOperationResult.SuccessResult();
                
                // Cargar configuración
                await LoadConfiguration();
                
                // Configurar endpoints
                ConfigureEndpoints();
                
                // Iniciar timers
                _reconnectTimer.Change(TimeSpan.Zero, TimeSpan.FromMilliseconds(RECONNECT_INTERVAL_MS));
                _heartbeatTimer.Change(TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(HEARTBEAT_INTERVAL_MS));
                
                _isInitialized = true;
                
                _logManager.LogInfo("ApiClient inicializado", ModuleId, new Dictionary<string, object>
                {
                    { "baseUrl", _baseUrl },
                    { "deviceId", CryptoHelper.MaskSensitiveData(_deviceId) },
                    { "tenantId", CryptoHelper.MaskSensitiveData(_tenantId) },
                    { "endpoints", _endpoints.Keys }
                });
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando ApiClient: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el cliente API
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            // Conectar WebSocket
            await ConnectWebSocketAsync();
            
            // Conectar HTTP
            await TestHttpConnectionAsync();
            
            _logManager.LogInfo("ApiClient iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene el cliente API
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            // Desconectar WebSocket
            await DisconnectWebSocketAsync();
            
            // Detener timers
            _reconnectTimer.Change(Timeout.Infinite, Timeout.Infinite);
            _heartbeatTimer.Change(Timeout.Infinite, Timeout.Infinite);
            
            _isConnected = false;
            
            _logManager.LogInfo("ApiClient detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Pausa el cliente API
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            await DisconnectWebSocketAsync();
            _isConnected = false;
            
            _logManager.LogInfo("ApiClient pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el cliente API
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            await ConnectWebSocketAsync();
            
            _logManager.LogInfo("ApiClient reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Envía una solicitud HTTP
        /// </summary>
        public async Task<ApiResponse<TResponse>> SendRequestAsync<TResponse>(
            string endpoint, 
            HttpMethod method, 
            object data = null,
            Dictionary<string, string> headers = null,
            int timeoutSeconds = 30)
        {
            var requestId = Guid.NewGuid().ToString();
            
            try
            {
                await _httpLock.WaitAsync();
                
                var url = GetFullUrl(endpoint);
                var request = new HttpRequestMessage(method, url);
                
                // Agregar headers
                AddDefaultHeaders(request.Headers);
                if (headers != null)
                {
                    foreach (var header in headers)
                    {
                        request.Headers.Add(header.Key, header.Value);
                    }
                }
                
                // Agregar cuerpo si hay datos
                if (data != null)
                {
                    var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }
                
                // Configurar timeout
                var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
                
                _logManager.LogDebug($"Enviando request {method} a {endpoint}", ModuleId, new Dictionary<string, object>
                {
                    { "requestId", requestId },
                    { "endpoint", endpoint },
                    { "method", method.Method },
                    { "url", url }
                });
                
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                var response = await _httpClient.SendAsync(request, timeoutCts.Token);
                stopwatch.Stop();
                
                var responseContent = await response.Content.ReadAsStringAsync();
                
                _logManager.LogDebug($"Response recibido de {endpoint}", ModuleId, new Dictionary<string, object>
                {
                    { "requestId", requestId },
                    { "statusCode", (int)response.StatusCode },
                    { "responseTimeMs", stopwatch.ElapsedMilliseconds },
                    { "contentLength", responseContent.Length }
                });
                
                // Actualizar estadísticas
                lock (_statsLock)
                {
                    _totalRequests++;
                    _lastSuccessfulRequest = DateTime.UtcNow;
                    
                    if (response.IsSuccessStatusCode)
                    {
                        _consecutiveFailures = 0;
                    }
                    else
                    {
                        _totalFailures++;
                        _consecutiveFailures++;
                    }
                }
                
                // Procesar respuesta
                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        var result = JsonSerializer.Deserialize<TResponse>(responseContent, new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true
                        });
                        
                        return ApiResponse<TResponse>.Success(result, (int)response.StatusCode);
                    }
                    catch (JsonException ex)
                    {
                        _logManager.LogError($"Error deserializando respuesta: {ex}", ModuleId);
                        return ApiResponse<TResponse>.Error("Error deserializando respuesta", 500);
                    }
                }
                else
                {
                    _logManager.LogError($"Error HTTP {response.StatusCode} en {endpoint}: {responseContent}", 
                        ModuleId, new Dictionary<string, object>
                        {
                            { "requestId", requestId },
                            { "statusCode", (int)response.StatusCode },
                            { "response", responseContent }
                        });
                    
                    return ApiResponse<TResponse>.Error($"HTTP {response.StatusCode}", (int)response.StatusCode);
                }
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                lock (_statsLock)
                {
                    _totalFailures++;
                    _consecutiveFailures++;
                }
                
                _logManager.LogError($"Timeout en request a {endpoint}", ModuleId);
                return ApiResponse<TResponse>.Error("Timeout", 408);
            }
            catch (HttpRequestException ex)
            {
                lock (_statsLock)
                {
                    _totalFailures++;
                    _consecutiveFailures++;
                }
                
                _logManager.LogError($"Error de red en request a {endpoint}: {ex.Message}", ModuleId);
                return ApiResponse<TResponse>.Error($"Error de red: {ex.Message}", 0);
            }
            catch (Exception ex)
            {
                lock (_statsLock)
                {
                    _totalFailures++;
                    _consecutiveFailures++;
                }
                
                _logManager.LogError($"Error inesperado en request a {endpoint}: {ex}", ModuleId);
                return ApiResponse<TResponse>.Error($"Error inesperado: {ex.Message}", 0);
            }
            finally
            {
                _httpLock.Release();
                
                // Verificar si necesitamos reconectar
                if (_consecutiveFailures >= MAX_CONSECUTIVE_FAILURES && _isWebSocketConnected)
                {
                    _logManager.LogWarning($"Muchos fallos consecutivos ({_consecutiveFailures}), reconectando...", ModuleId);
                    await ReconnectAsync();
                }
            }
        }
        
        /// <summary>
        /// Envía un mensaje a través de WebSocket
        /// </summary>
        public async Task<WebSocketResponse> SendWebSocketMessageAsync(string messageType, object data)
        {
            if (!_isWebSocketConnected || _webSocket?.State != WebSocketState.Open)
            {
                return WebSocketResponse.Error("WebSocket no conectado");
            }
            
            var messageId = Guid.NewGuid().ToString();
            
            try
            {
                await _wsLock.WaitAsync();
                
                var message = new
                {
                    messageId,
                    type = messageType,
                    timestamp = DateTime.UtcNow,
                    deviceId = _deviceId,
                    sessionId = _sessionId,
                    data
                };
                
                var json = JsonSerializer.Serialize(message, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                
                var bytes = Encoding.UTF8.GetBytes(json);
                
                await _webSocket.SendAsync(
                    new ArraySegment<byte>(bytes),
                    WebSocketMessageType.Text,
                    true,
                    _wsCancellationToken.Token);
                
                _logManager.LogDebug($"Mensaje WebSocket enviado: {messageType}", ModuleId, new Dictionary<string, object>
                {
                    { "messageId", messageId },
                    { "type", messageType },
                    { "length", bytes.Length }
                });
                
                // Esperar respuesta si es un request/response
                if (messageType.StartsWith("request:"))
                {
                    var tcs = new TaskCompletionSource<string>();
                    _pendingRequests[messageId] = tcs;
                    
                    // Timeout de 30 segundos
                    var timeoutTask = Task.Delay(30000);
                    var completedTask = await Task.WhenAny(tcs.Task, timeoutTask);
                    
                    if (completedTask == tcs.Task)
                    {
                        var response = await tcs.Task;
                        return WebSocketResponse.Success(response);
                    }
                    else
                    {
                        _pendingRequests.Remove(messageId);
                        return WebSocketResponse.Error("Timeout esperando respuesta");
                    }
                }
                
                return WebSocketResponse.Success();
            }
            catch (WebSocketException ex)
            {
                _logManager.LogError($"Error WebSocket enviando mensaje: {ex}", ModuleId);
                await HandleWebSocketError();
                return WebSocketResponse.Error($"WebSocket error: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error enviando mensaje WebSocket: {ex}", ModuleId);
                return WebSocketResponse.Error($"Error: {ex.Message}");
            }
            finally
            {
                _wsLock.Release();
            }
        }
        
        /// <summary>
        /// Registra un manejador de mensajes WebSocket
        /// </summary>
        public void RegisterMessageHandler(string messageType, Func<string, Task> handler)
        {
            _messageHandlers[messageType] = handler;
            _logManager.LogInfo($"Manejador registrado para: {messageType}", ModuleId);
        }
        
        /// <summary>
        /// Sube un archivo al servidor
        /// </summary>
        public async Task<ApiResponse<FileUploadResponse>> UploadFileAsync(
            string endpoint, 
            byte[] fileData, 
            string fileName, 
            string contentType = "application/octet-stream")
        {
            try
            {
                await _httpLock.WaitAsync();
                
                var url = GetFullUrl(endpoint);
                using var content = new MultipartFormDataContent();
                
                var fileContent = new ByteArrayContent(fileData);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue(contentType);
                content.Add(fileContent, "file", fileName);
                
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Content = content;
                AddDefaultHeaders(request.Headers);
                
                var response = await _httpClient.SendAsync(request);
                var responseContent = await response.Content.ReadAsStringAsync();
                
                if (response.IsSuccessStatusCode)
                {
                    var result = JsonSerializer.Deserialize<FileUploadResponse>(responseContent);
                    return ApiResponse<FileUploadResponse>.Success(result, (int)response.StatusCode);
                }
                else
                {
                    return ApiResponse<FileUploadResponse>.Error(
                        $"Upload failed: {response.StatusCode}", 
                        (int)response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error subiendo archivo: {ex}", ModuleId);
                return ApiResponse<FileUploadResponse>.Error($"Upload error: {ex.Message}", 0);
            }
            finally
            {
                _httpLock.Release();
            }
        }
        
        /// <summary>
        /// Descarga un archivo del servidor
        /// </summary>
        public async Task<ApiResponse<byte[]>> DownloadFileAsync(string endpoint)
        {
            try
            {
                await _httpLock.WaitAsync();
                
                var url = GetFullUrl(endpoint);
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                AddDefaultHeaders(request.Headers);
                
                var response = await _httpClient.SendAsync(request);
                
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsByteArrayAsync();
                    return ApiResponse<byte[]>.Success(data, (int)response.StatusCode);
                }
                else
                {
                    return ApiResponse<byte[]>.Error(
                        $"Download failed: {response.StatusCode}", 
                        (int)response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descargando archivo: {ex}", ModuleId);
                return ApiResponse<byte[]>.Error($"Download error: {ex.Message}", 0);
            }
            finally
            {
                _httpLock.Release();
            }
        }
        
        /// <summary>
        /// Realiza long-polling para recibir comandos
        /// </summary>
        public async Task StartLongPollingAsync(string endpoint, CancellationToken cancellationToken = default)
        {
            while (!cancellationToken.IsCancellationRequested && _isConnected)
            {
                try
                {
                    var url = GetFullUrl(endpoint);
                    var request = new HttpRequestMessage(HttpMethod.Get, url);
                    AddDefaultHeaders(request.Headers);
                    
                    // Timeout largo para long-polling
                    var response = await _longPollingClient.SendAsync(request, cancellationToken);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        if (!string.IsNullOrEmpty(content))
                        {
                            await ProcessIncomingMessage(content);
                        }
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                    {
                        // Timeout esperado en long-polling, continuar
                        continue;
                    }
                    else
                    {
                        _logManager.LogError($"Error en long-polling: {response.StatusCode}", ModuleId);
                        await Task.Delay(5000, cancellationToken); // Esperar antes de reintentar
                    }
                }
                catch (TaskCanceledException)
                {
                    // Timeout esperado o cancelación
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en long-polling: {ex}", ModuleId);
                    await Task.Delay(5000, cancellationToken);
                }
            }
        }
        
        /// <summary>
        /// Verifica conectividad con el servidor
        /// </summary>
        public async Task<ConnectivityTestResult> TestConnectivityAsync()
        {
            var results = new List<EndpointTestResult>();
            
            // Probar endpoints principales
            var endpointsToTest = new[]
            {
                "health",
                "api/v1/telemetry/ping",
                "api/v1/device/status"
            };
            
            foreach (var endpoint in endpointsToTest)
            {
                try
                {
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var response = await SendRequestAsync<object>(endpoint, HttpMethod.Get);
                    stopwatch.Stop();
                    
                    results.Add(new EndpointTestResult
                    {
                        Endpoint = endpoint,
                        Success = response.Success,
                        StatusCode = response.StatusCode,
                        ResponseTimeMs = stopwatch.ElapsedMilliseconds,
                        Error = response.Success ? null : response.Error
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new EndpointTestResult
                    {
                        Endpoint = endpoint,
                        Success = false,
                        StatusCode = 0,
                        ResponseTimeMs = 0,
                        Error = ex.Message
                    });
                }
            }
            
            // Probar WebSocket
            var wsResult = new EndpointTestResult
            {
                Endpoint = "websocket",
                Success = _isWebSocketConnected
            };
            
            if (!_isWebSocketConnected)
            {
                wsResult.Error = "WebSocket no conectado";
            }
            
            results.Add(wsResult);
            
            return new ConnectivityTestResult
            {
                Timestamp = DateTime.UtcNow,
                BaseUrl = _baseUrl,
                DeviceId = _deviceId,
                IsConnected = _isConnected,
                IsWebSocketConnected = _isWebSocketConnected,
                EndpointResults = results,
                TotalRequests = _totalRequests,
                TotalFailures = _totalFailures,
                ConsecutiveFailures = _consecutiveFailures
            };
        }
        
        /// <summary>
        /// Verifica salud del cliente API
        /// </summary>
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var connectivity = await TestConnectivityAsync();
                var issues = new List<string>();
                
                // Verificar conectividad HTTP
                var httpSuccessRate = connectivity.EndpointResults
                    .Where(r => r.Endpoint != "websocket")
                    .Count(r => r.Success);
                
                if (httpSuccessRate < connectivity.EndpointResults.Count - 1)
                {
                    issues.Add($"Algunos endpoints HTTP no responden: {httpSuccessRate}/{connectivity.EndpointResults.Count - 1}");
                }
                
                // Verificar WebSocket
                if (!_isWebSocketConnected)
                {
                    issues.Add("WebSocket no conectado");
                }
                
                // Verificar tasa de fallos
                if (_totalRequests > 0)
                {
                    var failureRate = (double)_totalFailures / _totalRequests;
                    if (failureRate > 0.2) // Más del 20% de fallos
                    {
                        issues.Add($"Alta tasa de fallos: {failureRate:P2}");
                    }
                }
                
                // Verificar última comunicación exitosa
                if ((DateTime.UtcNow - _lastSuccessfulRequest).TotalMinutes > 5 && _totalRequests > 0)
                {
                    issues.Add($"Sin comunicación exitosa en {(DateTime.UtcNow - _lastSuccessfulRequest).TotalMinutes:F0} minutos");
                }
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy(
                        $"API Client saludable: {_totalRequests} requests, {connectivity.EndpointResults.Count(r => r.Success)}/{connectivity.EndpointResults.Count} endpoints respondiendo",
                        new Dictionary<string, object>
                        {
                            { "connectivity", connectivity },
                            { "stats", GetStats() }
                        });
                }
                else
                {
                    return HealthCheckResult.Degraded(
                        $"API Client con problemas: {string.Join(", ", issues)}",
                        new Dictionary<string, object>
                        {
                            { "issues", issues },
                            { "connectivity", connectivity },
                            { "stats", GetStats() }
                        });
                }
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error verificando salud de API Client: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "exception", ex.ToString() }
                    });
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del cliente API
        /// </summary>
        public ApiClientStats GetStats()
        {
            lock (_statsLock)
            {
                return new ApiClientStats
                {
                    Timestamp = DateTime.UtcNow,
                    IsInitialized = _isInitialized,
                    IsConnected = _isConnected,
                    IsWebSocketConnected = _isWebSocketConnected,
                    BaseUrl = _baseUrl,
                    DeviceId = _deviceId,
                    SessionId = _sessionId,
                    
                    TotalRequests = _totalRequests,
                    TotalFailures = _totalFailures,
                    ConsecutiveFailures = _consecutiveFailures,
                    LastSuccessfulRequest = _lastSuccessfulRequest,
                    LastHeartbeat = _lastHeartbeat,
                    
                    ReconnectAttempt = _reconnectAttempt,
                    MaxReconnectAttempts = MAX_RECONNECT_ATTEMPTS,
                    MaxConsecutiveFailures = MAX_CONSECUTIVE_FAILURES,
                    
                    MessageHandlersCount = _messageHandlers.Count,
                    PendingRequestsCount = _pendingRequests.Count,
                    EndpointsCount = _endpoints.Count
                };
            }
        }
        
        /// <summary>
        /// Configura credenciales
        /// </summary>
        public void SetCredentials(string deviceId, string tenantId, string authToken, string baseUrl = null)
        {
            _deviceId = deviceId;
            _tenantId = tenantId;
            _authToken = authToken;
            
            if (!string.IsNullOrEmpty(baseUrl))
            {
                _baseUrl = baseUrl;
                ConfigureEndpoints();
            }
            
            _logManager.LogInfo("Credenciales actualizadas", ModuleId, new Dictionary<string, object>
            {
                { "deviceId", CryptoHelper.MaskSensitiveData(deviceId) },
                { "tenantId", CryptoHelper.MaskSensitiveData(tenantId) },
                { "baseUrl", _baseUrl }
            });
        }
        
        /// <summary>
        /// Reinicia la conexión
        /// </summary>
        public async Task ReconnectAsync()
        {
            _logManager.LogInfo("Reconectando API Client...", ModuleId);
            
            await DisconnectWebSocketAsync();
            await Task.Delay(1000);
            await ConnectWebSocketAsync();
            
            _reconnectAttempt = 0;
            _consecutiveFailures = 0;
        }
        
        /// <summary>
        /// Reinicia estadísticas
        /// </summary>
        public void ResetStats()
        {
            lock (_statsLock)
            {
                _totalRequests = 0;
                _totalFailures = 0;
                _consecutiveFailures = 0;
                _lastSuccessfulRequest = DateTime.UtcNow;
            }
            
            _logManager.LogInfo("Estadísticas de API Client reiniciadas", ModuleId);
        }
        
        #region Métodos Privados
        
        private async Task LoadConfiguration()
        {
            // Cargar desde configuración o registro
            _baseUrl = "https://api.bwp-enterprise.com";
            _deviceId = Environment.MachineName;
            _tenantId = "default";
            _authToken = "initial-token"; // En producción, cargar desde almacén seguro
            
            _sessionId = Guid.NewGuid().ToString();
        }
        
        private void ConfigureEndpoints()
        {
            _endpoints.Clear();
            
            _endpoints["health"] = $"{_baseUrl}/health";
            _endpoints["telemetry"] = $"{_baseUrl}/api/v1/telemetry";
            _endpoints["telemetry_batch"] = $"{_baseUrl}/api/v1/telemetry/batch";
            _endpoints["telemetry_ping"] = $"{_baseUrl}/api/v1/telemetry/ping";
            _endpoints["device_register"] = $"{_baseUrl}/api/v1/device/register";
            _endpoints["device_status"] = $"{_baseUrl}/api/v1/device/status";
            _endpoints["policy_get"] = $"{_baseUrl}/api/v1/policy";
            _endpoints["alerts"] = $"{_baseUrl}/api/v1/alerts";
            _endpoints["commands"] = $"{_baseUrl}/api/v1/commands";
            _endpoints["websocket"] = _baseUrl.Replace("https://", "wss://").Replace("http://", "ws://") + "/ws";
        }
        
        private async Task ConnectWebSocketAsync()
        {
            if (_isWebSocketConnected)
                return;
            
            try
            {
                await _wsLock.WaitAsync();
                
                _webSocket?.Dispose();
                _webSocket = new ClientWebSocket();
                
                // Configurar opciones
                _webSocket.Options.SetRequestHeader("User-Agent", USER_AGENT);
                _webSocket.Options.SetRequestHeader("X-Device-Id", _deviceId);
                _webSocket.Options.SetRequestHeader("X-Tenant-Id", _tenantId);
                _webSocket.Options.SetRequestHeader("X-Session-Id", _sessionId);
                
                if (!string.IsNullOrEmpty(_authToken))
                {
                    _webSocket.Options.SetRequestHeader("Authorization", $"Bearer {_authToken}");
                }
                
                var wsUrl = _endpoints["websocket"];
                
                _logManager.LogInfo($"Conectando WebSocket a {wsUrl}", ModuleId);
                
                await _webSocket.ConnectAsync(new Uri(wsUrl), _wsCancellationToken.Token);
                
                _isWebSocketConnected = true;
                _isConnected = true;
                _reconnectAttempt = 0;
                
                // Iniciar recepción de mensajes
                _ = Task.Run(() => ReceiveWebSocketMessagesAsync());
                
                OnConnectionStatusChanged(true, "WebSocket connected");
                
                _logManager.LogInfo("WebSocket conectado exitosamente", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error conectando WebSocket: {ex}", ModuleId);
                _isWebSocketConnected = false;
                _isConnected = false;
                OnConnectionStatusChanged(false, $"WebSocket connection failed: {ex.Message}");
            }
            finally
            {
                _wsLock.Release();
            }
        }
        
        private async Task DisconnectWebSocketAsync()
        {
            if (!_isWebSocketConnected || _webSocket == null)
                return;
            
            try
            {
                await _wsLock.WaitAsync();
                
                if (_webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Client disconnecting",
                        CancellationToken.None);
                }
                
                _webSocket.Dispose();
                _webSocket = null;
                _isWebSocketConnected = false;
                _isConnected = false;
                
                OnConnectionStatusChanged(false, "WebSocket disconnected");
                
                _logManager.LogInfo("WebSocket desconectado", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error desconectando WebSocket: {ex}", ModuleId);
            }
            finally
            {
                _wsLock.Release();
            }
        }
        
        private async Task ReceiveWebSocketMessagesAsync()
        {
            var buffer = new byte[BUFFER_SIZE];
            
            while (_isWebSocketConnected && _webSocket?.State == WebSocketState.Open)
            {
                try
                {
                    var result = await _webSocket.ReceiveAsync(
                        new ArraySegment<byte>(buffer),
                        _wsCancellationToken.Token);
                    
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        _logManager.LogInfo("WebSocket recibió mensaje de cierre", ModuleId);
                        await HandleWebSocketClose(result.CloseStatus, result.CloseStatusDescription);
                        break;
                    }
                    
                    if (result.MessageType == WebSocketMessageType.Text)
                    {
                        var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        
                        // Si el mensaje no está completo, seguir recibiendo
                        if (!result.EndOfMessage)
                        {
                            var fullMessage = new StringBuilder(message);
                            while (!result.EndOfMessage)
                            {
                                result = await _webSocket.ReceiveAsync(
                                    new ArraySegment<byte>(buffer),
                                    _wsCancellationToken.Token);
                                fullMessage.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                            }
                            message = fullMessage.ToString();
                        }
                        
                        await ProcessIncomingMessage(message);
                    }
                }
                catch (WebSocketException ex)
                {
                    _logManager.LogError($"Error WebSocket recibiendo mensaje: {ex}", ModuleId);
                    await HandleWebSocketError();
                    break;
                }
                catch (OperationCanceledException)
                {
                    // Cancelación esperada
                    break;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error recibiendo mensaje WebSocket: {ex}", ModuleId);
                    await Task.Delay(1000); // Esperar antes de reintentar
                }
            }
        }
        
        private async Task ProcessIncomingMessage(string message)
        {
            try
            {
                var json = JsonDocument.Parse(message);
                var root = json.RootElement;
                
                string messageId = null;
                string messageType = null;
                string correlationId = null;
                
                if (root.TryGetProperty("messageId", out var messageIdProp))
                    messageId = messageIdProp.GetString();
                
                if (root.TryGetProperty("type", out var typeProp))
                    messageType = typeProp.GetString();
                
                if (root.TryGetProperty("correlationId", out var correlationIdProp))
                    correlationId = correlationIdProp.GetString();
                
                _logManager.LogDebug($"Mensaje WebSocket recibido: {messageType}", ModuleId, new Dictionary<string, object>
                {
                    { "messageId", messageId },
                    { "type", messageType },
                    { "length", message.Length }
                });
                
                // Procesar según tipo
                if (!string.IsNullOrEmpty(correlationId) && _pendingRequests.TryGetValue(correlationId, out var tcs))
                {
                    // Es respuesta a un request pendiente
                    tcs.SetResult(message);
                    _pendingRequests.Remove(correlationId);
                }
                else if (!string.IsNullOrEmpty(messageType) && _messageHandlers.TryGetValue(messageType, out var handler))
                {
                    // Tiene manejador registrado
                    await handler(message);
                }
                else
                {
                    // Disparar evento genérico
                    OnMessageReceived(messageType, message);
                }
                
                // Actualizar último heartbeat
                _lastHeartbeat = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error procesando mensaje WebSocket: {ex}", ModuleId);
            }
        }
        
        private async Task HandleWebSocketClose(WebSocketCloseStatus? closeStatus, string description)
        {
            _logManager.LogInfo($"WebSocket cerrado: {closeStatus} - {description}", ModuleId);
            
            _isWebSocketConnected = false;
            _isConnected = false;
            
            OnConnectionStatusChanged(false, $"WebSocket closed: {closeStatus}");
            
            // Intentar reconectar si no fue un cierre normal
            if (closeStatus != WebSocketCloseStatus.NormalClosure)
            {
                await Task.Delay(RECONNECT_INTERVAL_MS);
                await ConnectWebSocketAsync();
            }
        }
        
        private async Task HandleWebSocketError()
        {
            _logManager.LogWarning("Error de WebSocket, reconectando...", ModuleId);
            
            _isWebSocketConnected = false;
            _isConnected = false;
            
            OnConnectionStatusChanged(false, "WebSocket error");
            
            await Task.Delay(RECONNECT_INTERVAL_MS);
            await ConnectWebSocketAsync();
        }
        
        private async Task TestHttpConnectionAsync()
        {
            try
            {
                var response = await SendRequestAsync<object>("health", HttpMethod.Get);
                _isConnected = response.Success;
                
                if (_isConnected)
                {
                    _logManager.LogInfo("Conexión HTTP verificada", ModuleId);
                }
                else
                {
                    _logManager.LogWarning("No se pudo verificar conexión HTTP", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando conexión HTTP: {ex}", ModuleId);
                _isConnected = false;
            }
        }
        
        private async void ReconnectCallback(object state)
        {
            if (_isWebSocketConnected && _isConnected)
                return;
            
            if (_reconnectAttempt >= MAX_RECONNECT_ATTEMPTS)
            {
                _logManager.LogError($"Máximo de intentos de reconexión alcanzado ({MAX_RECONNECT_ATTEMPTS})", ModuleId);
                _reconnectTimer.Change(Timeout.Infinite, Timeout.Infinite);
                return;
            }
            
            _reconnectAttempt++;
            
            _logManager.LogInfo($"Intento de reconexión {_reconnectAttempt}/{MAX_RECONNECT_ATTEMPTS}", ModuleId);
            
            if (!_isWebSocketConnected)
            {
                await ConnectWebSocketAsync();
            }
            
            if (!_isConnected)
            {
                await TestHttpConnectionAsync();
            }
        }
        
        private async void HeartbeatCallback(object state)
        {
            if (!_isWebSocketConnected)
                return;
            
            try
            {
                // Enviar heartbeat
                await SendWebSocketMessageAsync("heartbeat", new
                {
                    timestamp = DateTime.UtcNow,
                    agentVersion = Version,
                    memoryUsage = Environment.WorkingSet
                });
                
                // Verificar si el último heartbeat fue hace mucho
                if ((DateTime.UtcNow - _lastHeartbeat).TotalSeconds > HEARTBEAT_INTERVAL_MS * 2)
                {
                    _logManager.LogWarning($"Sin heartbeat en {(DateTime.UtcNow - _lastHeartbeat).TotalSeconds:F0}s, reconectando...", ModuleId);
                    await ReconnectAsync();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en heartbeat: {ex}", ModuleId);
            }
        }
        
        private string GetFullUrl(string endpoint)
        {
            if (_endpoints.TryGetValue(endpoint, out var fullUrl))
                return fullUrl;
            
            // Si no está en el diccionario, asumir que es una ruta relativa
            return $"{_baseUrl}/{endpoint.TrimStart('/')}";
        }
        
        private void AddDefaultHeaders(HttpRequestHeaders headers)
        {
            headers.Add("X-Device-Id", _deviceId);
            headers.Add("X-Tenant-Id", _tenantId);
            headers.Add("X-Session-Id", _sessionId);
            headers.Add("X-Request-Id", Guid.NewGuid().ToString());
            headers.Add("X-Agent-Version", Version);
            
            if (!string.IsNullOrEmpty(_authToken))
            {
                headers.Authorization = new AuthenticationHeaderValue("Bearer", _authToken);
            }
        }
        
        private void OnMessageReceived(string messageType, string message)
        {
            MessageReceived?.Invoke(this, new MessageReceivedEventArgs
            {
                MessageType = messageType,
                Message = message,
                Timestamp = DateTime.UtcNow
            });
        }
        
        private void OnConnectionStatusChanged(bool connected, string reason)
        {
            ConnectionStatusChanged?.Invoke(this, new ConnectionStatusChangedEventArgs
            {
                IsConnected = connected,
                Reason = reason,
                Timestamp = DateTime.UtcNow
            });
        }
        
        #endregion
        
        #region Clases y Enums de Soporte
        
        public class ApiResponse<T>
        {
            public bool Success { get; set; }
            public T Data { get; set; }
            public string Error { get; set; }
            public int StatusCode { get; set; }
            public Dictionary<string, object> Metadata { get; set; }
            
            public static ApiResponse<T> Success(T data, int statusCode = 200)
            {
                return new ApiResponse<T>
                {
                    Success = true,
                    Data = data,
                    StatusCode = statusCode,
                    Metadata = new Dictionary<string, object>()
                };
            }
            
            public static ApiResponse<T> Error(string error, int statusCode = 0)
            {
                return new ApiResponse<T>
                {
                    Success = false,
                    Error = error,
                    StatusCode = statusCode,
                    Metadata = new Dictionary<string, object>()
                };
            }
        }
        
        public class WebSocketResponse
        {
            public bool Success { get; set; }
            public string Data { get; set; }
            public string Error { get; set; }
            
            public static WebSocketResponse Success(string data = null)
            {
                return new WebSocketResponse
                {
                    Success = true,
                    Data = data
                };
            }
            
            public static WebSocketResponse Error(string error)
            {
                return new WebSocketResponse
                {
                    Success = false,
                    Error = error
                };
            }
        }
        
        public class FileUploadResponse
        {
            public string FileId { get; set; }
            public string FileUrl { get; set; }
            public long FileSize { get; set; }
            public string ContentType { get; set; }
            public DateTime UploadedAt { get; set; }
        }
        
        public class ConnectivityTestResult
        {
            public DateTime Timestamp { get; set; }
            public string BaseUrl { get; set; }
            public string DeviceId { get; set; }
            public bool IsConnected { get; set; }
            public bool IsWebSocketConnected { get; set; }
            public List<EndpointTestResult> EndpointResults { get; set; }
            public long TotalRequests { get; set; }
            public long TotalFailures { get; set; }
            public long ConsecutiveFailures { get; set; }
        }
        
        public class EndpointTestResult
        {
            public string Endpoint { get; set; }
            public bool Success { get; set; }
            public int StatusCode { get; set; }
            public long ResponseTimeMs { get; set; }
            public string Error { get; set; }
        }
        
        public class ApiClientStats
        {
            public DateTime Timestamp { get; set; }
            public bool IsInitialized { get; set; }
            public bool IsConnected { get; set; }
            public bool IsWebSocketConnected { get; set; }
            public string BaseUrl { get; set; }
            public string DeviceId { get; set; }
            public string SessionId { get; set; }
            
            public long TotalRequests { get; set; }
            public long TotalFailures { get; set; }
            public long ConsecutiveFailures { get; set; }
            public DateTime LastSuccessfulRequest { get; set; }
            public DateTime LastHeartbeat { get; set; }
            
            public int ReconnectAttempt { get; set; }
            public int MaxReconnectAttempts { get; set; }
            public int MaxConsecutiveFailures { get; set; }
            
            public int MessageHandlersCount { get; set; }
            public int PendingRequestsCount { get; set; }
            public int EndpointsCount { get; set; }
        }
        
        public class MessageReceivedEventArgs : EventArgs
        {
            public string MessageType { get; set; }
            public string Message { get; set; }
            public DateTime Timestamp { get; set; }
        }
        
        public class ConnectionStatusChangedEventArgs : EventArgs
        {
            public bool IsConnected { get; set; }
            public string Reason { get; set; }
            public DateTime Timestamp { get; set; }
        }
        
        #endregion
    }
}