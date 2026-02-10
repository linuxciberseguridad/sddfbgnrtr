using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.TenantManagement;
using BWP.Enterprise.Cloud.DeviceRegistry;

namespace BWP.Enterprise.Cloud.Api
{
    /// <summary>
    /// Servidor WebSocket para comunicación bidireccional en tiempo real
    /// Maneja conexiones persistentes para telemetría, alertas y comandos
    /// </summary>
    public class WebSocketServer : IWebSocketServer
    {
        private readonly ILogger<WebSocketServer> _logger;
        private readonly ITenantManager _tenantManager;
        private readonly IDeviceRegistry _deviceRegistry;
        private readonly ConcurrentDictionary<string, WebSocketConnection> _connections;
        private readonly ConcurrentDictionary<string, List<string>> _tenantConnections;
        private readonly ConcurrentDictionary<string, List<string>> _deviceConnections;
        private readonly Timer _healthCheckTimer;
        private readonly Timer _cleanupTimer;
        private bool _isRunning;
        
        private const int RECEIVE_BUFFER_SIZE = 4096;
        private const int MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
        private const int HEALTH_CHECK_INTERVAL_MS = 30000; // 30 segundos
        private const int CLEANUP_INTERVAL_MS = 60000; // 1 minuto
        private const int PING_INTERVAL_MS = 25000; // 25 segundos
        private const int CONNECTION_TIMEOUT_MS = 30000; // 30 segundos sin actividad
        
        public WebSocketServer(
            ILogger<WebSocketServer> logger,
            ITenantManager tenantManager,
            IDeviceRegistry deviceRegistry)
        {
            _logger = logger;
            _tenantManager = tenantManager;
            _deviceRegistry = deviceRegistry;
            _connections = new ConcurrentDictionary<string, WebSocketConnection>();
            _tenantConnections = new ConcurrentDictionary<string, List<string>>();
            _deviceConnections = new ConcurrentDictionary<string, List<string>>();
            _isRunning = false;
            
            // Inicializar timers
            _healthCheckTimer = new Timer(HealthCheckCallback, null, Timeout.Infinite, Timeout.Infinite);
            _cleanupTimer = new Timer(CleanupCallback, null, Timeout.Infinite, Timeout.Infinite);
        }
        
        /// <summary>
        /// Inicia el servidor WebSocket
        /// </summary>
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_isRunning)
                return Task.CompletedTask;
            
            _isRunning = true;
            
            // Iniciar timers
            _healthCheckTimer.Change(TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(HEALTH_CHECK_INTERVAL_MS));
            _cleanupTimer.Change(TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(CLEANUP_INTERVAL_MS));
            
            _logger.LogInformation("WebSocket server iniciado");
            return Task.CompletedTask;
        }
        
        /// <summary>
        /// Detiene el servidor WebSocket
        /// </summary>
        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            if (!_isRunning)
                return;
            
            _isRunning = false;
            
            // Detener timers
            _healthCheckTimer.Change(Timeout.Infinite, Timeout.Infinite);
            _cleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
            
            // Cerrar todas las conexiones
            await CloseAllConnectionsAsync(cancellationToken);
            
            _logger.LogInformation("WebSocket server detenido");
        }
        
        /// <summary>
        /// Maneja una solicitud WebSocket entrante
        /// </summary>
        public async Task HandleWebSocketRequestAsync(HttpContext context)
        {
            if (!context.WebSockets.IsWebSocketRequest)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Expected WebSocket request");
                return;
            }
            
            WebSocket webSocket = null;
            WebSocketConnection connection = null;
            
            try
            {
                // 1. Aceptar conexión WebSocket
                webSocket = await context.WebSockets.AcceptWebSocketAsync();
                
                // 2. Autenticar y autorizar
                var authResult = await AuthenticateConnectionAsync(context, webSocket);
                if (!authResult.IsAuthenticated)
                {
                    await CloseWithErrorAsync(webSocket, authResult.ErrorMessage, 
                        WebSocketCloseStatus.PolicyViolation, cancellationToken: default);
                    return;
                }
                
                // 3. Crear objeto de conexión
                connection = CreateConnection(webSocket, authResult, context.Connection);
                
                // 4. Registrar conexión
                if (!RegisterConnection(connection))
                {
                    await CloseWithErrorAsync(webSocket, "Too many connections", 
                        WebSocketCloseStatus.PolicyViolation, cancellationToken: default);
                    return;
                }
                
                _logger.LogInformation(
                    "Conexión WebSocket establecida: ConnectionId={ConnectionId}, Tenant={TenantId}, Device={DeviceId}, User={UserId}",
                    connection.ConnectionId, connection.TenantId, connection.DeviceId, connection.UserId);
                
                // 5. Manejar comunicación
                await HandleConnectionCommunicationAsync(connection);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error manejando solicitud WebSocket");
                
                if (webSocket != null && webSocket.State == WebSocketState.Open)
                {
                    await CloseWithErrorAsync(webSocket, "Internal server error", 
                        WebSocketCloseStatus.InternalServerError, cancellationToken: default);
                }
            }
            finally
            {
                // 6. Limpiar recursos
                if (connection != null)
                {
                    await CleanupConnectionAsync(connection);
                }
            }
        }
        
        /// <summary>
        /// Envía un mensaje a un tenant específico
        /// </summary>
        public async Task<bool> SendToTenantAsync(
            string tenantId, 
            WebSocketMessage message,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(tenantId) || message == null)
                return false;
            
            try
            {
                if (!_tenantConnections.TryGetValue(tenantId, out var connectionIds))
                {
                    _logger.LogDebug("No hay conexiones activas para el tenant {TenantId}", tenantId);
                    return false;
                }
                
                var tasks = new List<Task<bool>>();
                var sentCount = 0;
                
                foreach (var connectionId in connectionIds)
                {
                    if (_connections.TryGetValue(connectionId, out var connection))
                    {
                        tasks.Add(SendToConnectionAsync(connection, message, cancellationToken));
                    }
                }
                
                var results = await Task.WhenAll(tasks);
                sentCount = results.Count(r => r);
                
                _logger.LogDebug("Mensaje enviado a {Sent}/{Total} conexiones del tenant {TenantId}", 
                    sentCount, connectionIds.Count, tenantId);
                
                return sentCount > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando mensaje al tenant {TenantId}", tenantId);
                return false;
            }
        }
        
        /// <summary>
        /// Envía un mensaje a un dispositivo específico
        /// </summary>
        public async Task<bool> SendToDeviceAsync(
            string tenantId, 
            string deviceId, 
            WebSocketMessage message,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(deviceId) || message == null)
                return false;
            
            try
            {
                var deviceKey = $"{tenantId}:{deviceId}";
                if (!_deviceConnections.TryGetValue(deviceKey, out var connectionIds))
                {
                    _logger.LogDebug("No hay conexiones activas para el dispositivo {DeviceId} del tenant {TenantId}", 
                        deviceId, tenantId);
                    return false;
                }
                
                var tasks = new List<Task<bool>>();
                
                foreach (var connectionId in connectionIds)
                {
                    if (_connections.TryGetValue(connectionId, out var connection))
                    {
                        tasks.Add(SendToConnectionAsync(connection, message, cancellationToken));
                    }
                }
                
                var results = await Task.WhenAll(tasks);
                var sentCount = results.Count(r => r);
                
                _logger.LogDebug("Mensaje enviado a {Sent}/{Total} conexiones del dispositivo {DeviceId}", 
                    sentCount, connectionIds.Count, deviceId);
                
                return sentCount > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando mensaje al dispositivo {DeviceId}", deviceId);
                return false;
            }
        }
        
        /// <summary>
        /// Envía un mensaje a una conexión específica
        /// </summary>
        public async Task<bool> SendToConnectionAsync(
            string connectionId, 
            WebSocketMessage message,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(connectionId) || message == null)
                return false;
            
            try
            {
                if (!_connections.TryGetValue(connectionId, out var connection))
                {
                    _logger.LogWarning("Conexión no encontrada: {ConnectionId}", connectionId);
                    return false;
                }
                
                return await SendToConnectionAsync(connection, message, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando mensaje a la conexión {ConnectionId}", connectionId);
                return false;
            }
        }
        
        /// <summary>
        /// Transmite un mensaje a todas las conexiones
        /// </summary>
        public async Task<int> BroadcastAsync(
            WebSocketMessage message,
            Func<WebSocketConnection, bool> filter = null,
            CancellationToken cancellationToken = default)
        {
            if (message == null)
                return 0;
            
            try
            {
                var tasks = new List<Task<bool>>();
                var connectionCount = 0;
                
                foreach (var connection in _connections.Values)
                {
                    if (filter == null || filter(connection))
                    {
                        tasks.Add(SendToConnectionAsync(connection, message, cancellationToken));
                        connectionCount++;
                    }
                }
                
                var results = await Task.WhenAll(tasks);
                var sentCount = results.Count(r => r);
                
                _logger.LogDebug("Mensaje transmitido a {Sent}/{Total} conexiones", 
                    sentCount, connectionCount);
                
                return sentCount;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error transmitiendo mensaje");
                return 0;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del servidor
        /// </summary>
        public WebSocketServerStats GetStats()
        {
            return new WebSocketServerStats
            {
                Timestamp = DateTime.UtcNow,
                IsRunning = _isRunning,
                TotalConnections = _connections.Count,
                TotalTenants = _tenantConnections.Count,
                TotalDevices = _deviceConnections.Count,
                ConnectionsByTenant = _tenantConnections.ToDictionary(kv => kv.Key, kv => kv.Value.Count),
                ConnectionsByStatus = GetConnectionsByStatus()
            };
        }
        
        /// <summary>
        /// Cierra conexiones inactivas
        /// </summary>
        public async Task<int> CloseInactiveConnectionsAsync(TimeSpan maxInactivity)
        {
            var cutoff = DateTime.UtcNow - maxInactivity;
            var inactiveConnections = _connections.Values
                .Where(c => c.LastActivity < cutoff)
                .ToList();
            
            var closedCount = 0;
            
            foreach (var connection in inactiveConnections)
            {
                try
                {
                    if (connection.WebSocket.State == WebSocketState.Open)
                    {
                        await connection.WebSocket.CloseAsync(
                            WebSocketCloseStatus.NormalClosure,
                            "Connection inactive",
                            CancellationToken.None);
                        
                        closedCount++;
                        
                        _logger.LogInformation(
                            "Conexión inactiva cerrada: ConnectionId={ConnectionId}, InactiveFor={InactiveSeconds}s",
                            connection.ConnectionId, (DateTime.UtcNow - connection.LastActivity).TotalSeconds);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error cerrando conexión inactiva {ConnectionId}", connection.ConnectionId);
                }
            }
            
            return closedCount;
        }
        
        #region Métodos privados
        
        private async Task<AuthenticationResult> AuthenticateConnectionAsync(HttpContext context, WebSocket webSocket)
        {
            try
            {
                // 1. Extraer token del query string o headers
                var token = ExtractTokenFromRequest(context);
                if (string.IsNullOrEmpty(token))
                {
                    return AuthenticationResult.Failed("Authentication token not provided");
                }
                
                // 2. Extraer tenantId
                var tenantId = ExtractTenantIdFromRequest(context);
                if (string.IsNullOrEmpty(tenantId))
                {
                    return AuthenticationResult.Failed("Tenant ID not provided");
                }
                
                // 3. Validar token
                var validationResult = await _tenantManager.ValidateTokenAsync(token, tenantId);
                if (!validationResult.IsValid)
                {
                    return AuthenticationResult.Failed($"Invalid token: {validationResult.ErrorMessage}");
                }
                
                // 4. Verificar permisos para WebSocket
                var hasPermission = await _tenantManager.CheckPermissionAsync(
                    validationResult.TenantId,
                    validationResult.UserId,
                    "/api/ws",
                    "CONNECT");
                
                if (!hasPermission)
                {
                    return AuthenticationResult.Failed("Permission denied for WebSocket connection");
                }
                
                // 5. Extraer deviceId si es conexión de dispositivo
                var deviceId = ExtractDeviceIdFromRequest(context);
                
                return AuthenticationResult.Success(
                    validationResult.TenantId,
                    validationResult.UserId,
                    validationResult.Roles,
                    validationResult.Claims,
                    deviceId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error autenticando conexión WebSocket");
                return AuthenticationResult.Failed($"Authentication error: {ex.Message}");
            }
        }
        
        private WebSocketConnection CreateConnection(
            WebSocket webSocket, 
            AuthenticationResult authResult,
            ConnectionInfo connectionInfo)
        {
            var connectionId = Guid.NewGuid().ToString();
            
            return new WebSocketConnection
            {
                ConnectionId = connectionId,
                WebSocket = webSocket,
                TenantId = authResult.TenantId,
                UserId = authResult.UserId,
                DeviceId = authResult.DeviceId,
                Roles = authResult.Roles,
                Claims = authResult.Claims,
                RemoteIpAddress = connectionInfo.RemoteIpAddress?.ToString(),
                ConnectedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                IsAuthenticated = true,
                MessageCount = 0,
                LastPingSent = null,
                LastPongReceived = null
            };
        }
        
        private bool RegisterConnection(WebSocketConnection connection)
        {
            try
            {
                // Registrar en diccionario principal
                if (!_connections.TryAdd(connection.ConnectionId, connection))
                {
                    _logger.LogError("No se pudo registrar conexión {ConnectionId}", connection.ConnectionId);
                    return false;
                }
                
                // Registrar por tenant
                _tenantConnections.AddOrUpdate(connection.TenantId,
                    new List<string> { connection.ConnectionId },
                    (key, existingList) =>
                    {
                        existingList.Add(connection.ConnectionId);
                        return existingList;
                    });
                
                // Registrar por dispositivo si aplica
                if (!string.IsNullOrEmpty(connection.DeviceId))
                {
                    var deviceKey = $"{connection.TenantId}:{connection.DeviceId}";
                    _deviceConnections.AddOrUpdate(deviceKey,
                        new List<string> { connection.ConnectionId },
                        (key, existingList) =>
                        {
                            existingList.Add(connection.ConnectionId);
                            return existingList;
                        });
                }
                
                _logger.LogDebug("Conexión registrada: {ConnectionId} (Tenant: {TenantId}, Device: {DeviceId})", 
                    connection.ConnectionId, connection.TenantId, connection.DeviceId);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando conexión {ConnectionId}", connection.ConnectionId);
                return false;
            }
        }
        
        private async Task HandleConnectionCommunicationAsync(WebSocketConnection connection)
        {
            var buffer = new byte[RECEIVE_BUFFER_SIZE];
            var receiveBuffer = new List<byte>();
            
            try
            {
                while (connection.WebSocket.State == WebSocketState.Open && _isRunning)
                {
                    var result = await connection.WebSocket.ReceiveAsync(
                        new ArraySegment<byte>(buffer), CancellationToken.None);
                    
                    connection.LastActivity = DateTime.UtcNow;
                    
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await HandleCloseMessageAsync(connection, result);
                        break;
                    }
                    
                    // Acumular datos del mensaje
                    receiveBuffer.AddRange(buffer.Take(result.Count));
                    
                    // Si es el final del mensaje, procesarlo
                    if (result.EndOfMessage)
                    {
                        await ProcessMessageAsync(connection, receiveBuffer.ToArray(), result.MessageType);
                        receiveBuffer.Clear();
                    }
                    
                    // Verificar tamaño del buffer
                    if (receiveBuffer.Count > MAX_MESSAGE_SIZE)
                    {
                        _logger.LogWarning("Mensaje demasiado grande de {ConnectionId}, cerrando conexión", 
                            connection.ConnectionId);
                        await CloseWithErrorAsync(connection.WebSocket, "Message too large", 
                            WebSocketCloseStatus.MessageTooBig, CancellationToken.None);
                        break;
                    }
                }
            }
            catch (WebSocketException ex)
            {
                _logger.LogWarning(ex, "Error WebSocket en conexión {ConnectionId}", connection.ConnectionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error manejando comunicación de conexión {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task ProcessMessageAsync(
            WebSocketConnection connection, 
            byte[] messageData, 
            WebSocketMessageType messageType)
        {
            try
            {
                connection.MessageCount++;
                
                if (messageType == WebSocketMessageType.Text)
                {
                    var messageText = Encoding.UTF8.GetString(messageData);
                    await ProcessTextMessageAsync(connection, messageText);
                }
                else if (messageType == WebSocketMessageType.Binary)
                {
                    await ProcessBinaryMessageAsync(connection, messageData);
                }
                // Ping/Pong son manejados automáticamente por ASP.NET Core
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando mensaje de conexión {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task ProcessTextMessageAsync(WebSocketConnection connection, string messageText)
        {
            try
            {
                var message = JsonSerializer.Deserialize<WebSocketMessage>(messageText, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                if (message == null)
                {
                    _logger.LogWarning("Mensaje inválido de conexión {ConnectionId}", connection.ConnectionId);
                    return;
                }
                
                // Actualizar metadata de conexión si es necesario
                if (!string.IsNullOrEmpty(message.DeviceId))
                {
                    connection.DeviceId = message.DeviceId;
                }
                
                // Procesar según tipo de mensaje
                switch (message.MessageType?.ToUpperInvariant())
                {
                    case "PING":
                        await HandlePingMessageAsync(connection, message);
                        break;
                        
                    case "TELEMETRY":
                        await HandleTelemetryMessageAsync(connection, message);
                        break;
                        
                    case "ALERT":
                        await HandleAlertMessageAsync(connection, message);
                        break;
                        
                    case "COMMAND":
                        await HandleCommandMessageAsync(connection, message);
                        break;
                        
                    case "SUBSCRIBE":
                        await HandleSubscribeMessageAsync(connection, message);
                        break;
                        
                    case "UNSUBSCRIBE":
                        await HandleUnsubscribeMessageAsync(connection, message);
                        break;
                        
                    default:
                        _logger.LogDebug("Mensaje de tipo desconocido: {MessageType} de {ConnectionId}", 
                            message.MessageType, connection.ConnectionId);
                        break;
                }
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Mensaje JSON inválido de conexión {ConnectionId}", connection.ConnectionId);
                
                // Enviar error al cliente
                await SendToConnectionAsync(connection, new WebSocketMessage
                {
                    MessageId = Guid.NewGuid().ToString(),
                    MessageType = "ERROR",
                    Timestamp = DateTime.UtcNow,
                    Data = new Dictionary<string, object>
                    {
                        { "error", "Invalid message format" },
                        { "details", ex.Message }
                    }
                }, CancellationToken.None);
            }
        }
        
        private async Task ProcessBinaryMessageAsync(WebSocketConnection connection, byte[] messageData)
        {
            // Procesar mensaje binario (por ejemplo, datos comprimidos)
            try
            {
                // Implementar lógica específica para mensajes binarios
                _logger.LogDebug("Mensaje binario recibido de {ConnectionId}, tamaño: {Size} bytes", 
                    connection.ConnectionId, messageData.Length);
                
                // Por ahora, solo registrar
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando mensaje binario de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task HandlePingMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Responder con pong
            await SendToConnectionAsync(connection, new WebSocketMessage
            {
                MessageId = message.MessageId,
                MessageType = "PONG",
                Timestamp = DateTime.UtcNow,
                Data = new Dictionary<string, object>
                {
                    { "timestamp", DateTime.UtcNow },
                    { "server_time", DateTime.UtcNow }
                }
            }, CancellationToken.None);
        }
        
        private async Task HandleTelemetryMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Procesar telemetría del dispositivo
            try
            {
                // Validar que sea un dispositivo
                if (string.IsNullOrEmpty(connection.DeviceId))
                {
                    _logger.LogWarning("Telemetría recibida de conexión no dispositivo: {ConnectionId}", 
                        connection.ConnectionId);
                    return;
                }
                
                // Aquí se procesaría la telemetría
                // Por ahora, solo registrar
                _logger.LogDebug("Telemetría recibida de dispositivo {DeviceId}: {Data}", 
                    connection.DeviceId, message.Data?.ToString());
                
                // Reenviar a otras conexiones interesadas en este dispositivo
                await BroadcastTelemetryAsync(connection, message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando telemetría de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task HandleAlertMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Procesar alerta
            try
            {
                // Aquí se procesarían las alertas
                _logger.LogDebug("Alerta recibida de {ConnectionId}: {Data}", 
                    connection.ConnectionId, message.Data?.ToString());
                
                // Reenviar a otras conexiones del mismo tenant
                await SendToTenantAsync(connection.TenantId, message, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando alerta de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task HandleCommandMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Procesar comando
            try
            {
                // Validar permisos para comandos
                if (!connection.Roles.Contains("Administrator") && 
                    !connection.Roles.Contains("DeviceManager"))
                {
                    _logger.LogWarning("Intento de comando no autorizado de {ConnectionId}", connection.ConnectionId);
                    
                    await SendToConnectionAsync(connection, new WebSocketMessage
                    {
                        MessageId = message.MessageId,
                        MessageType = "COMMAND_RESPONSE",
                        Timestamp = DateTime.UtcNow,
                        Data = new Dictionary<string, object>
                        {
                            { "success", false },
                            { "error", "Permission denied" }
                        }
                    }, CancellationToken.None);
                    
                    return;
                }
                
                // Procesar comando específico
                var command = message.Data?["command"]?.ToString();
                var parameters = message.Data?["parameters"] as Dictionary<string, object>;
                
                _logger.LogInformation("Comando recibido: {Command} de {ConnectionId}", 
                    command, connection.ConnectionId);
                
                // Aquí se ejecutaría el comando
                // Por ahora, solo responder
                await SendToConnectionAsync(connection, new WebSocketMessage
                {
                    MessageId = message.MessageId,
                    MessageType = "COMMAND_RESPONSE",
                    Timestamp = DateTime.UtcNow,
                    Data = new Dictionary<string, object>
                    {
                        { "success", true },
                        { "command", command },
                        { "executed_at", DateTime.UtcNow },
                        { "result", "Command processed" }
                    }
                }, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando comando de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task HandleSubscribeMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Manejar suscripciones a canales/tópicos
            try
            {
                var channels = message.Data?["channels"] as List<string>;
                if (channels == null || !channels.Any())
                {
                    return;
                }
                
                // Registrar suscripciones
                foreach (var channel in channels)
                {
                    connection.SubscribedChannels.Add(channel);
                }
                
                _logger.LogDebug("Suscripción de {ConnectionId} a canales: {Channels}", 
                    connection.ConnectionId, string.Join(", ", channels));
                
                await SendToConnectionAsync(connection, new WebSocketMessage
                {
                    MessageId = message.MessageId,
                    MessageType = "SUBSCRIBE_RESPONSE",
                    Timestamp = DateTime.UtcNow,
                    Data = new Dictionary<string, object>
                    {
                        { "success", true },
                        { "channels", channels },
                        { "subscribed_at", DateTime.UtcNow }
                    }
                }, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando suscripción de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task HandleUnsubscribeMessageAsync(WebSocketConnection connection, WebSocketMessage message)
        {
            // Manejar cancelación de suscripciones
            try
            {
                var channels = message.Data?["channels"] as List<string>;
                if (channels == null)
                {
                    // Cancelar todas las suscripciones
                    connection.SubscribedChannels.Clear();
                }
                else
                {
                    foreach (var channel in channels)
                    {
                        connection.SubscribedChannels.Remove(channel);
                    }
                }
                
                _logger.LogDebug("Cancelación de suscripción de {ConnectionId}", connection.ConnectionId);
                
                await SendToConnectionAsync(connection, new WebSocketMessage
                {
                    MessageId = message.MessageId,
                    MessageType = "UNSUBSCRIBE_RESPONSE",
                    Timestamp = DateTime.UtcNow,
                    Data = new Dictionary<string, object>
                    {
                        { "success", true },
                        { "channels", channels },
                        { "unsubscribed_at", DateTime.UtcNow }
                    }
                }, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando cancelación de suscripción de {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task BroadcastTelemetryAsync(WebSocketConnection senderConnection, WebSocketMessage message)
        {
            // Encontrar conexiones suscritas a telemetría de este dispositivo
            var subscriberConnections = _connections.Values
                .Where(c => c.ConnectionId != senderConnection.ConnectionId && // No enviar al emisor
                           c.TenantId == senderConnection.TenantId && // Mismo tenant
                           c.SubscribedChannels.Contains($"telemetry:{senderConnection.DeviceId}"))
                .ToList();
            
            if (!subscriberConnections.Any())
                return;
            
            // Enviar a cada suscriptor
            foreach (var connection in subscriberConnections)
            {
                await SendToConnectionAsync(connection, message, CancellationToken.None);
            }
        }
        
        private async Task<bool> SendToConnectionAsync(
            WebSocketConnection connection, 
            WebSocketMessage message,
            CancellationToken cancellationToken)
        {
            if (connection.WebSocket.State != WebSocketState.Open)
            {
                _logger.LogDebug("Conexión {ConnectionId} no está abierta, estado: {State}", 
                    connection.ConnectionId, connection.WebSocket.State);
                return false;
            }
            
            try
            {
                var messageJson = JsonSerializer.Serialize(message);
                var messageBytes = Encoding.UTF8.GetBytes(messageJson);
                
                await connection.WebSocket.SendAsync(
                    new ArraySegment<byte>(messageBytes),
                    WebSocketMessageType.Text,
                    endOfMessage: true,
                    cancellationToken);
                
                connection.LastActivity = DateTime.UtcNow;
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando mensaje a conexión {ConnectionId}", connection.ConnectionId);
                return false;
            }
        }
        
        private async Task HandleCloseMessageAsync(WebSocketConnection connection, WebSocketReceiveResult result)
        {
            try
            {
                if (connection.WebSocket.State == WebSocketState.Open)
                {
                    await connection.WebSocket.CloseAsync(
                        result.CloseStatus ?? WebSocketCloseStatus.NormalClosure,
                        result.CloseStatusDescription ?? "Client closed connection",
                        CancellationToken.None);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cerrando conexión {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task CloseWithErrorAsync(
            WebSocket webSocket, 
            string reason, 
            WebSocketCloseStatus closeStatus,
            CancellationToken cancellationToken)
        {
            try
            {
                if (webSocket.State == WebSocketState.Open)
                {
                    await webSocket.CloseAsync(closeStatus, reason, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cerrando WebSocket con error");
            }
        }
        
        private async Task CleanupConnectionAsync(WebSocketConnection connection)
        {
            try
            {
                // Remover de diccionarios
                _connections.TryRemove(connection.ConnectionId, out _);
                
                // Remover de tenant connections
                if (_tenantConnections.TryGetValue(connection.TenantId, out var tenantConnections))
                {
                    tenantConnections.Remove(connection.ConnectionId);
                    if (!tenantConnections.Any())
                    {
                        _tenantConnections.TryRemove(connection.TenantId, out _);
                    }
                }
                
                // Remover de device connections
                if (!string.IsNullOrEmpty(connection.DeviceId))
                {
                    var deviceKey = $"{connection.TenantId}:{connection.DeviceId}";
                    if (_deviceConnections.TryGetValue(deviceKey, out var deviceConnections))
                    {
                        deviceConnections.Remove(connection.ConnectionId);
                        if (!deviceConnections.Any())
                        {
                            _deviceConnections.TryRemove(deviceKey, out _);
                        }
                    }
                }
                
                // Cerrar WebSocket si aún está abierto
                if (connection.WebSocket.State == WebSocketState.Open)
                {
                    await connection.WebSocket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Connection cleanup",
                        CancellationToken.None);
                }
                
                var duration = DateTime.UtcNow - connection.ConnectedAt;
                _logger.LogInformation(
                    "Conexión limpiada: ConnectionId={ConnectionId}, Tenant={TenantId}, Device={DeviceId}, Duration={Duration}s, Messages={MessageCount}",
                    connection.ConnectionId, connection.TenantId, connection.DeviceId, 
                    duration.TotalSeconds, connection.MessageCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error limpiando conexión {ConnectionId}", connection.ConnectionId);
            }
        }
        
        private async Task CloseAllConnectionsAsync(CancellationToken cancellationToken)
        {
            var connectionIds = _connections.Keys.ToList();
            
            foreach (var connectionId in connectionIds)
            {
                if (_connections.TryGetValue(connectionId, out var connection))
                {
                    try
                    {
                        if (connection.WebSocket.State == WebSocketState.Open)
                        {
                            await connection.WebSocket.CloseAsync(
                                WebSocketCloseStatus.EndpointUnavailable,
                                "Server shutting down",
                                cancellationToken);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error cerrando conexión {ConnectionId} durante shutdown", connectionId);
                    }
                }
            }
            
            // Limpiar diccionarios
            _connections.Clear();
            _tenantConnections.Clear();
            _deviceConnections.Clear();
        }
        
        private void HealthCheckCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                // Verificar conexiones inactivas
                var inactiveCutoff = DateTime.UtcNow.AddMilliseconds(-CONNECTION_TIMEOUT_MS);
                var inactiveConnections = _connections.Values
                    .Where(c => c.LastActivity < inactiveCutoff)
                    .ToList();
                
                foreach (var connection in inactiveConnections)
                {
                    _logger.LogInformation(
                        "Conexión inactiva detectada: ConnectionId={ConnectionId}, LastActivity={LastActivity}, InactiveFor={InactiveSeconds}s",
                        connection.ConnectionId, connection.LastActivity, 
                        (DateTime.UtcNow - connection.LastActivity).TotalSeconds);
                    
                    // Intentar enviar ping
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await SendToConnectionAsync(connection, new WebSocketMessage
                            {
                                MessageId = Guid.NewGuid().ToString(),
                                MessageType = "PING",
                                Timestamp = DateTime.UtcNow
                            }, CancellationToken.None);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error enviando ping a conexión inactiva {ConnectionId}", 
                                connection.ConnectionId);
                        }
                    });
                }
                
                // Log estadísticas
                LogHealthStats();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en health check callback");
            }
        }
        
        private void CleanupCallback(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                // Limpiar conexiones zombie
                var zombieConnections = _connections.Values
                    .Where(c => c.WebSocket.State != WebSocketState.Open && 
                               c.WebSocket.State != WebSocketState.Connecting)
                    .ToList();
                
                foreach (var connection in zombieConnections)
                {
                    _logger.LogDebug("Limpiando conexión zombie: ConnectionId={ConnectionId}, State={State}", 
                        connection.ConnectionId, connection.WebSocket.State);
                    
                    _ = Task.Run(async () => await CleanupConnectionAsync(connection));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en cleanup callback");
            }
        }
        
        private void LogHealthStats()
        {
            var stats = GetStats();
            
            _logger.LogInformation(
                "WebSocket server stats: Connections={TotalConnections}, Tenants={TotalTenants}, Devices={TotalDevices}",
                stats.TotalConnections, stats.TotalTenants, stats.TotalDevices);
        }
        
        private Dictionary<string, int> GetConnectionsByStatus()
        {
            var statusCounts = new Dictionary<string, int>();
            
            foreach (var connection in _connections.Values)
            {
                var status = connection.WebSocket.State.ToString();
                statusCounts[status] = statusCounts.GetValueOrDefault(status) + 1;
            }
            
            return statusCounts;
        }
        
        private string ExtractTokenFromRequest(HttpContext context)
        {
            // Intentar de query string primero (común en WebSocket)
            if (context.Request.Query.TryGetValue("token", out var tokenValues))
            {
                return tokenValues.FirstOrDefault();
            }
            
            // Intentar de headers
            var authHeader = context.Request.Headers["Authorization"].ToString();
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                return authHeader.Substring("Bearer ".Length);
            }
            
            return null;
        }
        
        private string ExtractTenantIdFromRequest(HttpContext context)
        {
            // De query string
            if (context.Request.Query.TryGetValue("tenantId", out var tenantIdValues))
            {
                return tenantIdValues.FirstOrDefault();
            }
            
            // De headers
            if (context.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantIdHeader))
            {
                return tenantIdHeader.FirstOrDefault();
            }
            
            return null;
        }
        
        private string ExtractDeviceIdFromRequest(HttpContext context)
        {
            // De query string
            if (context.Request.Query.TryGetValue("deviceId", out var deviceIdValues))
            {
                return deviceIdValues.FirstOrDefault();
            }
            
            // De headers
            if (context.Request.Headers.TryGetValue("X-Device-Id", out var deviceIdHeader))
            {
                return deviceIdHeader.FirstOrDefault();
            }
            
            return null;
        }
        
        #endregion
    }
    
    #region Modelos de datos
    
    public interface IWebSocketServer
    {
        Task StartAsync(CancellationToken cancellationToken = default);
        Task StopAsync(CancellationToken cancellationToken = default);
        Task HandleWebSocketRequestAsync(HttpContext context);
        Task<bool> SendToTenantAsync(string tenantId, WebSocketMessage message, CancellationToken cancellationToken = default);
        Task<bool> SendToDeviceAsync(string tenantId, string deviceId, WebSocketMessage message, CancellationToken cancellationToken = default);
        Task<bool> SendToConnectionAsync(string connectionId, WebSocketMessage message, CancellationToken cancellationToken = default);
        Task<int> BroadcastAsync(WebSocketMessage message, Func<WebSocketConnection, bool> filter = null, CancellationToken cancellationToken = default);
        WebSocketServerStats GetStats();
        Task<int> CloseInactiveConnectionsAsync(TimeSpan maxInactivity);
    }
    
    public class WebSocketConnection
    {
        public string ConnectionId { get; set; }
        public WebSocket WebSocket { get; set; }
        public string TenantId { get; set; }
        public string UserId { get; set; }
        public string DeviceId { get; set; }
        public string[] Roles { get; set; }
        public Dictionary<string, string> Claims { get; set; }
        public string RemoteIpAddress { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsAuthenticated { get; set; }
        public long MessageCount { get; set; }
        public DateTime? LastPingSent { get; set; }
        public DateTime? LastPongReceived { get; set; }
        public HashSet<string> SubscribedChannels { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public WebSocketConnection()
        {
            Roles = Array.Empty<string>();
            Claims = new Dictionary<string, string>();
            SubscribedChannels = new HashSet<string>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class WebSocketMessage
    {
        public string MessageId { get; set; }
        public string MessageType { get; set; }
        public DateTime Timestamp { get; set; }
        public string TenantId { get; set; }
        public string DeviceId { get; set; }
        public string UserId { get; set; }
        public Dictionary<string, object> Data { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public WebSocketMessage()
        {
            MessageId = Guid.NewGuid().ToString();
            Timestamp = DateTime.UtcNow;
            Data = new Dictionary<string, object>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class WebSocketServerStats
    {
        public DateTime Timestamp { get; set; }
        public bool IsRunning { get; set; }
        public int TotalConnections { get; set; }
        public int TotalTenants { get; set; }
        public int TotalDevices { get; set; }
        public Dictionary<string, int> ConnectionsByTenant { get; set; }
        public Dictionary<string, int> ConnectionsByStatus { get; set; }
        public long TotalMessagesSent { get; set; }
        public long TotalMessagesReceived { get; set; }
        
        public WebSocketServerStats()
        {
            ConnectionsByTenant = new Dictionary<string, int>();
            ConnectionsByStatus = new Dictionary<string, int>();
        }
    }
    
    #endregion
}