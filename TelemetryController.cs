using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.ThreatGraph;
using BWP.Enterprise.Cloud.DeviceRegistry;
using BWP.Enterprise.Cloud.TenantManagement;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Cloud.Api.Controllers
{
    /// <summary>
    /// Controlador para recepción y procesamiento de telemetría desde agentes
    /// Maneja alta concurrencia, validación y enrutamiento de eventos
    /// </summary>
    [ApiController]
    [Route("api/v1/[controller]")]
    public class TelemetryController : ControllerBase
    {
        private readonly ILogger<TelemetryController> _logger;
        private readonly GraphCorrelationEngine _correlationEngine;
        private readonly DeviceRegistry _deviceRegistry;
        private readonly TenantManager _tenantManager;
        private readonly TelemetryProcessor _telemetryProcessor;
        private readonly ConcurrentDictionary<string, DateTime> _lastBatchPerDevice;
        
        public TelemetryController(
            ILogger<TelemetryController> logger,
            GraphCorrelationEngine correlationEngine,
            DeviceRegistry deviceRegistry,
            TenantManager tenantManager,
            TelemetryProcessor telemetryProcessor)
        {
            _logger = logger;
            _correlationEngine = correlationEngine;
            _deviceRegistry = deviceRegistry;
            _tenantManager = tenantManager;
            _telemetryProcessor = telemetryProcessor;
            _lastBatchPerDevice = new ConcurrentDictionary<string, DateTime>();
        }
        
        /// <summary>
        /// Endpoint para recepción de lotes de telemetría
        /// </summary>
        [HttpPost("batch")]
        [ProducesResponseType(typeof(TelemetryBatchResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ReceiveTelemetryBatch([FromBody] TelemetryBatchRequest request)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                // 1. Validar autenticación y autorización
                var authResult = await AuthenticateAndAuthorizeAsync(request);
                if (!authResult.IsAuthenticated)
                {
                    return Unauthorized(new ErrorResponse
                    {
                        Error = "Autenticación fallida",
                        Message = authResult.ErrorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                // 2. Validar rate limiting
                var rateLimitResult = await CheckRateLimitAsync(request.DeviceId);
                if (!rateLimitResult.Allowed)
                {
                    return StatusCode(StatusCodes.Status429TooManyRequests, new ErrorResponse
                    {
                        Error = "Rate limit excedido",
                        Message = $"Máximo {rateLimitResult.MaxBatchesPerMinute} lotes por minuto permitidos",
                        Timestamp = DateTime.UtcNow,
                        RetryAfter = rateLimitResult.RetryAfterSeconds
                    });
                }
                
                // 3. Validar integridad del dispositivo
                var deviceValidation = await ValidateDeviceAsync(request.DeviceId, request.TenantId);
                if (!deviceValidation.IsValid)
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "Dispositivo no válido",
                        Message = deviceValidation.ErrorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                // 4. Validar estructura del batch
                var validationResult = ValidateBatchRequest(request);
                if (!validationResult.IsValid)
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "Batch no válido",
                        Message = validationResult.ErrorMessage,
                        Timestamp = DateTime.UtcNow,
                        Details = validationResult.ValidationErrors
                    });
                }
                
                // 5. Procesar eventos en paralelo
                var processingResult = await ProcessTelemetryBatchAsync(request);
                
                // 6. Actualizar última actividad del dispositivo
                await UpdateDeviceLastActivityAsync(request.DeviceId);
                
                // 7. Registrar métricas
                var duration = DateTime.UtcNow - startTime;
                await RecordTelemetryMetricsAsync(request, processingResult, duration);
                
                // 8. Responder con resultado
                var response = CreateSuccessResponse(request, processingResult, duration);
                
                _logger.LogInformation(
                    "Batch procesado: Device={DeviceId}, Events={EventCount}, Processed={ProcessedCount}, Duration={DurationMs}ms",
                    request.DeviceId,
                    request.Events.Count,
                    processingResult.ProcessedEvents,
                    duration.TotalMilliseconds);
                
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando batch de telemetría: Device={DeviceId}", request?.DeviceId);
                
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "Error interno del servidor",
                    Message = "Ocurrió un error procesando la telemetría",
                    Timestamp = DateTime.UtcNow,
                    RequestId = HttpContext.TraceIdentifier
                });
            }
        }
        
        /// <summary>
        /// Endpoint para recepción de eventos individuales
        /// </summary>
        [HttpPost("event")]
        [ProducesResponseType(typeof(TelemetryEventResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ReceiveTelemetryEvent([FromBody] TelemetryEventRequest request)
        {
            try
            {
                // Validar autenticación
                var authResult = await AuthenticateAndAuthorizeAsync(request);
                if (!authResult.IsAuthenticated)
                {
                    return Unauthorized(new ErrorResponse
                    {
                        Error = "Autenticación fallida",
                        Message = authResult.ErrorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                // Validar dispositivo
                var deviceValidation = await ValidateDeviceAsync(request.DeviceId, request.TenantId);
                if (!deviceValidation.IsValid)
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "Dispositivo no válido",
                        Message = deviceValidation.ErrorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                // Validar evento
                var validationResult = ValidateEventRequest(request);
                if (!validationResult.IsValid)
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "Evento no válido",
                        Message = validationResult.ErrorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                // Procesar evento
                var processingResult = await ProcessTelemetryEventAsync(request);
                
                // Actualizar actividad del dispositivo
                await UpdateDeviceLastActivityAsync(request.DeviceId);
                
                var response = new TelemetryEventResponse
                {
                    Success = true,
                    EventId = request.EventId,
                    ProcessedAt = DateTime.UtcNow,
                    CorrelationId = processingResult.CorrelationId,
                    Actions = processingResult.Actions
                };
                
                _logger.LogDebug("Evento procesado: Device={DeviceId}, EventId={EventId}, Type={EventType}",
                    request.DeviceId, request.EventId, request.EventType);
                
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando evento de telemetría: Device={DeviceId}", request?.DeviceId);
                
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "Error interno del servidor",
                    Message = "Ocurrió un error procesando el evento",
                    Timestamp = DateTime.UtcNow,
                    RequestId = HttpContext.TraceIdentifier
                });
            }
        }
        
        /// <summary>
        /// Endpoint para consultar estado de procesamiento
        /// </summary>
        [HttpGet("status/{correlationId}")]
        [ProducesResponseType(typeof(ProcessingStatusResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetProcessingStatus(string correlationId)
        {
            try
            {
                var status = await _telemetryProcessor.GetProcessingStatusAsync(correlationId);
                
                if (status == null)
                {
                    return NotFound(new ErrorResponse
                    {
                        Error = "No encontrado",
                        Message = $"No se encontró estado para correlationId: {correlationId}",
                        Timestamp = DateTime.UtcNow
                    });
                }
                
                return Ok(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo estado de procesamiento: CorrelationId={CorrelationId}", correlationId);
                
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "Error interno del servidor",
                    Message = "Ocurrió un error obteniendo el estado",
                    Timestamp = DateTime.UtcNow,
                    RequestId = HttpContext.TraceIdentifier
                });
            }
        }
        
        /// <summary>
        /// Endpoint para métricas de telemetría
        /// </summary>
        [HttpGet("metrics")]
        [ProducesResponseType(typeof(TelemetryMetricsResponse), StatusCodes.Status200OK)]
        public async Task<IActionResult> GetTelemetryMetrics(
            [FromQuery] string tenantId = null,
            [FromQuery] string deviceId = null,
            [FromQuery] DateTime? startTime = null,
            [FromQuery] DateTime? endTime = null)
        {
            try
            {
                startTime ??= DateTime.UtcNow.AddHours(-1);
                endTime ??= DateTime.UtcNow;
                
                var metrics = await _telemetryProcessor.GetMetricsAsync(
                    tenantId, deviceId, startTime.Value, endTime.Value);
                
                return Ok(metrics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo métricas de telemetría");
                
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "Error interno del servidor",
                    Message = "Ocurrió un error obteniendo las métricas",
                    Timestamp = DateTime.UtcNow,
                    RequestId = HttpContext.TraceIdentifier
                });
            }
        }
        
        #region Métodos privados
        
        private async Task<AuthenticationResult> AuthenticateAndAuthorizeAsync(TelemetryBatchRequest request)
        {
            try
            {
                // Verificar token JWT en header
                var authHeader = HttpContext.Request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return AuthenticationResult.Failed("Token de autenticación no proporcionado");
                }
                
                var token = authHeader.Substring("Bearer ".Length);
                
                // Validar token con TenantManager
                var tokenValidation = await _tenantManager.ValidateTokenAsync(token, request.TenantId);
                if (!tokenValidation.IsValid)
                {
                    return AuthenticationResult.Failed($"Token inválido: {tokenValidation.ErrorMessage}");
                }
                
                // Verificar que el dispositivo pertenezca al tenant
                var deviceBelongsToTenant = await _deviceRegistry.DeviceBelongsToTenantAsync(
                    request.DeviceId, request.TenantId);
                
                if (!deviceBelongsToTenant)
                {
                    return AuthenticationResult.Failed("Dispositivo no pertenece al tenant especificado");
                }
                
                return AuthenticationResult.Success(tokenValidation.TenantId, tokenValidation.DeviceId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en autenticación");
                return AuthenticationResult.Failed($"Error de autenticación: {ex.Message}");
            }
        }
        
        private async Task<RateLimitResult> CheckRateLimitAsync(string deviceId)
        {
            try
            {
                var now = DateTime.UtcNow;
                var maxBatchesPerMinute = 60; // Configurable
                
                // Obtener últimos batches del dispositivo
                var lastBatchTime = _lastBatchPerDevice.GetOrAdd(deviceId, DateTime.MinValue);
                
                if (lastBatchTime != DateTime.MinValue)
                {
                    var timeSinceLastBatch = now - lastBatchTime;
                    var batchesInLastMinute = await GetBatchesInLastMinuteAsync(deviceId);
                    
                    if (batchesInLastMinute >= maxBatchesPerMinute)
                    {
                        var retryAfter = TimeSpan.FromMinutes(1) - timeSinceLastBatch;
                        return RateLimitResult.Exceeded(maxBatchesPerMinute, (int)retryAfter.TotalSeconds);
                    }
                }
                
                // Actualizar último batch
                _lastBatchPerDevice[deviceId] = now;
                
                return RateLimitResult.Allowed(maxBatchesPerMinute);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verificando rate limit para dispositivo: {DeviceId}", deviceId);
                return RateLimitResult.Allowed(60); // Fallback seguro
            }
        }
        
        private async Task<int> GetBatchesInLastMinuteAsync(string deviceId)
        {
            var oneMinuteAgo = DateTime.UtcNow.AddMinutes(-1);
            
            // Contar batches en el último minuto
            var batches = _lastBatchPerDevice
                .Where(kv => kv.Key == deviceId && kv.Value >= oneMinuteAgo)
                .Count();
                
            return batches;
        }
        
        private async Task<DeviceValidationResult> ValidateDeviceAsync(string deviceId, string tenantId)
        {
            try
            {
                // Verificar que el dispositivo existe
                var device = await _deviceRegistry.GetDeviceAsync(deviceId);
                if (device == null)
                {
                    return DeviceValidationResult.Invalid($"Dispositivo no encontrado: {deviceId}");
                }
                
                // Verificar que esté activo
                if (device.Status != DeviceStatus.Online && device.Status != DeviceStatus.Degraded)
                {
                    return DeviceValidationResult.Invalid($"Dispositivo no está activo. Estado: {device.Status}");
                }
                
                // Verificar que no esté en cuarentena
                if (device.IsQuarantined)
                {
                    return DeviceValidationResult.Invalid("Dispositivo en cuarentena");
                }
                
                // Verificar última versión del agente
                if (!string.IsNullOrEmpty(device.AgentVersion))
                {
                    var versionCheck = await CheckAgentVersionAsync(device.AgentVersion);
                    if (!versionCheck.IsCompatible)
                    {
                        return DeviceValidationResult.Invalid(
                            $"Versión del agente no compatible: {device.AgentVersion}. Requerida: {versionCheck.RequiredVersion}");
                    }
                }
                
                return DeviceValidationResult.Valid(device);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validando dispositivo: {DeviceId}", deviceId);
                return DeviceValidationResult.Invalid($"Error validando dispositivo: {ex.Message}");
            }
        }
        
        private async Task<VersionCheckResult> CheckAgentVersionAsync(string agentVersion)
        {
            // Implementar lógica de verificación de versión
            // Por ahora, siempre compatible
            return VersionCheckResult.Compatible("1.0.0+");
        }
        
        private ValidationResult ValidateBatchRequest(TelemetryBatchRequest request)
        {
            var errors = new List<string>();
            
            if (request == null)
            {
                errors.Add("Request no puede ser nulo");
                return ValidationResult.Invalid("Request inválido", errors);
            }
            
            // Validar campos requeridos
            if (string.IsNullOrEmpty(request.BatchId))
                errors.Add("BatchId es requerido");
            
            if (string.IsNullOrEmpty(request.DeviceId))
                errors.Add("DeviceId es requerido");
            
            if (string.IsNullOrEmpty(request.TenantId))
                errors.Add("TenantId es requerido");
            
            if (request.Events == null || !request.Events.Any())
                errors.Add("Debe incluir al menos un evento");
            
            // Validar timestamp
            if (request.Timestamp > DateTime.UtcNow.AddMinutes(5))
                errors.Add("Timestamp no puede estar en el futuro");
            
            if (request.Timestamp < DateTime.UtcNow.AddHours(-24))
                errors.Add("Timestamp es muy antiguo");
            
            // Validar tamaño del batch
            if (request.Events.Count > 1000)
                errors.Add($"Batch demasiado grande: {request.Events.Count} eventos (máximo: 1000)");
            
            // Validar cada evento
            for (int i = 0; i < request.Events.Count; i++)
            {
                var eventValidation = ValidateTelemetryEvent(request.Events[i]);
                if (!eventValidation.IsValid)
                {
                    errors.Add($"Evento {i}: {eventValidation.ErrorMessage}");
                }
            }
            
            if (errors.Any())
            {
                return ValidationResult.Invalid("Validación fallida", errors);
            }
            
            return ValidationResult.Valid();
        }
        
        private ValidationResult ValidateEventRequest(TelemetryEventRequest request)
        {
            var errors = new List<string>();
            
            if (request == null)
            {
                errors.Add("Request no puede ser nulo");
                return ValidationResult.Invalid("Request inválido", errors);
            }
            
            if (string.IsNullOrEmpty(request.EventId))
                errors.Add("EventId es requerido");
            
            if (string.IsNullOrEmpty(request.DeviceId))
                errors.Add("DeviceId es requerido");
            
            if (string.IsNullOrEmpty(request.TenantId))
                errors.Add("TenantId es requerido");
            
            if (string.IsNullOrEmpty(request.EventType))
                errors.Add("EventType es requerido");
            
            if (request.Timestamp > DateTime.UtcNow.AddMinutes(5))
                errors.Add("Timestamp no puede estar en el futuro");
            
            if (errors.Any())
            {
                return ValidationResult.Invalid("Validación fallida", errors);
            }
            
            return ValidationResult.Valid();
        }
        
        private ValidationResult ValidateTelemetryEvent(TelemetryEvent telemetryEvent)
        {
            var errors = new List<string>();
            
            if (telemetryEvent == null)
            {
                errors.Add("Evento no puede ser nulo");
                return ValidationResult.Invalid("Evento inválido", errors);
            }
            
            if (string.IsNullOrEmpty(telemetryEvent.EventId))
                errors.Add("EventId es requerido");
            
            if (string.IsNullOrEmpty(telemetryEvent.EventType))
                errors.Add("EventType es requerido");
            
            if (telemetryEvent.Timestamp > DateTime.UtcNow.AddMinutes(5))
                errors.Add("Timestamp no puede estar en el futuro");
            
            if (telemetryEvent.Timestamp < DateTime.UtcNow.AddHours(-24))
                errors.Add("Timestamp es muy antiguo");
            
            // Validar tamaño de datos
            if (telemetryEvent.Data != null)
            {
                var dataSize = System.Text.Json.JsonSerializer.Serialize(telemetryEvent.Data).Length;
                if (dataSize > 1024 * 1024) // 1MB
                {
                    errors.Add($"Datos del evento demasiado grandes: {dataSize} bytes (máximo: 1MB)");
                }
            }
            
            if (errors.Any())
            {
                return ValidationResult.Invalid("Evento inválido", errors);
            }
            
            return ValidationResult.Valid();
        }
        
        private async Task<BatchProcessingResult> ProcessTelemetryBatchAsync(TelemetryBatchRequest request)
        {
            var processingResult = new BatchProcessingResult
            {
                BatchId = request.BatchId,
                StartTime = DateTime.UtcNow,
                TotalEvents = request.Events.Count
            };
            
            try
            {
                // Agrupar eventos por tipo para procesamiento paralelo
                var eventGroups = request.Events
                    .GroupBy(e => e.EventType)
                    .ToList();
                
                var processingTasks = new List<Task<List<EventProcessingResult>>>();
                
                foreach (var group in eventGroups)
                {
                    processingTasks.Add(Task.Run(async () =>
                    {
                        var groupResults = new List<EventProcessingResult>();
                        
                        foreach (var telemetryEvent in group)
                        {
                            var eventResult = await ProcessSingleEventAsync(telemetryEvent, request);
                            groupResults.Add(eventResult);
                        }
                        
                        return groupResults;
                    }));
                }
                
                // Esperar a que todos los grupos terminen
                var allGroupResults = await Task.WhenAll(processingTasks);
                
                // Consolidar resultados
                foreach (var groupResults in allGroupResults)
                {
                    processingResult.ProcessedEvents += groupResults.Count(r => r.Success);
                    processingResult.FailedEvents += groupResults.Count(r => !r.Success);
                    processingResult.EventResults.AddRange(groupResults);
                    
                    // Acumular acciones recomendadas
                    foreach (var result in groupResults.Where(r => r.Actions != null))
                    {
                        processingResult.Actions.AddRange(result.Actions);
                    }
                }
                
                // Enviar a motor de correlación
                if (processingResult.ProcessedEvents > 0)
                {
                    var eventsForCorrelation = request.Events
                        .Where(e => processingResult.EventResults
                            .FirstOrDefault(r => r.EventId == e.EventId)?.Success == true)
                        .ToList();
                    
                    if (eventsForCorrelation.Any())
                    {
                        var correlationResult = await _correlationEngine.ProcessEventsAsync(
                            new EventBatch
                            {
                                DeviceId = request.DeviceId,
                                TenantId = request.TenantId,
                                Events = eventsForCorrelation,
                                Timestamp = DateTime.UtcNow
                            });
                        
                        processingResult.CorrelationId = correlationResult.CorrelationId;
                        processingResult.CorrelationResults = correlationResult.Results;
                    }
                }
                
                processingResult.EndTime = DateTime.UtcNow;
                processingResult.Success = processingResult.FailedEvents == 0;
                
                return processingResult;
            }
            catch (Exception ex)
            {
                processingResult.EndTime = DateTime.UtcNow;
                processingResult.Success = false;
                processingResult.ErrorMessage = ex.Message;
                
                _logger.LogError(ex, "Error procesando batch: {BatchId}", request.BatchId);
                
                return processingResult;
            }
        }
        
        private async Task<EventProcessingResult> ProcessSingleEventAsync(
            TelemetryEvent telemetryEvent,
            TelemetryBatchRequest batchRequest)
        {
            var result = new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                StartTime = DateTime.UtcNow
            };
            
            try
            {
                // Enriquecer evento con metadatos
                var enrichedEvent = await EnrichEventAsync(telemetryEvent, batchRequest);
                
                // Procesar según tipo de evento
                switch (telemetryEvent.EventType)
                {
                    case "ProcessCreated":
                    case "ProcessTerminated":
                        result = await ProcessProcessEventAsync(enrichedEvent);
                        break;
                        
                    case "FileCreated":
                    case "FileModified":
                    case "FileDeleted":
                        result = await ProcessFileEventAsync(enrichedEvent);
                        break;
                        
                    case "NetworkConnection":
                    case "DNSQuery":
                        result = await ProcessNetworkEventAsync(enrichedEvent);
                        break;
                        
                    case "RegistryModified":
                        result = await ProcessRegistryEventAsync(enrichedEvent);
                        break;
                        
                    case "ThreatDetected":
                        result = await ProcessThreatEventAsync(enrichedEvent);
                        break;
                        
                    default:
                        result = await ProcessGenericEventAsync(enrichedEvent);
                        break;
                }
                
                result.EndTime = DateTime.UtcNow;
                result.Success = true;
                
                return result;
            }
            catch (Exception ex)
            {
                result.EndTime = DateTime.UtcNow;
                result.Success = false;
                result.ErrorMessage = ex.Message;
                
                _logger.LogError(ex, "Error procesando evento: {EventId}", telemetryEvent.EventId);
                
                return result;
            }
        }
        
        private async Task<TelemetryEvent> EnrichEventAsync(
            TelemetryEvent telemetryEvent,
            TelemetryBatchRequest batchRequest)
        {
            // Añadir metadatos adicionales
            var enrichedEvent = telemetryEvent.Clone();
            
            enrichedEvent.Metadata ??= new Dictionary<string, object>();
            enrichedEvent.Metadata["BatchId"] = batchRequest.BatchId;
            enrichedEvent.Metadata["ReceivedAt"] = DateTime.UtcNow;
            enrichedEvent.Metadata["DeviceId"] = batchRequest.DeviceId;
            enrichedEvent.Metadata["TenantId"] = batchRequest.TenantId;
            
            // Obtener información del dispositivo
            var deviceInfo = await _deviceRegistry.GetDeviceAsync(batchRequest.DeviceId);
            if (deviceInfo != null)
            {
                enrichedEvent.Metadata["DeviceName"] = deviceInfo.DeviceName;
                enrichedEvent.Metadata["DeviceType"] = deviceInfo.DeviceType;
                enrichedEvent.Metadata["OsVersion"] = deviceInfo.OsVersion;
                enrichedEvent.Metadata["AgentVersion"] = deviceInfo.AgentVersion;
            }
            
            // Obtener información del tenant
            var tenantInfo = await _tenantManager.GetTenantAsync(batchRequest.TenantId);
            if (tenantInfo != null)
            {
                enrichedEvent.Metadata["TenantName"] = tenantInfo.Name;
                enrichedEvent.Metadata["TenantTier"] = tenantInfo.Tier;
            }
            
            return enrichedEvent;
        }
        
        private async Task<EventProcessingResult> ProcessProcessEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento de proceso
            await Task.Delay(1); // Simular procesamiento
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessFileEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento de archivo
            await Task.Delay(1);
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessNetworkEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento de red
            await Task.Delay(1);
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessRegistryEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento de registro
            await Task.Delay(1);
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessThreatEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento de amenaza
            await Task.Delay(1);
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessGenericEventAsync(TelemetryEvent telemetryEvent)
        {
            // Procesar evento genérico
            await Task.Delay(1);
            
            return new EventProcessingResult
            {
                EventId = telemetryEvent.EventId,
                EventType = telemetryEvent.EventType,
                Success = true,
                Actions = new List<ActionRecommendation>()
            };
        }
        
        private async Task<EventProcessingResult> ProcessTelemetryEventAsync(TelemetryEventRequest request)
        {
            var result = new EventProcessingResult
            {
                EventId = request.EventId,
                EventType = request.EventType,
                StartTime = DateTime.UtcNow
            };
            
            try
            {
                // Convertir a TelemetryEvent
                var telemetryEvent = new TelemetryEvent
                {
                    EventId = request.EventId,
                    EventType = request.EventType,
                    Timestamp = request.Timestamp,
                    Data = request.Data,
                    Metadata = request.Metadata
                };
                
                // Procesar evento
                var processingResult = await ProcessSingleEventAsync(telemetryEvent, new TelemetryBatchRequest
                {
                    DeviceId = request.DeviceId,
                    TenantId = request.TenantId,
                    BatchId = $"single-{request.EventId}"
                });
                
                result = processingResult;
                result.EndTime = DateTime.UtcNow;
                
                return result;
            }
            catch (Exception ex)
            {
                result.EndTime = DateTime.UtcNow;
                result.Success = false;
                result.ErrorMessage = ex.Message;
                
                _logger.LogError(ex, "Error procesando evento individual: {EventId}", request.EventId);
                
                return result;
            }
        }
        
        private async Task UpdateDeviceLastActivityAsync(string deviceId)
        {
            try
            {
                await _deviceRegistry.UpdateLastActivityAsync(deviceId, DateTime.UtcNow);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando última actividad del dispositivo: {DeviceId}", deviceId);
            }
        }
        
        private async Task RecordTelemetryMetricsAsync(
            TelemetryBatchRequest request,
            BatchProcessingResult processingResult,
            TimeSpan duration)
        {
            try
            {
                var metrics = new TelemetryMetrics
                {
                    BatchId = request.BatchId,
                    DeviceId = request.DeviceId,
                    TenantId = request.TenantId,
                    Timestamp = DateTime.UtcNow,
                    EventCount = request.Events.Count,
                    ProcessedCount = processingResult.ProcessedEvents,
                    FailedCount = processingResult.FailedEvents,
                    ProcessingTimeMs = duration.TotalMilliseconds,
                    EventsByType = request.Events
                        .GroupBy(e => e.EventType)
                        .ToDictionary(g => g.Key, g => g.Count())
                };
                
                await _telemetryProcessor.RecordMetricsAsync(metrics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando métricas de telemetría");
            }
        }
        
        private TelemetryBatchResponse CreateSuccessResponse(
            TelemetryBatchRequest request,
            BatchProcessingResult processingResult,
            TimeSpan duration)
        {
            return new TelemetryBatchResponse
            {
                Success = true,
                BatchId = request.BatchId,
                ProcessedAt = DateTime.UtcNow,
                ProcessedEvents = processingResult.ProcessedEvents,
                FailedEvents = processingResult.FailedEvents,
                ProcessingTimeMs = duration.TotalMilliseconds,
                CorrelationId = processingResult.CorrelationId,
                Actions = processingResult.Actions,
                Recommendations = GenerateRecommendations(processingResult)
            };
        }
        
        private List<string> GenerateRecommendations(BatchProcessingResult processingResult)
        {
            var recommendations = new List<string>();
            
            if (processingResult.FailedEvents > 0)
            {
                recommendations.Add($"Revisar {processingResult.FailedEvents} eventos fallados");
            }
            
            if (processingResult.Actions.Any(a => a.Priority == ActionPriority.Critical))
            {
                recommendations.Add("Acciones críticas requieren atención inmediata");
            }
            
            return recommendations;
        }
        
        #endregion
    }
    
    #region Clases auxiliares
    
    public class TelemetryBatchRequest
    {
        public string BatchId { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public DateTime Timestamp { get; set; }
        public List<TelemetryEvent> Events { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public TelemetryBatchRequest()
        {
            Events = new List<TelemetryEvent>();
            Metadata = new Dictionary<string, object>();
            Timestamp = DateTime.UtcNow;
        }
    }
    
    public class TelemetryEventRequest
    {
        public string EventId { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public Dictionary<string, object> Data { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public TelemetryEventRequest()
        {
            Data = new Dictionary<string, object>();
            Metadata = new Dictionary<string, object>();
            Timestamp = DateTime.UtcNow;
        }
    }
    
    public class TelemetryEvent
    {
        public string EventId { get; set; }
        public string EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public Dictionary<string, object> Data { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public TelemetryEvent()
        {
            Data = new Dictionary<string, object>();
            Metadata = new Dictionary<string, object>();
        }
        
        public TelemetryEvent Clone()
        {
            return new TelemetryEvent
            {
                EventId = this.EventId,
                EventType = this.EventType,
                Timestamp = this.Timestamp,
                Data = this.Data != null ? new Dictionary<string, object>(this.Data) : null,
                Metadata = this.Metadata != null ? new Dictionary<string, object>(this.Metadata) : null
            };
        }
    }
    
    public class TelemetryBatchResponse
    {
        public bool Success { get; set; }
        public string BatchId { get; set; }
        public DateTime ProcessedAt { get; set; }
        public int ProcessedEvents { get; set; }
        public int FailedEvents { get; set; }
        public double ProcessingTimeMs { get; set; }
        public string CorrelationId { get; set; }
        public List<ActionRecommendation> Actions { get; set; }
        public List<string> Recommendations { get; set; }
        
        public TelemetryBatchResponse()
        {
            Actions = new List<ActionRecommendation>();
            Recommendations = new List<string>();
        }
    }
    
    public class TelemetryEventResponse
    {
        public bool Success { get; set; }
        public string EventId { get; set; }
        public DateTime ProcessedAt { get; set; }
        public string CorrelationId { get; set; }
        public List<ActionRecommendation> Actions { get; set; }
        
        public TelemetryEventResponse()
        {
            Actions = new List<ActionRecommendation>();
        }
    }
    
    public class ErrorResponse
    {
        public string Error { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
        public string RequestId { get; set; }
        public object Details { get; set; }
        public int? RetryAfter { get; set; }
    }
    
    public class ProcessingStatusResponse
    {
        public string CorrelationId { get; set; }
        public string Status { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public int ProcessedEvents { get; set; }
        public int TotalEvents { get; set; }
        public List<EventStatus> EventStatuses { get; set; }
        
        public ProcessingStatusResponse()
        {
            EventStatuses = new List<EventStatus>();
        }
    }
    
    public class EventStatus
    {
        public string EventId { get; set; }
        public string Status { get; set; }
        public DateTime? ProcessedAt { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class TelemetryMetricsResponse
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string TenantId { get; set; }
        public string DeviceId { get; set; }
        public int TotalBatches { get; set; }
        public int TotalEvents { get; set; }
        public double AverageProcessingTimeMs { get; set; }
        public Dictionary<string, int> EventsByType { get; set; }
        public Dictionary<string, int> DevicesByStatus { get; set; }
        
        public TelemetryMetricsResponse()
        {
            EventsByType = new Dictionary<string, int>();
            DevicesByStatus = new Dictionary<string, int>();
        }
    }
    
    public class AuthenticationResult
    {
        public bool IsAuthenticated { get; set; }
        public string TenantId { get; set; }
        public string DeviceId { get; set; }
        public string ErrorMessage { get; set; }
        
        public static AuthenticationResult Success(string tenantId, string deviceId)
        {
            return new AuthenticationResult
            {
                IsAuthenticated = true,
                TenantId = tenantId,
                DeviceId = deviceId
            };
        }
        
        public static AuthenticationResult Failed(string errorMessage)
        {
            return new AuthenticationResult
            {
                IsAuthenticated = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class RateLimitResult
    {
        public bool Allowed { get; set; }
        public int MaxBatchesPerMinute { get; set; }
        public int? RetryAfterSeconds { get; set; }
        
        public static RateLimitResult Allowed(int maxBatchesPerMinute)
        {
            return new RateLimitResult
            {
                Allowed = true,
                MaxBatchesPerMinute = maxBatchesPerMinute
            };
        }
        
        public static RateLimitResult Exceeded(int maxBatchesPerMinute, int retryAfterSeconds)
        {
            return new RateLimitResult
            {
                Allowed = false,
                MaxBatchesPerMinute = maxBatchesPerMinute,
                RetryAfterSeconds = retryAfterSeconds
            };
        }
    }
    
    public class DeviceValidationResult
    {
        public bool IsValid { get; set; }
        public DeviceInfo DeviceInfo { get; set; }
        public string ErrorMessage { get; set; }
        
        public static DeviceValidationResult Valid(DeviceInfo deviceInfo)
        {
            return new DeviceValidationResult
            {
                IsValid = true,
                DeviceInfo = deviceInfo
            };
        }
        
        public static DeviceValidationResult Invalid(string errorMessage)
        {
            return new DeviceValidationResult
            {
                IsValid = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class VersionCheckResult
    {
        public bool IsCompatible { get; set; }
        public string RequiredVersion { get; set; }
        public string CurrentVersion { get; set; }
        
        public static VersionCheckResult Compatible(string requiredVersion)
        {
            return new VersionCheckResult
            {
                IsCompatible = true,
                RequiredVersion = requiredVersion
            };
        }
        
        public static VersionCheckResult Incompatible(string requiredVersion, string currentVersion)
        {
            return new VersionCheckResult
            {
                IsCompatible = false,
                RequiredVersion = requiredVersion,
                CurrentVersion = currentVersion
            };
        }
    }
    
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; }
        public List<string> ValidationErrors { get; set; }
        
        public ValidationResult()
        {
            ValidationErrors = new List<string>();
        }
        
        public static ValidationResult Valid()
        {
            return new ValidationResult { IsValid = true };
        }
        
        public static ValidationResult Invalid(string errorMessage, List<string> errors = null)
        {
            return new ValidationResult
            {
                IsValid = false,
                ErrorMessage = errorMessage,
                ValidationErrors = errors ?? new List<string>()
            };
        }
    }
    
    public class BatchProcessingResult
    {
        public string BatchId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int TotalEvents { get; set; }
        public int ProcessedEvents { get; set; }
        public int FailedEvents { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string CorrelationId { get; set; }
        public List<EventProcessingResult> EventResults { get; set; }
        public List<ActionRecommendation> Actions { get; set; }
        public List<CorrelationResult> CorrelationResults { get; set; }
        
        public BatchProcessingResult()
        {
            EventResults = new List<EventProcessingResult>();
            Actions = new List<ActionRecommendation>();
            CorrelationResults = new List<CorrelationResult>();
        }
    }
    
    public class EventProcessingResult
    {
        public string EventId { get; set; }
        public string EventType { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<ActionRecommendation> Actions { get; set; }
        
        public EventProcessingResult()
        {
            Actions = new List<ActionRecommendation>();
        }
    }
    
    public class ActionRecommendation
    {
        public string ActionId { get; set; }
        public string ActionType { get; set; }
        public ActionPriority Priority { get; set; }
        public string Description { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        
        public ActionRecommendation()
        {
            Parameters = new Dictionary<string, object>();
            Priority = ActionPriority.Medium;
        }
    }
    
    public class TelemetryMetrics
    {
        public string BatchId { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public DateTime Timestamp { get; set; }
        public int EventCount { get; set; }
        public int ProcessedCount { get; set; }
        public int FailedCount { get; set; }
        public double ProcessingTimeMs { get; set; }
        public Dictionary<string, int> EventsByType { get; set; }
        
        public TelemetryMetrics()
        {
            EventsByType = new Dictionary<string, int>();
        }
    }
    
    public class EventBatch
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public List<TelemetryEvent> Events { get; set; }
        public DateTime Timestamp { get; set; }
        
        public EventBatch()
        {
            Events = new List<TelemetryEvent>();
        }
    }
    
    public class CorrelationResult
    {
        public string CorrelationId { get; set; }
        public string PatternName { get; set; }
        public double Confidence { get; set; }
        public List<string> MatchedEvents { get; set; }
        
        public CorrelationResult()
        {
            MatchedEvents = new List<string>();
        }
    }
    
    public enum ActionPriority
    {
        Low,
        Medium,
        High,
        Critical
    }
    
    #endregion
}