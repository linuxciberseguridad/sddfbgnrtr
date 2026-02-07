using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.Telemetry
{
    /// <summary>
    /// Serializador de eventos optimizado para telemetría con schema validation y transformación
    /// Soporta múltiples formatos de salida y optimización de tamaño
    /// </summary>
    public sealed class EventSerializer : IAgentModule
    {
        private static readonly Lazy<EventSerializer> _instance = 
            new Lazy<EventSerializer>(() => new EventSerializer());
        
        public static EventSerializer Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly JsonSerializerOptions _compactOptions;
        private readonly JsonSerializerOptions _prettyOptions;
        private readonly JsonSerializerOptions _camelCaseOptions;
        private readonly Dictionary<string, EventSchema> _schemas;
        private bool _isInitialized;
        
        public string ModuleId => "EventSerializer";
        public string Version => "1.0.0";
        public string Description => "Serializador de eventos optimizado para telemetría";
        
        private EventSerializer()
        {
            _logManager = LogManager.Instance;
            
            // Opciones para serialización compacta
            _compactOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            
            // Opciones para debugging
            _prettyOptions = new JsonSerializerOptions(_compactOptions)
            {
                WriteIndented = true
            };
            
            // Opciones camelCase estándar
            _camelCaseOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            
            // Registrar convertidores
            RegisterConverters();
            
            _schemas = new Dictionary<string, EventSchema>();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el serializador
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                if (_isInitialized)
                    return ModuleOperationResult.SuccessResult();
                
                // Cargar schemas
                await LoadSchemasAsync();
                
                _isInitialized = true;
                
                _logManager.LogInfo("EventSerializer inicializado", ModuleId, new Dictionary<string, object>
                {
                    { "schemasLoaded", _schemas.Count },
                    { "formatsSupported", new[] { "JSON", "XML", "MessagePack", "Compact" } }
                });
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando EventSerializer: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el serializador
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            _logManager.LogInfo("EventSerializer iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene el serializador
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            _logManager.LogInfo("EventSerializer detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Pausa el serializador
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _logManager.LogInfo("EventSerializer pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el serializador
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _logManager.LogInfo("EventSerializer reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Serializa un evento de telemetría a JSON compacto
        /// </summary>
        public string SerializeToJson(TelemetryEvent telemetryEvent, bool pretty = false)
        {
            if (telemetryEvent == null)
                return "null";
            
            try
            {
                var options = pretty ? _prettyOptions : _compactOptions;
                return JsonSerializer.Serialize(telemetryEvent, options);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando evento a JSON: {ex}", ModuleId);
                return SerializeError(telemetryEvent?.EventId, ex);
            }
        }
        
        /// <summary>
        /// Serializa múltiples eventos a JSON batch
        /// </summary>
        public string SerializeBatchToJson(List<TelemetryEvent> events, bool pretty = false)
        {
            if (events == null || events.Count == 0)
                return "[]";
            
            try
            {
                var batch = new
                {
                    batchId = Guid.NewGuid().ToString(),
                    timestamp = DateTime.UtcNow,
                    count = events.Count,
                    events = events.Select(e => TransformForSerialization(e)).ToList()
                };
                
                var options = pretty ? _prettyOptions : _compactOptions;
                return JsonSerializer.Serialize(batch, options);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando batch a JSON: {ex}", ModuleId);
                return SerializeError("batch", ex);
            }
        }
        
        /// <summary>
        /// Serializa a formato compacto optimizado
        /// </summary>
        public byte[] SerializeToCompact(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return Array.Empty<byte>();
            
            try
            {
                var transformed = TransformForSerialization(telemetryEvent);
                var json = JsonSerializer.Serialize(transformed, _compactOptions);
                
                // Optimizar: eliminar espacios, nombres largos, etc.
                var optimized = OptimizeJson(json);
                return Encoding.UTF8.GetBytes(optimized);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a compacto: {ex}", ModuleId);
                return Encoding.UTF8.GetBytes(SerializeError(telemetryEvent.EventId, ex));
            }
        }
        
        /// <summary>
        /// Serializa a MessagePack (más compacto que JSON)
        /// </summary>
        public byte[] SerializeToMessagePack(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return Array.Empty<byte>();
            
            try
            {
                // Usar MessagePack-CSharp si está disponible
                // Fallback a JSON comprimido
                var json = SerializeToJson(telemetryEvent, false);
                return CryptoHelper.ToCompressedJson(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a MessagePack: {ex}", ModuleId);
                return Array.Empty<byte>();
            }
        }
        
        /// <summary>
        /// Serializa a XML (para integración con sistemas legacy)
        /// </summary>
        public string SerializeToXml(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return "<Event/>";
            
            try
            {
                var transformed = TransformForSerialization(telemetryEvent);
                
                var xml = new StringBuilder();
                xml.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                xml.AppendLine("<TelemetryEvent>");
                
                xml.AppendLine($"  <EventId>{EscapeXml(transformed.EventId)}</EventId>");
                xml.AppendLine($"  <Timestamp>{transformed.Timestamp:o}</Timestamp>");
                xml.AppendLine($"  <EventType>{EscapeXml(transformed.EventType)}</EventType>");
                xml.AppendLine($"  <Severity>{EscapeXml(transformed.Severity)}</Severity>");
                
                if (transformed.Data != null && transformed.Data.Count > 0)
                {
                    xml.AppendLine("  <Data>");
                    foreach (var kvp in transformed.Data)
                    {
                        xml.AppendLine($"    <{EscapeXml(kvp.Key)}>{EscapeXml(kvp.Value?.ToString())}</{EscapeXml(kvp.Key)}>");
                    }
                    xml.AppendLine("  </Data>");
                }
                
                if (transformed.Metadata != null && transformed.Metadata.Count > 0)
                {
                    xml.AppendLine("  <Metadata>");
                    foreach (var kvp in transformed.Metadata)
                    {
                        xml.AppendLine($"    <{EscapeXml(kvp.Key)}>{EscapeXml(kvp.Value?.ToString())}</{EscapeXml(kvp.Key)}>");
                    }
                    xml.AppendLine("  </Metadata>");
                }
                
                xml.AppendLine("</TelemetryEvent>");
                
                return xml.ToString();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a XML: {ex}", ModuleId);
                return $"<Error>{EscapeXml(ex.Message)}</Error>";
            }
        }
        
        /// <summary>
        /// Deserializa JSON a evento de telemetría
        /// </summary>
        public TelemetryEvent DeserializeFromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;
            
            try
            {
                return JsonSerializer.Deserialize<TelemetryEvent>(json, _camelCaseOptions);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando JSON: {ex}", ModuleId);
                return CreateErrorEvent("deserialize_error", ex);
            }
        }
        
        /// <summary>
        /// Deserializa JSON batch a lista de eventos
        /// </summary>
        public List<TelemetryEvent> DeserializeBatchFromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return new List<TelemetryEvent>();
            
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                if (root.TryGetProperty("events", out var eventsArray))
                {
                    var events = new List<TelemetryEvent>();
                    foreach (var eventElement in eventsArray.EnumerateArray())
                    {
                        try
                        {
                            var telemetryEvent = JsonSerializer.Deserialize<TelemetryEvent>(
                                eventElement.GetRawText(), _camelCaseOptions);
                            events.Add(telemetryEvent);
                        }
                        catch
                        {
                            // Continuar con siguiente evento
                        }
                    }
                    return events;
                }
                
                return new List<TelemetryEvent>();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando batch: {ex}", ModuleId);
                return new List<TelemetryEvent>();
            }
        }
        
        /// <summary>
        /// Valida evento contra schema
        /// </summary>
        public ValidationResult ValidateAgainstSchema(TelemetryEvent telemetryEvent, string schemaName = null)
        {
            if (telemetryEvent == null)
                return ValidationResult.Error("Evento es null");
            
            try
            {
                var schema = GetSchemaForEvent(telemetryEvent, schemaName);
                var issues = new List<string>();
                
                // Validar campos requeridos
                if (string.IsNullOrEmpty(telemetryEvent.EventId))
                    issues.Add("EventId es requerido");
                
                if (telemetryEvent.Timestamp == default)
                    issues.Add("Timestamp es requerido");
                
                if (string.IsNullOrEmpty(telemetryEvent.EventType))
                    issues.Add("EventType es requerido");
                
                // Validar formato de EventId (debe ser GUID o similar)
                if (!string.IsNullOrEmpty(telemetryEvent.EventId) && 
                    !IsValidEventId(telemetryEvent.EventId))
                    issues.Add($"EventId formato inválido: {telemetryEvent.EventId}");
                
                // Validar timestamp (no puede ser futuro)
                if (telemetryEvent.Timestamp > DateTime.UtcNow.AddMinutes(5))
                    issues.Add($"Timestamp en futuro: {telemetryEvent.Timestamp:o}");
                
                // Validar tamaño de datos
                var json = SerializeToJson(telemetryEvent, false);
                if (json.Length > 1024 * 1024) // 1MB
                    issues.Add($"Evento demasiado grande: {json.Length} bytes");
                
                // Validar contra schema específico si existe
                if (schema != null)
                {
                    issues.AddRange(ValidateWithSchema(telemetryEvent, schema));
                }
                
                if (issues.Count == 0)
                {
                    return ValidationResult.Valid();
                }
                else
                {
                    return ValidationResult.Invalid(issues);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error validando evento: {ex}", ModuleId);
                return ValidationResult.Error($"Error de validación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Transforma evento para optimización (reduce tamaño)
        /// </summary>
        public TelemetryEvent TransformForOptimization(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return null;
            
            var transformed = CloneEvent(telemetryEvent);
            
            try
            {
                // 1. Eliminar metadatos innecesarios
                if (transformed.Metadata != null)
                {
                    var keysToRemove = transformed.Metadata.Keys
                        .Where(k => k.StartsWith("_temp") || k.StartsWith("debug_"))
                        .ToList();
                    
                    foreach (var key in keysToRemove)
                    {
                        transformed.Metadata.Remove(key);
                    }
                }
                
                // 2. Comprimir datos grandes
                if (transformed.Data != null)
                {
                    foreach (var key in transformed.Data.Keys.ToList())
                    {
                        var value = transformed.Data[key];
                        if (value is string str && str.Length > 1000)
                        {
                            // Comprimir strings largos
                            transformed.Data[key] = new
                            {
                                _compressed = true,
                                _originalLength = str.Length,
                                data = Convert.ToBase64String(
                                    Encoding.UTF8.GetBytes(str.Substring(0, 1000))) + "..."
                            };
                        }
                    }
                }
                
                // 3. Acortar nombres de propiedades largos
                transformed.Data = TransformPropertyNames(transformed.Data, true);
                transformed.Metadata = TransformPropertyNames(transformed.Metadata, false);
                
                // 4. Convertir timestamps a formato UNIX (más compacto)
                if (transformed.Data.ContainsKey("timestamp"))
                {
                    var timestamp = transformed.Data["timestamp"];
                    if (timestamp is DateTime dt)
                    {
                        transformed.Data["timestamp"] = new DateTimeOffset(dt).ToUnixTimeSeconds();
                    }
                }
                
                return transformed;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error transformando evento: {ex}", ModuleId);
                return telemetryEvent; // Devolver original si falla
            }
        }
        
        /// <summary>
        /// Normaliza evento (estandariza formato)
        /// </summary>
        public TelemetryEvent NormalizeEvent(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return null;
            
            var normalized = CloneEvent(telemetryEvent);
            
            try
            {
                // 1. Asegurar EventId
                if (string.IsNullOrEmpty(normalized.EventId))
                {
                    normalized.EventId = Guid.NewGuid().ToString();
                }
                
                // 2. Asegurar Timestamp
                if (normalized.Timestamp == default)
                {
                    normalized.Timestamp = DateTime.UtcNow;
                }
                
                // 3. Normalizar Severity
                if (!string.IsNullOrEmpty(normalized.Severity))
                {
                    normalized.Severity = normalized.Severity.ToLowerInvariant();
                }
                
                // 4. Normalizar EventType (camelCase)
                if (!string.IsNullOrEmpty(normalized.EventType))
                {
                    normalized.EventType = ToCamelCase(normalized.EventType);
                }
                
                // 5. Normalizar claves de Data y Metadata (camelCase)
                normalized.Data = NormalizeDictionaryKeys(normalized.Data);
                normalized.Metadata = NormalizeDictionaryKeys(normalized.Metadata);
                
                // 6. Añadir metadatos estándar
                if (normalized.Metadata == null)
                    normalized.Metadata = new Dictionary<string, object>();
                
                normalized.Metadata["normalizedAt"] = DateTime.UtcNow;
                normalized.Metadata["normalizerVersion"] = Version;
                
                // 7. Validar y corregir tipos de datos
                normalized.Data = FixDataTypes(normalized.Data);
                
                return normalized;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error normalizando evento: {ex}", ModuleId);
                return telemetryEvent;
            }
        }
        
        /// <summary>
        /// Calcula huella digital del evento (para deduplicación)
        /// </summary>
        public string CalculateEventFingerprint(TelemetryEvent telemetryEvent)
        {
            if (telemetryEvent == null)
                return string.Empty;
            
            try
            {
                // Crear string canónico para hashing
                var canonical = new StringBuilder();
                
                canonical.Append(telemetryEvent.EventType ?? "");
                canonical.Append("|");
                canonical.Append(telemetryEvent.Severity ?? "");
                canonical.Append("|");
                
                // Ordenar y añadir datos
                if (telemetryEvent.Data != null)
                {
                    var sortedKeys = telemetryEvent.Data.Keys.OrderBy(k => k);
                    foreach (var key in sortedKeys)
                    {
                        canonical.Append(key);
                        canonical.Append("=");
                        canonical.Append(telemetryEvent.Data[key]?.ToString() ?? "");
                        canonical.Append("|");
                    }
                }
                
                // Excluir campos variables como timestamp y eventId
                var canonicalString = canonical.ToString();
                return CryptoHelper.ComputeSha256Hash(canonicalString);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error calculando fingerprint: {ex}", ModuleId);
                return Guid.NewGuid().ToString();
            }
        }
        
        /// <summary>
        /// Comprime evento para transmisión
        /// </summary>
        public byte[] CompressEvent(TelemetryEvent telemetryEvent, CompressionFormat format = CompressionFormat.GZip)
        {
            if (telemetryEvent == null)
                return Array.Empty<byte>();
            
            try
            {
                var json = SerializeToJson(telemetryEvent, false);
                
                return format switch
                {
                    CompressionFormat.GZip => CryptoHelper.ToCompressedJson(json),
                    CompressionFormat.Deflate => CompressDeflate(json),
                    _ => Encoding.UTF8.GetBytes(json)
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error comprimiendo evento: {ex}", ModuleId);
                return Array.Empty<byte>();
            }
        }
        
        /// <summary>
        /// Descomprime evento
        /// </summary>
        public TelemetryEvent DecompressEvent(byte[] compressedData, CompressionFormat format = CompressionFormat.GZip)
        {
            if (compressedData == null || compressedData.Length == 0)
                return null;
            
            try
            {
                string json;
                
                switch (format)
                {
                    case CompressionFormat.GZip:
                        json = CryptoHelper.FromCompressedJson<string>(compressedData);
                        break;
                        
                    case CompressionFormat.Deflate:
                        json = DecompressDeflate(compressedData);
                        break;
                        
                    default:
                        json = Encoding.UTF8.GetString(compressedData);
                        break;
                }
                
                return DeserializeFromJson(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descomprimiendo evento: {ex}", ModuleId);
                return null;
            }
        }
        
        /// <summary>
        /// Compara dos eventos para equivalencia
        /// </summary>
        public bool AreEventsEquivalent(TelemetryEvent event1, TelemetryEvent event2, 
                                       bool ignoreTimestamps = true, 
                                       bool ignoreMetadata = false)
        {
            if (event1 == null && event2 == null)
                return true;
            
            if (event1 == null || event2 == null)
                return false;
            
            try
            {
                // Comparar fingerprint
                var fp1 = CalculateEventFingerprint(event1);
                var fp2 = CalculateEventFingerprint(event2);
                
                return CryptoHelper.SecureCompare(fp1, fp2);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error comparando eventos: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Agrega eventos similares
        /// </summary>
        public TelemetryEvent AggregateSimilarEvents(List<TelemetryEvent> events)
        {
            if (events == null || events.Count == 0)
                return null;
            
            if (events.Count == 1)
                return events[0];
            
            try
            {
                var firstEvent = events[0];
                var aggregated = CloneEvent(firstEvent);
                
                aggregated.EventId = Guid.NewGuid().ToString();
                aggregated.Timestamp = DateTime.UtcNow;
                aggregated.EventType = $"{firstEvent.EventType}_Aggregated";
                
                // Agregar metadatos
                aggregated.Metadata["aggregatedCount"] = events.Count;
                aggregated.Metadata["aggregatedFrom"] = events.Select(e => e.EventId).ToList();
                aggregated.Metadata["aggregatedAt"] = DateTime.UtcNow;
                
                // Agregar datos
                aggregated.Data["_aggregation"] = new
                {
                    count = events.Count,
                    timeRange = new
                    {
                        first = events.Min(e => e.Timestamp),
                        last = events.Max(e => e.Timestamp)
                    },
                    distinctEventIds = events.Select(e => e.EventId).Distinct().Count()
                };
                
                return aggregated;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error agregando eventos: {ex}", ModuleId);
                return null;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas de serialización
        /// </summary>
        public SerializationStats GetStats()
        {
            return new SerializationStats
            {
                Timestamp = DateTime.UtcNow,
                IsInitialized = _isInitialized,
                SchemasLoaded = _schemas.Count,
                FormatsSupported = new[] { "JSON", "XML", "MessagePack", "Compact", "GZip", "Deflate" }
            };
        }
        
        #region Métodos Privados
        
        private void RegisterConverters()
        {
            _compactOptions.Converters.Add(new JsonStringEnumConverter());
            _compactOptions.Converters.Add(new DateTimeConverter());
            _compactOptions.Converters.Add(new TimeSpanConverter());
            
            _prettyOptions.Converters.Add(new JsonStringEnumConverter());
            _prettyOptions.Converters.Add(new DateTimeConverter());
            _prettyOptions.Converters.Add(new TimeSpanConverter());
            
            _camelCaseOptions.Converters.Add(new JsonStringEnumConverter());
            _camelCaseOptions.Converters.Add(new DateTimeConverter());
        }
        
        private async Task LoadSchemasAsync()
        {
            try
            {
                // Cargar schemas predefinidos
                _schemas["ProcessEvent"] = new EventSchema
                {
                    Name = "ProcessEvent",
                    RequiredFields = new[] { "processId", "processName", "timestamp" },
                    FieldTypes = new Dictionary<string, Type>
                    {
                        { "processId", typeof(int) },
                        { "processName", typeof(string) },
                        { "timestamp", typeof(DateTime) }
                    }
                };
                
                _schemas["FileEvent"] = new EventSchema
                {
                    Name = "FileEvent",
                    RequiredFields = new[] { "filePath", "operation", "timestamp" },
                    FieldTypes = new Dictionary<string, Type>
                    {
                        { "filePath", typeof(string) },
                        { "operation", typeof(string) },
                        { "timestamp", typeof(DateTime) }
                    }
                };
                
                _schemas["NetworkEvent"] = new EventSchema
                {
                    Name = "NetworkEvent",
                    RequiredFields = new[] { "remoteAddress", "remotePort", "protocol" },
                    FieldTypes = new Dictionary<string, Type>
                    {
                        { "remoteAddress", typeof(string) },
                        { "remotePort", typeof(int) },
                        { "protocol", typeof(string) }
                    }
                };
                
                // En producción, cargar desde archivos o API
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando schemas: {ex}", ModuleId);
            }
        }
        
        private EventSchema GetSchemaForEvent(TelemetryEvent telemetryEvent, string schemaName = null)
        {
            if (!string.IsNullOrEmpty(schemaName) && _schemas.ContainsKey(schemaName))
                return _schemas[schemaName];
            
            // Intentar inferir schema basado en EventType
            if (!string.IsNullOrEmpty(telemetryEvent.EventType))
            {
                var eventType = telemetryEvent.EventType.ToLowerInvariant();
                
                if (eventType.Contains("process"))
                    return _schemas.GetValueOrDefault("ProcessEvent");
                
                if (eventType.Contains("file"))
                    return _schemas.GetValueOrDefault("FileEvent");
                
                if (eventType.Contains("network") || eventType.Contains("dns"))
                    return _schemas.GetValueOrDefault("NetworkEvent");
            }
            
            return null;
        }
        
        private List<string> ValidateWithSchema(TelemetryEvent telemetryEvent, EventSchema schema)
        {
            var issues = new List<string>();
            
            // Validar campos requeridos
            foreach (var requiredField in schema.RequiredFields)
            {
                if (!telemetryEvent.Data.ContainsKey(requiredField))
                {
                    issues.Add($"Campo requerido faltante: {requiredField}");
                }
            }
            
            // Validar tipos de campos
            foreach (var fieldType in schema.FieldTypes)
            {
                if (telemetryEvent.Data.TryGetValue(fieldType.Key, out var value))
                {
                    if (value != null && value.GetType() != fieldType.Value)
                    {
                        issues.Add($"Tipo incorrecto para {fieldType.Key}: esperado {fieldType.Value.Name}, obtenido {value.GetType().Name}");
                    }
                }
            }
            
            return issues;
        }
        
        private TelemetryEvent TransformForSerialization(TelemetryEvent telemetryEvent)
        {
            var transformed = CloneEvent(telemetryEvent);
            
            // Añadir metadatos de serialización
            if (transformed.Metadata == null)
                transformed.Metadata = new Dictionary<string, object>();
            
            transformed.Metadata["serializedAt"] = DateTime.UtcNow;
            transformed.Metadata["serializerVersion"] = Version;
            transformed.Metadata["serializerId"] = ModuleId;
            
            return transformed;
        }
        
        private string OptimizeJson(string json)
        {
            // Eliminar espacios innecesarios
            var optimized = json
                .Replace("  ", "")
                .Replace("\n", "")
                .Replace("\r", "")
                .Replace("\t", "");
            
            // Acortar nombres de propiedades conocidas
            var replacements = new Dictionary<string, string>
            {
                { "\"eventId\"", "\"id\"" },
                { "\"timestamp\"", "\"ts\"" },
                { "\"eventType\"", "\"type\"" },
                { "\"metadata\"", "\"meta\"" },
                { "\"data\"", "\"d\"" }
            };
            
            foreach (var replacement in replacements)
            {
                optimized = optimized.Replace(replacement.Key, replacement.Value);
            }
            
            return optimized;
        }
        
        private TelemetryEvent CloneEvent(TelemetryEvent original)
        {
            return new TelemetryEvent
            {
                EventId = original.EventId,
                Timestamp = original.Timestamp,
                EventType = original.EventType,
                Severity = original.Severity,
                Data = original.Data != null ? 
                    new Dictionary<string, object>(original.Data) : 
                    new Dictionary<string, object>(),
                Metadata = original.Metadata != null ? 
                    new Dictionary<string, object>(original.Metadata) : 
                    new Dictionary<string, object>()
            };
        }
        
        private Dictionary<string, object> TransformPropertyNames(Dictionary<string, object> dict, bool aggressive)
        {
            if (dict == null)
                return new Dictionary<string, object>();
            
            var transformed = new Dictionary<string, object>();
            
            foreach (var kvp in dict)
            {
                var newKey = aggressive ? ShortenPropertyName(kvp.Key) : ToCamelCase(kvp.Key);
                transformed[newKey] = kvp.Value;
            }
            
            return transformed;
        }
        
        private string ShortenPropertyName(string name)
        {
            if (name.Length <= 3)
                return name;
            
            var knownShortcuts = new Dictionary<string, string>
            {
                { "timestamp", "ts" },
                { "datetime", "dt" },
                { "identifier", "id" },
                { "configuration", "cfg" },
                { "temporary", "temp" },
                { "additional", "add" },
                { "information", "info" },
                { "authentication", "auth" },
                { "authorization", "authz" }
            };
            
            if (knownShortcuts.ContainsKey(name.ToLowerInvariant()))
                return knownShortcuts[name.ToLowerInvariant()];
            
            // Usar primeras letras de palabras
            var words = name.Split(new[] { '_', '-', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 1)
            {
                return string.Concat(words.Select(w => w[0])).ToLowerInvariant();
            }
            
            // Usar primeras 3 letras
            return name.Length > 3 ? name.Substring(0, 3).ToLowerInvariant() : name.ToLowerInvariant();
        }
        
        private string ToCamelCase(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;
            
            var words = input.Split(new[] { '_', '-', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0)
                return input;
            
            var result = words[0].ToLowerInvariant();
            for (int i = 1; i < words.Length; i++)
            {
                result += char.ToUpperInvariant(words[i][0]) + words[i].Substring(1).ToLowerInvariant();
            }
            
            return result;
        }
        
        private Dictionary<string, object> NormalizeDictionaryKeys(Dictionary<string, object> dict)
        {
            if (dict == null)
                return new Dictionary<string, object>();
            
            var normalized = new Dictionary<string, object>();
            
            foreach (var kvp in dict)
            {
                var normalizedKey = ToCamelCase(kvp.Key);
                normalized[normalizedKey] = kvp.Value;
            }
            
            return normalized;
        }
        
        private Dictionary<string, object> FixDataTypes(Dictionary<string, object> dict)
        {
            if (dict == null)
                return new Dictionary<string, object>();
            
            var fixedDict = new Dictionary<string, object>();
            
            foreach (var kvp in dict)
            {
                object fixedValue = kvp.Value;
                
                // Intentar convertir strings numéricas a números
                if (kvp.Value is string strValue)
                {
                    if (int.TryParse(strValue, out int intValue))
                    {
                        fixedValue = intValue;
                    }
                    else if (long.TryParse(strValue, out long longValue))
                    {
                        fixedValue = longValue;
                    }
                    else if (double.TryParse(strValue, out double doubleValue))
                    {
                        fixedValue = doubleValue;
                    }
                    else if (bool.TryParse(strValue, out bool boolValue))
                    {
                        fixedValue = boolValue;
                    }
                    else if (DateTime.TryParse(strValue, out DateTime dateValue))
                    {
                        fixedValue = dateValue;
                    }
                }
                
                fixedDict[kvp.Key] = fixedValue;
            }
            
            return fixedDict;
        }
        
        private bool IsValidEventId(string eventId)
        {
            if (string.IsNullOrEmpty(eventId))
                return false;
            
            // Debe ser GUID o alfanumérico con longitud razonable
            if (Guid.TryParse(eventId, out _))
                return true;
            
            if (eventId.Length > 100)
                return false;
            
            // Solo caracteres alfanuméricos y guiones
            return eventId.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
        }
        
        private byte[] CompressDeflate(string input)
        {
            using var output = new System.IO.MemoryStream();
            using (var compressor = new System.IO.Compression.DeflateStream(
                output, System.IO.Compression.CompressionLevel.Optimal))
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                compressor.Write(bytes, 0, bytes.Length);
            }
            return output.ToArray();
        }
        
        private string DecompressDeflate(byte[] compressed)
        {
            using var input = new System.IO.MemoryStream(compressed);
            using var decompressor = new System.IO.Compression.DeflateStream(
                input, System.IO.Compression.CompressionMode.Decompress);
            using var reader = new System.IO.StreamReader(decompressor, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        
        private string SerializeError(string eventId, Exception ex)
        {
            return JsonSerializer.Serialize(new
            {
                error = true,
                eventId = eventId ?? "unknown",
                message = ex.Message,
                timestamp = DateTime.UtcNow,
                serializer = ModuleId
            }, _compactOptions);
        }
        
        private TelemetryEvent CreateErrorEvent(string errorType, Exception ex)
        {
            return new TelemetryEvent
            {
                EventId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                EventType = "SerializationError",
                Severity = "Error",
                Data = new Dictionary<string, object>
                {
                    { "errorType", errorType },
                    { "errorMessage", ex.Message },
                    { "stackTrace", ex.StackTrace }
                },
                Metadata = new Dictionary<string, object>
                {
                    { "createdBy", ModuleId },
                    { "isError", true }
                }
            };
        }
        
        private string EscapeXml(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;
            
            return input
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&apos;");
        }
        
        #endregion
        
        #region Clases y Enums de Soporte
        
        private class EventSchema
        {
            public string Name { get; set; }
            public string[] RequiredFields { get; set; }
            public Dictionary<string, Type> FieldTypes { get; set; }
            public Dictionary<string, object> FieldConstraints { get; set; }
        }
        
        public class ValidationResult
        {
            public bool IsValid { get; set; }
            public List<string> Issues { get; set; }
            public string Error { get; set; }
            
            public static ValidationResult Valid()
            {
                return new ValidationResult
                {
                    IsValid = true,
                    Issues = new List<string>()
                };
            }
            
            public static ValidationResult Invalid(List<string> issues)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    Issues = issues ?? new List<string>()
                };
            }
            
            public static ValidationResult Error(string error)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    Error = error,
                    Issues = new List<string>()
                };
            }
        }
        
        public class SerializationStats
        {
            public DateTime Timestamp { get; set; }
            public bool IsInitialized { get; set; }
            public int SchemasLoaded { get; set; }
            public string[] FormatsSupported { get; set; }
        }
        
        public enum CompressionFormat
        {
            None,
            GZip,
            Deflate
        }
        
        private class DateTimeConverter : JsonConverter<DateTime>
        {
            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    if (DateTime.TryParse(reader.GetString(), out var dateTime))
                        return dateTime;
                }
                return DateTime.MinValue;
            }
            
            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString("o"));
            }
        }
        
        private class TimeSpanConverter : JsonConverter<TimeSpan>
        {
            public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    if (TimeSpan.TryParse(reader.GetString(), out var timeSpan))
                        return timeSpan;
                }
                return TimeSpan.Zero;
            }
            
            public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString());
            }
        }
        
        #endregion
    }
}