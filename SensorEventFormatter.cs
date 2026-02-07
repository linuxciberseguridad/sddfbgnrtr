using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Agent.Sensors
{
    /// <summary>
    /// Formateador de eventos de sensores
    /// Convierte eventos de todos los sensores a formato JSON/XML estandarizado
    /// </summary>
    public sealed class SensorEventFormatter : IAgentModule
    {
        private static readonly Lazy<SensorEventFormatter> _instance = 
            new Lazy<SensorEventFormatter>(() => new SensorEventFormatter());
        
        public static SensorEventFormatter Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly Dictionary<EventType, string> _eventTypeDescriptions;
        private bool _isInitialized;
        
        public string ModuleId => "SensorEventFormatter";
        public string Version => "1.0.0";
        public string Description => "Formateador de eventos de sensores";
        
        private SensorEventFormatter()
        {
            _logManager = LogManager.Instance;
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                Converters = { new JsonStringEnumConverter() }
            };
            
            _eventTypeDescriptions = new Dictionary<EventType, string>();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el formateador
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                InitializeEventTypeDescriptions();
                _isInitialized = true;
                
                _logManager.LogInfo("SensorEventFormatter inicializado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar SensorEventFormatter: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el formateador
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                return await InitializeAsync();
            }
            
            _logManager.LogInfo("SensorEventFormatter iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Detiene el formateador
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            _logManager.LogInfo("SensorEventFormatter detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Pausa el formateador
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _logManager.LogInfo("SensorEventFormatter pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el formateador
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _logManager.LogInfo("SensorEventFormatter reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Formatea un evento de proceso
        /// </summary>
        public SensorEvent FormatProcessEvent(string rawJsonEvent)
        {
            try
            {
                var processEvent = JsonSerializer.Deserialize<ProcessSensorData>(rawJsonEvent, _jsonOptions);
                if (processEvent == null)
                {
                    throw new FormatException("No se pudo deserializar evento de proceso");
                }
                
                return new SensorEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = processEvent.Timestamp,
                    EventType = processEvent.EventType,
                    SourceModule = "ProcessSensor",
                    SensorType = SensorType.Process,
                    Severity = CalculateProcessEventSeverity(processEvent),
                    Data = new EventData
                    {
                        ProcessId = processEvent.ProcessId,
                        ParentProcessId = processEvent.ParentProcessId,
                        ProcessName = processEvent.ProcessName,
                        ImagePath = processEvent.ImagePath,
                        CommandLine = processEvent.CommandLine,
                        UserSid = processEvent.UserSid,
                        IntegrityLevel = processEvent.IntegrityLevel,
                        IsElevated = processEvent.IsElevated,
                        SessionId = processEvent.SessionId,
                        WorkingSetSize = processEvent.WorkingSetSize,
                        ProcessHash = processEvent.ProcessHash,
                        AdditionalData = GetAdditionalProcessData(processEvent)
                    },
                    Metadata = new EventMetadata
                    {
                        SourceHost = Environment.MachineName,
                        SourceIp = GetLocalIpAddress(),
                        UserName = Environment.UserName,
                        Domain = Environment.UserDomainName
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al formatear evento de proceso: {ex}", ModuleId);
                return CreateErrorEvent(rawJsonEvent, ex);
            }
        }
        
        /// <summary>
        /// Formatea un evento de sistema de archivos
        /// </summary>
        public SensorEvent FormatFileSystemEvent(string rawJsonEvent)
        {
            try
            {
                var fileEvent = JsonSerializer.Deserialize<FileSystemSensorData>(rawJsonEvent, _jsonOptions);
                if (fileEvent == null)
                {
                    throw new FormatException("No se pudo deserializar evento de sistema de archivos");
                }
                
                return new SensorEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = fileEvent.Timestamp,
                    EventType = fileEvent.EventType,
                    SourceModule = "FileSystemSensor",
                    SensorType = SensorType.FileSystem,
                    Severity = CalculateFileSystemEventSeverity(fileEvent),
                    Data = new EventData
                    {
                        FilePath = fileEvent.FilePath,
                        OldFilePath = fileEvent.OldFilePath,
                        ProcessId = fileEvent.ProcessId,
                        ProcessName = fileEvent.ProcessName,
                        UserName = fileEvent.UserName,
                        OperationType = fileEvent.OperationType,
                        FileSize = fileEvent.FileSize,
                        IsDirectory = fileEvent.IsDirectory,
                        FileAttributes = fileEvent.FileAttributes,
                        FileHash = fileEvent.FileHash,
                        CreationTime = fileEvent.CreationTime,
                        LastWriteTime = fileEvent.LastWriteTime,
                        AdditionalData = GetAdditionalFileSystemData(fileEvent)
                    },
                    Metadata = new EventMetadata
                    {
                        SourceHost = Environment.MachineName,
                        SourceIp = GetLocalIpAddress(),
                        UserName = Environment.UserName,
                        Domain = Environment.UserDomainName
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al formatear evento de sistema de archivos: {ex}", ModuleId);
                return CreateErrorEvent(rawJsonEvent, ex);
            }
        }
        
        /// <summary>
        /// Formatea un evento de red
        /// </summary>
        public SensorEvent FormatNetworkEvent(string rawJsonEvent)
        {
            try
            {
                var networkEvent = JsonSerializer.Deserialize<NetworkSensorData>(rawJsonEvent, _jsonOptions);
                if (networkEvent == null)
                {
                    throw new FormatException("No se pudo deserializar evento de red");
                }
                
                return new SensorEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = networkEvent.Timestamp,
                    EventType = networkEvent.EventType,
                    SourceModule = "NetworkSensor",
                    SensorType = SensorType.Network,
                    Severity = CalculateNetworkEventSeverity(networkEvent),
                    Data = new EventData
                    {
                        ProcessId = networkEvent.ProcessId,
                        ProcessName = networkEvent.ProcessName,
                        LocalAddress = networkEvent.LocalAddress,
                        LocalPort = networkEvent.LocalPort,
                        RemoteAddress = networkEvent.RemoteAddress,
                        RemotePort = networkEvent.RemotePort,
                        Protocol = networkEvent.Protocol,
                        State = networkEvent.State,
                        IsOutbound = networkEvent.IsOutbound,
                        UserName = networkEvent.UserName,
                        DnsName = networkEvent.DnsName,
                        BytesSent = networkEvent.BytesSent,
                        BytesReceived = networkEvent.BytesReceived,
                        AdditionalData = GetAdditionalNetworkData(networkEvent)
                    },
                    Metadata = new EventMetadata
                    {
                        SourceHost = Environment.MachineName,
                        SourceIp = GetLocalIpAddress(),
                        UserName = Environment.UserName,
                        Domain = Environment.UserDomainName
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al formatear evento de red: {ex}", ModuleId);
                return CreateErrorEvent(rawJsonEvent, ex);
            }
        }
        
        /// <summary>
        /// Formatea un evento de registro
        /// </summary>
        public SensorEvent FormatRegistryEvent(string rawJsonEvent)
        {
            try
            {
                var registryEvent = JsonSerializer.Deserialize<RegistrySensorData>(rawJsonEvent, _jsonOptions);
                if (registryEvent == null)
                {
                    throw new FormatException("No se pudo deserializar evento de registro");
                }
                
                return new SensorEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = registryEvent.Timestamp,
                    EventType = registryEvent.EventType,
                    SourceModule = "RegistrySensor",
                    SensorType = SensorType.Registry,
                    Severity = CalculateRegistryEventSeverity(registryEvent),
                    Data = new EventData
                    {
                        ProcessId = registryEvent.ProcessId,
                        ProcessName = registryEvent.ProcessName,
                        RegistryPath = registryEvent.RegistryPath,
                        ValueName = registryEvent.ValueName,
                        OldValueData = registryEvent.OldValueData,
                        NewValueData = registryEvent.NewValueData,
                        Operation = registryEvent.Operation,
                        ValueType = registryEvent.ValueType,
                        UserName = registryEvent.UserName,
                        IsSystemKey = registryEvent.IsSystemKey,
                        IsAutoRun = registryEvent.IsAutoRun,
                        AdditionalData = GetAdditionalRegistryData(registryEvent)
                    },
                    Metadata = new EventMetadata
                    {
                        SourceHost = Environment.MachineName,
                        SourceIp = GetLocalIpAddress(),
                        UserName = Environment.UserName,
                        Domain = Environment.UserDomainName
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al formatear evento de registro: {ex}", ModuleId);
                return CreateErrorEvent(rawJsonEvent, ex);
            }
        }
        
        /// <summary>
        /// Formatea un evento genérico a partir de JSON crudo
        /// </summary>
        public SensorEvent FormatEvent(string rawJsonEvent, SensorType sensorType)
        {
            return sensorType switch
            {
                SensorType.Process => FormatProcessEvent(rawJsonEvent),
                SensorType.FileSystem => FormatFileSystemEvent(rawJsonEvent),
                SensorType.Network => FormatNetworkEvent(rawJsonEvent),
                SensorType.Registry => FormatRegistryEvent(rawJsonEvent),
                _ => FormatGenericEvent(rawJsonEvent, sensorType)
            };
        }
        
        /// <summary>
        /// Formatea múltiples eventos
        /// </summary>
        public List<SensorEvent> FormatEvents(List<string> rawJsonEvents, SensorType sensorType)
        {
            var formattedEvents = new List<SensorEvent>();
            
            foreach (var rawEvent in rawJsonEvents)
            {
                try
                {
                    var formattedEvent = FormatEvent(rawEvent, sensorType);
                    formattedEvents.Add(formattedEvent);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al formatear evento: {ex}", ModuleId);
                }
            }
            
            return formattedEvents;
        }
        
        /// <summary>
        /// Convierte un SensorEvent a JSON
        /// </summary>
        public string ToJson(SensorEvent sensorEvent)
        {
            try
            {
                return JsonSerializer.Serialize(sensorEvent, _jsonOptions);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al serializar evento a JSON: {ex}", ModuleId);
                return $"{{ \"error\": \"{ex.Message}\" }}";
            }
        }
        
        /// <summary>
        /// Convierte un SensorEvent a XML
        /// </summary>
        public string ToXml(SensorEvent sensorEvent)
        {
            try
            {
                var xml = new StringBuilder();
                xml.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                xml.AppendLine("<SensorEvent>");
                xml.AppendLine($"  <EventId>{EscapeXml(sensorEvent.EventId)}</EventId>");
                xml.AppendLine($"  <Timestamp>{sensorEvent.Timestamp:o}</Timestamp>");
                xml.AppendLine($"  <EventType>{(int)sensorEvent.EventType}</EventType>");
                xml.AppendLine($"  <EventTypeDescription>{GetEventTypeDescription(sensorEvent.EventType)}</EventTypeDescription>");
                xml.AppendLine($"  <SourceModule>{EscapeXml(sensorEvent.SourceModule)}</SourceModule>");
                xml.AppendLine($"  <SensorType>{sensorEvent.SensorType}</SensorType>");
                xml.AppendLine($"  <Severity>{sensorEvent.Severity}</Severity>");
                
                xml.AppendLine("  <Data>");
                AppendEventDataToXml(xml, sensorEvent.Data);
                xml.AppendLine("  </Data>");
                
                xml.AppendLine("  <Metadata>");
                xml.AppendLine($"    <SourceHost>{EscapeXml(sensorEvent.Metadata.SourceHost)}</SourceHost>");
                xml.AppendLine($"    <SourceIp>{EscapeXml(sensorEvent.Metadata.SourceIp)}</SourceIp>");
                xml.AppendLine($"    <UserName>{EscapeXml(sensorEvent.Metadata.UserName)}</UserName>");
                xml.AppendLine($"    <Domain>{EscapeXml(sensorEvent.Metadata.Domain)}</Domain>");
                xml.AppendLine("  </Metadata>");
                
                xml.AppendLine("</SensorEvent>");
                
                return xml.ToString();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al convertir evento a XML: {ex}", ModuleId);
                return $"<Error>{EscapeXml(ex.Message)}</Error>";
            }
        }
        
        /// <summary>
        /// Valida si un JSON es un evento válido
        /// </summary>
        public bool ValidateEventJson(string json, SensorType expectedSensorType)
        {
            try
            {
                var eventType = GetEventTypeFromJson(json);
                if (!eventType.HasValue)
                {
                    return false;
                }
                
                // Validar campos mínimos según tipo de sensor
                return expectedSensorType switch
                {
                    SensorType.Process => ValidateProcessEventJson(json),
                    SensorType.FileSystem => ValidateFileSystemEventJson(json),
                    SensorType.Network => ValidateNetworkEventJson(json),
                    SensorType.Registry => ValidateRegistryEventJson(json),
                    _ => true
                };
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene el tipo de evento desde JSON
        /// </summary>
        public EventType? GetEventTypeFromJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("eventType", out var eventTypeProp))
                {
                    if (eventTypeProp.ValueKind == JsonValueKind.Number && 
                        eventTypeProp.TryGetInt32(out int eventTypeValue))
                    {
                        return (EventType)eventTypeValue;
                    }
                }
                return null;
            }
            catch
            {
                return null;
            }
        }
        
        /// <summary>
        /// Normaliza datos de evento para consistencia
        /// </summary>
        public void NormalizeEventData(SensorEvent sensorEvent)
        {
            if (sensorEvent == null || sensorEvent.Data == null)
                return;
            
            // Normalizar rutas de archivos
            if (!string.IsNullOrEmpty(sensorEvent.Data.FilePath))
            {
                sensorEvent.Data.FilePath = NormalizePath(sensorEvent.Data.FilePath);
            }
            
            if (!string.IsNullOrEmpty(sensorEvent.Data.OldFilePath))
            {
                sensorEvent.Data.OldFilePath = NormalizePath(sensorEvent.Data.OldFilePath);
            }
            
            if (!string.IsNullOrEmpty(sensorEvent.Data.ImagePath))
            {
                sensorEvent.Data.ImagePath = NormalizePath(sensorEvent.Data.ImagePath);
            }
            
            // Normalizar nombres de proceso
            if (!string.IsNullOrEmpty(sensorEvent.Data.ProcessName))
            {
                sensorEvent.Data.ProcessName = sensorEvent.Data.ProcessName.ToLowerInvariant();
            }
            
            // Normalizar direcciones IP
            if (!string.IsNullOrEmpty(sensorEvent.Data.RemoteAddress))
            {
                sensorEvent.Data.RemoteAddress = NormalizeIpAddress(sensorEvent.Data.RemoteAddress);
            }
            
            // Normalizar rutas de registro
            if (!string.IsNullOrEmpty(sensorEvent.Data.RegistryPath))
            {
                sensorEvent.Data.RegistryPath = NormalizeRegistryPath(sensorEvent.Data.RegistryPath);
            }
            
            // Asegurar campos obligatorios
            if (string.IsNullOrEmpty(sensorEvent.EventId))
            {
                sensorEvent.EventId = Guid.NewGuid().ToString();
            }
            
            if (sensorEvent.Timestamp == default)
            {
                sensorEvent.Timestamp = DateTime.UtcNow;
            }
        }
        
        #region Métodos privados
        
        private void InitializeEventTypeDescriptions()
        {
            _eventTypeDescriptions[EventType.ProcessCreated] = "Creación de proceso";
            _eventTypeDescriptions[EventType.ProcessTerminated] = "Terminación de proceso";
            _eventTypeDescriptions[EventType.ProcessSuspicious] = "Proceso sospechoso";
            _eventTypeDescriptions[EventType.FileCreated] = "Creación de archivo";
            _eventTypeDescriptions[EventType.FileModified] = "Modificación de archivo";
            _eventTypeDescriptions[EventType.FileDeleted] = "Eliminación de archivo";
            _eventTypeDescriptions[EventType.FileRenamed] = "Renombrado de archivo";
            _eventTypeDescriptions[EventType.FileSuspiciousChange] = "Cambio sospechoso en archivo";
            _eventTypeDescriptions[EventType.FileIntegrityViolation] = "Violación de integridad de archivo";
            _eventTypeDescriptions[EventType.TcpConnection] = "Conexión TCP";
            _eventTypeDescriptions[EventType.UdpActivity] = "Actividad UDP";
            _eventTypeDescriptions[EventType.DnsQuery] = "Consulta DNS";
            _eventTypeDescriptions[EventType.SuspiciousConnection] = "Conexión sospechosa";
            _eventTypeDescriptions[EventType.SuspiciousDns] = "Consulta DNS sospechosa";
            _eventTypeDescriptions[EventType.SuspiciousDataTransfer] = "Transferencia de datos sospechosa";
            _eventTypeDescriptions[EventType.RegistryKeyCreated] = "Clave de registro creada";
            _eventTypeDescriptions[EventType.RegistryKeyDeleted] = "Clave de registro eliminada";
            _eventTypeDescriptions[EventType.RegistryValueSet] = "Valor de registro establecido";
            _eventTypeDescriptions[EventType.RegistryValueDeleted] = "Valor de registro eliminado";
            _eventTypeDescriptions[EventType.SuspiciousRegistryChange] = "Cambio sospechoso en registro";
            _eventTypeDescriptions[EventType.MaliciousPersistence] = "Persistencia maliciosa detectada";
        }
        
        private ThreatSeverity CalculateProcessEventSeverity(ProcessSensorData processEvent)
        {
            // Lógica de severidad para eventos de proceso
            if (processEvent.EventType == EventType.ProcessSuspicious)
                return ThreatSeverity.High;
            
            if (processEvent.IntegrityLevel == "Low" && processEvent.IsElevated)
                return ThreatSeverity.Medium;
            
            if (IsSuspiciousProcessName(processEvent.ProcessName))
                return ThreatSeverity.Medium;
            
            return ThreatSeverity.Low;
        }
        
        private ThreatSeverity CalculateFileSystemEventSeverity(FileSystemSensorData fileEvent)
        {
            // Lógica de severidad para eventos de sistema de archivos
            if (fileEvent.EventType == EventType.FileIntegrityViolation)
                return ThreatSeverity.Critical;
            
            if (fileEvent.EventType == EventType.FileSuspiciousChange)
                return ThreatSeverity.High;
            
            if (IsCriticalSystemFile(fileEvent.FilePath))
                return ThreatSeverity.High;
            
            if (IsSuspiciousFileExtension(fileEvent.FilePath))
                return ThreatSeverity.Medium;
            
            return ThreatSeverity.Low;
        }
        
        private ThreatSeverity CalculateNetworkEventSeverity(NetworkSensorData networkEvent)
        {
            // Lógica de severidad para eventos de red
            if (networkEvent.EventType == EventType.SuspiciousConnection ||
                networkEvent.EventType == EventType.SuspiciousDns ||
                networkEvent.EventType == EventType.SuspiciousDataTransfer)
                return ThreatSeverity.High;
            
            if (IsSuspiciousPort(networkEvent.RemotePort))
                return ThreatSeverity.Medium;
            
            if (IsPrivateIpAddress(networkEvent.RemoteAddress) && networkEvent.IsOutbound)
                return ThreatSeverity.Low;
            
            return ThreatSeverity.Info;
        }
        
        private ThreatSeverity CalculateRegistryEventSeverity(RegistrySensorData registryEvent)
        {
            // Lógica de severidad para eventos de registro
            if (registryEvent.EventType == EventType.MaliciousPersistence)
                return ThreatSeverity.Critical;
            
            if (registryEvent.EventType == EventType.SuspiciousRegistryChange)
                return ThreatSeverity.High;
            
            if (registryEvent.IsAutoRun)
                return ThreatSeverity.Medium;
            
            if (registryEvent.IsSystemKey)
                return ThreatSeverity.Medium;
            
            return ThreatSeverity.Low;
        }
        
        private bool IsSuspiciousProcessName(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;
                
            var suspiciousNames = new[] { "powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32" };
            var lowerName = processName.ToLowerInvariant();
            
            return suspiciousNames.Any(name => lowerName.Contains(name));
        }
        
        private bool IsCriticalSystemFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;
                
            var criticalPaths = new[] 
            {
                @"C:\Windows\System32\",
                @"C:\Windows\SysWOW64\",
                @"C:\Windows\system32\drivers\"
            };
            
            var normalizedPath = NormalizePath(filePath);
            return criticalPaths.Any(path => normalizedPath.StartsWith(path, StringComparison.OrdinalIgnoreCase));
        }
        
        private bool IsSuspiciousFileExtension(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;
                
            var suspiciousExtensions = new[] { ".ps1", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".wsh", ".scr" };
            var lowerPath = filePath.ToLowerInvariant();
            
            return suspiciousExtensions.Any(ext => lowerPath.EndsWith(ext));
        }
        
        private bool IsSuspiciousPort(int port)
        {
            var suspiciousPorts = new[] { 4444, 5555, 6666, 6667, 6668, 6669, 31337, 12345, 12346, 20034, 27374 };
            return suspiciousPorts.Contains(port);
        }
        
        private bool IsPrivateIpAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;
                
            var privateRanges = new[] 
            {
                "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
            };
            
            return privateRanges.Any(range => ipAddress.StartsWith(range));
        }
        
        private Dictionary<string, object> GetAdditionalProcessData(ProcessSensorData processEvent)
        {
            var additionalData = new Dictionary<string, object>();
            
            if (!string.IsNullOrEmpty(processEvent.ProcessHash))
                additionalData["ProcessHash"] = processEvent.ProcessHash;
            
            if (processEvent.WorkingSetSize > 0)
                additionalData["MemoryUsageMB"] = processEvent.WorkingSetSize / (1024 * 1024);
            
            return additionalData;
        }
        
        private Dictionary<string, object> GetAdditionalFileSystemData(FileSystemSensorData fileEvent)
        {
            var additionalData = new Dictionary<string, object>();
            
            if (fileEvent.FileSize > 0)
                additionalData["FileSizeMB"] = fileEvent.FileSize / (1024 * 1024);
            
            if (fileEvent.FileAttributes > 0)
                additionalData["FileAttributesDescription"] = GetFileAttributesDescription(fileEvent.FileAttributes);
            
            return additionalData;
        }
        
        private Dictionary<string, object> GetAdditionalNetworkData(NetworkSensorData networkEvent)
        {
            var additionalData = new Dictionary<string, object>();
            
            if (networkEvent.BytesSent > 0 || networkEvent.BytesReceived > 0)
            {
                additionalData["TotalBytes"] = networkEvent.BytesSent + networkEvent.BytesReceived;
                additionalData["TotalBytesMB"] = (networkEvent.BytesSent + networkEvent.BytesReceived) / (1024 * 1024);
            }
            
            if (networkEvent.Protocol == 6) // TCP
                additionalData["ProtocolName"] = "TCP";
            else if (networkEvent.Protocol == 17) // UDP
                additionalData["ProtocolName"] = "UDP";
            else
                additionalData["ProtocolName"] = $"Unknown ({networkEvent.Protocol})";
            
            return additionalData;
        }
        
        private Dictionary<string, object> GetAdditionalRegistryData(RegistrySensorData registryEvent)
        {
            var additionalData = new Dictionary<string, object>();
            
            if (registryEvent.ValueType > 0)
                additionalData["ValueTypeName"] = GetRegistryValueTypeName(registryEvent.ValueType);
            
            return additionalData;
        }
        
        private SensorEvent FormatGenericEvent(string rawJsonEvent, SensorType sensorType)
        {
            try
            {
                var genericEvent = JsonSerializer.Deserialize<Dictionary<string, object>>(rawJsonEvent, _jsonOptions);
                
                return new SensorEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = EventType.Unknown,
                    SourceModule = sensorType.ToString(),
                    SensorType = sensorType,
                    Severity = ThreatSeverity.Info,
                    Data = new EventData
                    {
                        AdditionalData = genericEvent
                    },
                    Metadata = new EventMetadata
                    {
                        SourceHost = Environment.MachineName,
                        SourceIp = GetLocalIpAddress(),
                        UserName = Environment.UserName,
                        Domain = Environment.UserDomainName
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al formatear evento genérico: {ex}", ModuleId);
                return CreateErrorEvent(rawJsonEvent, ex);
            }
        }
        
        private SensorEvent CreateErrorEvent(string rawEvent, Exception ex)
        {
            return new SensorEvent
            {
                EventId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                EventType = EventType.FormatError,
                SourceModule = ModuleId,
                SensorType = SensorType.Internal,
                Severity = ThreatSeverity.High,
                Data = new EventData
                {
                    AdditionalData = new Dictionary<string, object>
                    {
                        { "RawEvent", rawEvent },
                        { "ErrorMessage", ex.Message },
                        { "ErrorStackTrace", ex.StackTrace }
                    }
                },
                Metadata = new EventMetadata
                {
                    SourceHost = Environment.MachineName,
                    SourceIp = GetLocalIpAddress(),
                    UserName = Environment.UserName,
                    Domain = Environment.UserDomainName,
                    AdditionalInfo = new Dictionary<string, object>
                    {
                        { "IsError", true },
                        { "ErrorTimestamp", DateTime.UtcNow }
                    }
                }
            };
        }
        
        private string GetEventTypeDescription(EventType eventType)
        {
            return _eventTypeDescriptions.TryGetValue(eventType, out var description) 
                ? description 
                : "Tipo de evento desconocido";
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
        
        private void AppendEventDataToXml(StringBuilder xml, EventData data)
        {
            if (data == null)
                return;
                
            if (!string.IsNullOrEmpty(data.ProcessId))
                xml.AppendLine($"    <ProcessId>{data.ProcessId}</ProcessId>");
                
            if (!string.IsNullOrEmpty(data.ProcessName))
                xml.AppendLine($"    <ProcessName>{EscapeXml(data.ProcessName)}</ProcessName>");
                
            if (!string.IsNullOrEmpty(data.FilePath))
                xml.AppendLine($"    <FilePath>{EscapeXml(data.FilePath)}</FilePath>");
                
            if (!string.IsNullOrEmpty(data.RemoteAddress))
                xml.AppendLine($"    <RemoteAddress>{EscapeXml(data.RemoteAddress)}</RemoteAddress>");
                
            if (data.RemotePort > 0)
                xml.AppendLine($"    <RemotePort>{data.RemotePort}</RemotePort>");
                
            if (!string.IsNullOrEmpty(data.RegistryPath))
                xml.AppendLine($"    <RegistryPath>{EscapeXml(data.RegistryPath)}</RegistryPath>");
                
            // Agregar datos adicionales
            if (data.AdditionalData != null && data.AdditionalData.Count > 0)
            {
                xml.AppendLine("    <AdditionalData>");
                foreach (var kvp in data.AdditionalData)
                {
                    xml.AppendLine($"      <{EscapeXml(kvp.Key)}>{EscapeXml(kvp.Value?.ToString() ?? "")}</{EscapeXml(kvp.Key)}>");
                }
                xml.AppendLine("    </AdditionalData>");
            }
        }
        
        private bool ValidateProcessEventJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                return root.TryGetProperty("processId", out _) &&
                       root.TryGetProperty("processName", out _) &&
                       root.TryGetProperty("timestamp", out _);
            }
            catch
            {
                return false;
            }
        }
        
        private bool ValidateFileSystemEventJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                return root.TryGetProperty("filePath", out _) &&
                       root.TryGetProperty("operationType", out _) &&
                       root.TryGetProperty("timestamp", out _);
            }
            catch
            {
                return false;
            }
        }
        
        private bool ValidateNetworkEventJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                return root.TryGetProperty("remoteAddress", out _) &&
                       root.TryGetProperty("remotePort", out _) &&
                       root.TryGetProperty("timestamp", out _);
            }
            catch
            {
                return false;
            }
        }
        
        private bool ValidateRegistryEventJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                return root.TryGetProperty("registryPath", out _) &&
                       root.TryGetProperty("operation", out _) &&
                       root.TryGetProperty("timestamp", out _);
            }
            catch
            {
                return false;
            }
        }
        
        private string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return path;
                
            return path.Replace('/', '\\').TrimEnd('\\');
        }
        
        private string NormalizeIpAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return ipAddress;
                
            // Simplificar IPv6
            if (ipAddress.Contains(":"))
            {
                return ipAddress.ToLowerInvariant();
            }
            
            return ipAddress;
        }
        
        private string NormalizeRegistryPath(string registryPath)
        {
            if (string.IsNullOrEmpty(registryPath))
                return registryPath;
                
            // Convertir abreviaturas comunes
            var normalized = registryPath
                .Replace("HKLM\\", "HKEY_LOCAL_MACHINE\\")
                .Replace("HKCU\\", "HKEY_CURRENT_USER\\")
                .Replace("HKCR\\", "HKEY_CLASSES_ROOT\\")
                .Replace("HKU\\", "HKEY_USERS\\")
                .Replace("HKCC\\", "HKEY_CURRENT_CONFIG\\");
                
            return normalized.ToUpperInvariant();
        }
        
        private string GetLocalIpAddress()
        {
            try
            {
                var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
                return "127.0.0.1";
            }
            catch
            {
                return "127.0.0.1";
            }
        }
        
        private string GetFileAttributesDescription(uint attributes)
        {
            var descriptions = new List<string>();
            
            if ((attributes & 0x1) != 0) descriptions.Add("READONLY");
            if ((attributes & 0x2) != 0) descriptions.Add("HIDDEN");
            if ((attributes & 0x4) != 0) descriptions.Add("SYSTEM");
            if ((attributes & 0x10) != 0) descriptions.Add("DIRECTORY");
            if ((attributes & 0x20) != 0) descriptions.Add("ARCHIVE");
            
            return string.Join(", ", descriptions);
        }
        
        private string GetRegistryValueTypeName(uint valueType)
        {
            return valueType switch
            {
                0 => "REG_NONE",
                1 => "REG_SZ",
                2 => "REG_EXPAND_SZ",
                3 => "REG_BINARY",
                4 => "REG_DWORD",
                5 => "REG_DWORD_BIG_ENDIAN",
                6 => "REG_LINK",
                7 => "REG_MULTI_SZ",
                8 => "REG_RESOURCE_LIST",
                9 => "REG_FULL_RESOURCE_DESCRIPTOR",
                10 => "REG_RESOURCE_REQUIREMENTS_LIST",
                11 => "REG_QWORD",
                _ => $"UNKNOWN ({valueType})"
            };
        }
        
        #endregion
        
        #region Clases de datos
        
        private class ProcessSensorData
        {
            public DateTime Timestamp { get; set; }
            public EventType EventType { get; set; }
            public string Source { get; set; }
            public int ProcessId { get; set; }
            public int ParentProcessId { get; set; }
            public string ProcessName { get; set; }
            public string ImagePath { get; set; }
            public string CommandLine { get; set; }
            public string UserSid { get; set; }
            public string IntegrityLevel { get; set; }
            public bool IsElevated { get; set; }
            public int SessionId { get; set; }
            public long WorkingSetSize { get; set; }
            public string ProcessHash { get; set; }
        }
        
        private class FileSystemSensorData
        {
            public DateTime Timestamp { get; set; }
            public EventType EventType { get; set; }
            public string Source { get; set; }
            public string FilePath { get; set; }
            public string OldFilePath { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string UserName { get; set; }
            public string OperationType { get; set; }
            public long FileSize { get; set; }
            public bool IsDirectory { get; set; }
            public uint FileAttributes { get; set; }
            public string FileHash { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
        }
        
        private class NetworkSensorData
        {
            public DateTime Timestamp { get; set; }
            public EventType EventType { get; set; }
            public string Source { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string LocalAddress { get; set; }
            public int LocalPort { get; set; }
            public string RemoteAddress { get; set; }
            public int RemotePort { get; set; }
            public int Protocol { get; set; }
            public int State { get; set; }
            public bool IsOutbound { get; set; }
            public string UserName { get; set; }
            public string DnsName { get; set; }
            public long BytesSent { get; set; }
            public long BytesReceived { get; set; }
        }
        
        private class RegistrySensorData
        {
            public DateTime Timestamp { get; set; }
            public EventType EventType { get; set; }
            public string Source { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string RegistryPath { get; set; }
            public string ValueName { get; set; }
            public string OldValueData { get; set; }
            public string NewValueData { get; set; }
            public int Operation { get; set; }
            public uint ValueType { get; set; }
            public string UserName { get; set; }
            public bool IsSystemKey { get; set; }
            public bool IsAutoRun { get; set; }
        }
        
        #endregion
    }
    
    /// <summary>
    /// Evento de sensor formateado
    /// </summary>
    public class SensorEvent
    {
        public string EventId { get; set; }
        public DateTime Timestamp { get; set; }
        public EventType EventType { get; set; }
        public string SourceModule { get; set; }
        public SensorType SensorType { get; set; }
        public ThreatSeverity Severity { get; set; }
        public EventData Data { get; set; }
        public EventMetadata Metadata { get; set; }
        
        public SensorEvent()
        {
            Data = new EventData();
            Metadata = new EventMetadata();
        }
    }
    
    /// <summary>
    /// Datos del evento
    /// </summary>
    public class EventData
    {
        // Campos comunes
        public string ProcessId { get; set; }
        public string ParentProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ImagePath { get; set; }
        public string CommandLine { get; set; }
        public string UserSid { get; set; }
        public string IntegrityLevel { get; set; }
        public bool? IsElevated { get; set; }
        public int? SessionId { get; set; }
        public long? WorkingSetSize { get; set; }
        public string ProcessHash { get; set; }
        
        // Campos de sistema de archivos
        public string FilePath { get; set; }
        public string OldFilePath { get; set; }
        public string UserName { get; set; }
        public string OperationType { get; set; }
        public long? FileSize { get; set; }
        public bool? IsDirectory { get; set; }
        public uint? FileAttributes { get; set; }
        public string FileHash { get; set; }
        public DateTime? CreationTime { get; set; }
        public DateTime? LastWriteTime { get; set; }
        
        // Campos de red
        public string LocalAddress { get; set; }
        public int? LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int? RemotePort { get; set; }
        public int? Protocol { get; set; }
        public int? State { get; set; }
        public bool? IsOutbound { get; set; }
        public string DnsName { get; set; }
        public long? BytesSent { get; set; }
        public long? BytesReceived { get; set; }
        
        // Campos de registro
        public string RegistryPath { get; set; }
        public string ValueName { get; set; }
        public string OldValueData { get; set; }
        public string NewValueData { get; set; }
        public int? Operation { get; set; }
        public uint? ValueType { get; set; }
        public bool? IsSystemKey { get; set; }
        public bool? IsAutoRun { get; set; }
        
        // Datos adicionales
        public Dictionary<string, object> AdditionalData { get; set; }
        
        public EventData()
        {
            AdditionalData = new Dictionary<string, object>();
        }
    }
    
    /// <summary>
    /// Metadatos del evento
    /// </summary>
    public class EventMetadata
    {
        public string SourceHost { get; set; }
        public string SourceIp { get; set; }
        public string UserName { get; set; }
        public string Domain { get; set; }
        public Dictionary<string, object> AdditionalInfo { get; set; }
        
        public EventMetadata()
        {
            AdditionalInfo = new Dictionary<string, object>();
        }
    }
    
    /// <summary>
    /// Tipos de sensor
    /// </summary>
    public enum SensorType
    {
        Process,
        FileSystem,
        Network,
        Registry,
        Internal,
        Unknown
    }
    
    /// <summary>
    /// Tipos de evento (extendido)
    /// </summary>
    public enum EventType
    {
        Unknown = 0,
        
        // Proceso
        ProcessCreated = 1001,
        ProcessTerminated = 1002,
        ProcessSuspicious = 1003,
        
        // Sistema de archivos
        FileCreated = 2001,
        FileModified = 2002,
        FileDeleted = 2003,
        FileRenamed = 2004,
        FileSuspiciousChange = 2005,
        FileIntegrityViolation = 2006,
        
        // Red
        TcpConnection = 3001,
        UdpActivity = 3002,
        DnsQuery = 3003,
        SuspiciousConnection = 3004,
        SuspiciousDns = 3005,
        SuspiciousDataTransfer = 3006,
        
        // Registro
        RegistryKeyCreated = 4001,
        RegistryKeyDeleted = 4002,
        RegistryValueSet = 4003,
        RegistryValueDeleted = 4004,
        RegistryKeyRenamed = 4005,
        SuspiciousRegistryChange = 4006,
        MaliciousPersistence = 4007,
        
        // Internos
        FormatError = 9998,
        SystemError = 9999
    }
    
    /// <summary>
    /// Severidad de amenaza
    /// </summary>
    public enum ThreatSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}