using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Sensors;
using BWP.Enterprise.Agent.Storage;

namespace BWP.Enterprise.Agent.Detection
{
    /// <summary>
    /// Motor de reglas para detección de amenazas conocidas
    /// Usa hashes, firmas y reglas estáticas para detectar malware
    /// </summary>
    public sealed class RuleEngine : IAgentModule, IDetectionEngine
    {
        private static readonly Lazy<RuleEngine> _instance = 
            new Lazy<RuleEngine>(() => new RuleEngine());
        
        public static RuleEngine Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly ConcurrentDictionary<string, ThreatSignature> _signatures;
        private readonly ConcurrentDictionary<string, ThreatRule> _rules;
        private readonly ConcurrentBag<DetectionRule> _yaraRules;
        private readonly ConcurrentDictionary<string, DateTime> _hashCache;
        private bool _isInitialized;
        private bool _isRunning;
        private Task _processingTask;
        private CancellationTokenSource _cancellationTokenSource;
        private const int MAX_HASH_CACHE_SIZE = 10000;
        private const int RULE_PROCESSING_BATCH_SIZE = 100;
        
        public string ModuleId => "RuleEngine";
        public string Version => "1.0.0";
        public string Description => "Motor de detección basado en reglas y firmas";
        
        private RuleEngine()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _signatures = new ConcurrentDictionary<string, ThreatSignature>();
            _rules = new ConcurrentDictionary<string, ThreatRule>();
            _yaraRules = new ConcurrentBag<DetectionRule>();
            _hashCache = new ConcurrentDictionary<string, DateTime>();
            _isInitialized = false;
            _isRunning = false;
            _cancellationTokenSource = new CancellationTokenSource();
        }
        
        /// <summary>
        /// Inicializa el motor de reglas
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando RuleEngine...", ModuleId);
                
                // Cargar firmas desde base de datos local
                await LoadSignaturesFromDatabaseAsync();
                
                // Cargar reglas desde archivos/configuración
                await LoadRulesAsync();
                
                // Cargar reglas YARA si están disponibles
                await LoadYaraRulesAsync();
                
                // Inicializar caché de hashes
                InitializeHashCache();
                
                _isInitialized = true;
                _logManager.LogInfo($"RuleEngine inicializado: {_signatures.Count} firmas, {_rules.Count} reglas, {_yaraRules.Count} reglas YARA", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar RuleEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el procesamiento de reglas
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                {
                    return initResult;
                }
            }
            
            try
            {
                _cancellationTokenSource = new CancellationTokenSource();
                _isRunning = true;
                
                // Iniciar tarea de procesamiento
                _processingTask = Task.Run(() => ProcessEventsAsync(_cancellationTokenSource.Token));
                
                _logManager.LogInfo("RuleEngine iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar RuleEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el motor de reglas
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _isRunning = false;
                _cancellationTokenSource.Cancel();
                
                if (_processingTask != null)
                {
                    await _processingTask;
                }
                
                _logManager.LogInfo("RuleEngine detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener RuleEngine: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Pausa el motor de reglas
        /// </summary>
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("RuleEngine pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Reanuda el motor de reglas
        /// </summary>
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("RuleEngine reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        /// <summary>
        /// Analiza eventos usando reglas y firmas
        /// </summary>
        public async Task<List<DetectionResult>> AnalyzeEventsAsync(List<SensorEvent> events)
        {
            var results = new ConcurrentBag<DetectionResult>();
            
            if (events == null || events.Count == 0)
            {
                return results.ToList();
            }
            
            try
            {
                // Procesar eventos en paralelo por lotes
                var batches = events.Chunk(RULE_PROCESSING_BATCH_SIZE);
                
                var tasks = batches.Select(batch => Task.Run(async () =>
                {
                    foreach (var evt in batch)
                    {
                        try
                        {
                            var detectionResults = await AnalyzeSingleEventAsync(evt);
                            foreach (var result in detectionResults)
                            {
                                results.Add(result);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logManager.LogError($"Error al analizar evento: {ex}", ModuleId);
                        }
                    }
                }));
                
                await Task.WhenAll(tasks);
                
                _logManager.LogDebug($"RuleEngine analizó {events.Count} eventos, detectó {results.Count} amenazas", ModuleId);
                
                return results.ToList();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en AnalyzeEventsAsync: {ex}", ModuleId);
                return new List<DetectionResult>();
            }
        }
        
        /// <summary>
        /// Analiza un solo evento
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeSingleEventAsync(SensorEvent sensorEvent)
        {
            var detectionResults = new List<DetectionResult>();
            
            // Aplicar reglas según tipo de sensor
            switch (sensorEvent.SensorType)
            {
                case SensorType.Process:
                    detectionResults.AddRange(await AnalyzeProcessEventAsync(sensorEvent));
                    break;
                    
                case SensorType.FileSystem:
                    detectionResults.AddRange(await AnalyzeFileSystemEventAsync(sensorEvent));
                    break;
                    
                case SensorType.Network:
                    detectionResults.AddRange(await AnalyzeNetworkEventAsync(sensorEvent));
                    break;
                    
                case SensorType.Registry:
                    detectionResults.AddRange(await AnalyzeRegistryEventAsync(sensorEvent));
                    break;
            }
            
            // Aplicar reglas YARA si corresponde
            if (sensorEvent.SensorType == SensorType.Process || sensorEvent.SensorType == SensorType.FileSystem)
            {
                detectionResults.AddRange(await ApplyYaraRulesAsync(sensorEvent));
            }
            
            return detectionResults;
        }
        
        /// <summary>
        /// Analiza evento de proceso
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeProcessEventAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // 1. Verificar por hash de proceso
            if (!string.IsNullOrEmpty(eventData.ProcessHash))
            {
                var hashDetection = CheckHashAgainstSignatures(eventData.ProcessHash, sensorEvent);
                if (hashDetection != null)
                {
                    results.Add(hashDetection);
                }
            }
            
            // 2. Verificar por nombre de proceso
            if (!string.IsNullOrEmpty(eventData.ProcessName))
            {
                var nameDetection = CheckProcessNameAgainstRules(eventData.ProcessName, sensorEvent);
                if (nameDetection != null)
                {
                    results.Add(nameDetection);
                }
            }
            
            // 3. Verificar por línea de comandos
            if (!string.IsNullOrEmpty(eventData.CommandLine))
            {
                var commandLineDetection = CheckCommandLineAgainstRules(eventData.CommandLine, sensorEvent);
                if (commandLineDetection != null)
                {
                    results.Add(commandLineDetection);
                }
            }
            
            // 4. Verificar por path de imagen
            if (!string.IsNullOrEmpty(eventData.ImagePath))
            {
                var pathDetection = CheckImagePathAgainstRules(eventData.ImagePath, sensorEvent);
                if (pathDetection != null)
                {
                    results.Add(pathDetection);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza evento de sistema de archivos
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeFileSystemEventAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // 1. Verificar por hash de archivo
            if (!string.IsNullOrEmpty(eventData.FileHash))
            {
                var hashDetection = CheckHashAgainstSignatures(eventData.FileHash, sensorEvent);
                if (hashDetection != null)
                {
                    results.Add(hashDetection);
                }
            }
            
            // 2. Verificar por path de archivo
            if (!string.IsNullOrEmpty(eventData.FilePath))
            {
                var pathDetection = CheckFilePathAgainstRules(eventData.FilePath, sensorEvent);
                if (pathDetection != null)
                {
                    results.Add(pathDetection);
                }
            }
            
            // 3. Verificar por extensión sospechosa
            if (!string.IsNullOrEmpty(eventData.FilePath))
            {
                var extensionDetection = CheckFileExtensionAgainstRules(eventData.FilePath, sensorEvent);
                if (extensionDetection != null)
                {
                    results.Add(extensionDetection);
                }
            }
            
            // 4. Verificar por operaciones sospechosas en ubicaciones críticas
            if (!string.IsNullOrEmpty(eventData.FilePath) && !string.IsNullOrEmpty(eventData.OperationType))
            {
                var locationDetection = CheckFileOperationInCriticalLocation(eventData.FilePath, eventData.OperationType, sensorEvent);
                if (locationDetection != null)
                {
                    results.Add(locationDetection);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza evento de red
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeNetworkEventAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // 1. Verificar por IP maliciosa
            if (!string.IsNullOrEmpty(eventData.RemoteAddress))
            {
                var ipDetection = CheckIpAddressAgainstRules(eventData.RemoteAddress, sensorEvent);
                if (ipDetection != null)
                {
                    results.Add(ipDetection);
                }
            }
            
            // 2. Verificar por puerto malicioso
            if (eventData.RemotePort.HasValue)
            {
                var portDetection = CheckPortAgainstRules(eventData.RemotePort.Value, sensorEvent);
                if (portDetection != null)
                {
                    results.Add(portDetection);
                }
            }
            
            // 3. Verificar por dominio malicioso
            if (!string.IsNullOrEmpty(eventData.DnsName))
            {
                var domainDetection = CheckDomainAgainstRules(eventData.DnsName, sensorEvent);
                if (domainDetection != null)
                {
                    results.Add(domainDetection);
                }
            }
            
            // 4. Verificar por protocolo/anomalías
            if (eventData.Protocol.HasValue)
            {
                var protocolDetection = CheckProtocolAnomalies(eventData.Protocol.Value, eventData, sensorEvent);
                if (protocolDetection != null)
                {
                    results.Add(protocolDetection);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Analiza evento de registro
        /// </summary>
        private async Task<List<DetectionResult>> AnalyzeRegistryEventAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            var eventData = sensorEvent.Data;
            
            // 1. Verificar por clave de auto-inicio
            if (eventData.IsAutoRun == true)
            {
                var autorunDetection = CheckAutoRunRegistryKey(eventData.RegistryPath, eventData.NewValueData, sensorEvent);
                if (autorunDetection != null)
                {
                    results.Add(autorunDetection);
                }
            }
            
            // 2. Verificar por claves sensibles
            if (!string.IsNullOrEmpty(eventData.RegistryPath))
            {
                var sensitiveKeyDetection = CheckSensitiveRegistryKey(eventData.RegistryPath, sensorEvent);
                if (sensitiveKeyDetection != null)
                {
                    results.Add(sensitiveKeyDetection);
                }
            }
            
            // 3. Verificar por valores sospechosos
            if (!string.IsNullOrEmpty(eventData.NewValueData))
            {
                var valueDetection = CheckRegistryValueAgainstRules(eventData.NewValueData, sensorEvent);
                if (valueDetection != null)
                {
                    results.Add(valueDetection);
                }
            }
            
            // 4. Verificar por persistencia maliciosa
            if (eventData.IsAutoRun == true && !string.IsNullOrEmpty(eventData.NewValueData))
            {
                var persistenceDetection = CheckMaliciousPersistence(eventData.RegistryPath, eventData.NewValueData, sensorEvent);
                if (persistenceDetection != null)
                {
                    results.Add(persistenceDetection);
                }
            }
            
            return results;
        }
        
        /// <summary>
        /// Verifica hash contra firmas conocidas
        /// </summary>
        private DetectionResult CheckHashAgainstSignatures(string hash, SensorEvent sensorEvent)
        {
            // Primero verificar caché
            if (_hashCache.ContainsKey(hash))
            {
                // Hash ya verificado recientemente
                return null;
            }
            
            // Buscar en firmas
            if (_signatures.TryGetValue(hash.ToUpperInvariant(), out var signature))
            {
                // Actualizar caché
                _hashCache[hash] = DateTime.UtcNow;
                
                // Limpiar caché si es necesario
                if (_hashCache.Count > MAX_HASH_CACHE_SIZE)
                {
                    var oldest = _hashCache.OrderBy(kv => kv.Value).First();
                    _hashCache.TryRemove(oldest.Key, out _);
                }
                
                return CreateDetectionResult(
                    sensorEvent,
                    signature.ThreatName,
                    $"Hash coincidente: {signature.ThreatName}",
                    signature.Severity,
                    DetectionType.HashSignature,
                    signature.Confidence,
                    new Dictionary<string, object>
                    {
                        { "Hash", hash },
                        { "SignatureId", signature.SignatureId },
                        { "ThreatType", signature.ThreatType },
                        { "FirstSeen", signature.FirstSeen },
                        { "LastSeen", signature.LastSeen }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica nombre de proceso contra reglas
        /// </summary>
        private DetectionResult CheckProcessNameAgainstRules(string processName, SensorEvent sensorEvent)
        {
            var lowerName = processName.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.ProcessName))
            {
                if (rule.Matches(lowerName))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.ProcessRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "ProcessName", processName },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica línea de comandos contra reglas
        /// </summary>
        private DetectionResult CheckCommandLineAgainstRules(string commandLine, SensorEvent sensorEvent)
        {
            var lowerCommandLine = commandLine.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.CommandLine))
            {
                if (rule.Matches(lowerCommandLine))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.CommandLineRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "CommandLine", commandLine },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica path de imagen contra reglas
        /// </summary>
        private DetectionResult CheckImagePathAgainstRules(string imagePath, SensorEvent sensorEvent)
        {
            var lowerPath = imagePath.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.ImagePath))
            {
                if (rule.Matches(lowerPath))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.ImagePathRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "ImagePath", imagePath },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica path de archivo contra reglas
        /// </summary>
        private DetectionResult CheckFilePathAgainstRules(string filePath, SensorEvent sensorEvent)
        {
            var lowerPath = filePath.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.FilePath))
            {
                if (rule.Matches(lowerPath))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.FilePathRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "FilePath", filePath },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica extensión de archivo contra reglas
        /// </summary>
        private DetectionResult CheckFileExtensionAgainstRules(string filePath, SensorEvent sensorEvent)
        {
            var extension = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.FileExtension))
            {
                if (rule.Matches(extension))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.FileExtensionRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "FilePath", filePath },
                            { "Extension", extension },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica operación en ubicación crítica
        /// </summary>
        private DetectionResult CheckFileOperationInCriticalLocation(string filePath, string operationType, SensorEvent sensorEvent)
        {
            var lowerPath = filePath.ToLowerInvariant();
            
            // Definir ubicaciones críticas
            var criticalLocations = new[]
            {
                @"c:\windows\system32\",
                @"c:\windows\syswow64\",
                @"c:\windows\system32\drivers\",
                @"c:\windows\system32\config\",
                @"c:\windows\system32\catroot\",
                @"c:\windows\system32\catroot2\",
                @"c:\windows\system32\winevt\logs\",
                @"c:\windows\tasks\",
                @"c:\windows\system32\tasks\"
            };
            
            // Definir operaciones sospechosas en ubicaciones críticas
            var suspiciousOperations = new[] { "CREATE", "MODIFY", "DELETE", "RENAME" };
            
            if (criticalLocations.Any(loc => lowerPath.StartsWith(loc)) &&
                suspiciousOperations.Contains(operationType.ToUpperInvariant()))
            {
                return CreateDetectionResult(
                    sensorEvent,
                    "Suspicious file operation in critical location",
                    $"Operación {operationType} en ubicación crítica: {filePath}",
                    ThreatSeverity.High,
                    DetectionType.CriticalLocationRule,
                    0.8,
                    new Dictionary<string, object>
                    {
                        { "FilePath", filePath },
                        { "Operation", operationType },
                        { "CriticalLocation", true }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica dirección IP contra reglas
        /// </summary>
        private DetectionResult CheckIpAddressAgainstRules(string ipAddress, SensorEvent sensorEvent)
        {
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.IPAddress))
            {
                if (rule.Matches(ipAddress))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.IPRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "IPAddress", ipAddress },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica puerto contra reglas
        /// </summary>
        private DetectionResult CheckPortAgainstRules(int port, SensorEvent sensorEvent)
        {
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.Port))
            {
                if (rule.Matches(port.ToString()))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.PortRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "Port", port },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica dominio contra reglas
        /// </summary>
        private DetectionResult CheckDomainAgainstRules(string domain, SensorEvent sensorEvent)
        {
            var lowerDomain = domain.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.Domain))
            {
                if (rule.Matches(lowerDomain))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.DomainRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "Domain", domain },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica anomalías de protocolo
        /// </summary>
        private DetectionResult CheckProtocolAnomalies(int protocol, EventData eventData, SensorEvent sensorEvent)
        {
            // Reglas heurísticas para protocolos
            if (protocol == 6) // TCP
            {
                // Puerto 0 en TCP es sospechoso
                if (eventData.RemotePort == 0 || eventData.LocalPort == 0)
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        "Suspicious TCP connection with port 0",
                        "Conexión TCP con puerto 0",
                        ThreatSeverity.Medium,
                        DetectionType.ProtocolAnomaly,
                        0.7,
                        new Dictionary<string, object>
                        {
                            { "Protocol", "TCP" },
                            { "LocalPort", eventData.LocalPort },
                            { "RemotePort", eventData.RemotePort },
                            { "Anomaly", "PortZero" }
                        }
                    );
                }
            }
            else if (protocol == 17) // UDP
            {
                // UDP a puertos bien conocidos puede ser sospechoso
                if (eventData.RemotePort < 1024 && eventData.RemotePort != 53) // No DNS
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        "Suspicious UDP connection to well-known port",
                        "Conexión UDP a puerto bien conocido",
                        ThreatSeverity.Low,
                        DetectionType.ProtocolAnomaly,
                        0.6,
                        new Dictionary<string, object>
                        {
                            { "Protocol", "UDP" },
                            { "RemotePort", eventData.RemotePort },
                            { "Anomaly", "WellKnownPortUDP" }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica clave de auto-inicio del registro
        /// </summary>
        private DetectionResult CheckAutoRunRegistryKey(string registryPath, string valueData, SensorEvent sensorEvent)
        {
            // Lista de claves de auto-inicio conocidas
            var autorunKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                @"SOFTWARE\Microsoft\Active Setup\Installed Components"
            };
            
            var upperPath = registryPath.ToUpperInvariant();
            
            if (autorunKeys.Any(key => upperPath.Contains(key.ToUpperInvariant())))
            {
                return CreateDetectionResult(
                    sensorEvent,
                    "Auto-run registry key modification",
                    $"Modificación en clave de auto-inicio: {registryPath}",
                    ThreatSeverity.Medium,
                    DetectionType.AutoRunRegistry,
                    0.8,
                    new Dictionary<string, object>
                    {
                        { "RegistryPath", registryPath },
                        { "ValueData", valueData },
                        { "IsAutoRun", true }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica clave sensible del registro
        /// </summary>
        private DetectionResult CheckSensitiveRegistryKey(string registryPath, SensorEvent sensorEvent)
        {
            // Claves sensibles del sistema
            var sensitiveKeys = new[]
            {
                @"SAM\Domains\Account\Users",
                @"SECURITY\Policy\Secrets",
                @"SECURITY\Policy\Accounts",
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
            };
            
            var upperPath = registryPath.ToUpperInvariant();
            
            if (sensitiveKeys.Any(key => upperPath.Contains(key.ToUpperInvariant())))
            {
                return CreateDetectionResult(
                    sensorEvent,
                    "Sensitive registry key access",
                    $"Acceso a clave sensible del registro: {registryPath}",
                    ThreatSeverity.High,
                    DetectionType.SensitiveRegistry,
                    0.9,
                    new Dictionary<string, object>
                    {
                        { "RegistryPath", registryPath },
                        { "IsSensitive", true }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica valor del registro contra reglas
        /// </summary>
        private DetectionResult CheckRegistryValueAgainstRules(string valueData, SensorEvent sensorEvent)
        {
            var lowerValue = valueData.ToLowerInvariant();
            
            foreach (var rule in _rules.Values.Where(r => r.RuleType == RuleType.RegistryValue))
            {
                if (rule.Matches(lowerValue))
                {
                    return CreateDetectionResult(
                        sensorEvent,
                        rule.ThreatName,
                        rule.Description,
                        rule.Severity,
                        DetectionType.RegistryValueRule,
                        rule.Confidence,
                        new Dictionary<string, object>
                        {
                            { "ValueData", valueData },
                            { "RuleId", rule.RuleId },
                            { "Pattern", rule.Pattern }
                        }
                    );
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Verifica persistencia maliciosa
        /// </summary>
        private DetectionResult CheckMaliciousPersistence(string registryPath, string valueData, SensorEvent sensorEvent)
        {
            var lowerValue = valueData.ToLowerInvariant();
            
            // Patrones de persistencia maliciosa
            var maliciousPatterns = new[]
            {
                "powershell", "cmd", "wscript", "cscript", "mshta",
                "rundll32", "regsvr32", "bitsadmin", "certutil",
                "-enc", "-e", "iex", "invoke-expression",
                "frombase64", "downloadstring", "webclient",
                "javascript:", "vbscript:", "data:text/html"
            };
            
            if (maliciousPatterns.Any(pattern => lowerValue.Contains(pattern)))
            {
                return CreateDetectionResult(
                    sensorEvent,
                    "Malicious persistence detected",
                    $"Persistencia maliciosa detectada en: {registryPath}",
                    ThreatSeverity.Critical,
                    DetectionType.MaliciousPersistence,
                    0.95,
                    new Dictionary<string, object>
                    {
                        { "RegistryPath", registryPath },
                        { "ValueData", valueData },
                        { "MaliciousPattern", true },
                        { "IsAutoRun", true }
                    }
                );
            }
            
            return null;
        }
        
        /// <summary>
        /// Aplica reglas YARA
        /// </summary>
        private async Task<List<DetectionResult>> ApplyYaraRulesAsync(SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            
            if (_yaraRules.IsEmpty)
            {
                return results;
            }
            
            try
            {
                // Verificar si el evento tiene datos para aplicar YARA
                if (sensorEvent.SensorType == SensorType.FileSystem && 
                    !string.IsNullOrEmpty(sensorEvent.Data.FilePath) &&
                    System.IO.File.Exists(sensorEvent.Data.FilePath))
                {
                    // Aplicar reglas YARA al archivo
                    var fileResults = await ApplyYaraToFileAsync(sensorEvent.Data.FilePath, sensorEvent);
                    results.AddRange(fileResults);
                }
                else if (sensorEvent.SensorType == SensorType.Process &&
                         !string.IsNullOrEmpty(sensorEvent.Data.ImagePath) &&
                         System.IO.File.Exists(sensorEvent.Data.ImagePath))
                {
                    // Aplicar reglas YARA al ejecutable del proceso
                    var processResults = await ApplyYaraToFileAsync(sensorEvent.Data.ImagePath, sensorEvent);
                    results.AddRange(processResults);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al aplicar reglas YARA: {ex}", ModuleId);
            }
            
            return results;
        }
        
        /// <summary>
        /// Aplica reglas YARA a un archivo
        /// </summary>
        private async Task<List<DetectionResult>> ApplyYaraToFileAsync(string filePath, SensorEvent sensorEvent)
        {
            var results = new List<DetectionResult>();
            
            try
            {
                // Implementación simplificada - en producción usar librería YARA real
                // Aquí simulamos la detección
                foreach (var yaraRule in _yaraRules)
                {
                    // Simular análisis YARA
                    await Task.Delay(1); // Simular procesamiento
                    
                    // Por ahora, solo verificar extensiones sospechosas
                    var extension = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
                    if (yaraRule.Matches(extension))
                    {
                        results.Add(CreateDetectionResult(
                            sensorEvent,
                            yaraRule.ThreatName,
                            yaraRule.Description,
                            yaraRule.Severity,
                            DetectionType.YaraRule,
                            yaraRule.Confidence,
                            new Dictionary<string, object>
                            {
                                { "FilePath", filePath },
                                { "YaraRule", yaraRule.Name },
                                { "RuleAuthor", yaraRule.Author }
                            }
                        ));
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en YARA para archivo {filePath}: {ex}", ModuleId);
            }
            
            return results;
        }
        
        /// <summary>
        /// Crea resultado de detección
        /// </summary>
        private DetectionResult CreateDetectionResult(
            SensorEvent sensorEvent,
            string threatName,
            string description,
            ThreatSeverity severity,
            DetectionType detectionType,
            double confidence,
            Dictionary<string, object> details)
        {
            return new DetectionResult
            {
                DetectionId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                EventId = sensorEvent.EventId,
                EventType = sensorEvent.EventType,
                SensorType = sensorEvent.SensorType,
                SourceModule = ModuleId,
                ThreatName = threatName,
                Description = description,
                Severity = severity,
                DetectionType = detectionType,
                Confidence = confidence,
                SourceEvent = sensorEvent,
                Details = details,
                RecommendedActions = GetRecommendedActions(detectionType, severity)
            };
        }
        
        /// <summary>
        /// Obtiene acciones recomendadas según tipo de detección
        /// </summary>
        private List<string> GetRecommendedActions(DetectionType detectionType, ThreatSeverity severity)
        {
            var actions = new List<string>();
            
            if (severity >= ThreatSeverity.High)
            {
                actions.Add("Quarantine");
                actions.Add("Block");
                actions.Add("Alert");
            }
            else if (severity >= ThreatSeverity.Medium)
            {
                actions.Add("Monitor");
                actions.Add("Alert");
                actions.Add("Investigate");
            }
            else
            {
                actions.Add("Log");
                actions.Add("Monitor");
            }
            
            // Acciones específicas por tipo
            switch (detectionType)
            {
                case DetectionType.HashSignature:
                    actions.Add("UpdateSignatures");
                    break;
                    
                case DetectionType.MaliciousPersistence:
                    actions.Add("RemoveRegistryEntry");
                    actions.Add("ScanSystem");
                    break;
                    
                case DetectionType.CriticalLocationRule:
                    actions.Add("RestoreFromBackup");
                    actions.Add("VerifyIntegrity");
                    break;
            }
            
            return actions;
        }
        
        /// <summary>
        /// Procesa eventos de forma continua
        /// </summary>
        private async Task ProcessEventsAsync(CancellationToken cancellationToken)
        {
            _logManager.LogInfo("Iniciando procesamiento de eventos en RuleEngine", ModuleId);
            
            while (!cancellationToken.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Obtener eventos de la cola
                    var events = await GetEventsFromQueueAsync(100);
                    
                    if (events.Count > 0)
                    {
                        // Analizar eventos
                        var results = await AnalyzeEventsAsync(events);
                        
                        // Procesar resultados
                        await ProcessDetectionResultsAsync(results);
                        
                        _logManager.LogDebug($"RuleEngine procesó {events.Count} eventos, {results.Count} detecciones", ModuleId);
                    }
                    
                    // Esperar antes de siguiente ciclo
                    await Task.Delay(1000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en ProcessEventsAsync: {ex}", ModuleId);
                    await Task.Delay(5000, cancellationToken);
                }
            }
            
            _logManager.LogInfo("Procesamiento de eventos detenido en RuleEngine", ModuleId);
        }
        
        /// <summary>
        /// Obtiene eventos de la cola
        /// </summary>
        private async Task<List<SensorEvent>> GetEventsFromQueueAsync(int maxCount)
        {
            // Implementar obtención de eventos desde cola compartida
            // Por ahora retornar lista vacía
            return new List<SensorEvent>();
        }
        
        /// <summary>
        /// Procesa resultados de detección
        /// </summary>
        private async Task ProcessDetectionResultsAsync(List<DetectionResult> results)
        {
            foreach (var result in results)
            {
                try
                {
                    // Guardar en base de datos
                    await _localDatabase.SaveDetectionResultAsync(result);
                    
                    // Enviar a telemetría si es necesario
                    if (result.Severity >= ThreatSeverity.Medium)
                    {
                        await SendToTelemetryAsync(result);
                    }
                    
                    // Log detección
                    _logManager.LogWarning(
                        $"Detección: {result.ThreatName} - Severidad: {result.Severity} - Confianza: {result.Confidence:P0}",
                        ModuleId);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al procesar resultado de detección: {ex}", ModuleId);
                }
            }
        }
        
        /// <summary>
        /// Envía resultado a telemetría
        /// </summary>
        private async Task SendToTelemetryAsync(DetectionResult result)
        {
            // Implementar envío a telemetría
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Carga firmas desde base de datos
        /// </summary>
        private async Task LoadSignaturesFromDatabaseAsync()
        {
            try
            {
                var signatures = await _localDatabase.GetThreatSignaturesAsync();
                
                foreach (var signature in signatures)
                {
                    _signatures[signature.Hash.ToUpperInvariant()] = signature;
                }
                
                _logManager.LogInfo($"Cargadas {signatures.Count} firmas desde base de datos", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar firmas desde base de datos: {ex}", ModuleId);
                
                // Cargar firmas por defecto
                LoadDefaultSignatures();
            }
        }
        
        /// <summary>
        /// Carga firmas por defecto
        /// </summary>
        private void LoadDefaultSignatures()
        {
            // Firmas de ejemplo (en producción cargar desde archivo/configuración)
            var defaultSignatures = new[]
            {
                new ThreatSignature
                {
                    SignatureId = "MAL001",
                    Hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                    ThreatName = "Example Malware",
                    ThreatType = "Trojan",
                    Severity = ThreatSeverity.High,
                    Confidence = 0.95,
                    FirstSeen = DateTime.UtcNow.AddDays(-30),
                    LastSeen = DateTime.UtcNow
                }
            };
            
            foreach (var signature in defaultSignatures)
            {
                _signatures[signature.Hash] = signature;
            }
        }
        
        /// <summary>
        /// Carga reglas desde archivos/configuración
        /// </summary>
        private async Task LoadRulesAsync()
        {
            try
            {
                // Cargar reglas desde base de datos
                var rules = await _localDatabase.GetThreatRulesAsync();
                
                foreach (var rule in rules)
                {
                    _rules[rule.RuleId] = rule;
                }
                
                // Si no hay reglas en BD, cargar por defecto
                if (_rules.IsEmpty)
                {
                    LoadDefaultRules();
                }
                
                _logManager.LogInfo($"Cargadas {_rules.Count} reglas", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar reglas: {ex}", ModuleId);
                LoadDefaultRules();
            }
        }
        
        /// <summary>
        /// Carga reglas por defecto
        /// </summary>
        private void LoadDefaultRules()
        {
            // Reglas de ejemplo para detección básica
            
            // Reglas de nombre de proceso
            AddRule(new ThreatRule
            {
                RuleId = "PROC001",
                RuleType = RuleType.ProcessName,
                Pattern = "mimikatz.exe",
                ThreatName = "Mimikatz detected",
                Description = "Credential dumping tool detected",
                Severity = ThreatSeverity.Critical,
                Confidence = 0.99
            });
            
            AddRule(new ThreatRule
            {
                RuleId = "PROC002",
                RuleType = RuleType.ProcessName,
                Pattern = "procdump.exe",
                ThreatName = "ProcDump detected",
                Description = "Memory dumping tool detected",
                Severity = ThreatSeverity.High,
                Confidence = 0.95
            });
            
            // Reglas de línea de comandos
            AddRule(new ThreatRule
            {
                RuleId = "CMD001",
                RuleType = RuleType.CommandLine,
                Pattern = "-enc ",
                ThreatName = "Encoded PowerShell command",
                Description = "Base64 encoded PowerShell command detected",
                Severity = ThreatSeverity.High,
                Confidence = 0.9
            });
            
            // Reglas de IP
            AddRule(new ThreatRule
            {
                RuleId = "IP001",
                RuleType = RuleType.IPAddress,
                Pattern = "192.0.2.", // IP de ejemplo para testing
                ThreatName = "Known malicious IP",
                Description = "Connection to known malicious IP address",
                Severity = ThreatSeverity.High,
                Confidence = 0.85
            });
            
            // Reglas de puerto
            AddRule(new ThreatRule
            {
                RuleId = "PORT001",
                RuleType = RuleType.Port,
                Pattern = "4444",
                ThreatName = "Meterpreter port",
                Description = "Connection to common Meterpreter port",
                Severity = ThreatSeverity.High,
                Confidence = 0.8
            });
            
            // Reglas de dominio
            AddRule(new ThreatRule
            {
                RuleId = "DOM001",
                RuleType = RuleType.Domain,
                Pattern = "pastebin.com",
                ThreatName = "Pastebin domain",
                Description = "Connection to pastebin.com (common for exfiltration)",
                Severity = ThreatSeverity.Medium,
                Confidence = 0.7
            });
        }
        
        /// <summary>
        /// Carga reglas YARA
        /// </summary>
        private async Task LoadYaraRulesAsync()
        {
            try
            {
                // En producción, cargar desde archivos .yar
                // Por ahora, reglas simuladas
                _yaraRules.Add(new DetectionRule
                {
                    Name = "SuspiciousScript",
                    Author = "BWP Enterprise",
                    Description = "Detects suspicious script files",
                    Severity = ThreatSeverity.Medium,
                    Confidence = 0.8
                });
                
                _logManager.LogInfo($"Cargadas {_yaraRules.Count} reglas YARA", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar reglas YARA: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Inicializa caché de hashes
        /// </summary>
        private void InitializeHashCache()
        {
            _hashCache.Clear();
        }
        
        /// <summary>
        /// Agrega una regla al motor
        /// </summary>
        public void AddRule(ThreatRule rule)
        {
            _rules[rule.RuleId] = rule;
        }
        
        /// <summary>
        /// Elimina una regla
        /// </summary>
        public bool RemoveRule(string ruleId)
        {
            return _rules.TryRemove(ruleId, out _);
        }
        
        /// <summary>
        /// Agrega una firma
        /// </summary>
        public void AddSignature(ThreatSignature signature)
        {
            _signatures[signature.Hash.ToUpperInvariant()] = signature;
        }
        
        /// <summary>
        /// Elimina una firma
        /// </summary>
        public bool RemoveSignature(string hash)
        {
            return _signatures.TryRemove(hash.ToUpperInvariant(), out _);
        }
        
        /// <summary>
        /// Obtiene estadísticas del motor
        /// </summary>
        public RuleEngineStats GetStats()
        {
            return new RuleEngineStats
            {
                Timestamp = DateTime.UtcNow,
                SignatureCount = _signatures.Count,
                RuleCount = _rules.Count,
                YaraRuleCount = _yaraRules.Count,
                HashCacheSize = _hashCache.Count,
                IsRunning = _isRunning,
                IsInitialized = _isInitialized
            };
        }
        
        /// <summary>
        /// Actualiza reglas desde fuente externa
        /// </summary>
        public async Task<bool> UpdateRulesAsync(List<ThreatRule> newRules)
        {
            try
            {
                foreach (var rule in newRules)
                {
                    _rules[rule.RuleId] = rule;
                }
                
                await _localDatabase.SaveThreatRulesAsync(newRules);
                
                _logManager.LogInfo($"Actualizadas {newRules.Count} reglas", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar reglas: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Actualiza firmas desde fuente externa
        /// </summary>
        public async Task<bool> UpdateSignaturesAsync(List<ThreatSignature> newSignatures)
        {
            try
            {
                foreach (var signature in newSignatures)
                {
                    _signatures[signature.Hash.ToUpperInvariant()] = signature;
                }
                
                await _localDatabase.SaveThreatSignaturesAsync(newSignatures);
                
                _logManager.LogInfo($"Actualizadas {newSignatures.Count} firmas", ModuleId);
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar firmas: {ex}", ModuleId);
                return false;
            }
        }
    }
    
    #region Clases y estructuras de datos
    
    /// <summary>
    /// Interfaz para motores de detección
    /// </summary>
    public interface IDetectionEngine
    {
        Task<List<DetectionResult>> AnalyzeEventsAsync(List<SensorEvent> events);
    }
    
    /// <summary>
    /// Resultado de detección
    /// </summary>
    public class DetectionResult
    {
        public string DetectionId { get; set; }
        public DateTime Timestamp { get; set; }
        public string EventId { get; set; }
        public EventType EventType { get; set; }
        public SensorType SensorType { get; set; }
        public string SourceModule { get; set; }
        public string ThreatName { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DetectionType DetectionType { get; set; }
        public double Confidence { get; set; }
        public SensorEvent SourceEvent { get; set; }
        public Dictionary<string, object> Details { get; set; }
        public List<string> RecommendedActions { get; set; }
        
        public DetectionResult()
        {
            Details = new Dictionary<string, object>();
            RecommendedActions = new List<string>();
        }
    }
    
    /// <summary>
    /// Firma de amenaza
    /// </summary>
    public class ThreatSignature
    {
        public string SignatureId { get; set; }
        public string Hash { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public ThreatSignature()
        {
            Metadata = new Dictionary<string, object>();
        }
    }
    
    /// <summary>
    /// Regla de amenaza
    /// </summary>
    public class ThreatRule
    {
        public string RuleId { get; set; }
        public RuleType RuleType { get; set; }
        public string Pattern { get; set; }
        public string ThreatName { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public DateTime Created { get; set; }
        public DateTime Updated { get; set; }
        public bool IsEnabled { get; set; }
        
        public ThreatRule()
        {
            Created = DateTime.UtcNow;
            Updated = DateTime.UtcNow;
            IsEnabled = true;
        }
        
        public bool Matches(string input)
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(Pattern))
                return false;
                
            // Soporte para diferentes tipos de patrones
            if (Pattern.StartsWith("*") && Pattern.EndsWith("*"))
            {
                // Contiene
                var pattern = Pattern.Trim('*');
                return input.Contains(pattern);
            }
            else if (Pattern.EndsWith("*"))
            {
                // Comienza con
                var pattern = Pattern.TrimEnd('*');
                return input.StartsWith(pattern);
            }
            else if (Pattern.StartsWith("*"))
            {
                // Termina con
                var pattern = Pattern.TrimStart('*');
                return input.EndsWith(pattern);
            }
            else
            {
                // Exacto
                return input == Pattern;
            }
        }
    }
    
    /// <summary>
    /// Regla de detección (para YARA u otros formatos)
    /// </summary>
    public class DetectionRule
    {
        public string Name { get; set; }
        public string Author { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public Dictionary<string, object> Conditions { get; set; }
        
        public DetectionRule()
        {
            Conditions = new Dictionary<string, object>();
        }
        
        public bool Matches(string input)
        {
            // Implementación básica de coincidencia
            // En producción, implementar lógica específica del motor
            return false;
        }
    }
    
    /// <summary>
    /// Tipos de reglas
    /// </summary>
    public enum RuleType
    {
        ProcessName,
        CommandLine,
        ImagePath,
        FilePath,
        FileExtension,
        IPAddress,
        Port,
        Domain,
        RegistryValue,
        YaraRule
    }
    
    /// <summary>
    /// Tipos de detección
    /// </summary>
    public enum DetectionType
    {
        HashSignature,
        ProcessRule,
        CommandLineRule,
        ImagePathRule,
        FilePathRule,
        FileExtensionRule,
        CriticalLocationRule,
        IPRule,
        PortRule,
        DomainRule,
        ProtocolAnomaly,
        AutoRunRegistry,
        SensitiveRegistry,
        RegistryValueRule,
        MaliciousPersistence,
        YaraRule
    }
    
    /// <summary>
    /// Estadísticas del motor de reglas
    /// </summary>
    public class RuleEngineStats
    {
        public DateTime Timestamp { get; set; }
        public int SignatureCount { get; set; }
        public int RuleCount { get; set; }
        public int YaraRuleCount { get; set; }
        public int HashCacheSize { get; set; }
        public bool IsRunning { get; set; }
        public bool IsInitialized { get; set; }
    }
    
    #endregion
}