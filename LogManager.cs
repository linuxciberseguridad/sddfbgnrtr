using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BWP.Enterprise.Agent.Logging
{
    /// <summary>
    /// Sistema de logging centralizado con rotación automática y compresión
    /// Singleton thread-safe para logging en toda la aplicación
    /// </summary>
    public sealed class LogManager : ILogManager
    {
        private static readonly Lazy<LogManager> _instance = 
            new Lazy<LogManager>(() => new LogManager());
        
        public static LogManager Instance => _instance.Value;
        
        private readonly ConcurrentQueue<LogEntry> _logQueue;
        private readonly Timer _flushTimer;
        private readonly List<ILogAppender> _appenders;
        private LogConfiguration _configuration;
        private bool _isInitialized;
        private bool _isDisposed;
        private readonly object _configLock = new object();
        private long _currentFileSize;
        private string _currentLogFilePath;
        private readonly SemaphoreSlim _fileLock = new SemaphoreSlim(1, 1);
        private const int FLUSH_INTERVAL_MS = 5000; // 5 segundos
        private const int MAX_QUEUE_SIZE = 10000;
        
        private LogManager()
        {
            _logQueue = new ConcurrentQueue<LogEntry>();
            _appenders = new List<ILogAppender>();
            _configuration = new LogConfiguration
            {
                LogLevel = LogLevel.Info,
                MaxFileSizeMB = 100,
                RetentionDays = 30,
                EnableCompression = true,
                EnableConsoleOutput = false,
                EnableEventLog = true
            };
            
            _flushTimer = new Timer(FlushLogsCallback, null, 
                Timeout.Infinite, Timeout.Infinite);
            
            _isInitialized = false;
            _isDisposed = false;
        }
        
        /// <summary>
        /// Configura el sistema de logging
        /// </summary>
        public void Configure(LogConfiguration configuration)
        {
            lock (_configLock)
            {
                _configuration = configuration;
                
                // Crear directorio de logs si no existe
                var logDirectory = GetLogDirectory();
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }
                
                // Inicializar archivo de log actual
                InitializeCurrentLogFile();
                
                // Configurar appenders
                ConfigureAppenders();
                
                // Iniciar timer de flush
                _flushTimer.Change(TimeSpan.Zero, 
                    TimeSpan.FromMilliseconds(FLUSH_INTERVAL_MS));
                
                _isInitialized = true;
                
                LogInternal(LogLevel.Info, "LogManager configurado correctamente", "LogManager");
            }
        }
        
        /// <summary>
        /// Registra un mensaje de log
        /// </summary>
        public void Log(LogLevel level, string message, string source, 
                       Exception exception = null, 
                       Dictionary<string, object> properties = null)
        {
            if (!_isInitialized || _isDisposed || level < _configuration.LogLevel)
                return;
            
            var logEntry = new LogEntry
            {
                Timestamp = DateTime.UtcNow,
                Level = level,
                Message = message,
                Source = source,
                ThreadId = Thread.CurrentThread.ManagedThreadId,
                Exception = exception,
                Properties = properties ?? new Dictionary<string, object>(),
                MachineName = Environment.MachineName,
                ProcessId = Environment.ProcessId,
                UserName = Environment.UserName
            };
            
            // Encolar para procesamiento asíncrono
            if (_logQueue.Count < MAX_QUEUE_SIZE)
            {
                _logQueue.Enqueue(logEntry);
            }
            else
            {
                // Si la cola está llena, escribir directamente (modo sincrónico)
                WriteLogImmediate(logEntry);
            }
            
            // Si es error crítico, flush inmediato
            if (level >= LogLevel.Critical)
            {
                Task.Run(() => FlushLogs());
            }
        }
        
        /// <summary>
        /// Métodos de conveniencia para diferentes niveles de log
        /// </summary>
        public void LogDebug(string message, string source, 
                           Dictionary<string, object> properties = null)
        {
            Log(LogLevel.Debug, message, source, null, properties);
        }
        
        public void LogInfo(string message, string source,
                          Dictionary<string, object> properties = null)
        {
            Log(LogLevel.Info, message, source, null, properties);
        }
        
        public void LogWarning(string message, string source,
                             Exception exception = null,
                             Dictionary<string, object> properties = null)
        {
            Log(LogLevel.Warning, message, source, exception, properties);
        }
        
        public void LogError(string message, string source,
                           Exception exception = null,
                           Dictionary<string, object> properties = null)
        {
            Log(LogLevel.Error, message, source, exception, properties);
        }
        
        public void LogCritical(string message, string source,
                              Exception exception = null,
                              Dictionary<string, object> properties = null)
        {
            Log(LogLevel.Critical, message, source, exception, properties);
        }
        
        /// <summary>
        /// Obtiene logs recientes con filtros
        /// </summary>
        public List<LogEntry> GetRecentLogs(DateTime? from = null, DateTime? to = null,
                                          LogLevel? minLevel = null, string source = null,
                                          int maxEntries = 1000)
        {
            var logs = new List<LogEntry>();
            
            try
            {
                var logDirectory = GetLogDirectory();
                var logFiles = Directory.GetFiles(logDirectory, "*.log")
                    .OrderByDescending(f => f)
                    .Take(5); // Últimos 5 archivos
                
                foreach (var file in logFiles)
                {
                    if (logs.Count >= maxEntries)
                        break;
                    
                    try
                    {
                        var fileLogs = ReadLogsFromFile(file, from, to, minLevel, source);
                        logs.AddRange(fileLogs);
                    }
                    catch { /* Continuar con siguiente archivo */ }
                }
                
                return logs.OrderByDescending(l => l.Timestamp)
                          .Take(maxEntries)
                          .ToList();
            }
            catch
            {
                return logs;
            }
        }
        
        /// <summary>
        /// Vacía los logs pendientes inmediatamente
        /// </summary>
        public void Flush()
        {
            FlushLogs();
        }
        
        /// <summary>
        /// Limpia logs antiguos según política de retención
        /// </summary>
        public void CleanupOldLogs()
        {
            try
            {
                var logDirectory = GetLogDirectory();
                var cutoffDate = DateTime.UtcNow.AddDays(-_configuration.RetentionDays);
                
                foreach (var file in Directory.GetFiles(logDirectory, "*.log"))
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.LastWriteTimeUtc < cutoffDate)
                    {
                        try
                        {
                            File.Delete(file);
                            
                            // Eliminar archivo comprimido si existe
                            var compressedFile = file + ".gz";
                            if (File.Exists(compressedFile))
                            {
                                File.Delete(compressedFile);
                            }
                        }
                        catch { /* Continuar con siguiente archivo */ }
                    }
                }
            }
            catch (Exception ex)
            {
                LogInternal(LogLevel.Error, 
                    $"Error limpiando logs antiguos: {ex.Message}", "LogManager");
            }
        }
        
        /// <summary>
        /// Comprime archivos de log antiguos
        /// </summary>
        public void CompressOldLogs()
        {
            if (!_configuration.EnableCompression)
                return;
                
            try
            {
                var logDirectory = GetLogDirectory();
                var filesToCompress = Directory.GetFiles(logDirectory, "*.log")
                    .Where(f => !f.EndsWith(".gz"))
                    .Where(f => new FileInfo(f).LastWriteTimeUtc < 
                                DateTime.UtcNow.AddHours(-1)); // Comprimir archivos > 1 hora
                
                foreach (var file in filesToCompress)
                {
                    try
                    {
                        CompressLogFile(file);
                    }
                    catch { /* Continuar con siguiente archivo */ }
                }
            }
            catch (Exception ex)
            {
                LogInternal(LogLevel.Error, 
                    $"Error comprimiendo logs: {ex.Message}", "LogManager");
            }
        }
        
        /// <summary>
        /// Genera reporte de uso de logs
        /// </summary>
        public LogUsageReport GetUsageReport()
        {
            try
            {
                var logDirectory = GetLogDirectory();
                var files = Directory.GetFiles(logDirectory);
                
                var report = new LogUsageReport
                {
                    Timestamp = DateTime.UtcNow,
                    LogDirectory = logDirectory,
                    TotalFiles = files.Length,
                    TotalSizeMB = files.Sum(f => new FileInfo(f).Length) / (1024 * 1024),
                    QueueSize = _logQueue.Count,
                    Configuration = _configuration,
                    FileDetails = files.Select(f => new LogFileInfo
                    {
                        FileName = Path.GetFileName(f),
                        SizeMB = new FileInfo(f).Length / (1024 * 1024),
                        LastModified = File.GetLastWriteTimeUtc(f),
                        IsCompressed = f.EndsWith(".gz")
                    }).ToList()
                };
                
                return report;
            }
            catch
            {
                return new LogUsageReport
                {
                    Timestamp = DateTime.UtcNow,
                    Error = "No se pudo generar reporte"
                };
            }
        }
        
        /// <summary>
        /// Disposición de recursos
        /// </summary>
        public void Dispose()
        {
            if (_isDisposed)
                return;
                
            _isDisposed = true;
            
            try
            {
                // Flush final
                FlushLogs();
                
                // Detener timer
                _flushTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _flushTimer?.Dispose();
                
                // Disposer appenders
                foreach (var appender in _appenders)
                {
                    if (appender is IDisposable disposable)
                    {
                        disposable.Dispose();
                    }
                }
                
                LogInternal(LogLevel.Info, "LogManager disposed", "LogManager");
            }
            catch { }
        }
        
        #region Métodos Privados
        
        private void InitializeCurrentLogFile()
        {
            var logDirectory = GetLogDirectory();
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd");
            _currentLogFilePath = Path.Combine(logDirectory, $"bwp_agent_{timestamp}.log");
            _currentFileSize = File.Exists(_currentLogFilePath) ? 
                new FileInfo(_currentLogFilePath).Length : 0;
        }
        
        private void ConfigureAppenders()
        {
            _appenders.Clear();
            
            // Appender de archivo
            _appenders.Add(new FileLogAppender(this));
            
            // Appender de consola (si está habilitado)
            if (_configuration.EnableConsoleOutput)
            {
                _appenders.Add(new ConsoleLogAppender());
            }
            
            // Appender de Event Log de Windows (si está habilitado)
            if (_configuration.EnableEventLog)
            {
                _appenders.Add(new EventLogAppender());
            }
            
            // Appender de telemetría para logs críticos
            _appenders.Add(new TelemetryLogAppender());
        }
        
        private void LogInternal(LogLevel level, string message, string source)
        {
            var entry = new LogEntry
            {
                Timestamp = DateTime.UtcNow,
                Level = level,
                Message = message,
                Source = source,
                ThreadId = Thread.CurrentThread.ManagedThreadId,
                MachineName = Environment.MachineName,
                ProcessId = Environment.ProcessId,
                UserName = Environment.UserName
            };
            
            WriteLogImmediate(entry);
        }
        
        private void WriteLogImmediate(LogEntry entry)
        {
            try
            {
                foreach (var appender in _appenders)
                {
                    try
                    {
                        appender.Append(entry);
                    }
                    catch { /* Continuar con siguiente appender */ }
                }
            }
            catch { }
        }
        
        private async void FlushLogsCallback(object state)
        {
            await FlushLogs();
        }
        
        private async Task FlushLogs()
        {
            if (_logQueue.IsEmpty)
                return;
                
            try
            {
                await _fileLock.WaitAsync();
                
                var entries = new List<LogEntry>();
                while (_logQueue.TryDequeue(out var entry))
                {
                    entries.Add(entry);
                }
                
                if (entries.Count > 0)
                {
                    await WriteLogsToFile(entries);
                }
            }
            catch (Exception ex)
            {
                WriteLogImmediate(new LogEntry
                {
                    Timestamp = DateTime.UtcNow,
                    Level = LogLevel.Error,
                    Message = $"Error flushing logs: {ex.Message}",
                    Source = "LogManager"
                });
            }
            finally
            {
                _fileLock.Release();
            }
        }
        
        private async Task WriteLogsToFile(List<LogEntry> entries)
        {
            try
            {
                // Rotar archivo si es necesario
                await RotateLogFileIfNeeded(entries);
                
                // Escribir logs al archivo
                var logLines = entries.Select(e => FormatLogEntry(e)).ToList();
                await File.AppendAllLinesAsync(_currentLogFilePath, logLines);
                
                _currentFileSize += logLines.Sum(l => Encoding.UTF8.GetByteCount(l + Environment.NewLine));
                
                // Notificar a appenders
                foreach (var entry in entries)
                {
                    foreach (var appender in _appenders)
                    {
                        try
                        {
                            appender.Append(entry);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                // Fallback a escritura simple
                try
                {
                    var fallbackPath = Path.Combine(GetLogDirectory(), "bwp_fallback.log");
                    await File.AppendAllTextAsync(fallbackPath, 
                        $"[{DateTime.UtcNow:o}] ERROR Writing logs: {ex.Message}{Environment.NewLine}");
                }
                catch { }
            }
        }
        
        private async Task RotateLogFileIfNeeded(List<LogEntry> entries)
        {
            var estimatedSize = entries.Sum(e => 
                Encoding.UTF8.GetByteCount(FormatLogEntry(e) + Environment.NewLine));
            
            var maxSizeBytes = _configuration.MaxFileSizeMB * 1024 * 1024;
            
            if (_currentFileSize + estimatedSize > maxSizeBytes)
            {
                // Comprimir archivo actual si está habilitado
                if (_configuration.EnableCompression)
                {
                    await Task.Run(() => CompressLogFile(_currentLogFilePath));
                }
                
                // Crear nuevo archivo
                InitializeCurrentLogFile();
            }
        }
        
        private void CompressLogFile(string filePath)
        {
            try
            {
                using var sourceStream = File.OpenRead(filePath);
                using var targetStream = File.Create(filePath + ".gz");
                using var compressionStream = new System.IO.Compression.GZipStream(
                    targetStream, System.IO.Compression.CompressionLevel.Optimal);
                
                sourceStream.CopyTo(compressionStream);
                
                // Eliminar archivo original después de comprimir
                File.Delete(filePath);
            }
            catch { }
        }
        
        private string FormatLogEntry(LogEntry entry)
        {
            var json = new
            {
                timestamp = entry.Timestamp.ToString("o"),
                level = entry.Level.ToString(),
                source = entry.Source,
                threadId = entry.ThreadId,
                message = entry.Message,
                exception = entry.Exception?.ToString(),
                properties = entry.Properties,
                machine = entry.MachineName,
                processId = entry.ProcessId,
                user = entry.UserName
            };
            
            return JsonSerializer.Serialize(json, new JsonSerializerOptions
            {
                WriteIndented = false,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
        }
        
        private List<LogEntry> ReadLogsFromFile(string filePath, DateTime? from, DateTime? to,
                                              LogLevel? minLevel, string source)
        {
            var logs = new List<LogEntry>();
            
            if (filePath.EndsWith(".gz"))
            {
                // Descomprimir y leer
                using var fileStream = File.OpenRead(filePath);
                using var decompressionStream = new System.IO.Compression.GZipStream(
                    fileStream, System.IO.Compression.CompressionMode.Decompress);
                using var reader = new StreamReader(decompressionStream);
                
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var entry = ParseLogLine(line, from, to, minLevel, source);
                    if (entry != null)
                    {
                        logs.Add(entry);
                    }
                }
            }
            else
            {
                // Leer archivo normal
                foreach (var line in File.ReadLines(filePath))
                {
                    var entry = ParseLogLine(line, from, to, minLevel, source);
                    if (entry != null)
                    {
                        logs.Add(entry);
                    }
                }
            }
            
            return logs;
        }
        
        private LogEntry ParseLogLine(string line, DateTime? from, DateTime? to,
                                    LogLevel? minLevel, string source)
        {
            try
            {
                var json = JsonSerializer.Deserialize<JsonElement>(line);
                
                var timestamp = DateTime.Parse(json.GetProperty("timestamp").GetString());
                
                // Aplicar filtros
                if (from.HasValue && timestamp < from.Value)
                    return null;
                if (to.HasValue && timestamp > to.Value)
                    return null;
                    
                var level = Enum.Parse<LogLevel>(json.GetProperty("level").GetString());
                if (minLevel.HasValue && level < minLevel.Value)
                    return null;
                    
                var entrySource = json.GetProperty("source").GetString();
                if (!string.IsNullOrEmpty(source) && !entrySource.Contains(source))
                    return null;
                
                var entry = new LogEntry
                {
                    Timestamp = timestamp,
                    Level = level,
                    Source = entrySource,
                    Message = json.GetProperty("message").GetString(),
                    ThreadId = json.GetProperty("threadId").GetInt32(),
                    MachineName = json.TryGetProperty("machine", out var machine) ? 
                        machine.GetString() : null,
                    ProcessId = json.TryGetProperty("processId", out var pid) ? 
                        pid.GetInt32() : 0,
                    UserName = json.TryGetProperty("user", out var user) ? 
                        user.GetString() : null
                };
                
                if (json.TryGetProperty("exception", out var exception))
                {
                    entry.Exception = new Exception(exception.GetString());
                }
                
                if (json.TryGetProperty("properties", out var properties))
                {
                    entry.Properties = JsonSerializer.Deserialize<Dictionary<string, object>>(
                        properties.GetRawText());
                }
                
                return entry;
            }
            catch
            {
                return null;
            }
        }
        
        private string GetLogDirectory()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(appData, "BWPEnterprise", "Logs");
        }
        
        #endregion
        
        #region Clases Internas
        
        private class FileLogAppender : ILogAppender
        {
            private readonly LogManager _logManager;
            
            public FileLogAppender(LogManager logManager)
            {
                _logManager = logManager;
            }
            
            public void Append(LogEntry entry)
            {
                // El archivo ya es manejado por el LogManager principal
                // Este appender solo existe para la interfaz
            }
            
            public void Dispose() { }
        }
        
        private class ConsoleLogAppender : ILogAppender
        {
            private static readonly Dictionary<LogLevel, ConsoleColor> _colors = new()
            {
                [LogLevel.Debug] = ConsoleColor.Gray,
                [LogLevel.Info] = ConsoleColor.White,
                [LogLevel.Warning] = ConsoleColor.Yellow,
                [LogLevel.Error] = ConsoleColor.Red,
                [LogLevel.Critical] = ConsoleColor.DarkRed
            };
            
            public void Append(LogEntry entry)
            {
                lock (Console.Out)
                {
                    var originalColor = Console.ForegroundColor;
                    Console.ForegroundColor = _colors[entry.Level];
                    Console.WriteLine($"[{entry.Timestamp:HH:mm:ss}] [{entry.Level}] [{entry.Source}] {entry.Message}");
                    Console.ForegroundColor = originalColor;
                    
                    if (entry.Exception != null)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Exception: {entry.Exception}");
                        Console.ForegroundColor = originalColor;
                    }
                }
            }
            
            public void Dispose() { }
        }
        
        private class EventLogAppender : ILogAppender
        {
            private const string SOURCE = "BWPEnterpriseAgent";
            private const string LOG_NAME = "Application";
            
            public EventLogAppender()
            {
                try
                {
                    if (!System.Diagnostics.EventLog.SourceExists(SOURCE))
                    {
                        System.Diagnostics.EventLog.CreateEventSource(SOURCE, LOG_NAME);
                    }
                }
                catch { }
            }
            
            public void Append(LogEntry entry)
            {
                if (entry.Level < LogLevel.Warning)
                    return;
                    
                try
                {
                    var eventLog = new System.Diagnostics.EventLog(LOG_NAME)
                    {
                        Source = SOURCE
                    };
                    
                    var entryType = entry.Level switch
                    {
                        LogLevel.Warning => System.Diagnostics.EventLogEntryType.Warning,
                        LogLevel.Error => System.Diagnostics.EventLogEntryType.Error,
                        LogLevel.Critical => System.Diagnostics.EventLogEntryType.Error,
                        _ => System.Diagnostics.EventLogEntryType.Information
                    };
                    
                    var message = $"[{entry.Source}] {entry.Message}";
                    if (entry.Exception != null)
                    {
                        message += $"\nException: {entry.Exception}";
                    }
                    
                    eventLog.WriteEntry(message, entryType, 1000 + (int)entry.Level);
                }
                catch { }
            }
            
            public void Dispose() { }
        }
        
        private class TelemetryLogAppender : ILogAppender
        {
            public void Append(LogEntry entry)
            {
                // Solo enviar logs críticos a telemetría
                if (entry.Level < LogLevel.Critical)
                    return;
                    
                try
                {
                    // Enviar a cola de telemetría
                    var telemetryQueue = TelemetryQueue.Instance;
                    if (telemetryQueue != null)
                    {
                        var telemetryEvent = new TelemetryEvent
                        {
                            EventId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            EventType = "CriticalLog",
                            Severity = "Critical",
                            Data = new
                            {
                                LogLevel = entry.Level.ToString(),
                                LogSource = entry.Source,
                                LogMessage = entry.Message,
                                Exception = entry.Exception?.ToString(),
                                Machine = entry.MachineName,
                                User = entry.UserName
                            }
                        };
                        
                        telemetryQueue.EnqueueAsync(telemetryEvent).Wait();
                    }
                }
                catch { }
            }
            
            public void Dispose() { }
        }
        
        #endregion
    }
    
    #region Interfaces y Clases de Soporte
    
    public interface ILogManager : IDisposable
    {
        void Configure(LogConfiguration configuration);
        void Log(LogLevel level, string message, string source, 
                Exception exception = null, 
                Dictionary<string, object> properties = null);
        void LogDebug(string message, string source, 
                     Dictionary<string, object> properties = null);
        void LogInfo(string message, string source,
                    Dictionary<string, object> properties = null);
        void LogWarning(string message, string source,
                       Exception exception = null,
                       Dictionary<string, object> properties = null);
        void LogError(string message, string source,
                     Exception exception = null,
                     Dictionary<string, object> properties = null);
        void LogCritical(string message, string source,
                        Exception exception = null,
                        Dictionary<string, object> properties = null);
        List<LogEntry> GetRecentLogs(DateTime? from = null, DateTime? to = null,
                                   LogLevel? minLevel = null, string source = null,
                                   int maxEntries = 1000);
        void Flush();
        void CleanupOldLogs();
        void CompressOldLogs();
        LogUsageReport GetUsageReport();
    }
    
    public interface ILogAppender : IDisposable
    {
        void Append(LogEntry entry);
    }
    
    public class LogConfiguration
    {
        public LogLevel LogLevel { get; set; } = LogLevel.Info;
        public int MaxFileSizeMB { get; set; } = 100;
        public int RetentionDays { get; set; } = 30;
        public bool EnableCompression { get; set; } = true;
        public bool EnableConsoleOutput { get; set; } = false;
        public bool EnableEventLog { get; set; } = true;
        public string CustomLogDirectory { get; set; }
    }
    
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public LogLevel Level { get; set; }
        public string Message { get; set; }
        public string Source { get; set; }
        public int ThreadId { get; set; }
        public Exception Exception { get; set; }
        public Dictionary<string, object> Properties { get; set; }
        public string MachineName { get; set; }
        public int ProcessId { get; set; }
        public string UserName { get; set; }
    }
    
    public enum LogLevel
    {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Critical = 4
    }
    
    public class LogUsageReport
    {
        public DateTime Timestamp { get; set; }
        public string LogDirectory { get; set; }
        public int TotalFiles { get; set; }
        public double TotalSizeMB { get; set; }
        public int QueueSize { get; set; }
        public LogConfiguration Configuration { get; set; }
        public List<LogFileInfo> FileDetails { get; set; }
        public string Error { get; set; }
    }
    
    public class LogFileInfo
    {
        public string FileName { get; set; }
        public double SizeMB { get; set; }
        public DateTime LastModified { get; set; }
        public bool IsCompressed { get; set; }
    }
    
    #endregion
}