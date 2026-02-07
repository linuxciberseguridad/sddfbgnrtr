using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace BWP.Enterprise.Agent.Storage
{
    /// <summary>
    /// Base de datos local SQLite para almacenamiento persistente de eventos, alertas y configuración
    /// Maneja concurrentes y optimizado para alta frecuencia de escritura
    /// </summary>
    public sealed class LocalDatabase : IDisposable
    {
        private static readonly Lazy<LocalDatabase> _instance = 
            new Lazy<LocalDatabase>(() => new LocalDatabase());
        
        public static LocalDatabase Instance => _instance.Value;
        
        private SqliteConnection _connection;
        private readonly SemaphoreSlim _dbLock = new SemaphoreSlim(1, 1);
        private readonly ConcurrentQueue<DatabaseOperation> _operationQueue;
        private readonly Timer _flushTimer;
        private bool _isInitialized;
        private bool _isDisposed;
        private string _databasePath;
        private const int FLUSH_INTERVAL_MS = 1000; // 1 segundo
        private const int MAX_QUEUE_SIZE = 10000;
        private const int BATCH_SIZE = 100;
        
        private LocalDatabase()
        {
            _operationQueue = new ConcurrentQueue<DatabaseOperation>();
            _flushTimer = new Timer(FlushOperationsCallback, null, 
                Timeout.Infinite, Timeout.Infinite);
            _isInitialized = false;
            _isDisposed = false;
        }
        
        /// <summary>
        /// Inicializa la base de datos
        /// </summary>
        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                // Determinar ruta de base de datos
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var dbDirectory = Path.Combine(appData, "BWPEnterprise", "Database");
                
                if (!Directory.Exists(dbDirectory))
                {
                    Directory.CreateDirectory(dbDirectory);
                }
                
                _databasePath = Path.Combine(dbDirectory, "bwp_agent.db");
                
                // Conectar a SQLite
                var connectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = _databasePath,
                    Mode = SqliteOpenMode.ReadWriteCreate,
                    Cache = SqliteCacheMode.Shared,
                    Pooling = true,
                    DefaultTimeout = 30
                }.ToString();
                
                _connection = new SqliteConnection(connectionString);
                await _connection.OpenAsync();
                
                // Crear tablas si no existen
                await CreateTablesAsync();
                
                // Crear índices
                await CreateIndexesAsync();
                
                // Configurar pragmas para mejor rendimiento
                await ConfigurePragmasAsync();
                
                // Iniciar timer de flush
                _flushTimer.Change(TimeSpan.Zero, 
                    TimeSpan.FromMilliseconds(FLUSH_INTERVAL_MS));
                
                _isInitialized = true;
                
                LogInfo("Base de datos local inicializada", "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error inicializando base de datos: {ex}", "LocalDatabase");
                throw;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Guarda un evento de seguridad
        /// </summary>
        public async Task SaveEventAsync(SecurityEvent securityEvent)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            var operation = new DatabaseOperation
            {
                Type = OperationType.InsertEvent,
                Data = securityEvent,
                Timestamp = DateTime.UtcNow
            };
            
            if (_operationQueue.Count < MAX_QUEUE_SIZE)
            {
                _operationQueue.Enqueue(operation);
            }
            else
            {
                // Si la cola está llena, escribir directamente
                await ExecuteOperationImmediate(operation);
            }
        }
        
        /// <summary>
        /// Guarda una alerta
        /// </summary>
        public async Task SaveAlertAsync(SecurityAlert alert)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            var operation = new DatabaseOperation
            {
                Type = OperationType.InsertAlert,
                Data = alert,
                Timestamp = DateTime.UtcNow
            };
            
            _operationQueue.Enqueue(operation);
        }
        
        /// <summary>
        /// Guarda un evento de telemetría
        /// </summary>
        public async Task SaveTelemetryEventAsync(TelemetryEvent telemetryEvent)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            var operation = new DatabaseOperation
            {
                Type = OperationType.InsertTelemetry,
                Data = telemetryEvent,
                Timestamp = DateTime.UtcNow
            };
            
            _operationQueue.Enqueue(operation);
        }
        
        /// <summary>
        /// Guarda una acción de remediación
        /// </summary>
        public async Task SaveRemediationActionAsync(RemediationAction action)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            var operation = new DatabaseOperation
            {
                Type = OperationType.InsertRemediation,
                Data = action,
                Timestamp = DateTime.UtcNow
            };
            
            _operationQueue.Enqueue(operation);
        }
        
        /// <summary>
        /// Guarda configuración
        /// </summary>
        public async Task SaveConfigAsync(string key, string value)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            var operation = new DatabaseOperation
            {
                Type = OperationType.InsertConfig,
                Data = new ConfigEntry { Key = key, Value = value },
                Timestamp = DateTime.UtcNow
            };
            
            _operationQueue.Enqueue(operation);
        }
        
        /// <summary>
        /// Obtiene configuración
        /// </summary>
        public async Task<string> GetConfigAsync(string key, string defaultValue = null)
        {
            if (!_isInitialized || _isDisposed)
                return defaultValue;
                
            try
            {
                await _dbLock.WaitAsync();
                
                using var command = _connection.CreateCommand();
                command.CommandText = @"
                    SELECT value FROM config 
                    WHERE key = @key 
                    ORDER BY updated_at DESC 
                    LIMIT 1";
                    
                command.Parameters.AddWithValue("@key", key);
                
                var result = await command.ExecuteScalarAsync();
                return result?.ToString() ?? defaultValue;
            }
            catch (Exception ex)
            {
                LogError($"Error obteniendo configuración: {ex}", "LocalDatabase");
                return defaultValue;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Obtiene eventos con filtros
        /// </summary>
        public async Task<List<SecurityEvent>> GetEventsAsync(DateTime? from = null, DateTime? to = null,
                                                            EventType? eventType = null, 
                                                            string source = null, int limit = 1000)
        {
            var events = new List<SecurityEvent>();
            
            if (!_isInitialized || _isDisposed)
                return events;
                
            try
            {
                await _dbLock.WaitAsync();
                
                var query = new StringBuilder(@"
                    SELECT id, event_type, source, timestamp, data, severity, processed
                    FROM security_events 
                    WHERE 1=1");
                
                var parameters = new List<SqliteParameter>();
                var paramIndex = 0;
                
                if (from.HasValue)
                {
                    query.Append($" AND timestamp >= @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", from.Value));
                    paramIndex++;
                }
                
                if (to.HasValue)
                {
                    query.Append($" AND timestamp <= @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", to.Value));
                    paramIndex++;
                }
                
                if (eventType.HasValue)
                {
                    query.Append($" AND event_type = @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", (int)eventType.Value));
                    paramIndex++;
                }
                
                if (!string.IsNullOrEmpty(source))
                {
                    query.Append($" AND source LIKE @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", $"%{source}%"));
                    paramIndex++;
                }
                
                query.Append($" ORDER BY timestamp DESC LIMIT {limit}");
                
                using var command = _connection.CreateCommand();
                command.CommandText = query.ToString();
                command.Parameters.AddRange(parameters.ToArray());
                
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    try
                    {
                        var eventData = JsonSerializer.Deserialize<SecurityEvent>(
                            reader.GetString(4));
                        events.Add(eventData);
                    }
                    catch { }
                }
                
                return events;
            }
            catch (Exception ex)
            {
                LogError($"Error obteniendo eventos: {ex}", "LocalDatabase");
                return events;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Obtiene alertas con filtros
        /// </summary>
        public async Task<List<SecurityAlert>> GetAlertsAsync(DateTime? from = null, DateTime? to = null,
                                                            ThreatSeverity? minSeverity = null,
                                                            AlertStatus? status = null, int limit = 1000)
        {
            var alerts = new List<SecurityAlert>();
            
            if (!_isInitialized || _isDisposed)
                return alerts;
                
            try
            {
                await _dbLock.WaitAsync();
                
                var query = new StringBuilder(@"
                    SELECT id, alert_id, timestamp, severity, title, details, 
                           source, status, acknowledged_by, acknowledged_at,
                           resolved_at, false_positive
                    FROM security_alerts 
                    WHERE 1=1");
                
                var parameters = new List<SqliteParameter>();
                var paramIndex = 0;
                
                if (from.HasValue)
                {
                    query.Append($" AND timestamp >= @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", from.Value));
                    paramIndex++;
                }
                
                if (to.HasValue)
                {
                    query.Append($" AND timestamp <= @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", to.Value));
                    paramIndex++;
                }
                
                if (minSeverity.HasValue)
                {
                    query.Append($" AND severity >= @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", (int)minSeverity.Value));
                    paramIndex++;
                }
                
                if (status.HasValue)
                {
                    query.Append($" AND status = @p{paramIndex}");
                    parameters.Add(new SqliteParameter($"@p{paramIndex}", (int)status.Value));
                    paramIndex++;
                }
                
                query.Append($" ORDER BY timestamp DESC LIMIT {limit}");
                
                using var command = _connection.CreateCommand();
                command.CommandText = query.ToString();
                command.Parameters.AddRange(parameters.ToArray());
                
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var alert = new SecurityAlert
                    {
                        AlertId = reader.GetString(1),
                        Timestamp = reader.GetDateTime(2),
                        Severity = (ThreatSeverity)reader.GetInt32(3),
                        Title = reader.GetString(4),
                        Details = reader.GetString(5),
                        Source = reader.GetString(6),
                        Status = (AlertStatus)reader.GetInt32(7),
                        AcknowledgedBy = reader.IsDBNull(8) ? null : reader.GetString(8),
                        AcknowledgedAt = reader.IsDBNull(9) ? null : reader.GetDateTime(9) as DateTime?,
                        ResolvedAt = reader.IsDBNull(10) ? null : reader.GetDateTime(10) as DateTime?,
                        FalsePositive = reader.GetBoolean(11)
                    };
                    
                    alerts.Add(alert);
                }
                
                return alerts;
            }
            catch (Exception ex)
            {
                LogError($"Error obteniendo alertas: {ex}", "LocalDatabase");
                return alerts;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Actualiza estado de una alerta
        /// </summary>
        public async Task UpdateAlertStatusAsync(string alertId, AlertStatus status, 
                                               string user = null, bool falsePositive = false)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                using var command = _connection.CreateCommand();
                command.CommandText = @"
                    UPDATE security_alerts 
                    SET status = @status, 
                        false_positive = @falsePositive,
                        acknowledged_by = @user,
                        acknowledged_at = CASE WHEN @user IS NOT NULL THEN @now ELSE acknowledged_at END,
                        resolved_at = CASE WHEN @status = 2 THEN @now ELSE resolved_at END,
                        updated_at = @now
                    WHERE alert_id = @alertId";
                    
                var now = DateTime.UtcNow;
                
                command.Parameters.AddWithValue("@alertId", alertId);
                command.Parameters.AddWithValue("@status", (int)status);
                command.Parameters.AddWithValue("@falsePositive", falsePositive);
                command.Parameters.AddWithValue("@user", user ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@now", now);
                
                await command.ExecuteNonQueryAsync();
                
                LogInfo($"Alerta {alertId} actualizada a {status}", "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error actualizando alerta: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Obtiene eventos de telemetría pendientes de envío
        /// </summary>
        public async Task<List<TelemetryEvent>> GetPendingTelemetryAsync(int limit = 100)
        {
            var events = new List<TelemetryEvent>();
            
            if (!_isInitialized || _isDisposed)
                return events;
                
            try
            {
                await _dbLock.WaitAsync();
                
                using var command = _connection.CreateCommand();
                command.CommandText = @"
                    SELECT id, event_id, timestamp, event_type, severity, data, sent, retry_count
                    FROM telemetry_events 
                    WHERE sent = 0 AND retry_count < 3
                    ORDER BY timestamp ASC 
                    LIMIT @limit";
                    
                command.Parameters.AddWithValue("@limit", limit);
                
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    try
                    {
                        var telemetryEvent = new TelemetryEvent
                        {
                            EventId = reader.GetString(1),
                            Timestamp = reader.GetDateTime(2),
                            EventType = reader.GetString(3),
                            Severity = reader.GetString(4),
                            Data = JsonSerializer.Deserialize<Dictionary<string, object>>(
                                reader.GetString(5))
                        };
                        
                        events.Add(telemetryEvent);
                    }
                    catch { }
                }
                
                return events;
            }
            catch (Exception ex)
            {
                LogError($"Error obteniendo telemetría pendiente: {ex}", "LocalDatabase");
                return events;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Marca eventos de telemetría como enviados
        /// </summary>
        public async Task MarkTelemetryAsSentAsync(List<string> eventIds)
        {
            if (!_isInitialized || _isDisposed || eventIds.Count == 0)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                // Crear lista de parámetros
                var parameters = new List<SqliteParameter>();
                var placeholders = new List<string>();
                
                for (int i = 0; i < eventIds.Count; i++)
                {
                    placeholders.Add($"@p{i}");
                    parameters.Add(new SqliteParameter($"@p{i}", eventIds[i]));
                }
                
                using var command = _connection.CreateCommand();
                command.CommandText = $@"
                    UPDATE telemetry_events 
                    SET sent = 1, sent_at = @now, updated_at = @now
                    WHERE event_id IN ({string.Join(",", placeholders)})";
                    
                command.Parameters.AddWithValue("@now", DateTime.UtcNow);
                command.Parameters.AddRange(parameters.ToArray());
                
                await command.ExecuteNonQueryAsync();
                
                LogInfo($"{eventIds.Count} eventos de telemetría marcados como enviados", 
                    "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error marcando telemetría como enviada: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Incrementa contador de reintentos para eventos de telemetría fallidos
        /// </summary>
        public async Task IncrementTelemetryRetryCountAsync(List<string> eventIds)
        {
            if (!_isInitialized || _isDisposed || eventIds.Count == 0)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                var parameters = new List<SqliteParameter>();
                var placeholders = new List<string>();
                
                for (int i = 0; i < eventIds.Count; i++)
                {
                    placeholders.Add($"@p{i}");
                    parameters.Add(new SqliteParameter($"@p{i}", eventIds[i]));
                }
                
                using var command = _connection.CreateCommand();
                command.CommandText = $@"
                    UPDATE telemetry_events 
                    SET retry_count = retry_count + 1, updated_at = @now
                    WHERE event_id IN ({string.Join(",", placeholders)})";
                    
                command.Parameters.AddWithValue("@now", DateTime.UtcNow);
                command.Parameters.AddRange(parameters.ToArray());
                
                await command.ExecuteNonQueryAsync();
                
                LogInfo($"{eventIds.Count} eventos de telemetría incrementados en retry count", 
                    "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error incrementando retry count: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Realiza limpieza de datos antiguos
        /// </summary>
        public async Task CleanupOldDataAsync(int retentionDays = 30)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
                
                // Limpiar eventos antiguos (mantener solo los no procesados)
                using var command1 = _connection.CreateCommand();
                command1.CommandText = @"
                    DELETE FROM security_events 
                    WHERE timestamp < @cutoffDate AND processed = 1";
                command1.Parameters.AddWithValue("@cutoffDate", cutoffDate);
                var deletedEvents = await command1.ExecuteNonQueryAsync();
                
                // Limpiar alertas resueltas antiguas
                using var command2 = _connection.CreateCommand();
                command2.CommandText = @"
                    DELETE FROM security_alerts 
                    WHERE timestamp < @cutoffDate AND status = 2";
                command2.Parameters.AddWithValue("@cutoffDate", cutoffDate);
                var deletedAlerts = await command2.ExecuteNonQueryAsync();
                
                // Limpiar telemetría enviada antigua
                using var command3 = _connection.CreateCommand();
                command3.CommandText = @"
                    DELETE FROM telemetry_events 
                    WHERE timestamp < @cutoffDate AND sent = 1";
                command3.Parameters.AddWithValue("@cutoffDate", cutoffDate);
                var deletedTelemetry = await command3.ExecuteNonQueryAsync();
                
                // Vacuum para recuperar espacio
                using var command4 = _connection.CreateCommand();
                command4.CommandText = "VACUUM";
                await command4.ExecuteNonQueryAsync();
                
                LogInfo($"Limpieza completada: {deletedEvents} eventos, " +
                       $"{deletedAlerts} alertas, {deletedTelemetry} telemetría eliminados", 
                       "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error en limpieza de datos: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Realiza backup de la base de datos
        /// </summary>
        public async Task BackupAsync(string backupPath = null)
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                if (string.IsNullOrEmpty(backupPath))
                {
                    var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    var backupDir = Path.Combine(appData, "BWPEnterprise", "Backups");
                    
                    if (!Directory.Exists(backupDir))
                    {
                        Directory.CreateDirectory(backupDir);
                    }
                    
                    backupPath = Path.Combine(backupDir, 
                        $"bwp_backup_{DateTime.UtcNow:yyyyMMdd_HHmmss}.db");
                }
                
                // Cerrar conexión temporalmente para backup
                await _connection.CloseAsync();
                
                // Copiar archivo
                File.Copy(_databasePath, backupPath, true);
                
                // Reabrir conexión
                await _connection.OpenAsync();
                
                LogInfo($"Backup creado: {backupPath}", "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error creando backup: {ex}", "LocalDatabase");
                
                // Intentar reabrir conexión si falló
                try
                {
                    await _connection.OpenAsync();
                }
                catch { }
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas de la base de datos
        /// </summary>
        public async Task<DatabaseStats> GetStatisticsAsync()
        {
            var stats = new DatabaseStats
            {
                Timestamp = DateTime.UtcNow,
                DatabasePath = _databasePath,
                IsConnected = _isInitialized && !_isDisposed
            };
            
            if (!_isInitialized || _isDisposed)
                return stats;
                
            try
            {
                await _dbLock.WaitAsync();
                
                // Obtener conteos
                using var command1 = _connection.CreateCommand();
                command1.CommandText = @"
                    SELECT 
                        (SELECT COUNT(*) FROM security_events) as event_count,
                        (SELECT COUNT(*) FROM security_alerts) as alert_count,
                        (SELECT COUNT(*) FROM telemetry_events WHERE sent = 0) as pending_telemetry,
                        (SELECT COUNT(*) FROM remediation_actions) as remediation_count,
                        (SELECT COUNT(*) FROM config) as config_count";
                
                using var reader1 = await command1.ExecuteReaderAsync();
                if (await reader1.ReadAsync())
                {
                    stats.EventCount = reader1.GetInt64(0);
                    stats.AlertCount = reader1.GetInt64(1);
                    stats.PendingTelemetryCount = reader1.GetInt64(2);
                    stats.RemediationCount = reader1.GetInt64(3);
                    stats.ConfigCount = reader1.GetInt64(4);
                }
                
                // Obtener tamaño de archivo
                if (File.Exists(_databasePath))
                {
                    var fileInfo = new FileInfo(_databasePath);
                    stats.DatabaseSizeMB = fileInfo.Length / (1024 * 1024);
                }
                
                // Obtener operaciones pendientes
                stats.PendingOperations = _operationQueue.Count;
                
                // Obtear uso de espacio por tabla
                using var command2 = _connection.CreateCommand();
                command2.CommandText = @"
                    SELECT name, SUM(pgsize) as size
                    FROM dbstat
                    GROUP BY name
                    ORDER BY size DESC";
                
                stats.TableSizes = new Dictionary<string, long>();
                using var reader2 = await command2.ExecuteReaderAsync();
                while (await reader2.ReadAsync())
                {
                    stats.TableSizes[reader2.GetString(0)] = reader2.GetInt64(1);
                }
                
                return stats;
            }
            catch (Exception ex)
            {
                LogError($"Error obteniendo estadísticas: {ex}", "LocalDatabase");
                stats.Error = ex.Message;
                return stats;
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        /// <summary>
        /// Cierra la base de datos
        /// </summary>
        public async Task CloseAsync()
        {
            if (!_isInitialized || _isDisposed)
                return;
                
            try
            {
                // Flush final de operaciones pendientes
                await FlushOperations();
                
                // Detener timer
                _flushTimer.Change(Timeout.Infinite, Timeout.Infinite);
                
                // Cerrar conexión
                if (_connection != null && _connection.State != ConnectionState.Closed)
                {
                    await _connection.CloseAsync();
                }
                
                _isInitialized = false;
                LogInfo("Base de datos cerrada", "LocalDatabase");
            }
            catch (Exception ex)
            {
                LogError($"Error cerrando base de datos: {ex}", "LocalDatabase");
            }
        }
        
        /// <summary>
        /// Verifica si la base de datos está conectada
        /// </summary>
        public bool IsConnected => _isInitialized && !_isDisposed && 
                                 _connection?.State == ConnectionState.Open;
        
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
                CloseAsync().Wait(TimeSpan.FromSeconds(5));
                
                _flushTimer?.Dispose();
                _dbLock?.Dispose();
                _connection?.Dispose();
            }
            catch { }
        }
        
        #region Métodos Privados
        
        private async Task CreateTablesAsync()
        {
            // Tabla de eventos de seguridad
            using var command1 = _connection.CreateCommand();
            command1.CommandText = @"
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    data TEXT NOT NULL,
                    severity INTEGER,
                    processed BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )";
            await command1.ExecuteNonQueryAsync();
            
            // Tabla de alertas
            using var command2 = _connection.CreateCommand();
            command2.CommandText = @"
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    timestamp DATETIME NOT NULL,
                    severity INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status INTEGER DEFAULT 0,
                    acknowledged_by TEXT,
                    acknowledged_at DATETIME,
                    resolved_at DATETIME,
                    false_positive BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )";
            await command2.ExecuteNonQueryAsync();
            
            // Tabla de telemetría
            using var command3 = _connection.CreateCommand();
            command3.CommandText = @"
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    data TEXT NOT NULL,
                    sent BOOLEAN DEFAULT 0,
                    sent_at DATETIME,
                    retry_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )";
            await command3.ExecuteNonQueryAsync();
            
            // Tabla de acciones de remediación
            using var command4 = _connection.CreateCommand();
            command4.CommandText = @"
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id TEXT UNIQUE NOT NULL,
                    timestamp DATETIME NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )";
            await command4.ExecuteNonQueryAsync();
            
            // Tabla de configuración
            using var command5 = _connection.CreateCommand();
            command5.CommandText = @"
                CREATE TABLE IF NOT EXISTS config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )";
            await command5.ExecuteNonQueryAsync();
        }
        
        private async Task CreateIndexesAsync()
        {
            // Índices para security_events
            var indexes = new[]
            {
                "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_security_events_processed ON security_events(processed)",
                
                // Índices para security_alerts
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity)",
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status)",
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_alert_id ON security_alerts(alert_id)",
                
                // Índices para telemetry_events
                "CREATE INDEX IF NOT EXISTS idx_telemetry_events_timestamp ON telemetry_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_telemetry_events_sent ON telemetry_events(sent)",
                "CREATE INDEX IF NOT EXISTS idx_telemetry_events_retry ON telemetry_events(retry_count)",
                
                // Índices para remediation_actions
                "CREATE INDEX IF NOT EXISTS idx_remediation_timestamp ON remediation_actions(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_remediation_type ON remediation_actions(action_type)",
                
                // Índices para config
                "CREATE INDEX IF NOT EXISTS idx_config_key ON config(key)"
            };
            
            foreach (var indexSql in indexes)
            {
                using var command = _connection.CreateCommand();
                command.CommandText = indexSql;
                await command.ExecuteNonQueryAsync();
            }
        }
        
        private async Task ConfigurePragmasAsync()
        {
            var pragmas = new[]
            {
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = NORMAL",
                "PRAGMA cache_size = -2000", // 2MB cache
                "PRAGMA temp_store = MEMORY",
                "PRAGMA mmap_size = 268435456", // 256MB memory mapping
                "PRAGMA busy_timeout = 5000", // 5 second timeout
                "PRAGMA foreign_keys = ON"
            };
            
            foreach (var pragma in pragmas)
            {
                using var command = _connection.CreateCommand();
                command.CommandText = pragma;
                await command.ExecuteNonQueryAsync();
            }
        }
        
        private async void FlushOperationsCallback(object state)
        {
            await FlushOperations();
        }
        
        private async Task FlushOperations()
        {
            if (_operationQueue.IsEmpty)
                return;
                
            try
            {
                await _dbLock.WaitAsync();
                
                var operations = new List<DatabaseOperation>();
                while (_operationQueue.TryDequeue(out var operation) && 
                       operations.Count < BATCH_SIZE)
                {
                    operations.Add(operation);
                }
                
                if (operations.Count > 0)
                {
                    await ExecuteOperationsBatch(operations);
                }
            }
            catch (Exception ex)
            {
                LogError($"Error flushing operations: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        private async Task ExecuteOperationsBatch(List<DatabaseOperation> operations)
        {
            using var transaction = await _connection.BeginTransactionAsync();
            
            try
            {
                foreach (var operation in operations)
                {
                    await ExecuteOperation(operation, transaction);
                }
                
                await transaction.CommitAsync();
                
                LogInfo($"{operations.Count} operaciones ejecutadas en batch", 
                    "LocalDatabase");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                
                LogError($"Error ejecutando batch: {ex}", "LocalDatabase");
                
                // Reintentar operaciones individualmente
                foreach (var operation in operations)
                {
                    try
                    {
                        await ExecuteOperationImmediate(operation);
                    }
                    catch { }
                }
            }
        }
        
        private async Task ExecuteOperation(DatabaseOperation operation, SqliteTransaction transaction)
        {
            switch (operation.Type)
            {
                case OperationType.InsertEvent:
                    await InsertSecurityEvent(operation.Data as SecurityEvent, transaction);
                    break;
                    
                case OperationType.InsertAlert:
                    await InsertSecurityAlert(operation.Data as SecurityAlert, transaction);
                    break;
                    
                case OperationType.InsertTelemetry:
                    await InsertTelemetryEvent(operation.Data as TelemetryEvent, transaction);
                    break;
                    
                case OperationType.InsertRemediation:
                    await InsertRemediationAction(operation.Data as RemediationAction, transaction);
                    break;
                    
                case OperationType.InsertConfig:
                    await InsertConfig(operation.Data as ConfigEntry, transaction);
                    break;
            }
        }
        
        private async Task ExecuteOperationImmediate(DatabaseOperation operation)
        {
            try
            {
                await _dbLock.WaitAsync();
                
                using var transaction = await _connection.BeginTransactionAsync();
                
                await ExecuteOperation(operation, transaction);
                
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                LogError($"Error ejecutando operación inmediata: {ex}", "LocalDatabase");
            }
            finally
            {
                _dbLock.Release();
            }
        }
        
        private async Task InsertSecurityEvent(SecurityEvent securityEvent, SqliteTransaction transaction)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT INTO security_events 
                (event_type, source, timestamp, data, severity)
                VALUES (@eventType, @source, @timestamp, @data, @severity)";
                
            command.Parameters.AddWithValue("@eventType", (int)securityEvent.EventType);
            command.Parameters.AddWithValue("@source", securityEvent.Source);
            command.Parameters.AddWithValue("@timestamp", securityEvent.Timestamp);
            command.Parameters.AddWithValue("@data", JsonSerializer.Serialize(securityEvent));
            command.Parameters.AddWithValue("@severity", (int?)securityEvent.Severity);
            
            await command.ExecuteNonQueryAsync();
        }
        
        private async Task InsertSecurityAlert(SecurityAlert alert, SqliteTransaction transaction)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT OR REPLACE INTO security_alerts 
                (alert_id, timestamp, severity, title, details, source, status)
                VALUES (@alertId, @timestamp, @severity, @title, @details, @source, @status)";
                
            command.Parameters.AddWithValue("@alertId", alert.AlertId);
            command.Parameters.AddWithValue("@timestamp", alert.Timestamp);
            command.Parameters.AddWithValue("@severity", (int)alert.Severity);
            command.Parameters.AddWithValue("@title", alert.Title);
            command.Parameters.AddWithValue("@details", alert.Details);
            command.Parameters.AddWithValue("@source", alert.Source);
            command.Parameters.AddWithValue("@status", (int)alert.Status);
            
            await command.ExecuteNonQueryAsync();
        }
        
        private async Task InsertTelemetryEvent(TelemetryEvent telemetryEvent, SqliteTransaction transaction)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT OR REPLACE INTO telemetry_events 
                (event_id, timestamp, event_type, severity, data)
                VALUES (@eventId, @timestamp, @eventType, @severity, @data)";
                
            command.Parameters.AddWithValue("@eventId", telemetryEvent.EventId);
            command.Parameters.AddWithValue("@timestamp", telemetryEvent.Timestamp);
            command.Parameters.AddWithValue("@eventType", telemetryEvent.EventType);
            command.Parameters.AddWithValue("@severity", telemetryEvent.Severity);
            command.Parameters.AddWithValue("@data", JsonSerializer.Serialize(telemetryEvent.Data));
            
            await command.ExecuteNonQueryAsync();
        }
        
        private async Task InsertRemediationAction(RemediationAction action, SqliteTransaction transaction)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT INTO remediation_actions 
                (action_id, timestamp, action_type, target, result, details)
                VALUES (@actionId, @timestamp, @actionType, @target, @result, @details)";
                
            command.Parameters.AddWithValue("@actionId", action.ActionId);
            command.Parameters.AddWithValue("@timestamp", action.Timestamp);
            command.Parameters.AddWithValue("@actionType", action.ActionType);
            command.Parameters.AddWithValue("@target", action.Target);
            command.Parameters.AddWithValue("@result", action.Result);
            command.Parameters.AddWithValue("@details", action.Details);
            
            await command.ExecuteNonQueryAsync();
        }
        
        private async Task InsertConfig(ConfigEntry config, SqliteTransaction transaction)
        {
            using var command = _connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT OR REPLACE INTO config (key, value, updated_at)
                VALUES (@key, @value, @updatedAt)";
                
            command.Parameters.AddWithValue("@key", config.Key);
            command.Parameters.AddWithValue("@value", config.Value);
            command.Parameters.AddWithValue("@updatedAt", DateTime.UtcNow);
            
            await command.ExecuteNonQueryAsync();
        }
        
        private void LogInfo(string message, string source)
        {
            try
            {
                var logManager = LogManager.Instance;
                logManager.LogInfo(message, source);
            }
            catch { }
        }
        
        private void LogError(string message, string source)
        {
            try
            {
                var logManager = LogManager.Instance;
                logManager.LogError(message, source);
            }
            catch { }
        }
        
        #endregion
        
        #region Clases Internas
        
        private class DatabaseOperation
        {
            public OperationType Type { get; set; }
            public object Data { get; set; }
            public DateTime Timestamp { get; set; }
        }
        
        private enum OperationType
        {
            InsertEvent,
            InsertAlert,
            InsertTelemetry,
            InsertRemediation,
            InsertConfig
        }
        
        private class ConfigEntry
        {
            public string Key { get; set; }
            public string Value { get; set; }
        }
        
        #endregion
    }
    
    #region Clases de Soporte
    
    public class DatabaseStats
    {
        public DateTime Timestamp { get; set; }
        public string DatabasePath { get; set; }
        public bool IsConnected { get; set; }
        public long EventCount { get; set; }
        public long AlertCount { get; set; }
        public long PendingTelemetryCount { get; set; }
        public long RemediationCount { get; set; }
        public long ConfigCount { get; set; }
        public double DatabaseSizeMB { get; set; }
        public int PendingOperations { get; set; }
        public Dictionary<string, long> TableSizes { get; set; }
        public string Error { get; set; }
    }
    
    // Estas clases deben coincidir con las definiciones en otros archivos
    public class SecurityEvent
    {
        public EventType EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public string Source { get; set; }
        public ThreatSeverity Severity { get; set; }
        public Dictionary<string, object> Data { get; set; }
    }
    
    public class SecurityAlert
    {
        public string AlertId { get; set; }
        public DateTime Timestamp { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Title { get; set; }
        public string Details { get; set; }
        public string Source { get; set; }
        public AlertStatus Status { get; set; }
        public string AcknowledgedBy { get; set; }
        public DateTime? AcknowledgedAt { get; set; }
        public DateTime? ResolvedAt { get; set; }
        public bool FalsePositive { get; set; }
    }
    
    public class TelemetryEvent
    {
        public string EventId { get; set; }
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
        public string Severity { get; set; }
        public Dictionary<string, object> Data { get; set; }
    }
    
    public class RemediationAction
    {
        public string ActionId { get; set; }
        public DateTime Timestamp { get; set; }
        public string ActionType { get; set; }
        public string Target { get; set; }
        public string Result { get; set; }
        public string Details { get; set; }
    }
    
    public enum EventType
    {
        Unknown = 0,
        ProcessCreated = 1001,
        ProcessTerminated = 1002,
        FileCreated = 2001,
        FileModified = 2002,
        FileDeleted = 2003,
        NetworkConnection = 3001,
        DNSQuery = 3002,
        ThreatDetected = 5001,
        RemediationApplied = 6001,
        AlertGenerated = 7001
    }
    
    public enum ThreatSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
    
    public enum AlertStatus
    {
        Active = 0,
        Acknowledged = 1,
        Resolved = 2,
        FalsePositive = 3
    }
    
    #endregion
}