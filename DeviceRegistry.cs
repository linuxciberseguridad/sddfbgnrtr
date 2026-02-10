using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using Newtonsoft.Json;

namespace BWP.Enterprise.Cloud.DeviceRegistry
{
    /// <summary>
    /// Registro centralizado de dispositivos con caching distribuido
    /// Maneja millones de dispositivos con alta concurrencia
    /// </summary>
    public sealed class DeviceRegistry : IDeviceRegistry
    {
        private readonly ILogger<DeviceRegistry> _logger;
        private readonly IMongoDatabase _database;
        private readonly IMongoCollection<DeviceRecord> _devicesCollection;
        private readonly IMongoCollection<DeviceGroup> _groupsCollection;
        
        // Caches en memoria para alta velocidad
        private readonly ConcurrentDictionary<string, DeviceRecord> _deviceCache;
        private readonly ConcurrentDictionary<string, DeviceGroup> _groupCache;
        private readonly ConcurrentDictionary<string, DateTime> _lastSeenCache;
        private readonly ConcurrentDictionary<string, List<string>> _tenantDevicesCache;
        
        private readonly Timer _cleanupTimer;
        private readonly Timer _syncTimer;
        private readonly SemaphoreSlim _cacheLock;
        
        private const int CACHE_EXPIRY_MINUTES = 5;
        private const int CLEANUP_INTERVAL_MINUTES = 10;
        private const int SYNC_INTERVAL_SECONDS = 30;
        private const int MAX_CACHE_SIZE = 100000;
        private const int BATCH_SIZE = 1000;
        
        public DeviceRegistry(
            ILogger<DeviceRegistry> logger,
            IMongoDatabase database)
        {
            _logger = logger;
            _database = database;
            
            // Configurar colecciones
            _devicesCollection = _database.GetCollection<DeviceRecord>("devices");
            _groupsCollection = _database.GetCollection<DeviceGroup>("device_groups");
            
            // Crear índices
            CreateIndexes();
            
            // Inicializar caches
            _deviceCache = new ConcurrentDictionary<string, DeviceRecord>();
            _groupCache = new ConcurrentDictionary<string, DeviceGroup>();
            _lastSeenCache = new ConcurrentDictionary<string, DateTime>();
            _tenantDevicesCache = new ConcurrentDictionary<string, List<string>>();
            
            _cacheLock = new SemaphoreSlim(1, 1);
            
            // Inicializar timers
            _cleanupTimer = new Timer(CleanupCache, null, 
                TimeSpan.FromMinutes(CLEANUP_INTERVAL_MINUTES), 
                TimeSpan.FromMinutes(CLEANUP_INTERVAL_MINUTES));
            
            _syncTimer = new Timer(SyncCacheWithDatabase, null, 
                TimeSpan.FromSeconds(SYNC_INTERVAL_SECONDS), 
                TimeSpan.FromSeconds(SYNC_INTERVAL_SECONDS));
            
            _logger.LogInformation("DeviceRegistry inicializado");
        }
        
        private void CreateIndexes()
        {
            try
            {
                // Índices para dispositivos
                var deviceIndexes = new List<CreateIndexModel<DeviceRecord>>
                {
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Ascending(d => d.DeviceId),
                        new CreateIndexOptions { Unique = true }),
                    
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Ascending(d => d.TenantId),
                        new CreateIndexOptions { Background = true }),
                    
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Ascending(d => d.GroupId),
                        new CreateIndexOptions { Background = true }),
                    
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Ascending(d => d.Status),
                        new CreateIndexOptions { Background = true }),
                    
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Ascending(d => d.LastSeen),
                        new CreateIndexOptions { Background = true }),
                    
                    new CreateIndexModel<DeviceRecord>(
                        Builders<DeviceRecord>.IndexKeys.Compound()
                            .Ascending(d => d.TenantId)
                            .Ascending(d => d.DeviceId),
                        new CreateIndexOptions { Unique = true })
                };
                
                _devicesCollection.Indexes.CreateMany(deviceIndexes);
                
                // Índices para grupos
                var groupIndexes = new List<CreateIndexModel<DeviceGroup>>
                {
                    new CreateIndexModel<DeviceGroup>(
                        Builders<DeviceGroup>.IndexKeys.Ascending(g => g.GroupId),
                        new CreateIndexOptions { Unique = true }),
                    
                    new CreateIndexModel<DeviceGroup>(
                        Builders<DeviceGroup>.IndexKeys.Ascending(g => g.TenantId),
                        new CreateIndexOptions { Background = true }),
                    
                    new CreateIndexModel<DeviceGroup>(
                        Builders<DeviceGroup>.IndexKeys.Compound()
                            .Ascending(g => g.TenantId)
                            .Ascending(g => g.GroupId),
                        new CreateIndexOptions { Unique = true })
                };
                
                _groupsCollection.Indexes.CreateMany(groupIndexes);
                
                _logger.LogInformation("Índices de DeviceRegistry creados");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando índices de DeviceRegistry");
            }
        }
        
        /// <summary>
        /// Registra o actualiza un dispositivo
        /// </summary>
        public async Task<DeviceRegistrationResult> RegisterDeviceAsync(
            DeviceRegistrationRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            
            try
            {
                await _cacheLock.WaitAsync(cancellationToken);
                
                try
                {
                    // 1. Verificar si el dispositivo ya existe
                    var existingDevice = await GetDeviceFromCacheOrDatabaseAsync(
                        request.DeviceId, request.TenantId, cancellationToken);
                    
                    DeviceRecord deviceRecord;
                    
                    if (existingDevice != null)
                    {
                        // Actualizar dispositivo existente
                        deviceRecord = UpdateExistingDevice(existingDevice, request);
                        await UpdateDeviceInDatabaseAsync(deviceRecord, cancellationToken);
                        
                        _logger.LogInformation("Dispositivo actualizado: {DeviceId} del tenant {TenantId}", 
                            request.DeviceId, request.TenantId);
                    }
                    else
                    {
                        // Crear nuevo dispositivo
                        deviceRecord = CreateNewDevice(request);
                        await InsertDeviceIntoDatabaseAsync(deviceRecord, cancellationToken);
                        
                        _logger.LogInformation("Dispositivo registrado: {DeviceId} del tenant {TenantId}", 
                            request.DeviceId, request.TenantId);
                    }
                    
                    // 2. Actualizar cache
                    UpdateDeviceCache(deviceRecord);
                    UpdateTenantDevicesCache(deviceRecord.TenantId, deviceRecord.DeviceId);
                    
                    // 3. Enriquecer con información del grupo si aplica
                    if (!string.IsNullOrEmpty(deviceRecord.GroupId))
                    {
                        await EnrichWithGroupInfoAsync(deviceRecord, cancellationToken);
                    }
                    
                    // 4. Registrar actividad
                    await RecordDeviceActivityAsync(deviceRecord, "REGISTER", cancellationToken);
                    
                    // 5. Retornar resultado
                    return new DeviceRegistrationResult
                    {
                        Success = true,
                        DeviceId = deviceRecord.DeviceId,
                        TenantId = deviceRecord.TenantId,
                        IsNewRegistration = existingDevice == null,
                        Timestamp = deviceRecord.LastSeen,
                        Metadata = new Dictionary<string, object>
                        {
                            { "assignedGroup", deviceRecord.GroupId },
                            { "deviceStatus", deviceRecord.Status.ToString() },
                            { "agentVersion", deviceRecord.AgentVersion }
                        }
                    };
                }
                finally
                {
                    _cacheLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando dispositivo {DeviceId} del tenant {TenantId}", 
                    request.DeviceId, request.TenantId);
                
                return new DeviceRegistrationResult
                {
                    Success = false,
                    DeviceId = request.DeviceId,
                    TenantId = request.TenantId,
                    ErrorMessage = ex.Message,
                    Timestamp = DateTime.UtcNow
                };
            }
        }
        
        /// <summary>
        /// Obtiene información de un dispositivo
        /// </summary>
        public async Task<DeviceRecord> GetDeviceAsync(
            string deviceId, 
            string tenantId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("DeviceId and TenantId are required");
            
            try
            {
                // 1. Intentar obtener del cache primero
                var cacheKey = $"{tenantId}:{deviceId}";
                if (_deviceCache.TryGetValue(cacheKey, out var cachedDevice))
                {
                    // Verificar si el cache está fresco
                    if (cachedDevice.LastSeen > DateTime.UtcNow.AddMinutes(-CACHE_EXPIRY_MINUTES))
                    {
                        _logger.LogDebug("Dispositivo obtenido del cache: {DeviceId}", deviceId);
                        return cachedDevice;
                    }
                }
                
                // 2. Buscar en base de datos
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                            Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                var device = await _devicesCollection
                    .Find(filter)
                    .FirstOrDefaultAsync(cancellationToken);
                
                if (device == null)
                {
                    _logger.LogDebug("Dispositivo no encontrado: {DeviceId} del tenant {TenantId}", 
                        deviceId, tenantId);
                    return null;
                }
                
                // 3. Actualizar cache
                _deviceCache[cacheKey] = device;
                _lastSeenCache[cacheKey] = DateTime.UtcNow;
                
                // 4. Enriquecer con información del grupo si aplica
                if (!string.IsNullOrEmpty(device.GroupId))
                {
                    await EnrichWithGroupInfoAsync(device, cancellationToken);
                }
                
                _logger.LogDebug("Dispositivo obtenido de base de datos: {DeviceId}", deviceId);
                
                return device;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo dispositivo {DeviceId} del tenant {TenantId}", 
                    deviceId, tenantId);
                throw;
            }
        }
        
        /// <summary>
        /// Verifica si un dispositivo pertenece a un tenant
        /// </summary>
        public async Task<bool> DeviceBelongsToTenantAsync(
            string deviceId, 
            string tenantId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(tenantId))
                return false;
            
            try
            {
                // Verificar cache primero
                var cacheKey = $"{tenantId}:{deviceId}";
                if (_deviceCache.ContainsKey(cacheKey))
                {
                    return true;
                }
                
                // Verificar en base de datos
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                            Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                var count = await _devicesCollection
                    .CountDocumentsAsync(filter, cancellationToken: cancellationToken);
                
                return count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verificando pertenencia de dispositivo {DeviceId} al tenant {TenantId}", 
                    deviceId, tenantId);
                return false;
            }
        }
        
        /// <summary>
        /// Actualiza la última actividad de un dispositivo
        /// </summary>
        public async Task<bool> UpdateLastActivityAsync(
            string deviceId, 
            DateTime lastActivity,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId))
                return false;
            
            try
            {
                // Actualizar en base de datos
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId);
                var update = Builders<DeviceRecord>.Update
                    .Set(d => d.LastSeen, lastActivity)
                    .Set(d => d.UpdatedAt, DateTime.UtcNow);
                
                var result = await _devicesCollection.UpdateOneAsync(
                    filter, update, cancellationToken: cancellationToken);
                
                if (result.ModifiedCount > 0)
                {
                    // Actualizar cache
                    var device = await GetDeviceByIdAsync(deviceId, cancellationToken);
                    if (device != null)
                    {
                        var cacheKey = $"{device.TenantId}:{deviceId}";
                        _lastSeenCache[cacheKey] = lastActivity;
                        
                        device.LastSeen = lastActivity;
                        _deviceCache[cacheKey] = device;
                    }
                    
                    _logger.LogDebug("Actividad actualizada para dispositivo {DeviceId}: {LastActivity}", 
                        deviceId, lastActivity);
                    
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando actividad del dispositivo {DeviceId}", deviceId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene dispositivos por tenant
        /// </summary>
        public async Task<List<DeviceRecord>> GetDevicesByTenantAsync(
            string tenantId,
            int skip = 0,
            int limit = 100,
            DeviceStatus? status = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("TenantId is required");
            
            try
            {
                // Construir filtro
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                if (status.HasValue)
                {
                    filter &= Builders<DeviceRecord>.Filter.Eq(d => d.Status, status.Value);
                }
                
                // Obtener dispositivos
                var devices = await _devicesCollection
                    .Find(filter)
                    .SortByDescending(d => d.LastSeen)
                    .Skip(skip)
                    .Limit(limit)
                    .ToListAsync(cancellationToken);
                
                // Enriquecer con información de grupos
                await EnrichDevicesWithGroupInfoAsync(devices, cancellationToken);
                
                _logger.LogDebug("Obtenidos {Count} dispositivos del tenant {TenantId}", 
                    devices.Count, tenantId);
                
                return devices;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo dispositivos del tenant {TenantId}", tenantId);
                throw;
            }
        }
        
        /// <summary>
        /// Busca dispositivos por criterios
        /// </summary>
        public async Task<List<DeviceRecord>> SearchDevicesAsync(
            DeviceSearchCriteria criteria,
            CancellationToken cancellationToken = default)
        {
            if (criteria == null)
                throw new ArgumentNullException(nameof(criteria));
            
            try
            {
                var filter = BuildFilterFromCriteria(criteria);
                
                var devices = await _devicesCollection
                    .Find(filter)
                    .SortByDescending(d => d.LastSeen)
                    .Limit(criteria.MaxResults ?? 100)
                    .ToListAsync(cancellationToken);
                
                // Enriquecer con información de grupos
                await EnrichDevicesWithGroupInfoAsync(devices, cancellationToken);
                
                _logger.LogDebug("Búsqueda de dispositivos retornó {Count} resultados", devices.Count);
                
                return devices;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error buscando dispositivos");
                throw;
            }
        }
        
        /// <summary>
        /// Cambia el estado de un dispositivo
        /// </summary>
        public async Task<bool> UpdateDeviceStatusAsync(
            string deviceId,
            string tenantId,
            DeviceStatus newStatus,
            string reason = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(tenantId))
                return false;
            
            try
            {
                await _cacheLock.WaitAsync(cancellationToken);
                
                try
                {
                    // Obtener dispositivo actual
                    var device = await GetDeviceAsync(deviceId, tenantId, cancellationToken);
                    if (device == null)
                    {
                        _logger.LogWarning("Dispositivo no encontrado para cambio de estado: {DeviceId}", deviceId);
                        return false;
                    }
                    
                    var oldStatus = device.Status;
                    
                    // Actualizar en base de datos
                    var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                                Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                    
                    var update = Builders<DeviceRecord>.Update
                        .Set(d => d.Status, newStatus)
                        .Set(d => d.UpdatedAt, DateTime.UtcNow);
                    
                    if (!string.IsNullOrEmpty(reason))
                    {
                        update = update.Set(d => d.StatusReason, reason);
                    }
                    
                    var result = await _devicesCollection.UpdateOneAsync(
                        filter, update, cancellationToken: cancellationToken);
                    
                    if (result.ModifiedCount > 0)
                    {
                        // Actualizar cache
                        device.Status = newStatus;
                        device.StatusReason = reason;
                        device.UpdatedAt = DateTime.UtcNow;
                        
                        var cacheKey = $"{tenantId}:{deviceId}";
                        _deviceCache[cacheKey] = device;
                        
                        // Registrar evento de cambio de estado
                        await RecordDeviceActivityAsync(device, 
                            $"STATUS_CHANGE:{oldStatus}->{newStatus}", 
                            cancellationToken,
                            new Dictionary<string, object>
                            {
                                { "oldStatus", oldStatus.ToString() },
                                { "newStatus", newStatus.ToString() },
                                { "reason", reason }
                            });
                        
                        _logger.LogInformation("Estado cambiado para dispositivo {DeviceId}: {OldStatus} -> {NewStatus}", 
                            deviceId, oldStatus, newStatus);
                        
                        return true;
                    }
                    
                    return false;
                }
                finally
                {
                    _cacheLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cambiando estado del dispositivo {DeviceId}", deviceId);
                return false;
            }
        }
        
        /// <summary>
        /// Asigna un dispositivo a un grupo
        /// </summary>
        public async Task<bool> AssignDeviceToGroupAsync(
            string deviceId,
            string tenantId,
            string groupId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(tenantId))
                return false;
            
            try
            {
                // Verificar que el grupo exista
                var group = await GetGroupAsync(groupId, tenantId, cancellationToken);
                if (group == null)
                {
                    _logger.LogWarning("Grupo no encontrado: {GroupId} del tenant {TenantId}", groupId, tenantId);
                    return false;
                }
                
                await _cacheLock.WaitAsync(cancellationToken);
                
                try
                {
                    // Actualizar en base de datos
                    var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                                Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                    
                    var update = Builders<DeviceRecord>.Update
                        .Set(d => d.GroupId, groupId)
                        .Set(d => d.UpdatedAt, DateTime.UtcNow);
                    
                    var result = await _devicesCollection.UpdateOneAsync(
                        filter, update, cancellationToken: cancellationToken);
                    
                    if (result.ModifiedCount > 0)
                    {
                        // Actualizar cache
                        var device = await GetDeviceAsync(deviceId, tenantId, cancellationToken);
                        if (device != null)
                        {
                            device.GroupId = groupId;
                            device.UpdatedAt = DateTime.UtcNow;
                            
                            var cacheKey = $"{tenantId}:{deviceId}";
                            _deviceCache[cacheKey] = device;
                            
                            // Enriquecer con información del grupo
                            await EnrichWithGroupInfoAsync(device, cancellationToken);
                        }
                        
                        // Actualizar contador del grupo
                        await UpdateGroupDeviceCountAsync(groupId, tenantId, cancellationToken);
                        
                        // Registrar evento
                        await RecordDeviceActivityAsync(device, 
                            "GROUP_ASSIGNMENT", 
                            cancellationToken,
                            new Dictionary<string, object>
                            {
                                { "groupId", groupId },
                                { "groupName", group.Name }
                            });
                        
                        _logger.LogInformation("Dispositivo {DeviceId} asignado al grupo {GroupId}", 
                            deviceId, groupId);
                        
                        return true;
                    }
                    
                    return false;
                }
                finally
                {
                    _cacheLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error asignando dispositivo {DeviceId} al grupo {GroupId}", 
                    deviceId, groupId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas de dispositivos por tenant
        /// </summary>
        public async Task<DeviceStatistics> GetDeviceStatisticsAsync(
            string tenantId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("TenantId is required");
            
            try
            {
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                var statistics = new DeviceStatistics
                {
                    TenantId = tenantId,
                    Timestamp = DateTime.UtcNow
                };
                
                // Contar por estado
                var statusCounts = await _devicesCollection
                    .Aggregate(cancellationToken)
                    .Match(filter)
                    .Group(d => d.Status, g => new 
                    { 
                        Status = g.Key, 
                        Count = g.Count() 
                    })
                    .ToListAsync(cancellationToken);
                
                foreach (var statusCount in statusCounts)
                {
                    switch (statusCount.Status)
                    {
                        case DeviceStatus.Online:
                            statistics.OnlineCount = statusCount.Count;
                            break;
                        case DeviceStatus.Offline:
                            statistics.OfflineCount = statusCount.Count;
                            break;
                        case DeviceStatus.Degraded:
                            statistics.DegradedCount = statusCount.Count;
                            break;
                        case DeviceStatus.Quarantined:
                            statistics.QuarantinedCount = statusCount.Count;
                            break;
                    }
                }
                
                statistics.TotalCount = statistics.OnlineCount + statistics.OfflineCount + 
                                       statistics.DegradedCount + statistics.QuarantinedCount;
                
                // Obtener dispositivos recientemente activos (última hora)
                var recentlyActiveFilter = filter & 
                    Builders<DeviceRecord>.Filter.Gte(d => d.LastSeen, 
                        DateTime.UtcNow.AddHours(-1));
                statistics.RecentlyActiveCount = await _devicesCollection
                    .CountDocumentsAsync(recentlyActiveFilter, cancellationToken: cancellationToken);
                
                // Obtener distribución por sistema operativo
                var osDistribution = await _devicesCollection
                    .Aggregate(cancellationToken)
                    .Match(filter)
                    .Group(d => d.OsType, g => new 
                    { 
                        OsType = g.Key, 
                        Count = g.Count() 
                    })
                    .ToListAsync(cancellationToken);
                
                statistics.OsDistribution = osDistribution
                    .ToDictionary(x => x.OsType ?? "Unknown", x => x.Count);
                
                // Obtener distribución por versión de agente
                var agentDistribution = await _devicesCollection
                    .Aggregate(cancellationToken)
                    .Match(filter)
                    .Group(d => d.AgentVersion, g => new 
                    { 
                        AgentVersion = g.Key, 
                        Count = g.Count() 
                    })
                    .ToListAsync(cancellationToken);
                
                statistics.AgentDistribution = agentDistribution
                    .Where(x => !string.IsNullOrEmpty(x.AgentVersion))
                    .ToDictionary(x => x.AgentVersion, x => x.Count);
                
                _logger.LogDebug("Estadísticas obtenidas para tenant {TenantId}: {Total} dispositivos", 
                    tenantId, statistics.TotalCount);
                
                return statistics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo estadísticas del tenant {TenantId}", tenantId);
                throw;
            }
        }
        
        /// <summary>
        /// Crea o actualiza un grupo de dispositivos
        /// </summary>
        public async Task<DeviceGroup> CreateOrUpdateGroupAsync(
            DeviceGroup group,
            CancellationToken cancellationToken = default)
        {
            if (group == null)
                throw new ArgumentNullException(nameof(group));
            
            try
            {
                var filter = Builders<DeviceGroup>.Filter.Eq(g => g.GroupId, group.GroupId) &
                            Builders<DeviceGroup>.Filter.Eq(g => g.TenantId, group.TenantId);
                
                var existingGroup = await _groupsCollection
                    .Find(filter)
                    .FirstOrDefaultAsync(cancellationToken);
                
                if (existingGroup != null)
                {
                    // Actualizar grupo existente
                    group.CreatedAt = existingGroup.CreatedAt;
                    group.UpdatedAt = DateTime.UtcNow;
                    
                    var update = Builders<DeviceGroup>.Update
                        .Set(g => g.Name, group.Name)
                        .Set(g => g.Description, group.Description)
                        .Set(g => g.Tags, group.Tags)
                        .Set(g => g.Policies, group.Policies)
                        .Set(g => g.UpdatedAt, group.UpdatedAt);
                    
                    await _groupsCollection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);
                    
                    _logger.LogInformation("Grupo actualizado: {GroupId} del tenant {TenantId}", 
                        group.GroupId, group.TenantId);
                }
                else
                {
                    // Crear nuevo grupo
                    group.CreatedAt = DateTime.UtcNow;
                    group.UpdatedAt = DateTime.UtcNow;
                    group.DeviceCount = 0;
                    
                    await _groupsCollection.InsertOneAsync(group, cancellationToken: cancellationToken);
                    
                    _logger.LogInformation("Grupo creado: {GroupId} del tenant {TenantId}", 
                        group.GroupId, group.TenantId);
                }
                
                // Actualizar cache
                var cacheKey = $"{group.TenantId}:{group.GroupId}";
                _groupCache[cacheKey] = group;
                
                return group;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando/actualizando grupo {GroupId}", group.GroupId);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene un grupo de dispositivos
        /// </summary>
        public async Task<DeviceGroup> GetGroupAsync(
            string groupId,
            string tenantId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(groupId) || string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("GroupId and TenantId are required");
            
            try
            {
                // Verificar cache
                var cacheKey = $"{tenantId}:{groupId}";
                if (_groupCache.TryGetValue(cacheKey, out var cachedGroup))
                {
                    return cachedGroup;
                }
                
                // Buscar en base de datos
                var filter = Builders<DeviceGroup>.Filter.Eq(g => g.GroupId, groupId) &
                            Builders<DeviceGroup>.Filter.Eq(g => g.TenantId, tenantId);
                
                var group = await _groupsCollection
                    .Find(filter)
                    .FirstOrDefaultAsync(cancellationToken);
                
                if (group != null)
                {
                    // Actualizar cache
                    _groupCache[cacheKey] = group;
                }
                
                return group;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo grupo {GroupId} del tenant {TenantId}", 
                    groupId, tenantId);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene dispositivos por grupo
        /// </summary>
        public async Task<List<DeviceRecord>> GetDevicesByGroupAsync(
            string groupId,
            string tenantId,
            int skip = 0,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(groupId) || string.IsNullOrEmpty(tenantId))
                throw new ArgumentException("GroupId and TenantId are required");
            
            try
            {
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.GroupId, groupId) &
                            Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                var devices = await _devicesCollection
                    .Find(filter)
                    .SortByDescending(d => d.LastSeen)
                    .Skip(skip)
                    .Limit(limit)
                    .ToListAsync(cancellationToken);
                
                // Enriquecer con información del grupo
                if (devices.Any())
                {
                    var group = await GetGroupAsync(groupId, tenantId, cancellationToken);
                    if (group != null)
                    {
                        foreach (var device in devices)
                        {
                            device.GroupInfo = group;
                        }
                    }
                }
                
                return devices;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo dispositivos del grupo {GroupId}", groupId);
                throw;
            }
        }
        
        /// <summary>
        /// Elimina un dispositivo
        /// </summary>
        public async Task<bool> DeleteDeviceAsync(
            string deviceId,
            string tenantId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(tenantId))
                return false;
            
            try
            {
                await _cacheLock.WaitAsync(cancellationToken);
                
                try
                {
                    // Obtener dispositivo para registrar evento
                    var device = await GetDeviceAsync(deviceId, tenantId, cancellationToken);
                    
                    // Eliminar de base de datos
                    var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                                Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                    
                    var result = await _devicesCollection.DeleteOneAsync(filter, cancellationToken);
                    
                    if (result.DeletedCount > 0)
                    {
                        // Eliminar de caches
                        var cacheKey = $"{tenantId}:{deviceId}";
                        _deviceCache.TryRemove(cacheKey, out _);
                        _lastSeenCache.TryRemove(cacheKey, out _);
                        
                        // Actualizar cache de tenant
                        if (_tenantDevicesCache.TryGetValue(tenantId, out var deviceIds))
                        {
                            deviceIds.Remove(deviceId);
                        }
                        
                        // Actualizar contador de grupo si aplica
                        if (device != null && !string.IsNullOrEmpty(device.GroupId))
                        {
                            await UpdateGroupDeviceCountAsync(device.GroupId, tenantId, cancellationToken);
                        }
                        
                        // Registrar evento de eliminación
                        if (device != null)
                        {
                            await RecordDeviceActivityAsync(device, "DEVICE_DELETED", cancellationToken);
                        }
                        
                        _logger.LogInformation("Dispositivo eliminado: {DeviceId} del tenant {TenantId}", 
                            deviceId, tenantId);
                        
                        return true;
                    }
                    
                    return false;
                }
                finally
                {
                    _cacheLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error eliminando dispositivo {DeviceId}", deviceId);
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del registry
        /// </summary>
        public DeviceRegistryStats GetStats()
        {
            return new DeviceRegistryStats
            {
                Timestamp = DateTime.UtcNow,
                DeviceCacheCount = _deviceCache.Count,
                GroupCacheCount = _groupCache.Count,
                LastSeenCacheCount = _lastSeenCache.Count,
                TenantDevicesCacheCount = _tenantDevicesCache.Count,
                EstimatedMemoryUsageMB = CalculateMemoryUsage(),
                CacheHitRate = CalculateCacheHitRate()
            };
        }
        
        #region Métodos privados
        
        private async Task<DeviceRecord> GetDeviceFromCacheOrDatabaseAsync(
            string deviceId, 
            string tenantId,
            CancellationToken cancellationToken)
        {
            var cacheKey = $"{tenantId}:{deviceId}";
            
            // Intentar del cache primero
            if (_deviceCache.TryGetValue(cacheKey, out var cachedDevice))
            {
                return cachedDevice;
            }
            
            // Buscar en base de datos
            var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId) &
                        Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
            
            return await _devicesCollection
                .Find(filter)
                .FirstOrDefaultAsync(cancellationToken);
        }
        
        private DeviceRecord CreateNewDevice(DeviceRegistrationRequest request)
        {
            var now = DateTime.UtcNow;
            
            return new DeviceRecord
            {
                DeviceId = request.DeviceId,
                TenantId = request.TenantId,
                DeviceName = request.DeviceName,
                DeviceType = request.DeviceType,
                OsType = request.OsType,
                OsVersion = request.OsVersion,
                AgentVersion = request.AgentVersion,
                IpAddress = request.IpAddress,
                MacAddress = request.MacAddress,
                GroupId = request.GroupId,
                Status = DeviceStatus.Online,
                CreatedAt = now,
                UpdatedAt = now,
                LastSeen = now,
                Metadata = request.Metadata ?? new Dictionary<string, object>(),
                Tags = request.Tags ?? new List<string>()
            };
        }
        
        private DeviceRecord UpdateExistingDevice(DeviceRecord existing, DeviceRegistrationRequest request)
        {
            existing.DeviceName = request.DeviceName ?? existing.DeviceName;
            existing.DeviceType = request.DeviceType ?? existing.DeviceType;
            existing.OsType = request.OsType ?? existing.OsType;
            existing.OsVersion = request.OsVersion ?? existing.OsVersion;
            existing.AgentVersion = request.AgentVersion ?? existing.AgentVersion;
            existing.IpAddress = request.IpAddress ?? existing.IpAddress;
            existing.MacAddress = request.MacAddress ?? existing.MacAddress;
            existing.LastSeen = DateTime.UtcNow;
            existing.UpdatedAt = DateTime.UtcNow;
            
            // Actualizar metadata
            if (request.Metadata != null)
            {
                foreach (var kvp in request.Metadata)
                {
                    existing.Metadata[kvp.Key] = kvp.Value;
                }
            }
            
            // Actualizar tags
            if (request.Tags != null)
            {
                existing.Tags = request.Tags;
            }
            
            // Si el dispositivo estaba offline, marcarlo como online
            if (existing.Status == DeviceStatus.Offline)
            {
                existing.Status = DeviceStatus.Online;
                existing.StatusReason = "Device reconnected";
            }
            
            return existing;
        }
        
        private async Task InsertDeviceIntoDatabaseAsync(DeviceRecord device, CancellationToken cancellationToken)
        {
            await _devicesCollection.InsertOneAsync(device, cancellationToken: cancellationToken);
        }
        
        private async Task UpdateDeviceInDatabaseAsync(DeviceRecord device, CancellationToken cancellationToken)
        {
            var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, device.DeviceId) &
                        Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, device.TenantId);
            
            var update = Builders<DeviceRecord>.Update
                .Set(d => d.DeviceName, device.DeviceName)
                .Set(d => d.DeviceType, device.DeviceType)
                .Set(d => d.OsType, device.OsType)
                .Set(d => d.OsVersion, device.OsVersion)
                .Set(d => d.AgentVersion, device.AgentVersion)
                .Set(d => d.IpAddress, device.IpAddress)
                .Set(d => d.MacAddress, device.MacAddress)
                .Set(d => d.Status, device.Status)
                .Set(d => d.LastSeen, device.LastSeen)
                .Set(d => d.UpdatedAt, device.UpdatedAt)
                .Set(d => d.Metadata, device.Metadata)
                .Set(d => d.Tags, device.Tags);
            
            await _devicesCollection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);
        }
        
        private void UpdateDeviceCache(DeviceRecord device)
        {
            var cacheKey = $"{device.TenantId}:{device.DeviceId}";
            _deviceCache[cacheKey] = device;
            _lastSeenCache[cacheKey] = device.LastSeen;
            
            // Limitar tamaño del cache
            if (_deviceCache.Count > MAX_CACHE_SIZE)
            {
                var oldest = _lastSeenCache.OrderBy(kv => kv.Value).FirstOrDefault();
                if (!string.IsNullOrEmpty(oldest.Key))
                {
                    _deviceCache.TryRemove(oldest.Key, out _);
                    _lastSeenCache.TryRemove(oldest.Key, out _);
                }
            }
        }
        
        private void UpdateTenantDevicesCache(string tenantId, string deviceId)
        {
            _tenantDevicesCache.AddOrUpdate(tenantId,
                new List<string> { deviceId },
                (key, existingList) =>
                {
                    if (!existingList.Contains(deviceId))
                    {
                        existingList.Add(deviceId);
                    }
                    return existingList;
                });
        }
        
        private async Task EnrichWithGroupInfoAsync(DeviceRecord device, CancellationToken cancellationToken)
        {
            if (!string.IsNullOrEmpty(device.GroupId))
            {
                var group = await GetGroupAsync(device.GroupId, device.TenantId, cancellationToken);
                if (group != null)
                {
                    device.GroupInfo = group;
                }
            }
        }
        
        private async Task EnrichDevicesWithGroupInfoAsync(List<DeviceRecord> devices, CancellationToken cancellationToken)
        {
            // Agrupar por grupo para optimizar queries
            var devicesByGroup = devices
                .Where(d => !string.IsNullOrEmpty(d.GroupId))
                .GroupBy(d => new { d.GroupId, d.TenantId });
            
            foreach (var group in devicesByGroup)
            {
                var groupInfo = await GetGroupAsync(group.Key.GroupId, group.Key.TenantId, cancellationToken);
                if (groupInfo != null)
                {
                    foreach (var device in group)
                    {
                        device.GroupInfo = groupInfo;
                    }
                }
            }
        }
        
        private async Task RecordDeviceActivityAsync(
            DeviceRecord device, 
            string activityType,
            CancellationToken cancellationToken,
            Dictionary<string, object> additionalData = null)
        {
            try
            {
                var activity = new DeviceActivity
                {
                    ActivityId = Guid.NewGuid().ToString(),
                    DeviceId = device.DeviceId,
                    TenantId = device.TenantId,
                    ActivityType = activityType,
                    Timestamp = DateTime.UtcNow,
                    DeviceStatus = device.Status,
                    DeviceIp = device.IpAddress,
                    Data = new Dictionary<string, object>
                    {
                        { "deviceName", device.DeviceName },
                        { "osType", device.OsType },
                        { "agentVersion", device.AgentVersion },
                        { "groupId", device.GroupId }
                    }
                };
                
                if (additionalData != null)
                {
                    foreach (var kvp in additionalData)
                    {
                        activity.Data[kvp.Key] = kvp.Value;
                    }
                }
                
                // Aquí se insertaría en una colección de actividades
                // Por ahora solo log
                _logger.LogDebug("Actividad registrada: {DeviceId} - {ActivityType}", 
                    device.DeviceId, activityType);
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando actividad del dispositivo {DeviceId}", device.DeviceId);
            }
        }
        
        private async Task UpdateGroupDeviceCountAsync(
            string groupId, 
            string tenantId,
            CancellationToken cancellationToken)
        {
            try
            {
                var filter = Builders<DeviceRecord>.Filter.Eq(d => d.GroupId, groupId) &
                            Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, tenantId);
                
                var deviceCount = await _devicesCollection
                    .CountDocumentsAsync(filter, cancellationToken: cancellationToken);
                
                var groupFilter = Builders<DeviceGroup>.Filter.Eq(g => g.GroupId, groupId) &
                                 Builders<DeviceGroup>.Filter.Eq(g => g.TenantId, tenantId);
                
                var update = Builders<DeviceGroup>.Update.Set(g => g.DeviceCount, deviceCount);
                
                await _groupsCollection.UpdateOneAsync(groupFilter, update, cancellationToken: cancellationToken);
                
                // Actualizar cache
                var cacheKey = $"{tenantId}:{groupId}";
                if (_groupCache.TryGetValue(cacheKey, out var group))
                {
                    group.DeviceCount = deviceCount;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando contador del grupo {GroupId}", groupId);
            }
        }
        
        private FilterDefinition<DeviceRecord> BuildFilterFromCriteria(DeviceSearchCriteria criteria)
        {
            var filters = new List<FilterDefinition<DeviceRecord>>();
            
            if (!string.IsNullOrEmpty(criteria.TenantId))
            {
                filters.Add(Builders<DeviceRecord>.Filter.Eq(d => d.TenantId, criteria.TenantId));
            }
            
            if (!string.IsNullOrEmpty(criteria.DeviceId))
            {
                filters.Add(Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, criteria.DeviceId));
            }
            
            if (!string.IsNullOrEmpty(criteria.DeviceName))
            {
                filters.Add(Builders<DeviceRecord>.Filter.Regex(d => d.DeviceName, 
                    new MongoDB.Bson.BsonRegularExpression(criteria.DeviceName, "i")));
            }
            
            if (!string.IsNullOrEmpty(criteria.GroupId))
            {
                filters.Add(Builders<DeviceRecord>.Filter.Eq(d => d.GroupId, criteria.GroupId));
            }
            
            if (criteria.Status.HasValue)
            {
                filters.Add(Builders<DeviceRecord>.Filter.Eq(d => d.Status, criteria.Status.Value));
            }
            
            if (criteria.OsType != null && criteria.OsType.Any())
            {
                filters.Add(Builders<DeviceRecord>.Filter.In(d => d.OsType, criteria.OsType));
            }
            
            if (!string.IsNullOrEmpty(criteria.AgentVersion))
            {
                filters.Add(Builders<DeviceRecord>.Filter.Eq(d => d.AgentVersion, criteria.AgentVersion));
            }
            
            if (criteria.LastSeenAfter.HasValue)
            {
                filters.Add(Builders<DeviceRecord>.Filter.Gte(d => d.LastSeen, criteria.LastSeenAfter.Value));
            }
            
            if (criteria.LastSeenBefore.HasValue)
            {
                filters.Add(Builders<DeviceRecord>.Filter.Lte(d => d.LastSeen, criteria.LastSeenBefore.Value));
            }
            
            if (criteria.Tags != null && criteria.Tags.Any())
            {
                filters.Add(Builders<DeviceRecord>.Filter.All(d => d.Tags, criteria.Tags));
            }
            
            if (filters.Count == 0)
            {
                return Builders<DeviceRecord>.Filter.Empty;
            }
            
            return Builders<DeviceRecord>.Filter.And(filters);
        }
        
        private async Task<DeviceRecord> GetDeviceByIdAsync(string deviceId, CancellationToken cancellationToken)
        {
            var filter = Builders<DeviceRecord>.Filter.Eq(d => d.DeviceId, deviceId);
            return await _devicesCollection
                .Find(filter)
                .FirstOrDefaultAsync(cancellationToken);
        }
        
        private void CleanupCache(object state)
        {
            try
            {
                var cutoff = DateTime.UtcNow.AddMinutes(-CACHE_EXPIRY_MINUTES * 2);
                var removedCount = 0;
                
                // Limpiar dispositivos inactivos del cache
                var inactiveDevices = _lastSeenCache
                    .Where(kv => kv.Value < cutoff)
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var key in inactiveDevices)
                {
                    _deviceCache.TryRemove(key, out _);
                    _lastSeenCache.TryRemove(key, out _);
                    removedCount++;
                }
                
                // Limpiar grupos antiguos del cache
                // (Los grupos se mantienen más tiempo)
                
                _logger.LogDebug("Cache limpiado: {Count} dispositivos removidos", removedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error limpiando cache");
            }
        }
        
        private async void SyncCacheWithDatabase(object state)
        {
            if (!_isRunning)
                return;
            
            try
            {
                // Sincronizar dispositivos que han sido actualizados recientemente
                var cutoff = DateTime.UtcNow.AddMinutes(-CACHE_EXPIRY_MINUTES);
                
                var devicesToSync = _deviceCache
                    .Where(kv => kv.Value.UpdatedAt < cutoff)
                    .Select(kv => kv.Value.DeviceId)
                    .Take(100)
                    .ToList();
                
                if (devicesToSync.Any())
                {
                    await SyncDevicesAsync(devicesToSync);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sincronizando cache con base de datos");
            }
        }
        
        private async Task SyncDevicesAsync(List<string> deviceIds)
        {
            try
            {
                var filter = Builders<DeviceRecord>.Filter.In(d => d.DeviceId, deviceIds);
                var updatedDevices = await _devicesCollection
                    .Find(filter)
                    .ToListAsync();
                
                foreach (var device in updatedDevices)
                {
                    var cacheKey = $"{device.TenantId}:{device.DeviceId}";
                    _deviceCache[cacheKey] = device;
                    _lastSeenCache[cacheKey] = device.LastSeen;
                }
                
                _logger.LogDebug("Cache sincronizado: {Count} dispositivos actualizados", updatedDevices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sincronizando dispositivos");
            }
        }
        
        private double CalculateMemoryUsage()
        {
            // Estimación simple
            var totalEntries = _deviceCache.Count + _groupCache.Count + 
                             _lastSeenCache.Count + _tenantDevicesCache.Count;
            return totalEntries * 0.1; // ~100KB por entrada en promedio
        }
        
        private double CalculateCacheHitRate()
        {
            // En producción, implementar contadores reales
            var totalRequests = 1000; // Placeholder
            var cacheHits = 850; // Placeholder
            return totalRequests > 0 ? (double)cacheHits / totalRequests : 0.85;
        }
        
        #endregion
    }
    
    #region Modelos de datos
    
    public interface IDeviceRegistry
    {
        Task<DeviceRegistrationResult> RegisterDeviceAsync(DeviceRegistrationRequest request, CancellationToken cancellationToken = default);
        Task<DeviceRecord> GetDeviceAsync(string deviceId, string tenantId, CancellationToken cancellationToken = default);
        Task<bool> DeviceBelongsToTenantAsync(string deviceId, string tenantId, CancellationToken cancellationToken = default);
        Task<bool> UpdateLastActivityAsync(string deviceId, DateTime lastActivity, CancellationToken cancellationToken = default);
        Task<List<DeviceRecord>> GetDevicesByTenantAsync(string tenantId, int skip = 0, int limit = 100, DeviceStatus? status = null, CancellationToken cancellationToken = default);
        Task<List<DeviceRecord>> SearchDevicesAsync(DeviceSearchCriteria criteria, CancellationToken cancellationToken = default);
        Task<bool> UpdateDeviceStatusAsync(string deviceId, string tenantId, DeviceStatus newStatus, string reason = null, CancellationToken cancellationToken = default);
        Task<bool> AssignDeviceToGroupAsync(string deviceId, string tenantId, string groupId, CancellationToken cancellationToken = default);
        Task<DeviceStatistics> GetDeviceStatisticsAsync(string tenantId, CancellationToken cancellationToken = default);
        Task<DeviceGroup> CreateOrUpdateGroupAsync(DeviceGroup group, CancellationToken cancellationToken = default);
        Task<DeviceGroup> GetGroupAsync(string groupId, string tenantId, CancellationToken cancellationToken = default);
        Task<List<DeviceRecord>> GetDevicesByGroupAsync(string groupId, string tenantId, int skip = 0, int limit = 100, CancellationToken cancellationToken = default);
        Task<bool> DeleteDeviceAsync(string deviceId, string tenantId, CancellationToken cancellationToken = default);
        DeviceRegistryStats GetStats();
    }
    
    public class DeviceRecord
    {
        [JsonProperty("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        [JsonProperty("deviceId")]
        public string DeviceId { get; set; }
        
        [JsonProperty("tenantId")]
        public string TenantId { get; set; }
        
        [JsonProperty("deviceName")]
        public string DeviceName { get; set; }
        
        [JsonProperty("deviceType")]
        public string DeviceType { get; set; }
        
        [JsonProperty("osType")]
        public string OsType { get; set; }
        
        [JsonProperty("osVersion")]
        public string OsVersion { get; set; }
        
        [JsonProperty("agentVersion")]
        public string AgentVersion { get; set; }
        
        [JsonProperty("ipAddress")]
        public string IpAddress { get; set; }
        
        [JsonProperty("macAddress")]
        public string MacAddress { get; set; }
        
        [JsonProperty("groupId")]
        public string GroupId { get; set; }
        
        [JsonProperty("status")]
        public DeviceStatus Status { get; set; }
        
        [JsonProperty("statusReason")]
        public string StatusReason { get; set; }
        
        [JsonProperty("createdAt")]
        public DateTime CreatedAt { get; set; }
        
        [JsonProperty("updatedAt")]
        public DateTime UpdatedAt { get; set; }
        
        [JsonProperty("lastSeen")]
        public DateTime LastSeen { get; set; }
        
        [JsonProperty("metadata")]
        public Dictionary<string, object> Metadata { get; set; }
        
        [JsonProperty("tags")]
        public List<string> Tags { get; set; }
        
        [JsonProperty("isQuarantined")]
        public bool IsQuarantined { get; set; }
        
        [JsonProperty("quarantineReason")]
        public string QuarantineReason { get; set; }
        
        [JsonProperty("quarantinedAt")]
        public DateTime? QuarantinedAt { get; set; }
        
        [JsonIgnore]
        public DeviceGroup GroupInfo { get; set; }
        
        public DeviceRecord()
        {
            Metadata = new Dictionary<string, object>();
            Tags = new List<string>();
            Status = DeviceStatus.Offline;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            LastSeen = DateTime.UtcNow;
        }
    }
    
    public enum DeviceStatus
    {
        Online,
        Offline,
        Degraded,
        Quarantined,
        Maintenance,
        Decommissioned
    }
    
    public class DeviceRegistrationRequest
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string OsType { get; set; }
        public string OsVersion { get; set; }
        public string AgentVersion { get; set; }
        public string IpAddress { get; set; }
        public string MacAddress { get; set; }
        public string GroupId { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public List<string> Tags { get; set; }
        
        public DeviceRegistrationRequest()
        {
            Metadata = new Dictionary<string, object>();
            Tags = new List<string>();
        }
    }
    
    public class DeviceRegistrationResult
    {
        public bool Success { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public bool IsNewRegistration { get; set; }
        public DateTime Timestamp { get; set; }
        public string ErrorMessage { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public DeviceRegistrationResult()
        {
            Metadata = new Dictionary<string, object>();
            Timestamp = DateTime.UtcNow;
        }
    }
    
    public class DeviceSearchCriteria
    {
        public string TenantId { get; set; }
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        public string GroupId { get; set; }
        public DeviceStatus? Status { get; set; }
        public List<string> OsType { get; set; }
        public string AgentVersion { get; set; }
        public DateTime? LastSeenAfter { get; set; }
        public DateTime? LastSeenBefore { get; set; }
        public List<string> Tags { get; set; }
        public int? MaxResults { get; set; }
        
        public DeviceSearchCriteria()
        {
            OsType = new List<string>();
            Tags = new List<string>();
        }
    }
    
    public class DeviceStatistics
    {
        public string TenantId { get; set; }
        public DateTime Timestamp { get; set; }
        public int TotalCount { get; set; }
        public int OnlineCount { get; set; }
        public int OfflineCount { get; set; }
        public int DegradedCount { get; set; }
        public int QuarantinedCount { get; set; }
        public int RecentlyActiveCount { get; set; }
        public Dictionary<string, int> OsDistribution { get; set; }
        public Dictionary<string, int> AgentDistribution { get; set; }
        public Dictionary<string, int> GroupDistribution { get; set; }
        
        public DeviceStatistics()
        {
            OsDistribution = new Dictionary<string, int>();
            AgentDistribution = new Dictionary<string, int>();
            GroupDistribution = new Dictionary<string, int>();
            Timestamp = DateTime.UtcNow;
        }
    }
    
    public class DeviceGroup
    {
        [JsonProperty("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        [JsonProperty("groupId")]
        public string GroupId { get; set; }
        
        [JsonProperty("tenantId")]
        public string TenantId { get; set; }
        
        [JsonProperty("name")]
        public string Name { get; set; }
        
        [JsonProperty("description")]
        public string Description { get; set; }
        
        [JsonProperty("tags")]
        public List<string> Tags { get; set; }
        
        [JsonProperty("policies")]
        public List<DevicePolicy> Policies { get; set; }
        
        [JsonProperty("deviceCount")]
        public long DeviceCount { get; set; }
        
        [JsonProperty("createdAt")]
        public DateTime CreatedAt { get; set; }
        
        [JsonProperty("updatedAt")]
        public DateTime UpdatedAt { get; set; }
        
        [JsonProperty("metadata")]
        public Dictionary<string, object> Metadata { get; set; }
        
        public DeviceGroup()
        {
            Tags = new List<string>();
            Policies = new List<DevicePolicy>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class DevicePolicy
    {
        public string PolicyId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public Dictionary<string, object> Settings { get; set; }
        public DateTime AppliedAt { get; set; }
        
        public DevicePolicy()
        {
            Settings = new Dictionary<string, object>();
        }
    }
    
    public class DeviceActivity
    {
        public string ActivityId { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string ActivityType { get; set; }
        public DateTime Timestamp { get; set; }
        public DeviceStatus DeviceStatus { get; set; }
        public string DeviceIp { get; set; }
        public Dictionary<string, object> Data { get; set; }
        
        public DeviceActivity()
        {
            Data = new Dictionary<string, object>();
            Timestamp = DateTime.UtcNow;
        }
    }
    
    public class DeviceRegistryStats
    {
        public DateTime Timestamp { get; set; }
        public int DeviceCacheCount { get; set; }
        public int GroupCacheCount { get; set; }
        public int LastSeenCacheCount { get; set; }
        public int TenantDevicesCacheCount { get; set; }
        public double EstimatedMemoryUsageMB { get; set; }
        public double CacheHitRate { get; set; }
        
        public DeviceRegistryStats()
        {
            Timestamp = DateTime.UtcNow;
        }
    }
    
    #endregion
}