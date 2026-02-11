using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using BWP.Enterprise.Cloud.Storage;

namespace BWP.Enterprise.Cloud.TenantManagement
{
    /// <summary>
    /// Gestor centralizado de tenants (clientes) para sistema multi-tenant
    /// </summary>
    public sealed class TenantManager : ITenantManager
    {
        private readonly ILogger<TenantManager> _logger;
        private readonly ITenantStorage _storage;
        private readonly ConcurrentDictionary<string, TenantInfo> _tenantCache;
        private readonly ConcurrentDictionary<string, TenantConfiguration> _configCache;
        private readonly ConcurrentDictionary<string, TenantUsage> _usageCache;
        private bool _isInitialized;
        private const int CACHE_TTL_MINUTES = 5;

        public TenantManager(
            ILogger<TenantManager> logger,
            ITenantStorage storage)
        {
            _logger = logger;
            _storage = storage;
            _tenantCache = new ConcurrentDictionary<string, TenantInfo>();
            _configCache = new ConcurrentDictionary<string, TenantConfiguration>();
            _usageCache = new ConcurrentDictionary<string, TenantUsage>();
            _isInitialized = false;
        }

        /// <summary>
        /// Inicializa el gestor de tenants
        /// </summary>
        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;

            try
            {
                // Inicializar almacenamiento
                await _storage.InitializeAsync();

                // Cargar tenants activos en caché
                await LoadActiveTenantsIntoCacheAsync();

                // Configurar limpieza periódica de caché
                StartCacheCleanupTimer();

                _isInitialized = true;
                _logger.LogInformation("TenantManager inicializado exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inicializando TenantManager");
                throw;
            }
        }

        /// <summary>
        /// Obtiene información de un tenant por ID
        /// </summary>
        public async Task<TenantInfo> GetTenantAsync(string tenantId)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            // Intentar obtener del caché
            if (_tenantCache.TryGetValue(tenantId, out var cachedTenant))
            {
                if (cachedTenant.IsActive && !IsCacheExpired(cachedTenant))
                {
                    return cachedTenant;
                }
            }

            // Obtener de almacenamiento
            var tenant = await _storage.GetTenantAsync(tenantId);
            if (tenant != null)
            {
                // Actualizar caché
                _tenantCache[tenantId] = tenant;
                return tenant;
            }

            return null;
        }

        /// <summary>
        /// Obtiene configuración de un tenant
        /// </summary>
        public async Task<TenantConfiguration> GetTenantConfigurationAsync(string tenantId)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            // Intentar obtener del caché
            if (_configCache.TryGetValue(tenantId, out var cachedConfig))
            {
                if (!IsConfigCacheExpired(cachedConfig))
                {
                    return cachedConfig;
                }
            }

            // Obtener de almacenamiento
            var config = await _storage.GetTenantConfigurationAsync(tenantId);
            if (config != null)
            {
                // Actualizar caché
                _configCache[tenantId] = config;
                return config;
            }

            // Configuración por defecto si no existe
            return CreateDefaultConfiguration(tenantId);
        }

        /// <summary>
        /// Crea un nuevo tenant
        /// </summary>
        public async Task<TenantCreationResult> CreateTenantAsync(TenantCreationRequest request)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                // Validar request
                var validationResult = ValidateTenantCreationRequest(request);
                if (!validationResult.IsValid)
                {
                    return TenantCreationResult.Invalid(validationResult.Errors);
                }

                // Verificar si tenant ya existe
                var existingTenant = await _storage.GetTenantByExternalIdAsync(request.ExternalId);
                if (existingTenant != null)
                {
                    return TenantCreationResult.Error($"Tenant ya existe con ID: {existingTenant.TenantId}");
                }

                // Crear tenant
                var tenantId = GenerateTenantId();
                var tenantInfo = new TenantInfo
                {
                    TenantId = tenantId,
                    ExternalId = request.ExternalId,
                    Name = request.Name,
                    Description = request.Description,
                    ContactEmail = request.ContactEmail,
                    ContactPhone = request.ContactPhone,
                    CompanyName = request.CompanyName,
                    Industry = request.Industry,
                    Country = request.Country,
                    Timezone = request.Timezone,
                    Language = request.Language,
                    SubscriptionTier = request.SubscriptionTier,
                    MaxDevices = request.MaxDevices,
                    MaxUsers = request.MaxUsers,
                    DataRetentionDays = request.DataRetentionDays,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    Metadata = request.Metadata
                };

                // Crear configuración por defecto
                var defaultConfig = CreateDefaultConfiguration(tenantId);

                // Crear en almacenamiento
                await _storage.CreateTenantAsync(tenantInfo, defaultConfig);

                // Actualizar cachés
                _tenantCache[tenantId] = tenantInfo;
                _configCache[tenantId] = defaultConfig;

                _logger.LogInformation("Tenant creado exitosamente: {TenantId} ({Name})", 
                    tenantId, request.Name);

                return TenantCreationResult.Success(tenantId, tenantInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando tenant");
                return TenantCreationResult.Error($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Actualiza información de un tenant
        /// </summary>
        public async Task<TenantUpdateResult> UpdateTenantAsync(string tenantId, TenantUpdateRequest request)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                // Verificar que tenant exista
                var existingTenant = await GetTenantAsync(tenantId);
                if (existingTenant == null)
                {
                    return TenantUpdateResult.Error($"Tenant no encontrado: {tenantId}");
                }

                // Validar actualización
                var validationResult = ValidateTenantUpdateRequest(request);
                if (!validationResult.IsValid)
                {
                    return TenantUpdateResult.Invalid(validationResult.Errors);
                }

                // Aplicar actualizaciones
                var updatedTenant = ApplyUpdates(existingTenant, request);
                updatedTenant.UpdatedAt = DateTime.UtcNow;

                // Actualizar en almacenamiento
                await _storage.UpdateTenantAsync(updatedTenant);

                // Actualizar caché
                _tenantCache[tenantId] = updatedTenant;

                _logger.LogInformation("Tenant actualizado: {TenantId}", tenantId);

                return TenantUpdateResult.Success(updatedTenant);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando tenant");
                return TenantUpdateResult.Error($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Activa/desactiva un tenant
        /// </summary>
        public async Task<ToggleResult> ToggleTenantActiveAsync(string tenantId, bool activate)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                var tenant = await GetTenantAsync(tenantId);
                if (tenant == null)
                {
                    return ToggleResult.Error($"Tenant no encontrado: {tenantId}");
                }

                if (tenant.IsActive == activate)
                {
                    return ToggleResult.Success(tenant, $"Tenant ya está {(activate ? "activo" : "inactivo")}");
                }

                tenant.IsActive = activate;
                tenant.UpdatedAt = DateTime.UtcNow;
                tenant.DeactivatedAt = activate ? null : DateTime.UtcNow as DateTime?;
                tenant.DeactivationReason = activate ? null : "Administrativo";

                await _storage.UpdateTenantAsync(tenant);
                _tenantCache[tenantId] = tenant;

                _logger.LogInformation("Tenant {TenantId} {Status}", 
                    tenantId, activate ? "activado" : "desactivado");

                return ToggleResult.Success(tenant, 
                    $"Tenant {(activate ? "activado" : "desactivado")} exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cambiando estado de tenant");
                return ToggleResult.Error($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Obtiene estadísticas de uso de un tenant
        /// </summary>
        public async Task<TenantUsageStats> GetTenantUsageStatsAsync(string tenantId, DateTimeRange range)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            // Intentar obtener del caché
            if (_usageCache.TryGetValue(tenantId, out var cachedUsage))
            {
                if (!IsUsageCacheExpired(cachedUsage))
                {
                    return cachedUsage.Stats;
                }
            }

            // Obtener de almacenamiento
            var usage = await _storage.GetTenantUsageAsync(tenantId, range);
            
            // Actualizar caché
            _usageCache[tenantId] = new TenantUsage
            {
                TenantId = tenantId,
                LastUpdated = DateTime.UtcNow,
                Stats = usage
            };

            return usage;
        }

        /// <summary>
        /// Obtiene todos los tenants (con paginación)
        /// </summary>
        public async Task<TenantListResult> GetAllTenantsAsync(TenantQueryOptions options)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                var result = await _storage.GetAllTenantsAsync(options);

                // Enriquecer con información de caché
                foreach (var tenant in result.Tenants)
                {
                    if (_configCache.TryGetValue(tenant.TenantId, out var config))
                    {
                        tenant.ConfigurationSummary = config.Summary;
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo lista de tenants");
                throw;
            }
        }

        /// <summary>
        /// Busca tenants por criterios
        /// </summary>
        public async Task<List<TenantInfo>> SearchTenantsAsync(TenantSearchCriteria criteria)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            // Primero buscar en caché
            var cachedResults = _tenantCache.Values
                .Where(t => MatchesSearchCriteria(t, criteria))
                .Take(criteria.MaxResults)
                .ToList();

            if (cachedResults.Count >= criteria.MaxResults)
            {
                return cachedResults;
            }

            // Buscar en almacenamiento
            var storageResults = await _storage.SearchTenantsAsync(criteria);
            
            // Combinar resultados
            var combined = cachedResults
                .Concat(storageResults.Where(r => !cachedResults.Any(c => c.TenantId == r.TenantId)))
                .Take(criteria.MaxResults)
                .ToList();

            return combined;
        }

        /// <summary>
        /// Obtiene reglas de retroalimentación personalizadas del tenant
        /// </summary>
        public async Task<List<FeedbackRule>> GetCustomFeedbackRulesAsync(string tenantId)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                var config = await GetTenantConfigurationAsync(tenantId);
                return config.FeedbackRules ?? new List<FeedbackRule>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo reglas de retroalimentación para tenant {TenantId}", tenantId);
                return new List<FeedbackRule>();
            }
        }

        /// <summary>
        /// Verifica si un tenant está activo y dentro de sus límites
        /// </summary>
        public async Task<TenantStatus> GetTenantStatusAsync(string tenantId)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            var tenant = await GetTenantAsync(tenantId);
            if (tenant == null)
            {
                return TenantStatus.NotFound;
            }

            if (!tenant.IsActive)
            {
                return TenantStatus.Inactive;
            }

            // Verificar límites de uso
            var usage = await GetTenantUsageStatsAsync(tenantId, 
                new DateTimeRange 
                { 
                    Start = DateTime.UtcNow.AddDays(-30), 
                    End = DateTime.UtcNow 
                });

            var status = TenantStatus.Active;

            if (usage.ActiveDevices >= tenant.MaxDevices * 0.9)
            {
                status = TenantStatus.NearDeviceLimit;
            }

            if (usage.DataSizeGB >= CalculateDataLimitGB(tenant) * 0.8)
            {
                status = TenantStatus.NearDataLimit;
            }

            if (usage.AlertCount >= GetAlertLimit(tenant) * 0.9)
            {
                status = TenantStatus.NearAlertLimit;
            }

            return status;
        }

        /// <summary>
        /// Exporta configuración de tenant para backup/migración
        /// </summary>
        public async Task<TenantExport> ExportTenantAsync(string tenantId)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                var tenant = await GetTenantAsync(tenantId);
                if (tenant == null)
                {
                    throw new ArgumentException($"Tenant no encontrado: {tenantId}");
                }

                var config = await GetTenantConfigurationAsync(tenantId);
                var usage = await GetTenantUsageStatsAsync(tenantId,
                    new DateTimeRange
                    {
                        Start = tenant.CreatedAt,
                        End = DateTime.UtcNow
                    });

                var export = new TenantExport
                {
                    ExportId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    TenantInfo = tenant,
                    Configuration = config,
                    UsageStats = usage,
                    ExportMetadata = new Dictionary<string, object>
                    {
                        { "exported_by", "system" },
                        { "export_format", "json" },
                        { "version", "1.0" }
                    }
                };

                _logger.LogInformation("Tenant {TenantId} exportado exitosamente", tenantId);

                return export;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exportando tenant {TenantId}", tenantId);
                throw;
            }
        }

        /// <summary>
        /// Importa configuración de tenant desde backup
        /// </summary>
        public async Task<TenantImportResult> ImportTenantAsync(TenantExport export, ImportOptions options)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("TenantManager no inicializado");

            try
            {
                // Validar export
                var validationResult = ValidateTenantExport(export);
                if (!validationResult.IsValid)
                {
                    return TenantImportResult.Invalid(validationResult.Errors);
                }

                // Verificar conflictos
                var conflictResult = await CheckImportConflictsAsync(export, options);
                if (conflictResult.HasConflicts && !options.Overwrite)
                {
                    return TenantImportResult.Conflicts(conflictResult.Conflicts);
                }

                string tenantId;
                if (options.UseExistingId && !string.IsNullOrEmpty(options.ExistingTenantId))
                {
                    // Usar ID existente
                    tenantId = options.ExistingTenantId;
                    
                    // Verificar que exista
                    var existing = await GetTenantAsync(tenantId);
                    if (existing == null)
                    {
                        return TenantImportResult.Error($"Tenant existente no encontrado: {tenantId}");
                    }

                    // Actualizar tenant existente
                    var updatedTenant = MergeTenantInfo(existing, export.TenantInfo);
                    await _storage.UpdateTenantAsync(updatedTenant);
                }
                else
                {
                    // Crear nuevo tenant
                    tenantId = options.GenerateNewId ? GenerateTenantId() : export.TenantInfo.TenantId;
                    
                    var newTenant = export.TenantInfo;
                    newTenant.TenantId = tenantId;
                    newTenant.CreatedAt = DateTime.UtcNow;
                    newTenant.UpdatedAt = DateTime.UtcNow;

                    await _storage.CreateTenantAsync(newTenant, export.Configuration);
                }

                // Actualizar configuración
                var config = export.Configuration;
                config.TenantId = tenantId;
                await _storage.UpdateTenantConfigurationAsync(config);

                // Limpiar cachés
                _tenantCache.TryRemove(tenantId, out _);
                _configCache.TryRemove(tenantId, out _);
                _usageCache.TryRemove(tenantId, out _);

                _logger.LogInformation("Tenant importado exitosamente: {TenantId}", tenantId);

                return TenantImportResult.Success(tenantId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importando tenant");
                return TenantImportResult.Error($"Error: {ex.Message}");
            }
        }

        #region Métodos Privados

        private async Task LoadActiveTenantsIntoCacheAsync()
        {
            try
            {
                var activeTenants = await _storage.GetActiveTenantsAsync();
                
                foreach (var tenant in activeTenants)
                {
                    _tenantCache[tenant.TenantId] = tenant;

                    // Precargar configuración común
                    var config = await _storage.GetTenantConfigurationAsync(tenant.TenantId);
                    if (config != null)
                    {
                        _configCache[tenant.TenantId] = config;
                    }
                }

                _logger.LogInformation("Cargados {Count} tenants activos en caché", activeTenants.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error precargando tenants en caché");
            }
        }

        private void StartCacheCleanupTimer()
        {
            // En producción usar Timer o background service
            Task.Run(async () =>
            {
                while (_isInitialized)
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMinutes(CACHE_TTL_MINUTES));
                        CleanupExpiredCacheEntries();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error en limpieza de caché");
                    }
                }
            });
        }

        private void CleanupExpiredCacheEntries()
        {
            var now = DateTime.UtcNow;

            // Limpiar caché de tenants
            var expiredTenants = _tenantCache
                .Where(kv => IsCacheExpired(kv.Value))
                .Select(kv => kv.Key)
                .ToList();

            foreach (var tenantId in expiredTenants)
            {
                _tenantCache.TryRemove(tenantId, out _);
            }

            // Limpiar caché de configuración
            var expiredConfigs = _configCache
                .Where(kv => IsConfigCacheExpired(kv.Value))
                .Select(kv => kv.Key)
                .ToList();

            foreach (var tenantId in expiredConfigs)
            {
                _configCache.TryRemove(tenantId, out _);
            }

            if (expiredTenants.Any() || expiredConfigs.Any())
            {
                _logger.LogDebug("Limpieza de caché: {TenantCount} tenants, {ConfigCount} configuraciones",
                    expiredTenants.Count, expiredConfigs.Count);
            }
        }

        private bool IsCacheExpired(TenantInfo tenant)
        {
            return tenant.UpdatedAt < DateTime.UtcNow.AddMinutes(-CACHE_TTL_MINUTES);
        }

        private bool IsConfigCacheExpired(TenantConfiguration config)
        {
            return config.UpdatedAt < DateTime.UtcNow.AddMinutes(-CACHE_TTL_MINUTES);
        }

        private bool IsUsageCacheExpired(TenantUsage usage)
        {
            return usage.LastUpdated < DateTime.UtcNow.AddMinutes(-CACHE_TTL_MINUTES / 2);
        }

        private ValidationResult ValidateTenantCreationRequest(TenantCreationRequest request)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(request.Name))
                errors.Add("Nombre es requerido");

            if (string.IsNullOrWhiteSpace(request.ExternalId))
                errors.Add("ID externo es requerido");

            if (string.IsNullOrWhiteSpace(request.ContactEmail))
                errors.Add("Email de contacto es requerido");

            if (!IsValidEmail(request.ContactEmail))
                errors.Add("Email de contacto no es válido");

            if (request.MaxDevices <= 0)
                errors.Add("Máximo de dispositivos debe ser mayor a 0");

            if (request.MaxUsers <= 0)
                errors.Add("Máximo de usuarios debe ser mayor a 0");

            if (request.DataRetentionDays < 30 || request.DataRetentionDays > 3650)
                errors.Add("Retención de datos debe estar entre 30 y 3650 días");

            return new ValidationResult
            {
                IsValid = !errors.Any(),
                Errors = errors
            };
        }

        private ValidationResult ValidateTenantUpdateRequest(TenantUpdateRequest request)
        {
            var errors = new List<string>();

            if (!string.IsNullOrEmpty(request.ContactEmail) && !IsValidEmail(request.ContactEmail))
                errors.Add("Email de contacto no es válido");

            if (request.MaxDevices.HasValue && request.MaxDevices <= 0)
                errors.Add("Máximo de dispositivos debe ser mayor a 0");

            if (request.MaxUsers.HasValue && request.MaxUsers <= 0)
                errors.Add("Máximo de usuarios debe ser mayor a 0");

            if (request.DataRetentionDays.HasValue && 
                (request.DataRetentionDays < 30 || request.DataRetentionDays > 3650))
                errors.Add("Retención de datos debe estar entre 30 y 3650 días");

            return new ValidationResult
            {
                IsValid = !errors.Any(),
                Errors = errors
            };
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private string GenerateTenantId()
        {
            return $"TEN_{Guid.NewGuid().ToString("N").Substring(0, 12).ToUpper()}";
        }

        private TenantConfiguration CreateDefaultConfiguration(string tenantId)
        {
            return new TenantConfiguration
            {
                TenantId = tenantId,
                SecurityPolicy = CreateDefaultSecurityPolicy(),
                NotificationSettings = CreateDefaultNotificationSettings(),
                IntegrationSettings = new Dictionary<string, object>(),
                CustomRules = new List<CustomRule>(),
                FeedbackRules = new List<FeedbackRule>(),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
        }

        private SecurityPolicy CreateDefaultSecurityPolicy()
        {
            return new SecurityPolicy
            {
                AlertSeverityThreshold = ThreatSeverity.Medium,
                AutoRemediationEnabled = true,
                AutoRemediationActions = new List<string> { "Quarantine", "BlockProcess" },
                RequireApprovalFor = new List<string> { "DeleteFile", "BlockIP" },
                DataEncryptionEnabled = true,
                LogRetentionDays = 90,
                AuditLogEnabled = true
            };
        }

        private NotificationSettings CreateDefaultNotificationSettings()
        {
            return new NotificationSettings
            {
                EmailEnabled = true,
                EmailAddresses = new List<string>(),
                SmsEnabled = false,
                SmsNumbers = new List<string>(),
                WebhookEnabled = false,
                WebhookUrls = new List<string>(),
                AlertFrequency = NotificationFrequency.Immediate,
                DigestSchedule = "0 9 * * *", // 9 AM daily
                CriticalAlertsOnly = false
            };
        }

        private TenantInfo ApplyUpdates(TenantInfo existing, TenantUpdateRequest request)
        {
            var updated = existing with { }; // Usar record copy en C# 9+

            if (!string.IsNullOrEmpty(request.Name))
                updated.Name = request.Name;

            if (!string.IsNullOrEmpty(request.Description))
                updated.Description = request.Description;

            if (!string.IsNullOrEmpty(request.ContactEmail))
                updated.ContactEmail = request.ContactEmail;

            if (!string.IsNullOrEmpty(request.ContactPhone))
                updated.ContactPhone = request.ContactPhone;

            if (!string.IsNullOrEmpty(request.CompanyName))
                updated.CompanyName = request.CompanyName;

            if (!string.IsNullOrEmpty(request.Industry))
                updated.Industry = request.Industry;

            if (!string.IsNullOrEmpty(request.Country))
                updated.Country = request.Country;

            if (!string.IsNullOrEmpty(request.Timezone))
                updated.Timezone = request.Timezone;

            if (!string.IsNullOrEmpty(request.Language))
                updated.Language = request.Language;

            if (request.SubscriptionTier.HasValue)
                updated.SubscriptionTier = request.SubscriptionTier.Value;

            if (request.MaxDevices.HasValue)
                updated.MaxDevices = request.MaxDevices.Value;

            if (request.MaxUsers.HasValue)
                updated.MaxUsers = request.MaxUsers.Value;

            if (request.DataRetentionDays.HasValue)
                updated.DataRetentionDays = request.DataRetentionDays.Value;

            if (request.Metadata != null)
                updated.Metadata = MergeMetadata(updated.Metadata, request.Metadata);

            return updated;
        }

        private Dictionary<string, object> MergeMetadata(
            Dictionary<string, object> existing, 
            Dictionary<string, object> updates)
        {
            var merged = new Dictionary<string, object>(existing);
            
            foreach (var kvp in updates)
            {
                merged[kvp.Key] = kvp.Value;
            }

            return merged;
        }

        private bool MatchesSearchCriteria(TenantInfo tenant, TenantSearchCriteria criteria)
        {
            if (!string.IsNullOrEmpty(criteria.Name) &&
                !tenant.Name.Contains(criteria.Name, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.IsNullOrEmpty(criteria.CompanyName) &&
                !tenant.CompanyName.Contains(criteria.CompanyName, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.IsNullOrEmpty(criteria.Industry) &&
                !tenant.Industry.Equals(criteria.Industry, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.IsNullOrEmpty(criteria.Country) &&
                !tenant.Country.Equals(criteria.Country, StringComparison.OrdinalIgnoreCase))
                return false;

            if (criteria.IsActive.HasValue && tenant.IsActive != criteria.IsActive.Value)
                return false;

            if (criteria.SubscriptionTier.HasValue && tenant.SubscriptionTier != criteria.SubscriptionTier.Value)
                return false;

            if (criteria.CreatedAfter.HasValue && tenant.CreatedAt < criteria.CreatedAfter.Value)
                return false;

            if (criteria.CreatedBefore.HasValue && tenant.CreatedAt > criteria.CreatedBefore.Value)
                return false;

            return true;
        }

        private double CalculateDataLimitGB(TenantInfo tenant)
        {
            return tenant.SubscriptionTier switch
            {
                SubscriptionTier.Basic => 10,
                SubscriptionTier.Standard => 100,
                SubscriptionTier.Professional => 1000,
                SubscriptionTier.Enterprise => 10000,
                _ => 10
            };
        }

        private int GetAlertLimit(TenantInfo tenant)
        {
            return tenant.SubscriptionTier switch
            {
                SubscriptionTier.Basic => 1000,
                SubscriptionTier.Standard => 10000,
                SubscriptionTier.Professional => 100000,
                SubscriptionTier.Enterprise => int.MaxValue,
                _ => 1000
            };
        }

        private ValidationResult ValidateTenantExport(TenantExport export)
        {
            var errors = new List<string>();

            if (export == null)
                errors.Add("Export es null");

            if (export?.TenantInfo == null)
                errors.Add("Información de tenant es requerida");

            if (export?.Configuration == null)
                errors.Add("Configuración es requerida");

            if (!string.IsNullOrEmpty(export?.TenantInfo?.TenantId) && 
                !export.TenantInfo.TenantId.StartsWith("TEN_"))
                errors.Add("ID de tenant no tiene formato válido");

            return new ValidationResult
            {
                IsValid = !errors.Any(),
                Errors = errors
            };
        }

        private async Task<ConflictCheckResult> CheckImportConflictsAsync(TenantExport export, ImportOptions options)
        {
            var conflicts = new List<ImportConflict>();

            // Verificar ID de tenant
            if (!options.GenerateNewId && !string.IsNullOrEmpty(export.TenantInfo.TenantId))
            {
                var existing = await GetTenantAsync(export.TenantInfo.TenantId);
                if (existing != null)
                {
                    conflicts.Add(new ImportConflict
                    {
                        Type = ConflictType.TenantIdExists,
                        Description = $"Tenant con ID {export.TenantInfo.TenantId} ya existe",
                        Severity = ConflictSeverity.High
                    });
                }
            }

            // Verificar ID externo
            if (!string.IsNullOrEmpty(export.TenantInfo.ExternalId))
            {
                var existing = await _storage.GetTenantByExternalIdAsync(export.TenantInfo.ExternalId);
                if (existing != null && existing.TenantId != options.ExistingTenantId)
                {
                    conflicts.Add(new ImportConflict
                    {
                        Type = ConflictType.ExternalIdExists,
                        Description = $"Tenant con ID externo {export.TenantInfo.ExternalId} ya existe",
                        Severity = ConflictSeverity.Medium
                    });
                }
            }

            return new ConflictCheckResult
            {
                HasConflicts = conflicts.Any(),
                Conflicts = conflicts
            };
        }

        private TenantInfo MergeTenantInfo(TenantInfo existing, TenantInfo imported)
        {
            return new TenantInfo
            {
                TenantId = existing.TenantId,
                ExternalId = imported.ExternalId ?? existing.ExternalId,
                Name = imported.Name ?? existing.Name,
                Description = imported.Description ?? existing.Description,
                ContactEmail = imported.ContactEmail ?? existing.ContactEmail,
                ContactPhone = imported.ContactPhone ?? existing.ContactPhone,
                CompanyName = imported.CompanyName ?? existing.CompanyName,
                Industry = imported.Industry ?? existing.Industry,
                Country = imported.Country ?? existing.Country,
                Timezone = imported.Timezone ?? existing.Timezone,
                Language = imported.Language ?? existing.Language,
                SubscriptionTier = imported.SubscriptionTier,
                MaxDevices = imported.MaxDevices,
                MaxUsers = imported.MaxUsers,
                DataRetentionDays = imported.DataRetentionDays,
                IsActive = imported.IsActive,
                CreatedAt = existing.CreatedAt,
                UpdatedAt = DateTime.UtcNow,
                DeactivatedAt = imported.DeactivatedAt,
                DeactivationReason = imported.DeactivationReason,
                Metadata = MergeMetadata(existing.Metadata, imported.Metadata ?? new Dictionary<string, object>())
            };
        }

        #endregion

        #region Clases y estructuras de datos

        public interface ITenantManager
        {
            Task InitializeAsync();
            Task<TenantInfo> GetTenantAsync(string tenantId);
            Task<TenantConfiguration> GetTenantConfigurationAsync(string tenantId);
            Task<TenantCreationResult> CreateTenantAsync(TenantCreationRequest request);
            Task<TenantUpdateResult> UpdateTenantAsync(string tenantId, TenantUpdateRequest request);
            Task<ToggleResult> ToggleTenantActiveAsync(string tenantId, bool activate);
            Task<TenantUsageStats> GetTenantUsageStatsAsync(string tenantId, DateTimeRange range);
            Task<TenantListResult> GetAllTenantsAsync(TenantQueryOptions options);
            Task<List<TenantInfo>> SearchTenantsAsync(TenantSearchCriteria criteria);
            Task<List<FeedbackRule>> GetCustomFeedbackRulesAsync(string tenantId);
            Task<TenantStatus> GetTenantStatusAsync(string tenantId);
            Task<TenantExport> ExportTenantAsync(string tenantId);
            Task<TenantImportResult> ImportTenantAsync(TenantExport export, ImportOptions options);
        }

        public class TenantInfo
        {
            public string TenantId { get; set; }
            public string ExternalId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public string ContactEmail { get; set; }
            public string ContactPhone { get; set; }
            public string CompanyName { get; set; }
            public string Industry { get; set; }
            public string Country { get; set; }
            public string Timezone { get; set; }
            public string Language { get; set; }
            public SubscriptionTier SubscriptionTier { get; set; }
            public int MaxDevices { get; set; }
            public int MaxUsers { get; set; }
            public int DataRetentionDays { get; set; }
            public bool IsActive { get; set; }
            public DateTime CreatedAt { get; set; }
            public DateTime UpdatedAt { get; set; }
            public DateTime? DeactivatedAt { get; set; }
            public string DeactivationReason { get; set; }
            public Dictionary<string, object> Metadata { get; set; }
            public string ConfigurationSummary { get; set; }
        }

        public enum SubscriptionTier
        {
            Basic,
            Standard,
            Professional,
            Enterprise
        }

        public class TenantConfiguration
        {
            public string TenantId { get; set; }
            public SecurityPolicy SecurityPolicy { get; set; }
            public NotificationSettings NotificationSettings { get; set; }
            public Dictionary<string, object> IntegrationSettings { get; set; }
            public List<CustomRule> CustomRules { get; set; }
            public List<FeedbackRule> FeedbackRules { get; set; }
            public DateTime CreatedAt { get; set; }
            public DateTime UpdatedAt { get; set; }
            public string Summary => $"Security: {SecurityPolicy?.AlertSeverityThreshold}, Notifications: {NotificationSettings?.EmailEnabled}";
        }

        public class SecurityPolicy
        {
            public ThreatSeverity AlertSeverityThreshold { get; set; }
            public bool AutoRemediationEnabled { get; set; }
            public List<string> AutoRemediationActions { get; set; }
            public List<string> RequireApprovalFor { get; set; }
            public bool DataEncryptionEnabled { get; set; }
            public int LogRetentionDays { get; set; }
            public bool AuditLogEnabled { get; set; }
        }

        public enum ThreatSeverity
        {
            Info,
            Low,
            Medium,
            High,
            Critical
        }

        public class NotificationSettings
        {
            public bool EmailEnabled { get; set; }
            public List<string> EmailAddresses { get; set; }
            public bool SmsEnabled { get; set; }
            public List<string> SmsNumbers { get; set; }
            public bool WebhookEnabled { get; set; }
            public List<string> WebhookUrls { get; set; }
            public NotificationFrequency AlertFrequency { get; set; }
            public string DigestSchedule { get; set; }
            public bool CriticalAlertsOnly { get; set; }
        }

        public enum NotificationFrequency
        {
            Immediate,
            Hourly,
            Daily,
            Weekly
        }

        public class CustomRule
        {
            public string RuleId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public string Condition { get; set; }
            public string Action { get; set; }
            public bool IsEnabled { get; set; }
        }

        public class FeedbackRule
        {
            public string RuleId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public string Condition { get; set; }
            public string FeedbackType { get; set; }
            public bool IsEnabled { get; set; }
        }
                #endregion
    }
}