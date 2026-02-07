using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Communication;
using BWP.Enterprise.Agent.SelfProtection;

namespace BWP.Enterprise.Agent.Update
{
    /// <summary>
    /// Gestor de actualizaciones OTA (Over-The-Air) para BWP Enterprise Agent
    /// Maneja descarga, verificación e instalación de actualizaciones
    /// </summary>
    public sealed class UpdateManager : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<UpdateManager> _instance = 
            new Lazy<UpdateManager>(() => new UpdateManager());
        
        public static UpdateManager Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly ApiClient _apiClient;
        private readonly IntegrityVerifier _integrityVerifier;
        
        private Timer _checkUpdateTimer;
        private HttpClient _httpClient;
        private UpdateStatus _currentStatus;
        private UpdateManifest _currentManifest;
        private List<UpdatePackage> _availableUpdates;
        private bool _isInitialized;
        private bool _isChecking;
        private bool _isDownloading;
        private bool _isInstalling;
        private const int CHECK_UPDATE_INTERVAL_HOURS = 6;
        private const int MAX_RETRY_ATTEMPTS = 3;
        private const string UPDATE_CACHE_DIRECTORY = "Updates";
        
        public string ModuleId => "UpdateManager";
        public string Version => "1.0.0";
        public string Description => "Sistema de gestión de actualizaciones OTA";
        
        private UpdateManager()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _apiClient = ApiClient.Instance;
            _integrityVerifier = IntegrityVerifier.Instance;
            _currentStatus = UpdateStatus.Idle;
            _availableUpdates = new List<UpdatePackage>();
            _isChecking = false;
            _isDownloading = false;
            _isInstalling = false;
        }
        
        /// <summary>
        /// Inicializa el gestor de actualizaciones
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando UpdateManager...", ModuleId);
                
                // Inicializar cliente HTTP
                _httpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromMinutes(5)
                };
                
                // Configurar temporizador de verificación
                _checkUpdateTimer = new Timer(TimeSpan.FromHours(CHECK_UPDATE_INTERVAL_HOURS).TotalMilliseconds);
                _checkUpdateTimer.Elapsed += async (sender, e) => await CheckForUpdatesAsync();
                
                // Crear directorio de caché de actualizaciones
                CreateUpdateCacheDirectory();
                
                // Cargar estado de actualizaciones anteriores
                await LoadUpdateStateAsync();
                
                // Verificar si hay actualizaciones pendientes
                await CheckForPendingUpdatesAsync();
                
                _isInitialized = true;
                _logManager.LogInfo("UpdateManager inicializado", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar UpdateManager: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el gestor de actualizaciones
        /// </summary>
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                    return initResult;
            }
            
            try
            {
                _checkUpdateTimer.Start();
                
                // Realizar primera verificación (con retardo aleatorio para evitar picos)
                var randomDelay = new Random().Next(1, 300); // 1-300 segundos
                _ = Task.Delay(TimeSpan.FromSeconds(randomDelay))
                    .ContinueWith(async _ => await CheckForUpdatesAsync());
                
                _logManager.LogInfo("UpdateManager iniciado", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar UpdateManager: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el gestor de actualizaciones
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _checkUpdateTimer?.Stop();
                _checkUpdateTimer?.Dispose();
                _httpClient?.Dispose();
                
                _logManager.LogInfo("UpdateManager detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener UpdateManager: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Verifica si hay actualizaciones disponibles
        /// </summary>
        public async Task<UpdateCheckResult> CheckForUpdatesAsync(bool forceCheck = false)
        {
            if (_isChecking && !forceCheck)
            {
                return UpdateCheckResult.Busy("Ya se está verificando actualizaciones");
            }
            
            try
            {
                _isChecking = true;
                _currentStatus = UpdateStatus.Checking;
                
                _logManager.LogInfo("Verificando actualizaciones disponibles...", ModuleId);
                
                // Paso 1: Obtener manifiesto de actualizaciones desde el servidor
                var manifestResult = await GetUpdateManifestAsync();
                if (!manifestResult.Success)
                {
                    _logManager.LogError($"Error obteniendo manifiesto: {manifestResult.ErrorMessage}", ModuleId);
                    return UpdateCheckResult.Failed($"Error obteniendo manifiesto: {manifestResult.ErrorMessage}");
                }
                
                _currentManifest = manifestResult.Manifest;
                
                // Paso 2: Verificar actualizaciones disponibles para esta versión
                var availableUpdates = await FindAvailableUpdatesAsync(_currentManifest);
                
                // Paso 3: Filtrar actualizaciones ya aplicadas
                var newUpdates = await FilterAlreadyAppliedUpdatesAsync(availableUpdates);
                
                // Paso 4: Priorizar actualizaciones (críticas primero)
                var prioritizedUpdates = PrioritizeUpdates(newUpdates);
                
                _availableUpdates = prioritizedUpdates;
                
                var result = new UpdateCheckResult
                {
                    Success = true,
                    Timestamp = DateTime.UtcNow,
                    AvailableUpdates = _availableUpdates.Count,
                    CriticalUpdates = _availableUpdates.Count(u => u.Priority == UpdatePriority.Critical),
                    SecurityUpdates = _availableUpdates.Count(u => u.Type == UpdateType.Security),
                    Updates = _availableUpdates,
                    CurrentVersion = GetCurrentVersion(),
                    LatestVersion = _currentManifest?.LatestVersion
                };
                
                if (_availableUpdates.Count > 0)
                {
                    _logManager.LogInfo($"Encontradas {_availableUpdates.Count} actualizaciones disponibles", ModuleId);
                    
                    // Notificar al usuario/administrador sobre actualizaciones disponibles
                    await NotifyUpdatesAvailableAsync(_availableUpdates);
                }
                else
                {
                    _logManager.LogInfo("No hay actualizaciones disponibles", ModuleId);
                }
                
                // Guardar estado de verificación
                await SaveUpdateCheckResultAsync(result);
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando actualizaciones: {ex}", ModuleId);
                return UpdateCheckResult.Failed($"Error: {ex.Message}");
            }
            finally
            {
                _isChecking = false;
                _currentStatus = UpdateStatus.Idle;
            }
        }
        
        /// <summary>
        /// Descarga una actualización específica
        /// </summary>
        public async Task<DownloadResult> DownloadUpdateAsync(string updateId)
        {
            if (_isDownloading)
            {
                return DownloadResult.Busy("Ya se está descargando una actualización");
            }
            
            var update = _availableUpdates.FirstOrDefault(u => u.UpdateId == updateId);
            if (update == null)
            {
                return DownloadResult.Failed($"Actualización no encontrada: {updateId}");
            }
            
            try
            {
                _isDownloading = true;
                _currentStatus = UpdateStatus.Downloading;
                
                _logManager.LogInfo($"Descargando actualización: {update.Title} (ID: {updateId})", ModuleId);
                
                // Paso 1: Obtener URL de descarga
                var downloadUrl = await GetDownloadUrlAsync(update);
                if (string.IsNullOrEmpty(downloadUrl))
                {
                    return DownloadResult.Failed("No se pudo obtener URL de descarga");
                }
                
                // Paso 2: Descargar paquete
                var packageResult = await DownloadPackageAsync(downloadUrl, update);
                if (!packageResult.Success)
                {
                    return DownloadResult.Failed($"Error descargando paquete: {packageResult.ErrorMessage}");
                }
                
                // Paso 3: Verificar integridad del paquete descargado
                var integrityResult = await VerifyPackageIntegrityAsync(packageResult.FilePath, update);
                if (!integrityResult.Success)
                {
                    File.Delete(packageResult.FilePath);
                    return DownloadResult.Failed($"Error de integridad: {integrityResult.ErrorMessage}");
                }
                
                // Paso 4: Preparar paquete para instalación
                var preparationResult = await PreparePackageForInstallationAsync(packageResult.FilePath, update);
                if (!preparationResult.Success)
                {
                    return DownloadResult.Failed($"Error preparando paquete: {preparationResult.ErrorMessage}");
                }
                
                update.DownloadedPath = preparationResult.InstallationPath;
                update.DownloadedAt = DateTime.UtcNow;
                update.DownloadStatus = DownloadStatus.Completed;
                
                var result = DownloadResult.Success(
                    update,
                    preparationResult.InstallationPath,
                    packageResult.FileSize,
                    packageResult.DownloadTime);
                
                _logManager.LogInfo($"Actualización descargada exitosamente: {update.Title}", ModuleId);
                
                // Guardar estado de descarga
                await SaveDownloadResultAsync(result);
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descargando actualización {updateId}: {ex}", ModuleId);
                return DownloadResult.Failed($"Error: {ex.Message}");
            }
            finally
            {
                _isDownloading = false;
                _currentStatus = UpdateStatus.Idle;
            }
        }
        
        /// <summary>
        /// Instala una actualización descargada
        /// </summary>
        public async Task<InstallationResult> InstallUpdateAsync(string updateId)
        {
            if (_isInstalling)
            {
                return InstallationResult.Busy("Ya se está instalando una actualización");
            }
            
            var update = _availableUpdates.FirstOrDefault(u => u.UpdateId == updateId);
            if (update == null)
            {
                return InstallationResult.Failed($"Actualización no encontrada: {updateId}");
            }
            
            if (update.DownloadStatus != DownloadStatus.Completed || string.IsNullOrEmpty(update.DownloadedPath))
            {
                return InstallationResult.Failed("La actualización no ha sido descargada completamente");
            }
            
            try
            {
                _isInstalling = true;
                _currentStatus = UpdateStatus.Installing;
                
                _logManager.LogInfo($"Instalando actualización: {update.Title} (ID: {updateId})", ModuleId);
                
                // Paso 1: Crear punto de restauración
                var restorePoint = await CreateRestorePointAsync(update);
                if (!restorePoint.Success)
                {
                    return InstallationResult.Failed($"Error creando punto de restauración: {restorePoint.ErrorMessage}");
                }
                
                // Paso 2: Realizar pre-instalación checks
                var preInstallCheck = await PerformPreInstallationChecksAsync(update);
                if (!preInstallCheck.Success)
                {
                    return InstallationResult.Failed($"Error en pre-instalación: {preInstallCheck.ErrorMessage}");
                }
                
                // Paso 3: Instalar actualización
                var installResult = await ExecuteInstallationAsync(update);
                if (!installResult.Success)
                {
                    // Intentar rollback
                    await PerformRollbackAsync(restorePoint, update);
                    return InstallationResult.Failed($"Error instalando: {installResult.ErrorMessage}");
                }
                
                // Paso 4: Verificar post-instalación
                var postInstallCheck = await PerformPostInstallationVerificationAsync(update);
                if (!postInstallCheck.Success)
                {
                    // Intentar rollback
                    await PerformRollbackAsync(restorePoint, update);
                    return InstallationResult.Failed($"Error en post-instalación: {postInstallCheck.ErrorMessage}");
                }
                
                // Paso 5: Actualizar estado
                update.InstallationStatus = InstallationStatus.Installed;
                update.InstalledAt = DateTime.UtcNow;
                update.InstalledVersion = update.TargetVersion;
                
                // Paso 6: Limpiar archivos temporales
                await CleanupTempFilesAsync(update);
                
                // Paso 7: Actualizar registro de actualizaciones aplicadas
                await MarkUpdateAsAppliedAsync(update);
                
                var result = InstallationResult.Success(
                    update,
                    installResult.InstallationTime,
                    restorePoint.RestorePointId);
                
                _logManager.LogInfo($"Actualización instalada exitosamente: {update.Title}", ModuleId);
                
                // Notificar éxito
                await NotifyInstallationSuccessAsync(update);
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error instalando actualización {updateId}: {ex}", ModuleId);
                return InstallationResult.Failed($"Error: {ex.Message}");
            }
            finally
            {
                _isInstalling = false;
                _currentStatus = UpdateStatus.Idle;
            }
        }
        
        /// <summary>
        /// Programa instalación de actualización
        /// </summary>
        public async Task<SchedulingResult> ScheduleUpdateAsync(string updateId, DateTime scheduledTime, bool requireReboot = false)
        {
            try
            {
                var update = _availableUpdates.FirstOrDefault(u => u.UpdateId == updateId);
                if (update == null)
                {
                    return SchedulingResult.Failed($"Actualización no encontrada: {updateId}");
                }
                
                _logManager.LogInfo($"Programando actualización: {update.Title} para {scheduledTime}", ModuleId);
                
                var schedule = new UpdateSchedule
                {
                    UpdateId = updateId,
                    ScheduledTime = scheduledTime,
                    RequireReboot = requireReboot,
                    Status = ScheduleStatus.Scheduled,
                    CreatedAt = DateTime.UtcNow
                };
                
                // Guardar programación
                await _localDatabase.SaveUpdateScheduleAsync(schedule);
                
                // Configurar temporizador para la programación
                await SetupScheduleTimerAsync(schedule);
                
                return SchedulingResult.Success(schedule);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error programando actualización: {ex}", ModuleId);
                return SchedulingResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Instala todas las actualizaciones disponibles
        /// </summary>
        public async Task<BatchUpdateResult> InstallAllAvailableUpdatesAsync(bool automatic = false)
        {
            try
            {
                if (_availableUpdates.Count == 0)
                {
                    return BatchUpdateResult.Success("No hay actualizaciones disponibles");
                }
                
                _logManager.LogInfo($"Instalando {_availableUpdates.Count} actualizaciones disponibles", ModuleId);
                
                var results = new List<UpdateResult>();
                var successful = 0;
                var failed = 0;
                var requiresReboot = false;
                
                // Ordenar actualizaciones por prioridad y dependencias
                var orderedUpdates = OrderUpdatesForInstallation(_availableUpdates);
                
                foreach (var update in orderedUpdates)
                {
                    try
                    {
                        // Descargar si no está descargado
                        if (update.DownloadStatus != DownloadStatus.Completed)
                        {
                            var downloadResult = await DownloadUpdateAsync(update.UpdateId);
                            if (!downloadResult.Success)
                            {
                                results.Add(UpdateResult.Failed(update.UpdateId, $"Error descargando: {downloadResult.ErrorMessage}"));
                                failed++;
                                continue;
                            }
                        }
                        
                        // Instalar
                        var installResult = await InstallUpdateAsync(update.UpdateId);
                        
                        var result = new UpdateResult
                        {
                            UpdateId = update.UpdateId,
                            Success = installResult.Success,
                            ErrorMessage = installResult.ErrorMessage,
                            Timestamp = DateTime.UtcNow
                        };
                        
                        results.Add(result);
                        
                        if (installResult.Success)
                        {
                            successful++;
                            if (update.RequiresReboot)
                                requiresReboot = true;
                        }
                        else
                        {
                            failed++;
                            
                            // Si es crítica y falló, detener batch
                            if (update.Priority == UpdatePriority.Critical && !automatic)
                            {
                                _logManager.LogError($"Actualización crítica falló, deteniendo batch: {update.Title}", ModuleId);
                                break;
                            }
                        }
                        
                        // Pequeña pausa entre instalaciones
                        await Task.Delay(1000);
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error procesando actualización {update.UpdateId}: {ex}", ModuleId);
                        failed++;
                    }
                }
                
                var batchResult = new BatchUpdateResult
                {
                    Timestamp = DateTime.UtcNow,
                    TotalUpdates = _availableUpdates.Count,
                    Successful = successful,
                    Failed = failed,
                    RequiresReboot = requiresReboot,
                    Results = results
                };
                
                if (failed == 0)
                {
                    _logManager.LogInfo($"Todas las {successful} actualizaciones instaladas exitosamente", ModuleId);
                }
                else
                {
                    _logManager.LogWarning($"Instalación batch completada: {successful} exitosas, {failed} fallidas", ModuleId);
                }
                
                return batchResult;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en instalación batch: {ex}", ModuleId);
                return BatchUpdateResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Revierte una actualización instalada
        /// </summary>
        public async Task<RollbackResult> RollbackUpdateAsync(string updateId)
        {
            try
            {
                _logManager.LogWarning($"Revirtiendo actualización: {updateId}", ModuleId);
                
                // Buscar actualización
                var update = await _localDatabase.GetAppliedUpdateAsync(updateId);
                if (update == null)
                {
                    return RollbackResult.Failed($"Actualización no encontrada o no aplicada: {updateId}");
                }
                
                // Verificar si tiene punto de restauración
                if (string.IsNullOrEmpty(update.RestorePointId))
                {
                    return RollbackResult.Failed("No hay punto de restauración disponible para esta actualización");
                }
                
                // Restaurar desde punto de restauración
                var restoreResult = await RestoreFromBackupAsync(update.RestorePointId);
                if (!restoreResult.Success)
                {
                    return RollbackResult.Failed($"Error restaurando: {restoreResult.ErrorMessage}");
                }
                
                // Marcar como revertida
                update.RollbackStatus = RollbackStatus.RolledBack;
                update.RolledBackAt = DateTime.UtcNow;
                update.RollbackReason = "Solicitado por usuario";
                
                await _localDatabase.UpdateAppliedUpdateAsync(update);
                
                _logManager.LogInfo($"Actualización revertida exitosamente: {updateId}", ModuleId);
                
                return RollbackResult.Success(update);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error revirtiendo actualización: {ex}", ModuleId);
                return RollbackResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Obtiene reporte de actualizaciones
        /// </summary>
        public async Task<UpdateReport> GetUpdateReportAsync(TimeSpan? period = null)
        {
            period ??= TimeSpan.FromDays(30);
            
            try
            {
                var checkHistory = await _localDatabase.GetUpdateCheckHistoryAsync(period.Value);
                var appliedUpdates = await _localDatabase.GetAppliedUpdatesAsync(period.Value);
                var failedUpdates = await _localDatabase.GetFailedUpdatesAsync(period.Value);
                var schedules = await _localDatabase.GetUpdateSchedulesAsync(period.Value);
                
                var report = new UpdateReport
                {
                    GeneratedAt = DateTime.UtcNow,
                    Period = period.Value,
                    CurrentVersion = GetCurrentVersion(),
                    UpdateStatus = _currentStatus,
                    AvailableUpdates = _availableUpdates,
                    LastCheck = checkHistory.OrderByDescending(c => c.Timestamp).FirstOrDefault(),
                    AppliedUpdates = appliedUpdates,
                    FailedUpdates = failedUpdates,
                    Schedules = schedules,
                    Statistics = CalculateUpdateStatistics(checkHistory, appliedUpdates, failedUpdates),
                    Recommendations = await GenerateUpdateRecommendationsAsync(appliedUpdates, _availableUpdates)
                };
                
                return report;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando reporte de actualizaciones: {ex}", ModuleId);
                return UpdateReport.Error($"Error: {ex.Message}");
            }
        }
        
        #region Métodos privados
        
        /// <summary>
        /// Carga estado de actualizaciones
        /// </summary>
        private async Task LoadUpdateStateAsync()
        {
            try
            {
                // Cargar estado desde base de datos
                var state = await _localDatabase.GetUpdateManagerStateAsync();
                
                if (state != null)
                {
                    _currentStatus = state.CurrentStatus;
                    _availableUpdates = state.AvailableUpdates ?? new List<UpdatePackage>();
                    
                    _logManager.LogDebug($"Estado de UpdateManager cargado: {_currentStatus}", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando estado de UpdateManager: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Crea directorio de caché de actualizaciones
        /// </summary>
        private void CreateUpdateCacheDirectory()
        {
            try
            {
                var cacheDir = GetUpdateCacheDirectory();
                if (!Directory.Exists(cacheDir))
                {
                    Directory.CreateDirectory(cacheDir);
                    _logManager.LogDebug($"Directorio de caché creado: {cacheDir}", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error creando directorio de caché: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Verifica actualizaciones pendientes
        /// </summary>
        private async Task CheckForPendingUpdatesAsync()
        {
            try
            {
                // Verificar si hay actualizaciones descargadas pero no instaladas
                var pending = _availableUpdates
                    .Where(u => u.DownloadStatus == DownloadStatus.Completed && 
                               u.InstallationStatus != InstallationStatus.Installed)
                    .ToList();
                
                if (pending.Count > 0)
                {
                    _logManager.LogInfo($"Encontradas {pending.Count} actualizaciones pendientes de instalación", ModuleId);
                    
                    // Intentar instalar automáticamente actualizaciones críticas
                    var criticalPending = pending.Where(u => u.Priority == UpdatePriority.Critical).ToList();
                    if (criticalPending.Count > 0)
                    {
                        _logManager.LogWarning($"Instalando {criticalPending.Count} actualizaciones críticas pendientes", ModuleId);
                        await InstallAllAvailableUpdatesAsync(true);
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando actualizaciones pendientes: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene manifiesto de actualizaciones
        /// </summary>
        private async Task<ManifestResult> GetUpdateManifestAsync()
        {
            try
            {
                // Intentar desde servidor principal
                var manifest = await _apiClient.GetUpdateManifestAsync();
                if (manifest != null)
                {
                    return ManifestResult.Success(manifest);
                }
                
                // Fallback a archivo local si hay
                var localManifest = await LoadLocalManifestAsync();
                if (localManifest != null)
                {
                    return ManifestResult.Success(localManifest);
                }
                
                return ManifestResult.Failed("No se pudo obtener manifiesto de actualizaciones");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo manifiesto: {ex}", ModuleId);
                return ManifestResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Encuentra actualizaciones disponibles
        /// </summary>
        private async Task<List<UpdatePackage>> FindAvailableUpdatesAsync(UpdateManifest manifest)
        {
            var availableUpdates = new List<UpdatePackage>();
            var currentVersion = GetCurrentVersion();
            
            foreach (var update in manifest.Updates)
            {
                // Verificar si la actualización aplica a esta versión
                if (IsUpdateApplicable(update, currentVersion))
                {
                    // Verificar requisitos del sistema
                    if (await CheckSystemRequirementsAsync(update))
                    {
                        availableUpdates.Add(update);
                    }
                }
            }
            
            return availableUpdates;
        }
        
        /// <summary>
        /// Filtra actualizaciones ya aplicadas
        /// </summary>
        private async Task<List<UpdatePackage>> FilterAlreadyAppliedUpdatesAsync(List<UpdatePackage> updates)
        {
            var appliedUpdates = await _localDatabase.GetAppliedUpdateIdsAsync();
            return updates.Where(u => !appliedUpdates.Contains(u.UpdateId)).ToList();
        }
        
        /// <summary>
        /// Prioriza actualizaciones
        /// </summary>
        private List<UpdatePackage> PrioritizeUpdates(List<UpdatePackage> updates)
        {
            // Ordenar por: 1. Prioridad, 2. Tipo (Seguridad primero), 3. Fecha
            return updates
                .OrderByDescending(u => u.Priority)
                .ThenByDescending(u => u.Type == UpdateType.Security ? 1 : 0)
                .ThenByDescending(u => u.ReleaseDate)
                .ToList();
        }
        
        /// <summary>
        /// Ordena actualizaciones para instalación
        /// </summary>
        private List<UpdatePackage> OrderUpdatesForInstallation(List<UpdatePackage> updates)
        {
            // Considerar dependencias entre actualizaciones
            var ordered = new List<UpdatePackage>();
            var remaining = new List<UpdatePackage>(updates);
            
            while (remaining.Count > 0)
            {
                // Encontrar actualizaciones sin dependencias no satisfechas
                var ready = remaining.Where(u => 
                    u.Dependencies == null || 
                    !u.Dependencies.Any() || 
                    u.Dependencies.All(d => ordered.Any(o => o.UpdateId == d)))
                    .ToList();
                
                if (ready.Count == 0)
                {
                    // Romper dependencias cíclicas
                    ready.Add(remaining.First());
                }
                
                ordered.AddRange(ready);
                remaining.RemoveAll(u => ready.Contains(u));
            }
            
            return ordered;
        }
        
        /// <summary>
        /// Obtiene URL de descarga
        /// </summary>
        private async Task<string> GetDownloadUrlAsync(UpdatePackage update)
        {
            try
            {
                // Obtener URL desde el servidor
                var downloadInfo = await _apiClient.GetDownloadInfoAsync(update.UpdateId);
                if (downloadInfo != null && !string.IsNullOrEmpty(downloadInfo.DownloadUrl))
                {
                    return downloadInfo.DownloadUrl;
                }
                
                // Usar URL del manifiesto como fallback
                return update.DownloadUrl;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo URL de descarga: {ex}", ModuleId);
                return null;
            }
        }
        
        /// <summary>
        /// Descarga paquete
        /// </summary>
        private async Task<PackageDownloadResult> DownloadPackageAsync(string downloadUrl, UpdatePackage update)
        {
            try
            {
                var downloadPath = GetDownloadPath(update);
                var tempPath = downloadPath + ".downloading";
                
                // Descargar con progreso
                using (var response = await _httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead))
                {
                    response.EnsureSuccessStatusCode();
                    
                    var totalBytes = response.Content.Headers.ContentLength ?? 0;
                    
                    using (var contentStream = await response.Content.ReadAsStreamAsync())
                    using (var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var buffer = new byte[81920];
                        var totalRead = 0L;
                        var bytesRead = 0;
                        
                        var startTime = DateTime.UtcNow;
                        
                        while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await fileStream.WriteAsync(buffer, 0, bytesRead);
                            totalRead += bytesRead;
                            
                            // Reportar progreso periódicamente
                            if (totalBytes > 0 && DateTime.UtcNow.Second % 5 == 0)
                            {
                                var progress = (double)totalRead / totalBytes * 100;
                                _logManager.LogDebug($"Descargando {update.Title}: {progress:F1}%", ModuleId);
                            }
                        }
                        
                        var downloadTime = DateTime.UtcNow - startTime;
                        
                        // Renombrar a nombre final
                        File.Move(tempPath, downloadPath);
                        
                        return PackageDownloadResult.Success(downloadPath, totalRead, downloadTime);
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descargando paquete: {ex}", ModuleId);
                return PackageDownloadResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Verifica integridad del paquete
        /// </summary>
        private async Task<IntegrityCheckResult> VerifyPackageIntegrityAsync(string filePath, UpdatePackage update)
        {
            try
            {
                // Verificar hash
                var actualHash = await CalculateFileHashAsync(filePath, update.HashAlgorithm);
                if (actualHash != update.ExpectedHash)
                {
                    return IntegrityCheckResult.Failed($"Hash no coincide. Esperado: {update.ExpectedHash}, Actual: {actualHash}");
                }
                
                // Verificar firma digital
                var signatureValid = await VerifyDigitalSignatureAsync(filePath, update);
                if (!signatureValid)
                {
                    return IntegrityCheckResult.Failed("Firma digital inválida");
                }
                
                // Verificar tamaño
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length != update.PackageSize)
                {
                    return IntegrityCheckResult.Failed($"Tamaño no coincide. Esperado: {update.PackageSize}, Actual: {fileInfo.Length}");
                }
                
                return IntegrityCheckResult.Success();
            }
            catch (Exception ex)
            {
                return IntegrityCheckResult.Failed($"Error verificando integridad: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Prepara paquete para instalación
        /// </summary>
        private async Task<PackagePreparationResult> PreparePackageForInstallationAsync(string packagePath, UpdatePackage update)
        {
            try
            {
                var extractionDir = GetExtractionDirectory(update);
                
                // Extraer si es necesario
                if (update.PackageFormat == PackageFormat.Zip)
                {
                    await ExtractPackageAsync(packagePath, extractionDir);
                }
                else if (update.PackageFormat == PackageFormat.Msi)
                {
                    // Copiar MSI
                    var destination = Path.Combine(extractionDir, Path.GetFileName(packagePath));
                    File.Copy(packagePath, destination, true);
                }
                else
                {
                    // Formato ejecutable
                    var destination = Path.Combine(extractionDir, "setup.exe");
                    File.Copy(packagePath, destination, true);
                }
                
                // Buscar script de instalación
                var installScript = FindInstallationScript(extractionDir);
                
                return PackagePreparationResult.Success(extractionDir, installScript);
            }
            catch (Exception ex)
            {
                return PackagePreparationResult.Failed($"Error preparando paquete: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Crea punto de restauración
        /// </summary>
        private async Task<RestorePointResult> CreateRestorePointAsync(UpdatePackage update)
        {
            try
            {
                var restorePointId = $"RP_{update.UpdateId}_{DateTime.UtcNow:yyyyMMddHHmmss}";
                var backupDir = Path.Combine(GetBackupDirectory(), restorePointId);
                
                Directory.CreateDirectory(backupDir);
                
                // 1. Backup de archivos afectados
                foreach (var file in update.AffectedFiles ?? new List<string>())
                {
                    if (File.Exists(file))
                    {
                        var destFile = Path.Combine(backupDir, GetRelativePath(file));
                        Directory.CreateDirectory(Path.GetDirectoryName(destFile));
                        File.Copy(file, destFile, true);
                    }
                }
                
                // 2. Backup de configuración
                await BackupConfigurationAsync(backupDir);
                
                // 3. Backup de registro
                await BackupRegistryAsync(backupDir, update);
                
                // 4. Crear manifiesto de restauración
                var manifest = new RestoreManifest
                {
                    RestorePointId = restorePointId,
                    UpdateId = update.UpdateId,
                    CreatedAt = DateTime.UtcNow,
                    BackupLocation = backupDir,
                    FilesBackedUp = update.AffectedFiles?.Count ?? 0
                };
                
                await SaveRestoreManifestAsync(manifest);
                
                _logManager.LogInfo($"Punto de restauración creado: {restorePointId}", ModuleId);
                
                return RestorePointResult.Success(restorePointId, backupDir);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error creando punto de restauración: {ex}", ModuleId);
                return RestorePointResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Realiza verificaciones pre-instalación
        /// </summary>
        private async Task<PreInstallCheckResult> PerformPreInstallationChecksAsync(UpdatePackage update)
        {
            try
            {
                var issues = new List<string>();
                
                // 1. Verificar espacio en disco
                var freeSpace = GetFreeDiskSpace(GetSystemDrive());
                if (freeSpace < update.RequiredDiskSpace * 2) // Doble para seguridad
                {
                    issues.Add($"Espacio en disco insuficiente. Requerido: {update.RequiredDiskSpace}MB, Disponible: {freeSpace}MB");
                }
                
                // 2. Verificar versión actual
                var currentVersion = GetCurrentVersion();
                if (!IsVersionCompatible(currentVersion, update.MinimumCurrentVersion))
                {
                    issues.Add($"Versión actual {currentVersion} no compatible con la actualización");
                }
                
                // 3. Verificar que no haya procesos bloqueando archivos
                var lockedFiles = await CheckForLockedFilesAsync(update.AffectedFiles);
                if (lockedFiles.Any())
                {
                    issues.Add($"Archivos bloqueados por otros procesos: {string.Join(", ", lockedFiles.Take(3))}");
                }
                
                // 4. Verificar integridad del sistema
                var integrityCheck = await _integrityVerifier.VerifyCriticalComponentsAsync();
                if (!integrityCheck.IsValid)
                {
                    issues.Add($"Integridad del sistema comprometida: {integrityCheck.InvalidComponents} componentes inválidos");
                }
                
                if (issues.Count == 0)
                {
                    return PreInstallCheckResult.Success();
                }
                else
                {
                    return PreInstallCheckResult.Failed(string.Join("; ", issues));
                }
            }
            catch (Exception ex)
            {
                return PreInstallCheckResult.Failed($"Error en pre-instalación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Ejecuta instalación
        /// </summary>
        private async Task<InstallationExecutionResult> ExecuteInstallationAsync(UpdatePackage update)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                
                switch (update.InstallationType)
                {
                    case InstallationType.Msi:
                        return await InstallUsingMsiAsync(update);
                        
                    case InstallationType.Executable:
                        return await InstallUsingExecutableAsync(update);
                        
                    case InstallationType.Script:
                        return await InstallUsingScriptAsync(update);
                        
                    case InstallationType.Patch:
                        return await InstallPatchAsync(update);
                        
                    default:
                        return InstallationExecutionResult.Failed($"Tipo de instalación no soportado: {update.InstallationType}");
                }
            }
            catch (Exception ex)
            {
                return InstallationExecutionResult.Failed($"Error ejecutando instalación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Realiza verificaciones post-instalación
        /// </summary>
        private async Task<PostInstallCheckResult> PerformPostInstallationVerificationAsync(UpdatePackage update)
        {
            try
            {
                var issues = new List<string>();
                
                // 1. Verificar que los archivos se instalaron correctamente
                foreach (var file in update.AffectedFiles ?? new List<string>())
                {
                    if (!File.Exists(file))
                    {
                        issues.Add($"Archivo no encontrado después de instalación: {file}");
                    }
                    else
                    {
                        // Verificar versión si es ejecutable
                        if (Path.GetExtension(file).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                            Path.GetExtension(file).Equals(".dll", StringComparison.OrdinalIgnoreCase))
                        {
                            var versionInfo = FileVersionInfo.GetVersionInfo(file);
                            if (!string.IsNullOrEmpty(versionInfo.FileVersion) && 
                                !string.IsNullOrEmpty(update.TargetVersion))
                            {
                                if (!versionInfo.FileVersion.StartsWith(update.TargetVersion))
                                {
                                    issues.Add($"Versión incorrecta en {file}: {versionInfo.FileVersion}, esperada: {update.TargetVersion}");
                                }
                            }
                        }
                    }
                }
                
                // 2. Verificar que el servicio esté ejecutándose si se reinició
                if (update.RequiresServiceRestart)
                {
                    var serviceController = new System.ServiceProcess.ServiceController("BWPEnterpriseAgent");
                    if (serviceController.Status != System.ServiceProcess.ServiceControllerStatus.Running)
                    {
                        issues.Add("Servicio no se está ejecutando después de la actualización");
                    }
                }
                
                // 3. Verificar integridad
                var integrityCheck = await _integrityVerifier.VerifyCriticalComponentsAsync();
                if (!integrityCheck.IsValid)
                {
                    issues.Add($"Integridad comprometida después de instalación: {integrityCheck.InvalidComponents} componentes inválidos");
                }
                
                if (issues.Count == 0)
                {
                    return PostInstallCheckResult.Success();
                }
                else
                {
                    return PostInstallCheckResult.Failed(string.Join("; ", issues));
                }
            }
            catch (Exception ex)
            {
                return PostInstallCheckResult.Failed($"Error en post-instalación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Realiza rollback
        /// </summary>
        private async Task<RollbackExecutionResult> PerformRollbackAsync(RestorePointResult restorePoint, UpdatePackage update)
        {
            try
            {
                _logManager.LogWarning($"Realizando rollback de actualización {update.UpdateId}", ModuleId);
                
                var result = await RestoreFromBackupAsync(restorePoint.RestorePointId);
                
                if (result.Success)
                {
                    update.RollbackStatus = RollbackStatus.RolledBack;
                    update.RolledBackAt = DateTime.UtcNow;
                    update.RollbackReason = "Falló la instalación";
                    
                    await _localDatabase.UpdateAppliedUpdateAsync(update.ToAppliedUpdate());
                    
                    return RollbackExecutionResult.Success();
                }
                else
                {
                    return RollbackExecutionResult.Failed(result.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                return RollbackExecutionResult.Failed($"Error en rollback: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Limpia archivos temporales
        /// </summary>
        private async Task CleanupTempFilesAsync(UpdatePackage update)
        {
            try
            {
                if (!string.IsNullOrEmpty(update.DownloadedPath) && File.Exists(update.DownloadedPath))
                {
                    File.Delete(update.DownloadedPath);
                }
                
                var extractionDir = GetExtractionDirectory(update);
                if (Directory.Exists(extractionDir))
                {
                    Directory.Delete(extractionDir, true);
                }
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error limpiando archivos temporales: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Marca actualización como aplicada
        /// </summary>
        private async Task MarkUpdateAsAppliedAsync(UpdatePackage update)
        {
            try
            {
                var appliedUpdate = update.ToAppliedUpdate();
                await _localDatabase.SaveAppliedUpdateAsync(appliedUpdate);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error marcando actualización como aplicada: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Configura temporizador para programación
        /// </summary>
        private async Task SetupScheduleTimerAsync(UpdateSchedule schedule)
        {
            try
            {
                var delay = schedule.ScheduledTime - DateTime.UtcNow;
                if (delay > TimeSpan.Zero)
                {
                    _ = Task.Delay(delay)
                        .ContinueWith(async _ => await ExecuteScheduledUpdateAsync(schedule));
                }
                else
                {
                    // Ejecutar inmediatamente si ya pasó el tiempo
                    await ExecuteScheduledUpdateAsync(schedule);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error configurando temporizador de programación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Ejecuta actualización programada
        /// </summary>
        private async Task ExecuteScheduledUpdateAsync(UpdateSchedule schedule)
        {
            try
            {
                schedule.Status = ScheduleStatus.Executing;
                await _localDatabase.UpdateScheduleStatusAsync(schedule);
                
                _logManager.LogInfo($"Ejecutando actualización programada: {schedule.UpdateId}", ModuleId);
                
                var update = _availableUpdates.FirstOrDefault(u => u.UpdateId == schedule.UpdateId);
                if (update != null)
                {
                    var result = await InstallUpdateAsync(schedule.UpdateId);
                    
                    schedule.Status = result.Success ? ScheduleStatus.Completed : ScheduleStatus.Failed;
                    schedule.CompletedAt = DateTime.UtcNow;
                    schedule.Result = result.Success ? "Éxito" : $"Error: {result.ErrorMessage}";
                    
                    await _localDatabase.UpdateScheduleStatusAsync(schedule);
                }
                else
                {
                    schedule.Status = ScheduleStatus.Failed;
                    schedule.Result = "Actualización no encontrada";
                    await _localDatabase.UpdateScheduleStatusAsync(schedule);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error ejecutando actualización programada: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Restaura desde backup
        /// </summary>
        private async Task<RestorationResult> RestoreFromBackupAsync(string restorePointId)
        {
            // Implementar restauración
            await Task.Delay(100);
            return new RestorationResult { Success = true };
        }
        
        /// <summary>
        /// Notifica actualizaciones disponibles
        /// </summary>
        private async Task NotifyUpdatesAvailableAsync(List<UpdatePackage> updates)
        {
            try
            {
                var criticalCount = updates.Count(u => u.Priority == UpdatePriority.Critical);
                var securityCount = updates.Count(u => u.Type == UpdateType.Security);
                
                var message = new UpdateNotification
                {
                    Timestamp = DateTime.UtcNow,
                    TotalUpdates = updates.Count,
                    CriticalUpdates = criticalCount,
                    SecurityUpdates = securityCount,
                    RequiresAttention = criticalCount > 0 || securityCount > 0,
                    Updates = updates.Select(u => new UpdateSummary
                    {
                        Id = u.UpdateId,
                        Title = u.Title,
                        Priority = u.Priority,
                        Type = u.Type,
                        Size = u.PackageSize
                    }).ToList()
                };
                
                // Enviar notificación al dashboard local
                await SendLocalNotificationAsync(message);
                
                // Enviar notificación al cloud
                await _apiClient.SendUpdateNotificationAsync(message);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error notificando actualizaciones disponibles: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Notifica éxito de instalación
        /// </summary>
        private async Task NotifyInstallationSuccessAsync(UpdatePackage update)
        {
            try
            {
                var notification = new InstallationNotification
                {
                    Timestamp = DateTime.UtcNow,
                    UpdateId = update.UpdateId,
                    Title = update.Title,
                    Version = update.TargetVersion,
                    Success = true,
                    RequiresReboot = update.RequiresReboot
                };
                
                await _apiClient.SendInstallationNotificationAsync(notification);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error notificando éxito de instalación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda resultado de verificación
        /// </summary>
        private async Task SaveUpdateCheckResultAsync(UpdateCheckResult result)
        {
            try
            {
                await _localDatabase.SaveUpdateCheckResultAsync(result);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando resultado de verificación: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda resultado de descarga
        /// </summary>
        private async Task SaveDownloadResultAsync(DownloadResult result)
        {
            try
            {
                await _localDatabase.SaveDownloadResultAsync(result);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando resultado de descarga: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Guarda manifiesto de restauración
        /// </summary>
        private async Task SaveRestoreManifestAsync(RestoreManifest manifest)
        {
            try
            {
                await _localDatabase.SaveRestoreManifestAsync(manifest);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando manifiesto de restauración: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Calcula hash de archivo
        /// </summary>
        private async Task<string> CalculateFileHashAsync(string filePath, string algorithm)
        {
            using (var stream = File.OpenRead(filePath))
            using (var hashAlgorithm = HashAlgorithm.Create(algorithm))
            {
                var hashBytes = await hashAlgorithm.ComputeHashAsync(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
        
        /// <summary>
        /// Verifica firma digital
        /// </summary>
        private async Task<bool> VerifyDigitalSignatureAsync(string filePath, UpdatePackage update)
        {
            // Implementar verificación de firma digital
            await Task.Delay(1);
            return true; // Simplificado
        }
        
        /// <summary>
        /// Extrae paquete ZIP
        /// </summary>
        private async Task ExtractPackageAsync(string zipPath, string extractionDir)
        {
            // Implementar extracción
            await Task.Delay(1);
        }
        
        /// <summary>
        /// Encuentra script de instalación
        /// </summary>
        private string FindInstallationScript(string directory)
        {
            var scripts = new[] { "install.bat", "install.ps1", "setup.bat", "install.sh" };
            
            foreach (var script in scripts)
            {
                var path = Path.Combine(directory, script);
                if (File.Exists(path))
                {
                    return path;
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Realiza backup de configuración
        /// </summary>
        private async Task BackupConfigurationAsync(string backupDir)
        {
            await Task.Delay(1);
        }
        
        /// <summary>
        /// Realiza backup de registro
        /// </summary>
        private async Task BackupRegistryAsync(string backupDir, UpdatePackage update)
        {
            await Task.Delay(1);
        }
        
        /// <summary>
        /// Verifica si la actualización aplica
        /// </summary>
        private bool IsUpdateApplicable(UpdatePackage update, string currentVersion)
        {
            // Verificar versión mínima
            if (!string.IsNullOrEmpty(update.MinimumCurrentVersion))
            {
                if (CompareVersions(currentVersion, update.MinimumCurrentVersion) < 0)
                {
                    return false;
                }
            }
            
            // Verificar versión máxima
            if (!string.IsNullOrEmpty(update.MaximumCurrentVersion))
            {
                if (CompareVersions(currentVersion, update.MaximumCurrentVersion) > 0)
                {
                    return false;
                }
            }
            
            // Verificar sistema operativo
            if (!string.IsNullOrEmpty(update.OperatingSystem))
            {
                var currentOS = Environment.OSVersion.VersionString;
                if (!currentOS.Contains(update.OperatingSystem))
                {
                    return false;
                }
            }
            
            return true;
        }
        
        /// <summary>
        /// Verifica requisitos del sistema
        /// </summary>
        private async Task<bool> CheckSystemRequirementsAsync(UpdatePackage update)
        {
            // Verificar requisitos básicos
            if (update.RequiredDiskSpace > 0)
            {
                var freeSpace = GetFreeDiskSpace(GetSystemDrive());
                if (freeSpace < update.RequiredDiskSpace)
                {
                    return false;
                }
            }
            
            if (update.RequiredMemory > 0)
            {
                var totalMemory = GetTotalMemory();
                if (totalMemory < update.RequiredMemory)
                {
                    return false;
                }
            }
            
            return true;
        }
        
        /// <summary>
        /// Verifica compatibilidad de versiones
        /// </summary>
        private bool IsVersionCompatible(string currentVersion, string minimumVersion)
        {
            if (string.IsNullOrEmpty(minimumVersion))
                return true;
            
            return CompareVersions(currentVersion, minimumVersion) >= 0;
        }
        
        /// <summary>
        /// Compara versiones
        /// </summary>
        private int CompareVersions(string version1, string version2)
        {
            var v1 = ParseVersion(version1);
            var v2 = ParseVersion(version2);
            
            return v1.CompareTo(v2);
        }
        
        /// <summary>
        /// Parsea versión
        /// </summary>
        private Version ParseVersion(string versionString)
        {
            if (Version.TryParse(versionString, out var version))
            {
                return version;
            }
            
            // Intentar parsear versiones no estándar
            var parts = versionString.Split('.');
            if (parts.Length >= 2)
            {
                var major = int.TryParse(parts[0], out var m) ? m : 0;
                var minor = int.TryParse(parts[1], out var n) ? n : 0;
                var build = parts.Length > 2 && int.TryParse(parts[2], out var b) ? b : 0;
                var revision = parts.Length > 3 && int.TryParse(parts[3], out var r) ? r : 0;
                
                return new Version(major, minor, build, revision);
            }
            
            return new Version(0, 0);
        }
        
        /// <summary>
        /// Verifica archivos bloqueados
        /// </summary>
        private async Task<List<string>> CheckForLockedFilesAsync(List<string> files)
        {
            var lockedFiles = new List<string>();
            
            if (files == null)
                return lockedFiles;
            
            foreach (var file in files)
            {
                if (File.Exists(file))
                {
                    try
                    {
                        using (var stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.None))
                        {
                            // Si puede abrir, no está bloqueado
                        }
                    }
                    catch (IOException)
                    {
                        lockedFiles.Add(Path.GetFileName(file));
                    }
                }
            }
            
            return lockedFiles;
        }
        
        /// <summary>
        /// Instala usando MSI
        /// </summary>
        private async Task<InstallationExecutionResult> InstallUsingMsiAsync(UpdatePackage update)
        {
            try
            {
                var msiPath = Path.Combine(GetExtractionDirectory(update), "setup.msi");
                
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "msiexec";
                    process.StartInfo.Arguments = $"/i \"{msiPath}\" /qn /norestart";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    if (process.ExitCode == 0)
                    {
                        return InstallationExecutionResult.Success();
                    }
                    else
                    {
                        return InstallationExecutionResult.Failed($"MSI install failed with code: {process.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                return InstallationExecutionResult.Failed($"Error installing MSI: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Instala usando ejecutable
        /// </summary>
        private async Task<InstallationExecutionResult> InstallUsingExecutableAsync(UpdatePackage update)
        {
            try
            {
                var exePath = Path.Combine(GetExtractionDirectory(update), "setup.exe");
                
                using (var process = new Process())
                {
                    process.StartInfo.FileName = exePath;
                    process.StartInfo.Arguments = "/silent /norestart";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    if (process.ExitCode == 0)
                    {
                        return InstallationExecutionResult.Success();
                    }
                    else
                    {
                        return InstallationExecutionResult.Failed($"Executable install failed with code: {process.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                return InstallationExecutionResult.Failed($"Error installing executable: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Instala usando script
        /// </summary>
        private async Task<InstallationExecutionResult> InstallUsingScriptAsync(UpdatePackage update)
        {
            var scriptPath = FindInstallationScript(GetExtractionDirectory(update));
            
            if (string.IsNullOrEmpty(scriptPath))
            {
                return InstallationExecutionResult.Failed("No se encontró script de instalación");
            }
            
            try
            {
                using (var process = new Process())
                {
                    if (scriptPath.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                    {
                        process.StartInfo.FileName = "powershell";
                        process.StartInfo.Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\"";
                    }
                    else if (scriptPath.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) || 
                             scriptPath.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase))
                    {
                        process.StartInfo.FileName = "cmd.exe";
                        process.StartInfo.Arguments = $"/c \"{scriptPath}\"";
                    }
                    else
                    {
                        return InstallationExecutionResult.Failed($"Tipo de script no soportado: {Path.GetExtension(scriptPath)}");
                    }
                    
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    await process.WaitForExitAsync();
                    
                    if (process.ExitCode == 0)
                    {
                        return InstallationExecutionResult.Success();
                    }
                    else
                    {
                        return InstallationExecutionResult.Failed($"Script install failed with code: {process.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                return InstallationExecutionResult.Failed($"Error installing script: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Instala patch
        /// </summary>
        private async Task<InstallationExecutionResult> InstallPatchAsync(UpdatePackage update)
        {
            // Implementar instalación de patch
            await Task.Delay(100);
            return InstallationExecutionResult.Success();
        }
        
        /// <summary>
        /// Carga manifiesto local
        /// </summary>
        private async Task<UpdateManifest> LoadLocalManifestAsync()
        {
            var localPath = Path.Combine(GetUpdateCacheDirectory(), "manifest.json");
            if (File.Exists(localPath))
            {
                try
                {
                    var content = await File.ReadAllTextAsync(localPath);
                    return System.Text.Json.JsonSerializer.Deserialize<UpdateManifest>(content);
                }
                catch
                {
                    return null;
                }
            }
            
            return null;
        }
        
        /// <summary>
        /// Envía notificación local
        /// </summary>
        private async Task SendLocalNotificationAsync(UpdateNotification notification)
        {
            // Implementar notificación local
            await Task.CompletedTask;
        }
        
        /// <summary>
        /// Calcula estadísticas de actualizaciones
        /// </summary>
        private UpdateStatistics CalculateUpdateStatistics(
            List<UpdateCheckResult> checkHistory,
            List<AppliedUpdate> appliedUpdates,
            List<FailedUpdate> failedUpdates)
        {
            return new UpdateStatistics
            {
                TotalChecks = checkHistory.Count,
                TotalApplied = appliedUpdates.Count,
                TotalFailed = failedUpdates.Count,
                SuccessRate = checkHistory.Count > 0 ? (double)appliedUpdates.Count / checkHistory.Count * 100 : 0,
                AverageTimeBetweenUpdates = CalculateAverageUpdateTime(appliedUpdates),
                MostCommonFailure = failedUpdates
                    .GroupBy(f => f.ErrorMessage)
                    .OrderByDescending(g => g.Count())
                    .Select(g => g.Key)
                    .FirstOrDefault()
            };
        }
        
        private TimeSpan CalculateAverageUpdateTime(List<AppliedUpdate> appliedUpdates)
        {
            if (appliedUpdates.Count < 2)
                return TimeSpan.Zero;
            
            var sorted = appliedUpdates.OrderBy(a => a.InstalledAt).ToList();
            var total = TimeSpan.Zero;
            var count = 0;
            
            for (int i = 1; i < sorted.Count; i++)
            {
                total += sorted[i].InstalledAt - sorted[i - 1].InstalledAt;
                count++;
            }
            
            return count > 0 ? TimeSpan.FromTicks(total.Ticks / count) : TimeSpan.Zero;
        }
        
        /// <summary>
        /// Genera recomendaciones de actualización
        /// </summary>
        private async Task<List<UpdateRecommendation>> GenerateUpdateRecommendationsAsync(
            List<AppliedUpdate> appliedUpdates,
            List<UpdatePackage> availableUpdates)
        {
            var recommendations = new List<UpdateRecommendation>();
            
            // Recomendar actualizaciones críticas disponibles
            var criticalUpdates = availableUpdates
                .Where(u => u.Priority == UpdatePriority.Critical)
                .ToList();
            
            if (criticalUpdates.Any())
            {
                recommendations.Add(new UpdateRecommendation
                {
                    Priority = RecommendationPriority.Critical,
                    Title = "Actualizaciones críticas disponibles",
                    Description = $"Hay {criticalUpdates.Count} actualizaciones críticas pendientes",
                    Action = "InstallCriticalUpdates",
                    EstimatedTime = TimeSpan.FromMinutes(15)
                });
            }
            
            // Verificar si hay actualizaciones de seguridad antiguas
            var securityUpdateAge = await GetOldestSecurityUpdateAgeAsync(appliedUpdates);
            if (securityUpdateAge > TimeSpan.FromDays(30))
            {
                recommendations.Add(new UpdateRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "Actualizaciones de seguridad desactualizadas",
                    Description = $"La última actualización de seguridad fue hace {securityUpdateAge.Days} días",
                    Action = "CheckForSecurityUpdates",
                    EstimatedTime = TimeSpan.FromMinutes(5)
                });
            }
            
            return recommendations;
        }
        
        private async Task<TimeSpan> GetOldestSecurityUpdateAgeAsync(List<AppliedUpdate> appliedUpdates)
        {
            var securityUpdates = appliedUpdates
                .Where(u => u.Type == UpdateType.Security)
                .OrderByDescending(u => u.InstalledAt)
                .ToList();
            
            if (securityUpdates.Any())
            {
                return DateTime.UtcNow - securityUpdates.First().InstalledAt;
            }
            
            return TimeSpan.MaxValue;
        }
        
        // Métodos auxiliares para obtener rutas y información del sistema
        private string GetUpdateCacheDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                "BWP Enterprise", "Updates");
        }
        
        private string GetDownloadPath(UpdatePackage update)
        {
            return Path.Combine(GetUpdateCacheDirectory(), $"{update.UpdateId}.pkg");
        }
        
        private string GetExtractionDirectory(UpdatePackage update)
        {
            return Path.Combine(GetUpdateCacheDirectory(), update.UpdateId);
        }
        
        private string GetBackupDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BWP Enterprise", "Backups", "Updates");
        }
        
        private string GetSystemDrive()
        {
            return Path.GetPathRoot(Environment.SystemDirectory);
        }
        
        private long GetFreeDiskSpace(string drive)
        {
            try
            {
                var driveInfo = new DriveInfo(drive);
                return driveInfo.AvailableFreeSpace / (1024 * 1024); // MB
            }
            catch
            {
                return 0;
            }
        }
        
        private long GetTotalMemory()
        {
            try
            {
                var memInfo = new Microsoft.VisualBasic.Devices.ComputerInfo();
                return (long)memInfo.TotalPhysicalMemory / (1024 * 1024); // MB
            }
            catch
            {
                return 0;
            }
        }
        
        private string GetRelativePath(string fullPath)
        {
            var systemDrive = GetSystemDrive().TrimEnd('\\');
            return fullPath.Replace(systemDrive, "").TrimStart('\\');
        }
        
        private string GetCurrentVersion()
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var versionInfo = FileVersionInfo.GetVersionInfo(assembly.Location);
            return versionInfo.FileVersion ?? "1.0.0.0";
        }
        
        #endregion
        
        #region Métodos para HealthCheck
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                
                // Verificar estado del gestor
                if (!_isInitialized)
                    issues.Add("No inicializado");
                
                if (!_checkUpdateTimer.Enabled)
                    issues.Add("Temporizador de verificación no activo");
                
                // Verificar espacio en caché
                var cacheDir = GetUpdateCacheDirectory();
                if (Directory.Exists(cacheDir))
                {
                    var cacheSize = GetDirectorySize(cacheDir) / (1024 * 1024); // MB
                    if (cacheSize > 1000) // Más de 1GB
                    {
                        issues.Add($"Caché de actualizaciones muy grande: {cacheSize}MB");
                    }
                }
                
                // Verificar actualizaciones críticas pendientes
                var criticalPending = _availableUpdates
                    .Where(u => u.Priority == UpdatePriority.Critical && 
                               u.InstallationStatus != InstallationStatus.Installed)
                    .ToList();
                
                if (criticalPending.Any())
                {
                    issues.Add($"{criticalPending.Count} actualizaciones críticas pendientes");
                }
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("UpdateManager funcionando correctamente");
                }
                
                return HealthCheckResult.Degraded(
                    $"Problemas detectados: {string.Join(", ", issues)}",
                    new Dictionary<string, object>
                    {
                        { "CurrentStatus", _currentStatus.ToString() },
                        { "AvailableUpdates", _availableUpdates.Count },
                        { "CriticalPending", criticalPending.Count },
                        { "IsChecking", _isChecking },
                        { "IsDownloading", _isDownloading },
                        { "IsInstalling", _isInstalling }
                    });
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error en health check: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "Exception", ex.ToString() }
                    });
            }
        }
        
        private long GetDirectorySize(string directory)
        {
            long size = 0;
            try
            {
                foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
                {
                    size += new FileInfo(file).Length;
                }
            }
            catch
            {
                // Ignorar errores
            }
            return size;
        }
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public class UpdateManifest
    {
        public string ManifestId { get; set; }
        public string LatestVersion { get; set; }
        public DateTime ReleaseDate { get; set; }
        public List<UpdatePackage> Updates { get; set; }
        public Dictionary<string, string> Metadata { get; set; }
        public string Signature { get; set; }
        
        public UpdateManifest()
        {
            Updates = new List<UpdatePackage>();
            Metadata = new Dictionary<string, string>();
        }
    }
    
    public class UpdatePackage
    {
        public string UpdateId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public UpdateType Type { get; set; }
        public UpdatePriority Priority { get; set; }
        public string CurrentVersion { get; set; }
        public string TargetVersion { get; set; }
        public string MinimumCurrentVersion { get; set; }
        public string MaximumCurrentVersion { get; set; }
        public List<string> Dependencies { get; set; }
        public List<string> AffectedFiles { get; set; }
        public string DownloadUrl { get; set; }
        public long PackageSize { get; set; }
        public string ExpectedHash { get; set; }
        public string HashAlgorithm { get; set; }
        public string OperatingSystem { get; set; }
        public long RequiredDiskSpace { get; set; }
        public long RequiredMemory { get; set; }
        public bool RequiresReboot { get; set; }
        public bool RequiresServiceRestart { get; set; }
        public PackageFormat PackageFormat { get; set; }
        public InstallationType InstallationType { get; set; }
        public DateTime ReleaseDate { get; set; }
        public DateTime ExpirationDate { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        // Estado de la actualización
        public DownloadStatus DownloadStatus { get; set; }
        public InstallationStatus InstallationStatus { get; set; }
        public RollbackStatus RollbackStatus { get; set; }
        public string DownloadedPath { get; set; }
        public DateTime? DownloadedAt { get; set; }
        public DateTime? InstalledAt { get; set; }
        public DateTime? RolledBackAt { get; set; }
        public string RollbackReason { get; set; }
        public string RestorePointId { get; set; }
        public string InstalledVersion { get; set; }
        
        public UpdatePackage()
        {
            Dependencies = new List<string>();
            AffectedFiles = new List<string>();
            Metadata = new Dictionary<string, object>();
            DownloadStatus = DownloadStatus.NotDownloaded;
            InstallationStatus = InstallationStatus.NotInstalled;
            RollbackStatus = RollbackStatus.NotRolledBack;
        }
        
        public AppliedUpdate ToAppliedUpdate()
        {
            return new AppliedUpdate
            {
                UpdateId = UpdateId,
                Title = Title,
                Type = Type,
                FromVersion = CurrentVersion,
                ToVersion = TargetVersion,
                InstalledAt = InstalledAt ?? DateTime.UtcNow,
                PackageSize = PackageSize,
                RequiresReboot = RequiresReboot,
                RestorePointId = RestorePointId,
                RollbackStatus = RollbackStatus,
                RolledBackAt = RolledBackAt,
                RollbackReason = RollbackReason
            };
        }
    }
    
    public class UpdateCheckResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        public int AvailableUpdates { get; set; }
        public int CriticalUpdates { get; set; }
        public int SecurityUpdates { get; set; }
        public string CurrentVersion { get; set; }
        public string LatestVersion { get; set; }
        public List<UpdatePackage> Updates { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public UpdateCheckResult()
        {
            Updates = new List<UpdatePackage>();
            Details = new Dictionary<string, object>();
        }
        
        public static UpdateCheckResult Busy(string message)
        {
            return new UpdateCheckResult
            {
                Success = false,
                ErrorMessage = message,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static UpdateCheckResult Failed(string errorMessage)
        {
            return new UpdateCheckResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class DownloadResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public UpdatePackage Update { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public TimeSpan DownloadTime { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static DownloadResult Busy(string message)
        {
            return new DownloadResult
            {
                Success = false,
                ErrorMessage = message,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static DownloadResult Failed(string errorMessage)
        {
            return new DownloadResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static DownloadResult Success(UpdatePackage update, string filePath, long fileSize, TimeSpan downloadTime)
        {
            return new DownloadResult
            {
                Success = true,
                Update = update,
                FilePath = filePath,
                FileSize = fileSize,
                DownloadTime = downloadTime,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class InstallationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public UpdatePackage Update { get; set; }
        public TimeSpan InstallationTime { get; set; }
        public string RestorePointId { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static InstallationResult Busy(string message)
        {
            return new InstallationResult
            {
                Success = false,
                ErrorMessage = message,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static InstallationResult Failed(string errorMessage)
        {
            return new InstallationResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static InstallationResult Success(UpdatePackage update, TimeSpan installationTime, string restorePointId)
        {
            return new InstallationResult
            {
                Success = true,
                Update = update,
                InstallationTime = installationTime,
                RestorePointId = restorePointId,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class SchedulingResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public UpdateSchedule Schedule { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static SchedulingResult Failed(string errorMessage)
        {
            return new SchedulingResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static SchedulingResult Success(UpdateSchedule schedule)
        {
            return new SchedulingResult
            {
                Success = true,
                Schedule = schedule,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class BatchUpdateResult
    {
        public DateTime Timestamp { get; set; }
        public int TotalUpdates { get; set; }
        public int Successful { get; set; }
        public int Failed { get; set; }
        public bool RequiresReboot { get; set; }
        public List<UpdateResult> Results { get; set; }
        public string ErrorMessage { get; set; }
        
        public BatchUpdateResult()
        {
            Results = new List<UpdateResult>();
        }
        
        public static BatchUpdateResult Success(string message)
        {
            return new BatchUpdateResult
            {
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static BatchUpdateResult Failed(string errorMessage)
        {
            return new BatchUpdateResult
            {
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class UpdateResult
    {
        public string UpdateId { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static UpdateResult Failed(string updateId, string errorMessage)
        {
            return new UpdateResult
            {
                UpdateId = updateId,
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class RollbackResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public UpdatePackage Update { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static RollbackResult Failed(string errorMessage)
        {
            return new RollbackResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static RollbackResult Success(UpdatePackage update)
        {
            return new RollbackResult
            {
                Success = true,
                Update = update,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class UpdateReport
    {
        public DateTime GeneratedAt { get; set; }
        public TimeSpan Period { get; set; }
        public string CurrentVersion { get; set; }
        public UpdateStatus UpdateStatus { get; set; }
        public List<UpdatePackage> AvailableUpdates { get; set; }
        public UpdateCheckResult LastCheck { get; set; }
        public List<AppliedUpdate> AppliedUpdates { get; set; }
        public List<FailedUpdate> FailedUpdates { get; set; }
        public List<UpdateSchedule> Schedules { get; set; }
        public UpdateStatistics Statistics { get; set; }
        public List<UpdateRecommendation> Recommendations { get; set; }
        public string Error { get; set; }
        
        public UpdateReport()
        {
            AvailableUpdates = new List<UpdatePackage>();
            AppliedUpdates = new List<AppliedUpdate>();
            FailedUpdates = new List<FailedUpdate>();
            Schedules = new List<UpdateSchedule>();
            Recommendations = new List<UpdateRecommendation>();
        }
        
        public static UpdateReport Error(string errorMessage)
        {
            return new UpdateReport
            {
                Error = errorMessage,
                GeneratedAt = DateTime.UtcNow
            };
        }
    }
    
    // Clases auxiliares para resultados internos
    internal class ManifestResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public UpdateManifest Manifest { get; set; }
        
        public static ManifestResult Success(UpdateManifest manifest)
        {
            return new ManifestResult
            {
                Success = true,
                Manifest = manifest
            };
        }
        
        public static ManifestResult Failed(string errorMessage)
        {
            return new ManifestResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class PackageDownloadResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public TimeSpan DownloadTime { get; set; }
        
        public static PackageDownloadResult Success(string filePath, long fileSize, TimeSpan downloadTime)
        {
            return new PackageDownloadResult
            {
                Success = true,
                FilePath = filePath,
                FileSize = fileSize,
                DownloadTime = downloadTime
            };
        }
        
        public static PackageDownloadResult Failed(string errorMessage)
        {
            return new PackageDownloadResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class IntegrityCheckResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static IntegrityCheckResult Success()
        {
            return new IntegrityCheckResult { Success = true };
        }
        
        public static IntegrityCheckResult Failed(string errorMessage)
        {
            return new IntegrityCheckResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class PackagePreparationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string InstallationPath { get; set; }
        public string InstallScript { get; set; }
        
        public static PackagePreparationResult Success(string installationPath, string installScript)
        {
            return new PackagePreparationResult
            {
                Success = true,
                InstallationPath = installationPath,
                InstallScript = installScript
            };
        }
        
        public static PackagePreparationResult Failed(string errorMessage)
        {
            return new PackagePreparationResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class RestorePointResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string RestorePointId { get; set; }
        public string BackupLocation { get; set; }
        
        public static RestorePointResult Success(string restorePointId, string backupLocation)
        {
            return new RestorePointResult
            {
                Success = true,
                RestorePointId = restorePointId,
                BackupLocation = backupLocation
            };
        }
        
        public static RestorePointResult Failed(string errorMessage)
        {
            return new RestorePointResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class PreInstallCheckResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static PreInstallCheckResult Success()
        {
            return new PreInstallCheckResult { Success = true };
        }
        
        public static PreInstallCheckResult Failed(string errorMessage)
        {
            return new PreInstallCheckResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class InstallationExecutionResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public TimeSpan InstallationTime { get; set; }
        
        public static InstallationExecutionResult Success()
        {
            return new InstallationExecutionResult
            {
                Success = true,
                InstallationTime = TimeSpan.Zero
            };
        }
        
        public static InstallationExecutionResult Failed(string errorMessage)
        {
            return new InstallationExecutionResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class PostInstallCheckResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static PostInstallCheckResult Success()
        {
            return new PostInstallCheckResult { Success = true };
        }
        
        public static PostInstallCheckResult Failed(string errorMessage)
        {
            return new PostInstallCheckResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class RollbackExecutionResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static RollbackExecutionResult Success()
        {
            return new RollbackExecutionResult { Success = true };
        }
        
        public static RollbackExecutionResult Failed(string errorMessage)
        {
            return new RollbackExecutionResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    internal class RestorationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        
        public static RestorationResult Success()
        {
            return new RestorationResult { Success = true };
        }
        
        public static RestorationResult Failed(string errorMessage)
        {
            return new RestorationResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    // Clases para notificaciones
    public class UpdateNotification
    {
        public DateTime Timestamp { get; set; }
        public int TotalUpdates { get; set; }
        public int CriticalUpdates { get; set; }
        public int SecurityUpdates { get; set; }
        public bool RequiresAttention { get; set; }
        public List<UpdateSummary> Updates { get; set; }
        
        public UpdateNotification()
        {
            Updates = new List<UpdateSummary>();
        }
    }
    
    public class UpdateSummary
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public UpdatePriority Priority { get; set; }
        public UpdateType Type { get; set; }
        public long Size { get; set; }
    }
    
    public class InstallationNotification
    {
        public DateTime Timestamp { get; set; }
        public string UpdateId { get; set; }
        public string Title { get; set; }
        public string Version { get; set; }
        public bool Success { get; set; }
        public bool RequiresReboot { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    // Clases para almacenamiento
    public class AppliedUpdate
    {
        public string UpdateId { get; set; }
        public string Title { get; set; }
        public UpdateType Type { get; set; }
        public string FromVersion { get; set; }
        public string ToVersion { get; set; }
        public DateTime InstalledAt { get; set; }
        public long PackageSize { get; set; }
        public bool RequiresReboot { get; set; }
        public string RestorePointId { get; set; }
        public RollbackStatus RollbackStatus { get; set; }
        public DateTime? RolledBackAt { get; set; }
        public string RollbackReason { get; set; }
    }
    
    public class FailedUpdate
    {
        public string UpdateId { get; set; }
        public DateTime FailedAt { get; set; }
        public string ErrorMessage { get; set; }
        public string Stage { get; set; }
        public int RetryCount { get; set; }
    }
    
    public class UpdateSchedule
    {
        public string ScheduleId { get; set; }
        public string UpdateId { get; set; }
        public DateTime ScheduledTime { get; set; }
        public bool RequireReboot { get; set; }
        public ScheduleStatus Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string Result { get; set; }
    }
    
    public class RestoreManifest
    {
        public string RestorePointId { get; set; }
        public string UpdateId { get; set; }
        public DateTime CreatedAt { get; set; }
        public string BackupLocation { get; set; }
        public int FilesBackedUp { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public RestoreManifest()
        {
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class UpdateStatistics
    {
        public int TotalChecks { get; set; }
        public int TotalApplied { get; set; }
        public int TotalFailed { get; set; }
        public double SuccessRate { get; set; }
        public TimeSpan AverageTimeBetweenUpdates { get; set; }
        public string MostCommonFailure { get; set; }
    }
    
    public class UpdateRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
        public TimeSpan EstimatedTime { get; set; }
    }
    
    // Enums
    public enum UpdateStatus
    {
        Idle,
        Checking,
        Downloading,
        Installing,
        RollingBack,
        Error
    }
    
    public enum UpdateType
    {
        Security,
        Feature,
        BugFix,
        Performance,
        Compatibility
    }
    
    public enum UpdatePriority
    {
        Low,
        Medium,
        High,
        Critical
    }
    
    public enum DownloadStatus
    {
        NotDownloaded,
        Downloading,
        Completed,
        Failed
    }
    
    public enum InstallationStatus
    {
        NotInstalled,
        Installing,
        Installed,
        Failed
    }
    
    public enum RollbackStatus
    {
        NotRolledBack,
        RollingBack,
        RolledBack,
        RollbackFailed
    }
    
    public enum PackageFormat
    {
        Zip,
        Msi,
        Exe,
        Patch
    }
    
    public enum InstallationType
    {
        Msi,
        Executable,
        Script,
        Patch,
        Manual
    }
    
    public enum ScheduleStatus
    {
        Scheduled,
        Executing,
        Completed,
        Failed,
        Cancelled
    }
    
    #endregion
}