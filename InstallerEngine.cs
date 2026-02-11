using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using System.IO;

namespace BWP.Installer.Engine
{
    public class InstallerEngine
    {
        private readonly InstallerLogger _logger;
        private readonly InstallationConfiguration _config;
        private readonly InstallationState _state;
        
        private readonly CertificateInstaller _certificateInstaller;
        private readonly DriverInstaller _driverInstaller;
        private readonly FileCopier _fileCopier;
        private readonly ServiceRegistrar _serviceRegistrar;
        
        private bool _isInitialized;
        private bool _installationInProgress;
        
        public InstallerEngine(InstallationConfiguration config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = new InstallerLogger(config.LogFilePath);
            _state = new InstallationState();
            
            _certificateInstaller = new CertificateInstaller();
            _driverInstaller = new DriverInstaller();
            _fileCopier = new FileCopier();
            _serviceRegistrar = new ServiceRegistrar();
            
            _isInitialized = false;
            _installationInProgress = false;
        }
        
        public class InstallationResult
        {
            public bool Success { get; set; }
            public bool RequiresReboot { get; set; }
            public string InstallationId { get; set; }
            public string ErrorMessage { get; set; }
            public Exception Exception { get; set; }
            public Dictionary<string, object> Details { get; set; }
            public TimeSpan InstallationDuration { get; set; }
            
            public InstallationResult()
            {
                Details = new Dictionary<string, object>();
            }
        }
        
        public async Task<InstallationResult> InstallAsync()
        {
            var result = new InstallationResult
            {
                InstallationId = Guid.NewGuid().ToString(),
                InstallationDuration = TimeSpan.Zero
            };
            
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                if (_installationInProgress)
                {
                    throw new InvalidOperationException("Ya hay una instalación en progreso");
                }
                
                _installationInProgress = true;
                _state.Reset();
                
                _logger.LogInfo($"Iniciando instalación {result.InstallationId}");
                _logger.LogInfo($"Producto: {_config.ProductName} v{_config.ProductVersion}");
                _logger.LogInfo($"Destino: {_config.InstallationPath}");
                
                // 1. Verificar requisitos previos
                await ValidatePrerequisitesAsync();
                
                // 2. Crear estructura de directorios
                await CreateDirectoryStructureAsync();
                
                // 3. Copiar archivos
                await CopyFilesAsync();
                
                // 4. Instalar certificados
                await InstallCertificatesAsync();
                
                // 5. Instalar drivers
                await InstallDriversAsync();
                
                // 6. Registrar servicios
                await RegisterServicesAsync();
                
                // 7. Configurar firewall
                await ConfigureFirewallAsync();
                
                // 8. Configurar auto-inicio
                await ConfigureAutoStartAsync();
                
                // 9. Crear accesos directos
                await CreateShortcutsAsync();
                
                // 10. Finalizar instalación
                await FinalizeInstallationAsync(result);
                
                result.Success = true;
                _logger.LogSuccess("Instalación completada exitosamente");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error durante la instalación: {ex.Message}", ex);
                
                // Revertir instalación en caso de error
                await RollbackInstallationAsync();
            }
            finally
            {
                stopwatch.Stop();
                result.InstallationDuration = stopwatch.Elapsed;
                _installationInProgress = false;
                
                _logger.LogInfo($"Duración total: {result.InstallationDuration.TotalSeconds:F2} segundos");
                
                if (result.Success)
                {
                    CreateInstallationReceipt(result);
                }
            }
            
            return result;
        }
        
        public async Task<InstallationResult> UninstallAsync(bool keepData = false)
        {
            var result = new InstallationResult
            {
                InstallationId = Guid.NewGuid().ToString(),
                InstallationDuration = TimeSpan.Zero
            };
            
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                _logger.LogInfo($"Iniciando desinstalación {result.InstallationId}");
                
                // 1. Detener servicios
                await StopServicesAsync();
                
                // 2. Eliminar servicios
                await DeleteServicesAsync();
                
                // 3. Desinstalar drivers
                await UninstallDriversAsync();
                
                // 4. Eliminar certificados
                await UninstallCertificatesAsync();
                
                // 5. Eliminar accesos directos
                await DeleteShortcutsAsync();
                
                // 6. Eliminar registros del firewall
                await RemoveFirewallRulesAsync();
                
                // 7. Eliminar configuración de auto-inicio
                await RemoveAutoStartAsync();
                
                // 8. Eliminar archivos
                await DeleteFilesAsync(keepData);
                
                // 9. Limpiar registro
                await CleanRegistryAsync();
                
                // 10. Finalizar desinstalación
                await FinalizeUninstallationAsync(result);
                
                result.Success = true;
                _logger.LogSuccess("Desinstalación completada exitosamente");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error durante la desinstalación: {ex.Message}", ex);
            }
            finally
            {
                stopwatch.Stop();
                result.InstallationDuration = stopwatch.Elapsed;
                
                _logger.LogInfo($"Duración total: {result.InstallationDuration.TotalSeconds:F2} segundos");
            }
            
            return result;
        }
        
        public async Task<InstallationResult> RepairAsync()
        {
            var result = new InstallationResult
            {
                InstallationId = Guid.NewGuid().ToString(),
                InstallationDuration = TimeSpan.Zero
            };
            
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                _logger.LogInfo($"Iniciando reparación {result.InstallationId}");
                
                // 1. Verificar instalación existente
                var existingInstallation = await VerifyExistingInstallationAsync();
                if (!existingInstallation.IsValid)
                {
                    throw new InvalidOperationException("No hay una instalación válida para reparar");
                }
                
                // 2. Detener servicios temporalmente
                await StopServicesAsync();
                
                // 3. Reparar archivos
                await RepairFilesAsync();
                
                // 4. Verificar y reparar certificados
                await RepairCertificatesAsync();
                
                // 5. Verificar y reparar drivers
                await RepairDriversAsync();
                
                // 6. Verificar y reparar servicios
                await RepairServicesAsync();
                
                // 7. Reiniciar servicios
                await StartServicesAsync();
                
                // 8. Verificar funcionalidad
                await VerifyFunctionalityAsync();
                
                result.Success = true;
                result.Details["RepairedComponents"] = existingInstallation.BrokenComponents;
                _logger.LogSuccess("Reparación completada exitosamente");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error durante la reparación: {ex.Message}", ex);
            }
            finally
            {
                stopwatch.Stop();
                result.InstallationDuration = stopwatch.Elapsed;
                
                _logger.LogInfo($"Duración total: {result.InstallationDuration.TotalSeconds:F2} segundos");
            }
            
            return result;
        }
        
        public async Task<InstallationResult> UpgradeAsync(string newVersionPath)
        {
            var result = new InstallationResult
            {
                InstallationId = Guid.NewGuid().ToString(),
                InstallationDuration = TimeSpan.Zero
            };
            
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                _logger.LogInfo($"Iniciando actualización a nueva versión");
                
                // 1. Verificar nueva versión
                await ValidateUpgradePackageAsync(newVersionPath);
                
                // 2. Crear punto de restauración
                await CreateRestorePointAsync();
                
                // 3. Detener servicios
                await StopServicesAsync();
                
                // 4. Respaldar configuración
                await BackupConfigurationAsync();
                
                // 5. Instalar nueva versión
                await InstallNewVersionAsync(newVersionPath);
                
                // 6. Restaurar configuración
                await RestoreConfigurationAsync();
                
                // 7. Migrar datos si es necesario
                await MigrateDataAsync();
                
                // 8. Iniciar servicios
                await StartServicesAsync();
                
                // 9. Limpiar versión anterior
                await CleanOldVersionAsync();
                
                // 10. Verificar actualización
                await VerifyUpgradeAsync();
                
                result.Success = true;
                _logger.LogSuccess("Actualización completada exitosamente");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error durante la actualización: {ex.Message}", ex);
                
                // Restaurar desde punto de restauración
                await RestoreFromBackupAsync();
            }
            finally
            {
                stopwatch.Stop();
                result.InstallationDuration = stopwatch.Elapsed;
                
                _logger.LogInfo($"Duración total: {result.InstallationDuration.TotalSeconds:F2} segundos");
            }
            
            return result;
        }
        
        #region Métodos de instalación
        
        private async Task ValidatePrerequisitesAsync()
        {
            _logger.LogInfo("Validando requisitos previos...");
            
            var prerequisites = new List<string>();
            
            // 1. Verificar sistema operativo
            if (!IsSupportedWindowsVersion())
            {
                throw new PlatformNotSupportedException(
                    $"Sistema operativo no soportado. Requiere Windows 10/11 o Windows Server 2016+");
            }
            
            // 2. Verificar arquitectura
            if (!IsSupportedArchitecture())
            {
                throw new PlatformNotSupportedException(
                    $"Arquitectura no soportada. Requiere x64");
            }
            
            // 3. Verificar privilegios de administrador
            if (!IsRunningAsAdministrator())
            {
                throw new UnauthorizedAccessException(
                    "Se requieren privilegios de administrador para la instalación");
            }
            
            // 4. Verificar espacio en disco
            var requiredSpace = CalculateRequiredDiskSpace();
            if (!HasSufficientDiskSpace(requiredSpace))
            {
                throw new IOException(
                    $"Espacio insuficiente en disco. Se requieren {requiredSpace / (1024 * 1024)} MB");
            }
            
            // 5. Verificar memoria RAM
            if (!HasSufficientMemory())
            {
                prerequisites.Add("Memoria RAM mínima recomendada: 2GB");
            }
            
            // 6. Verificar .NET Framework/CLR
            if (!IsDotNetFrameworkInstalled())
            {
                prerequisites.Add(".NET Framework 4.8 o superior requerido");
            }
            
            // 7. Verificar Windows Installer
            if (!IsWindowsInstallerUpToDate())
            {
                prerequisites.Add("Windows Installer 5.0 o superior requerido");
            }
            
            if (prerequisites.Count > 0)
            {
                _logger.LogWarning($"Prerrequisitos no cumplidos: {string.Join(", ", prerequisites)}");
            }
            
            await Task.CompletedTask;
        }
        
        private async Task CreateDirectoryStructureAsync()
        {
            _logger.LogInfo("Creando estructura de directorios...");
            
            try
            {
                // Directorio de instalación principal
                Directory.CreateDirectory(_config.InstallationPath);
                _state.AddCreatedDirectory(_config.InstallationPath);
                
                // Subdirectorios
                var subDirectories = new[]
                {
                    "bin",
                    "config",
                    "logs",
                    "data",
                    "plugins",
                    "temp",
                    "backup",
                    "certificates",
                    "drivers"
                };
                
                foreach (var dir in subDirectories)
                {
                    string fullPath = Path.Combine(_config.InstallationPath, dir);
                    Directory.CreateDirectory(fullPath);
                    _state.AddCreatedDirectory(fullPath);
                    
                    _logger.LogDebug($"Directorio creado: {fullPath}");
                }
                
                // Directorios del sistema
                if (_config.InstallSystemComponents)
                {
                    var systemDirs = new[]
                    {
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BWP Enterprise"),
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramData), "BWP Enterprise"),
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "BWP Enterprise")
                    };
                    
                    foreach (var dir in systemDirs)
                    {
                        Directory.CreateDirectory(dir);
                        _state.AddCreatedDirectory(dir);
                        
                        _logger.LogDebug($"Directorio del sistema creado: {dir}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creando estructura de directorios: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task CopyFilesAsync()
        {
            _logger.LogInfo("Copiando archivos...");
            
            try
            {
                // Archivos principales
                foreach (var file in _config.FilesToCopy)
                {
                    if (!File.Exists(file.SourcePath))
                    {
                        _logger.LogWarning($"Archivo fuente no encontrado: {file.SourcePath}");
                        continue;
                    }
                    
                    string destPath = Path.Combine(_config.InstallationPath, file.RelativeDestination);
                    var result = _fileCopier.CopyFile(file.SourcePath, destPath, new FileCopier.CopyOptions
                    {
                        OverwriteExisting = true,
                        VerifyAfterCopy = true,
                        SetPermissions = true,
                        CreateBackup = true
                    });
                    
                    if (result.Success)
                    {
                        _state.AddCopiedFile(destPath, result.FileHash);
                        _logger.LogDebug($"Archivo copiado: {file.SourcePath} -> {destPath}");
                    }
                    else
                    {
                        throw new IOException($"Error copiando archivo {file.SourcePath}: {result.ErrorMessage}");
                    }
                }
                
                // Archivos de configuración
                await CopyConfigurationFilesAsync();
                
                // Scripts y herramientas
                await CopyScriptsAndToolsAsync();
                
                // Archivos de soporte
                await CopySupportFilesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error copiando archivos: {ex.Message}", ex);
                throw;
            }
        }
        
        private async Task InstallCertificatesAsync()
        {
            _logger.LogInfo("Instalando certificados...");
            
            try
            {
                // Certificado raíz
                if (!string.IsNullOrEmpty(_config.RootCertificatePath) && File.Exists(_config.RootCertificatePath))
                {
                    var certData = File.ReadAllBytes(_config.RootCertificatePath);
                    var result = _certificateInstaller.InstallRootCertificate(certData);
                    
                    if (result.Success)
                    {
                        _state.AddInstalledCertificate(result.CertificateThumbprint, "Root");
                        _logger.LogInfo($"Certificado raíz instalado: {result.CertificateThumbprint}");
                    }
                    else
                    {
                        throw new SecurityException($"Error instalando certificado raíz: {result.ErrorMessage}");
                    }
                }
                
                // Certificado cliente
                if (!string.IsNullOrEmpty(_config.ClientCertificatePath) && File.Exists(_config.ClientCertificatePath))
                {
                    byte[] privateKeyData = null;
                    if (!string.IsNullOrEmpty(_config.ClientPrivateKeyPath) && File.Exists(_config.ClientPrivateKeyPath))
                    {
                        privateKeyData = File.ReadAllBytes(_config.ClientPrivateKeyPath);
                    }
                    
                    var certData = File.ReadAllBytes(_config.ClientCertificatePath);
                    var result = _certificateInstaller.InstallClientCertificate(certData, privateKeyData);
                    
                    if (result.Success)
                    {
                        _state.AddInstalledCertificate(result.CertificateThumbprint, "Client");
                        _logger.LogInfo($"Certificado cliente instalado: {result.CertificateThumbprint}");
                    }
                    else
                    {
                        throw new SecurityException($"Error instalando certificado cliente: {result.ErrorMessage}");
                    }
                }
                
                // Certificados adicionales
                foreach (var certPath in _config.AdditionalCertificates)
                {
                    if (File.Exists(certPath))
                    {
                        var certData = File.ReadAllBytes(certPath);
                        var result = _certificateInstaller.InstallRootCertificate(certData);
                        
                        if (result.Success)
                        {
                            _state.AddInstalledCertificate(result.CertificateThumbprint, "Additional");
                            _logger.LogInfo($"Certificado adicional instalado: {result.CertificateThumbprint}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error instalando certificados: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task InstallDriversAsync()
        {
            _logger.LogInfo("Instalando drivers...");
            
            try
            {
                // Drivers de kernel
                foreach (var driver in _config.KernelDrivers)
                {
                    if (!File.Exists(driver.Path))
                    {
                        _logger.LogWarning($"Driver no encontrado: {driver.Path}");
                        continue;
                    }
                    
                    var result = _driverInstaller.InstallKernelDriver(driver.Path, driver.InfPath);
                    
                    if (result.Success)
                    {
                        _state.AddInstalledDriver(driver.Name, driver.Path, result.RebootRequired);
                        _logger.LogInfo($"Driver instalado: {driver.Name}");
                        
                        if (result.RebootRequired)
                        {
                            _logger.LogWarning("Reinicio requerido después de instalar driver");
                        }
                    }
                    else
                    {
                        throw new IOException($"Error instalando driver {driver.Name}: {result.ErrorMessage}");
                    }
                }
                
                // Drivers en modo usuario
                foreach (var driver in _config.UserModeDrivers)
                {
                    if (!File.Exists(driver.Path))
                    {
                        _logger.LogWarning($"Driver no encontrado: {driver.Path}");
                        continue;
                    }
                    
                    var result = _driverInstaller.InstallUserModeDriver(driver.Path);
                    
                    if (result.Success)
                    {
                        _state.AddInstalledDriver(driver.Name, driver.Path, false);
                        _logger.LogInfo($"Driver en modo usuario instalado: {driver.Name}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error instalando drivers: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task RegisterServicesAsync()
        {
            _logger.LogInfo("Registrando servicios...");
            
            try
            {
                // Servicio principal
                var mainServiceResult = _serviceRegistrar.RegisterService(
                    _config.MainServiceName,
                    _config.MainServiceDisplayName,
                    _config.MainServiceDescription,
                    Path.Combine(_config.InstallationPath, "bin", "BWPEnterpriseAgent.exe"),
                    ServiceStartType.Auto,
                    ServiceAccount.LocalSystem,
                    new[] { "tcpip", "http" }
                );
                
                if (mainServiceResult.Success)
                {
                    _state.AddRegisteredService(_config.MainServiceName, mainServiceResult.ServiceHandle);
                    _logger.LogInfo($"Servicio registrado: {_config.MainServiceName}");
                }
                else
                {
                    throw new InvalidOperationException(
                        $"Error registrando servicio principal: {mainServiceResult.ErrorMessage}");
                }
                
                // Servicios adicionales
                foreach (var service in _config.AdditionalServices)
                {
                    var servicePath = Path.Combine(_config.InstallationPath, service.RelativePath);
                    
                    var result = _serviceRegistrar.RegisterService(
                        service.Name,
                        service.DisplayName,
                        service.Description,
                        servicePath,
                        service.StartType,
                        service.Account,
                        service.Dependencies
                    );
                    
                    if (result.Success)
                    {
                        _state.AddRegisteredService(service.Name, result.ServiceHandle);
                        _logger.LogInfo($"Servicio adicional registrado: {service.Name}");
                    }
                    else
                    {
                        _logger.LogWarning($"Error registrando servicio {service.Name}: {result.ErrorMessage}");
                    }
                }
                
                // Iniciar servicios si está configurado
                if (_config.StartServicesAfterInstall)
                {
                    await StartServicesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error registrando servicios: {ex.Message}", ex);
                throw;
            }
        }
        
        private async Task ConfigureFirewallAsync()
        {
            _logger.LogInfo("Configurando firewall...");
            
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "netsh.exe";
                    process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"BWP Enterprise Agent\" " +
                        $"dir=in action=allow program=\"{Path.Combine(_config.InstallationPath, "bin", "BWPEnterpriseAgent.exe")}\" " +
                        $"enable=yes profile=any";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(10000);
                    
                    if (process.ExitCode == 0)
                    {
                        _state.AddFirewallRule("BWP Enterprise Agent (Inbound)");
                        _logger.LogInfo("Regla de firewall agregada (entrante)");
                    }
                }
                
                // Agregar regla para puertos específicos
                foreach (var port in _config.FirewallPorts)
                {
                    using (var process = new Process())
                    {
                        process.StartInfo.FileName = "netsh.exe";
                        process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"BWP Port {port}\" " +
                            $"dir=in action=allow protocol=TCP localport={port} enable=yes profile=any";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;
                        
                        process.Start();
                        process.WaitForExit(5000);
                        
                        if (process.ExitCode == 0)
                        {
                            _state.AddFirewallRule($"BWP Port {port}");
                            _logger.LogDebug($"Regla de firewall para puerto {port} agregada");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error configurando firewall: {ex.Message}");
                // No lanzar excepción, continuar con instalación
            }
            
            await Task.CompletedTask;
        }
        
        private async Task ConfigureAutoStartAsync()
        {
            _logger.LogInfo("Configurando auto-inicio...");
            
            try
            {
                // Registro de auto-inicio
                string registryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key != null)
                    {
                        string agentPath = Path.Combine(_config.InstallationPath, "bin", "BWPEnterpriseAgent.exe");
                        key.SetValue("BWPEnterpriseAgent", $"\"{agentPath}\" --service");
                        
                        _state.AddRegistryEntry($@"HKLM\{registryPath}\BWPEnterpriseAgent");
                        _logger.LogInfo("Entrada de auto-inicio agregada al registro");
                    }
                }
                
                // Configurar tarea programada
                await ConfigureScheduledTaskAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error configurando auto-inicio: {ex.Message}");
                // No lanzar excepción, continuar con instalación
            }
        }
        
        private async Task CreateShortcutsAsync()
        {
            _logger.LogInfo("Creando accesos directos...");
            
            try
            {
                // Menú Inicio
                string startMenuPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                    "Programs",
                    "BWP Enterprise");
                
                Directory.CreateDirectory(startMenuPath);
                
                // Acceso directo principal
                string agentExe = Path.Combine(_config.InstallationPath, "bin", "BWPEnterpriseAgent.exe");
                string startMenuShortcut = Path.Combine(startMenuPath, "BWP Enterprise Agent.lnk");
                
                CreateShortcut(agentExe, startMenuShortcut, "BWP Enterprise Security Agent", 
                    "Protección avanzada de endpoints", agentExe);
                
                _state.AddCreatedShortcut(startMenuShortcut);
                _logger.LogDebug($"Acceso directo creado: {startMenuShortcut}");
                
                // Escritorio (opcional)
                if (_config.CreateDesktopShortcut)
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                    string desktopShortcut = Path.Combine(desktopPath, "BWP Enterprise Agent.lnk");
                    
                    CreateShortcut(agentExe, desktopShortcut, "BWP Enterprise Agent", 
                        "Iniciar consola de administración", agentExe);
                    
                    _state.AddCreatedShortcut(desktopShortcut);
                    _logger.LogDebug($"Acceso directo en escritorio creado: {desktopShortcut}");
                }
                
                // Accesos directos adicionales
                foreach (var shortcut in _config.AdditionalShortcuts)
                {
                    string sourcePath = Path.Combine(_config.InstallationPath, shortcut.RelativePath);
                    string shortcutPath = Path.Combine(startMenuPath, shortcut.Name + ".lnk");
                    
                    if (File.Exists(sourcePath))
                    {
                        CreateShortcut(sourcePath, shortcutPath, shortcut.DisplayName, 
                            shortcut.Description, Path.GetDirectoryName(sourcePath));
                        
                        _state.AddCreatedShortcut(shortcutPath);
                        _logger.LogDebug($"Acceso directo adicional creado: {shortcutPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error creando accesos directos: {ex.Message}");
                // No lanzar excepción, continuar con instalación
            }
            
            await Task.CompletedTask;
        }
        
        private async Task FinalizeInstallationAsync(InstallationResult result)
        {
            _logger.LogInfo("Finalizando instalación...");
            
            try
            {
                // Crear archivo de instalación completada
                string completionFile = Path.Combine(_config.InstallationPath, ".installation_complete");
                File.WriteAllText(completionFile, DateTime.UtcNow.ToString("o"));
                
                // Actualizar registro de instalaciones
                UpdateInstallationRegistry();
                
                // Configurar permisos finales
                SetFinalPermissions();
                
                // Limpiar archivos temporales
                CleanTempFiles();
                
                // Generar reporte de instalación
                GenerateInstallationReport(result);
                
                _logger.LogSuccess("Instalación finalizada exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error durante finalización: {ex.Message}");
                // No lanzar excepción ya que la instalación fue exitosa
            }
            
            await Task.CompletedTask;
        }
        
        #endregion
        
        #region Métodos de desinstalación
        
        private async Task StopServicesAsync()
        {
            _logger.LogInfo("Deteniendo servicios...");
            
            try
            {
                // Servicio principal
                _serviceRegistrar.StopService(_config.MainServiceName);
                _logger.LogDebug($"Servicio detenido: {_config.MainServiceName}");
                
                // Servicios adicionales
                foreach (var service in _config.AdditionalServices)
                {
                    try
                    {
                        _serviceRegistrar.StopService(service.Name);
                        _logger.LogDebug($"Servicio detenido: {service.Name}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error deteniendo servicio {service.Name}: {ex.Message}");
                    }
                }
                
                // Esperar a que los servicios se detengan
                await Task.Delay(3000);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error deteniendo servicios: {ex.Message}", ex);
                throw;
            }
        }
        
        private async Task DeleteServicesAsync()
        {
            _logger.LogInfo("Eliminando servicios...");
            
            try
            {
                // Servicio principal
                _serviceRegistrar.DeleteService(_config.MainServiceName);
                _logger.LogDebug($"Servicio eliminado: {_config.MainServiceName}");
                
                // Servicios adicionales
                foreach (var service in _config.AdditionalServices)
                {
                    try
                    {
                        _serviceRegistrar.DeleteService(service.Name);
                        _logger.LogDebug($"Servicio eliminado: {service.Name}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error eliminando servicio {service.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error eliminando servicios: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task UninstallDriversAsync()
        {
            _logger.LogInfo("Desinstalando drivers...");
            
            try
            {
                // Drivers de kernel
                foreach (var driver in _config.KernelDrivers)
                {
                    try
                    {
                        bool success = _driverInstaller.UninstallDriver(driver.Name);
                        if (success)
                        {
                            _logger.LogDebug($"Driver desinstalado: {driver.Name}");
                        }
                        else
                        {
                            _logger.LogWarning($"Error desinstalando driver: {driver.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error desinstalando driver {driver.Name}: {ex.Message}");
                    }
                }
                
                // Drivers en modo usuario
                foreach (var driver in _config.UserModeDrivers)
                {
                    try
                    {
                        bool success = _driverInstaller.UninstallDriver(driver.Name);
                        if (success)
                        {
                            _logger.LogDebug($"Driver en modo usuario desinstalado: {driver.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error desinstalando driver {driver.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error desinstalando drivers: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task UninstallCertificatesAsync()
        {
            _logger.LogInfo("Desinstalando certificados...");
            
            try
            {
                // Obtener thumbprints de certificados instalados
                var certificates = _state.GetInstalledCertificates();
                
                foreach (var cert in certificates)
                {
                    try
                    {
                        bool removed = _certificateInstaller.UninstallCertificate(cert.Thumbprint);
                        if (removed)
                        {
                            _logger.LogDebug($"Certificado desinstalado: {cert.Thumbprint}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error desinstalando certificado {cert.Thumbprint}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error desinstalando certificados: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task DeleteShortcutsAsync()
        {
            _logger.LogInfo("Eliminando accesos directos...");
            
            try
            {
                var shortcuts = _state.GetCreatedShortcuts();
                
                foreach (var shortcut in shortcuts)
                {
                    try
                    {
                        if (File.Exists(shortcut))
                        {
                            File.Delete(shortcut);
                            _logger.LogDebug($"Acceso directo eliminado: {shortcut}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error eliminando acceso directo {shortcut}: {ex.Message}");
                    }
                }
                
                // Eliminar carpeta del menú Inicio
                string startMenuPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                    "Programs",
                    "BWP Enterprise");
                
                if (Directory.Exists(startMenuPath))
                {
                    Directory.Delete(startMenuPath, true);
                    _logger.LogDebug($"Carpeta del menú Inicio eliminada: {startMenuPath}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error eliminando accesos directos: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task RemoveFirewallRulesAsync()
        {
            _logger.LogInfo("Eliminando reglas de firewall...");
            
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "netsh.exe";
                    process.StartInfo.Arguments = "advfirewall firewall delete rule name=\"BWP Enterprise Agent\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(5000);
                    
                    _logger.LogDebug("Reglas de firewall eliminadas");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error eliminando reglas de firewall: {ex.Message}");
            }
            
            await Task.CompletedTask;
        }
        
        private async Task RemoveAutoStartAsync()
        {
            _logger.LogInfo("Eliminando configuración de auto-inicio...");
            
            try
            {
                // Eliminar del registro
                string registryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key != null && key.GetValue("BWPEnterpriseAgent") != null)
                    {
                        key.DeleteValue("BWPEnterpriseAgent");
                        _logger.LogDebug("Entrada de auto-inicio eliminada del registro");
                    }
                }
                
                // Eliminar tarea programada
                await RemoveScheduledTaskAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error eliminando configuración de auto-inicio: {ex.Message}");
            }
            
            await Task.CompletedTask;
        }
        
        private async Task DeleteFilesAsync(bool keepData)
        {
            _logger.LogInfo("Eliminando archivos...");
            
            try
            {
                if (!keepData)
                {
                    // Eliminar directorio de instalación completo
                    if (Directory.Exists(_config.InstallationPath))
                    {
                        _fileCopier.CleanupFailedInstallation(_config.InstallationPath);
                        _logger.LogDebug($"Directorio de instalación eliminado: {_config.InstallationPath}");
                    }
                    
                    // Eliminar archivos del sistema
                    var systemPaths = _state.GetSystemPaths();
                    foreach (var path in systemPaths)
                    {
                        try
                        {
                            if (Directory.Exists(path))
                            {
                                Directory.Delete(path, true);
                                _logger.LogDebug($"Directorio del sistema eliminado: {path}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Error eliminando directorio {path}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    _logger.LogInfo("Conservando datos de usuario según configuración");
                    
                    // Solo eliminar binarios y configuración, mantener datos
                    string[] dirsToKeep = { "data", "logs", "backup" };
                    
                    foreach (var dir in Directory.GetDirectories(_config.InstallationPath))
                    {
                        string dirName = Path.GetFileName(dir);
                        if (!dirsToKeep.Contains(dirName))
                        {
                            Directory.Delete(dir, true);
                            _logger.LogDebug($"Directorio eliminado: {dir}");
                        }
                    }
                    
                    // Eliminar archivos en raíz excepto datos
                    foreach (var file in Directory.GetFiles(_config.InstallationPath))
                    {
                        if (!file.EndsWith(".db") && !file.EndsWith(".log"))
                        {
                            File.Delete(file);
                            _logger.LogDebug($"Archivo eliminado: {file}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error eliminando archivos: {ex.Message}", ex);
                throw;
            }
            
            await Task.CompletedTask;
        }
        
        private async Task CleanRegistryAsync()
        {
            _logger.LogInfo("Limpiando registro...");
            
            try
            {
                // Eliminar claves de registro creadas
                var registryEntries = _state.GetRegistryEntries();
                
                foreach (var entry in registryEntries)
                {
                    try
                    {
                        string[] parts = entry.Split('\\');
                        if (parts.Length > 1)
                        {
                            string root = parts[0];
                            string subKey = string.Join("\\", parts, 1, parts.Length - 2);
                            string valueName = parts[parts.Length - 1];
                            
                            RegistryKey rootKey = GetRegistryRootKey(root);
                            if (rootKey != null)
                            {
                                using (RegistryKey key = rootKey.OpenSubKey(subKey, true))
                                {
                                    if (key != null && key.GetValue(valueName) != null)
                                    {
                                        key.DeleteValue(valueName);
                                        _logger.LogDebug($"Entrada del registro eliminada: {entry}");
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error limpiando entrada del registro {entry}: {ex.Message}");
                    }
                }
                
                // Eliminar clave principal
                string mainKey = @"SOFTWARE\BWP Enterprise";
                Registry.LocalMachine.DeleteSubKeyTree(mainKey, false);
                _logger.LogDebug($"Clave principal del registro eliminada: {mainKey}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error limpiando registro: {ex.Message}");
            }
            
            await Task.CompletedTask;
        }
        
        private async Task FinalizeUninstallationAsync(InstallationResult result)
        {
            _logger.LogInfo("Finalizando desinstalación...");
            
            try
            {
                // Eliminar archivo de instalación completada
                string completionFile = Path.Combine(_config.InstallationPath, ".installation_complete");
                if (File.Exists(completionFile))
                {
                    File.Delete(completionFile);
                }
                
                // Actualizar registro de instalaciones
                RemoveInstallationFromRegistry();
                
                // Limpiar archivos temporales restantes
                CleanAllTempFiles();
                
                _logger.LogSuccess("Desinstalación finalizada exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error durante finalización: {ex.Message}");
            }
            
            await Task.CompletedTask;
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        private bool IsSupportedWindowsVersion()
        {
            var osVersion = Environment.OSVersion;
            var platform = osVersion.Platform;
            var version = osVersion.Version;
            
            // Windows 10/11 o Windows Server 2016+
            return platform == PlatformID.Win32NT && 
                   version.Major >= 10 && 
                   version.Build >= 14393; // Windows 10 Anniversary Update
        }
        
        private bool IsSupportedArchitecture()
        {
            return Environment.Is64BitOperatingSystem;
        }
        
        private bool IsRunningAsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        
        private long CalculateRequiredDiskSpace()
        {
            long totalSize = 0;
            
            // Sumar tamaño de archivos a copiar
            foreach (var file in _config.FilesToCopy)
            {
                if (File.Exists(file.SourcePath))
                {
                    var fileInfo = new FileInfo(file.SourcePath);
                    totalSize += fileInfo.Length;
                }
            }
            
            // Agregar espacio adicional para crecimiento
            totalSize += 100 * 1024 * 1024; // 100MB adicionales
            
            return totalSize;
        }
        
        private bool HasSufficientDiskSpace(long requiredSpace)
        {
            string drive = Path.GetPathRoot(_config.InstallationPath);
            var driveInfo = new DriveInfo(drive);
            
            return driveInfo.AvailableFreeSpace > requiredSpace * 2; // Doble del espacio requerido
        }
        
        private bool HasSufficientMemory()
        {
            // Verificar al menos 2GB de RAM
            var computerInfo = new Microsoft.VisualBasic.Devices.ComputerInfo();
            return computerInfo.TotalPhysicalMemory >= 2L * 1024 * 1024 * 1024;
        }
        
        private bool IsDotNetFrameworkInstalled()
        {
            try
            {
                using (RegistryKey ndpKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                {
                    if (ndpKey != null)
                    {
                        int releaseKey = (int)(ndpKey.GetValue("Release") ?? 0);
                        // .NET Framework 4.8 o superior (Release >= 528040)
                        return releaseKey >= 528040;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private bool IsWindowsInstallerUpToDate()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (key != null)
                    {
                        var subKeys = key.GetSubKeyNames();
                        return subKeys.Any(k => k.Contains("Windows Installer") && k.Contains("5.0"));
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private void CreateShortcut(string targetPath, string shortcutPath, string description, 
            string arguments, string workingDirectory)
        {
            try
            {
                // Usar Windows Script Host para crear acceso directo
                string script = $@"
                    Set oWS = WScript.CreateObject(""WScript.Shell"")
                    sLinkFile = ""{shortcutPath.Replace(@"\", @"\\")}""
                    Set oLink = oWS.CreateShortcut(sLinkFile)
                    oLink.TargetPath = ""{targetPath.Replace(@"\", @"\\")}""
                    oLink.Arguments = ""{arguments}""
                    oLink.WorkingDirectory = ""{workingDirectory.Replace(@"\", @"\\")}""
                    oLink.Description = ""{description}""
                    oLink.Save
                ";
                
                string tempScript = Path.GetTempFileName() + ".vbs";
                File.WriteAllText(tempScript, script);
                
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "wscript.exe";
                    process.StartInfo.Arguments = $"\"{tempScript}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(5000);
                    
                    File.Delete(tempScript);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error creando acceso directo: {ex.Message}");
            }
        }
        
        private RegistryKey GetRegistryRootKey(string root)
        {
            return root.ToUpperInvariant() switch
            {
                "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKCR" or "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
                "HKU" or "HKEY_USERS" => Registry.Users,
                "HKCC" or "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
                _ => null
            };
        }
        
        private void UpdateInstallationRegistry()
        {
            try
            {
                string registryPath = @"SOFTWARE\BWP Enterprise\Installations";
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        string installationKey = Guid.NewGuid().ToString("N");
                        using (RegistryKey installKey = key.CreateSubKey(installationKey))
                        {
                            if (installKey != null)
                            {
                                installKey.SetValue("InstallationPath", _config.InstallationPath, RegistryValueKind.String);
                                installKey.SetValue("InstallationDate", DateTime.UtcNow.ToString("o"), RegistryValueKind.String);
                                installKey.SetValue("ProductVersion", _config.ProductVersion, RegistryValueKind.String);
                                installKey.SetValue("ProductName", _config.ProductName, RegistryValueKind.String);
                                installKey.SetValue("InstallationId", _state.InstallationId, RegistryValueKind.String);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error actualizando registro de instalaciones: {ex.Message}");
            }
        }
        
        private void RemoveInstallationFromRegistry()
        {
            try
            {
                string registryPath = @"SOFTWARE\BWP Enterprise\Installations";
                Registry.LocalMachine.DeleteSubKeyTree(registryPath, false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error eliminando registro de instalación: {ex.Message}");
            }
        }
        
        private void SetFinalPermissions()
        {
            try
            {
                // Establecer permisos en directorio de instalación
                string cmd = $@"
                    icacls ""{_config.InstallationPath}"" /grant *S-1-5-18:(OI)(CI)F /T
                    icacls ""{_config.InstallationPath}"" /grant *S-1-5-32-544:(OI)(CI)F /T
                    icacls ""{_config.InstallationPath}"" /grant *S-1-5-32-545:(OI)(CI)RX /T
                ";
                
                string tempBat = Path.GetTempFileName() + ".bat";
                File.WriteAllText(tempBat, cmd);
                
                using (var process = new Process())
                {
                    process.StartInfo.FileName = tempBat;
                    process.StartInfo.UseShellExecute = true;
                    process.StartInfo.Verb = "runas";
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(10000);
                    
                    File.Delete(tempBat);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error estableciendo permisos: {ex.Message}");
            }
        }
        
        private void CleanTempFiles()
        {
            try
            {
                string tempDir = Path.Combine(_config.InstallationPath, "temp");
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, true);
                    Directory.CreateDirectory(tempDir);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error limpiando archivos temporales: {ex.Message}");
            }
        }
        
        private void CleanAllTempFiles()
        {
            try
            {
                // Limpiar directorio temporal de la aplicación
                string appTempDir = Path.Combine(Path.GetTempPath(), "BWPEnterprise");
                if (Directory.Exists(appTempDir))
                {
                    Directory.Delete(appTempDir, true);
                }
                
                // Limpiar directorio temporal de instalación
                string installTempDir = Path.Combine(_config.InstallationPath, "temp");
                if (Directory.Exists(installTempDir))
                {
                    Directory.Delete(installTempDir, true);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error limpiando todos los archivos temporales: {ex.Message}");
            }
        }
        
        private void GenerateInstallationReport(InstallationResult result)
        {
            try
            {
                string reportPath = Path.Combine(_config.InstallationPath, "InstallationReport.json");
                
                var report = new
                {
                    InstallationId = result.InstallationId,
                    Timestamp = DateTime.UtcNow,
                    ProductName = _config.ProductName,
                    ProductVersion = _config.ProductVersion,
                    InstallationPath = _config.InstallationPath,
                    DurationSeconds = result.InstallationDuration.TotalSeconds,
                    InstalledComponents = new
                    {
                        Files = _state.GetCopiedFiles().Count,
                        Directories = _state.GetCreatedDirectories().Count,
                        Services = _state.GetRegisteredServices().Count,
                        Drivers = _state.GetInstalledDrivers().Count,
                        Certificates = _state.GetInstalledCertificates().Count,
                        Shortcuts = _state.GetCreatedShortcuts().Count,
                        FirewallRules = _state.GetFirewallRules().Count
                    },
                    SystemInfo = new
                    {
                        OSVersion = Environment.OSVersion.ToString(),
                        MachineName = Environment.MachineName,
                        UserName = Environment.UserName,
                        ProcessorCount = Environment.ProcessorCount,
                        Is64Bit = Environment.Is64BitOperatingSystem,
                        MemoryGB = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory / (1024 * 1024 * 1024)
                    }
                };
                
                string json = Newtonsoft.Json.JsonConvert.SerializeObject(report, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(reportPath, json);
                
                _logger.LogInfo($"Reporte de instalación generado: {reportPath}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error generando reporte de instalación: {ex.Message}");
            }
        }
        
        private void CreateInstallationReceipt(InstallationResult result)
        {
            try
            {
                string receiptPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "BWP Enterprise",
                    "InstallationReceipt.xml");
                
                Directory.CreateDirectory(Path.GetDirectoryName(receiptPath));
                
                var receipt = new System.Xml.Linq.XDocument(
                    new System.Xml.Linq.XElement("InstallationReceipt",
                        new System.Xml.Linq.XElement("InstallationId", result.InstallationId),
                        new System.Xml.Linq.XElement("ProductName", _config.ProductName),
                        new System.Xml.Linq.XElement("ProductVersion", _config.ProductVersion),
                        new System.Xml.Linq.XElement("InstallationDate", DateTime.UtcNow.ToString("o")),
                        new System.Xml.Linq.XElement("InstallationPath", _config.InstallationPath),
                        new System.Xml.Linq.XElement("Success", result.Success),
                        new System.Xml.Linq.XElement("RequiresReboot", result.RequiresReboot)
                    )
                );
                
                receipt.Save(receiptPath);
                _logger.LogDebug($"Recibo de instalación creado: {receiptPath}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error creando recibo de instalación: {ex.Message}");
            }
        }
        
        private async Task RollbackInstallationAsync()
        {
            _logger.LogError("Iniciando rollback de instalación...");
            
            try
            {
                // Detener cualquier servicio iniciado
                await StopServicesAsync();
                
                // Eliminar servicios
                await DeleteServicesAsync();
                
                // Desinstalar drivers
                await UninstallDriversAsync();
                
                // Desinstalar certificados
                await UninstallCertificatesAsync();
                
                // Eliminar archivos copiados
                await DeleteFilesAsync(false);
                
                // Limpiar registro
                await CleanRegistryAsync();
                
                _logger.LogInfo("Rollback completado");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error durante rollback: {ex.Message}", ex);
                throw;
            }
        }
        
        #endregion
        
        #region Métodos para reparación y actualización (simplificados)
        
        private async Task<InstallationVerificationResult> VerifyExistingInstallationAsync()
        {
            // Implementación simplificada
            return await Task.FromResult(new InstallationVerificationResult
            {
                IsValid = Directory.Exists(_config.InstallationPath),
                BrokenComponents = new List<string>()
            });
        }
        
        private async Task RepairFilesAsync()
        {
            // Re-copiar archivos principales
            await CopyFilesAsync();
        }
        
        private async Task RepairCertificatesAsync()
        {
            // Re-instalar certificados
            await InstallCertificatesAsync();
        }
        
        private async Task RepairDriversAsync()
        {
            // Re-instalar drivers
            await InstallDriversAsync();
        }
        
        private async Task RepairServicesAsync()
        {
            // Re-registrar servicios
            await RegisterServicesAsync();
        }
        
        private async Task StartServicesAsync()
        {
            _serviceRegistrar.StartService(_config.MainServiceName);
            await Task.Delay(2000);
        }
        
        private async Task VerifyFunctionalityAsync()
        {
            // Verificar que los servicios estén ejecutándose
            await Task.Delay(1000);
        }
        
        private async Task ValidateUpgradePackageAsync(string newVersionPath)
        {
            // Validar integridad del paquete de actualización
            if (!Directory.Exists(newVersionPath))
            {
                throw new DirectoryNotFoundException($"Ruta de actualización no encontrada: {newVersionPath}");
            }
            
            await Task.CompletedTask;
        }
        
        private async Task CreateRestorePointAsync()
        {
            // Crear punto de restauración del sistema
            _logger.LogInfo("Creando punto de restauración...");
            await Task.CompletedTask;
        }
        
        private async Task BackupConfigurationAsync()
        {
            // Respaldar configuración actual
            string backupDir = Path.Combine(_config.InstallationPath, "backup", $"pre_upgrade_{DateTime.Now:yyyyMMdd_HHmmss}");
            Directory.CreateDirectory(backupDir);
            
            await Task.CompletedTask;
        }
        
        private async Task InstallNewVersionAsync(string newVersionPath)
        {
            // Instalar nueva versión
            _config.InstallationPath = newVersionPath;
            await InstallAsync();
        }
        
        private async Task RestoreConfigurationAsync()
        {
            // Restaurar configuración desde backup
            await Task.CompletedTask;
        }
        
        private async Task MigrateDataAsync()
        {
            // Migrar datos si es necesario
            await Task.CompletedTask;
        }
        
        private async Task CleanOldVersionAsync()
        {
            // Limpiar archivos de versión anterior
            await Task.CompletedTask;
        }
        
        private async Task VerifyUpgradeAsync()
        {
            // Verificar que la actualización fue exitosa
            await Task.CompletedTask;
        }
        
        private async Task RestoreFromBackupAsync()
        {
            // Restaurar desde backup en caso de error
            await Task.CompletedTask;
        }
        
        private async Task CopyConfigurationFilesAsync()
        {
            // Implementación específica
            await Task.CompletedTask;
        }
        
        private async Task CopyScriptsAndToolsAsync()
        {
            // Implementación específica
            await Task.CompletedTask;
        }
        
        private async Task CopySupportFilesAsync()
        {
            // Implementación específica
            await Task.CompletedTask;
        }
        
        private async Task ConfigureScheduledTaskAsync()
        {
            // Configurar tarea programada de Windows
            await Task.CompletedTask;
        }
        
        private async Task RemoveScheduledTaskAsync()
        {
            // Eliminar tarea programada
            await Task.CompletedTask;
        }
        
        #endregion
        
        #region Clases de soporte
        
        public class InstallationConfiguration
        {
            public string ProductName { get; set; } = "BWP Enterprise";
            public string ProductVersion { get; set; } = "1.0.0";
            public string InstallationPath { get; set; } = @"C:\Program Files\BWP Enterprise";
            public string LogFilePath { get; set; } = @"C:\ProgramData\BWP Enterprise\install.log";
            
            public bool InstallSystemComponents { get; set; } = true;
            public bool StartServicesAfterInstall { get; set; } = true;
            public bool CreateDesktopShortcut { get; set; } = true;
            
            public string MainServiceName { get; set; } = "BWPEnterpriseAgent";
            public string MainServiceDisplayName { get; set; } = "BWP Enterprise Security Agent";
            public string MainServiceDescription { get; set; } = "Protección avanzada de endpoints BWP Enterprise";
            
            public string RootCertificatePath { get; set; }
            public string ClientCertificatePath { get; set; }
            public string ClientPrivateKeyPath { get; set; }
            public List<string> AdditionalCertificates { get; set; } = new List<string>();
            
            public List<FileToCopy> FilesToCopy { get; set; } = new List<FileToCopy>();
            public List<KernelDriver> KernelDrivers { get; set; } = new List<KernelDriver>();
            public List<UserModeDriver> UserModeDrivers { get; set; } = new List<UserModeDriver>();
            public List<AdditionalService> AdditionalServices { get; set; } = new List<AdditionalService>();
            public List<AdditionalShortcut> AdditionalShortcuts { get; set; } = new List<AdditionalShortcut>();
            public List<int> FirewallPorts { get; set; } = new List<int> { 443, 8443 };
        }
        
        public class FileToCopy
        {
            public string SourcePath { get; set; }
            public string RelativeDestination { get; set; }
            public bool IsCritical { get; set; } = true;
        }
        
        public class KernelDriver
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public string InfPath { get; set; }
        }
        
        public class UserModeDriver
        {
            public string Name { get; set; }
            public string Path { get; set; }
        }
        
        public class AdditionalService
        {
            public string Name { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public string RelativePath { get; set; }
            public ServiceStartType StartType { get; set; } = ServiceStartType.Auto;
            public ServiceAccount Account { get; set; } = ServiceAccount.LocalSystem;
            public string[] Dependencies { get; set; } = Array.Empty<string>();
        }
        
        public class AdditionalShortcut
        {
            public string Name { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public string RelativePath { get; set; }
        }
        
        public enum ServiceStartType
        {
            Auto,
            Manual,
            Disabled,
            DelayedAuto
        }
        
        public enum ServiceAccount
        {
            LocalSystem,
            LocalService,
            NetworkService
        }
        
        private class InstallationState
        {
            public string InstallationId { get; } = Guid.NewGuid().ToString("N");
            
            private List<string> _createdDirectories = new List<string>();
            private List<CopiedFileInfo> _copiedFiles = new List<CopiedFileInfo>();
            private List<ServiceInfo> _registeredServices = new List<ServiceInfo>();
            private List<DriverInfo> _installedDrivers = new List<DriverInfo>();
            private List<CertificateInfo> _installedCertificates = new List<CertificateInfo>();
            private List<string> _createdShortcuts = new List<string>();
            private List<string> _firewallRules = new List<string>();
            private List<string> _registryEntries = new List<string>();
            private List<string> _systemPaths = new List<string>();
            
            public void Reset()
            {
                _createdDirectories.Clear();
                _copiedFiles.Clear();
                _registeredServices.Clear();
                _installedDrivers.Clear();
                _installedCertificates.Clear();
                _createdShortcuts.Clear();
                _firewallRules.Clear();
                _registryEntries.Clear();
                _systemPaths.Clear();
            }
            
            public void AddCreatedDirectory(string path) => _createdDirectories.Add(path);
            public void AddCopiedFile(string path, string hash) => _copiedFiles.Add(new CopiedFileInfo { Path = path, Hash = hash });
            public void AddRegisteredService(string name, IntPtr handle) => _registeredServices.Add(new ServiceInfo { Name = name, Handle = handle });
            public void AddInstalledDriver(string name, string path, bool requiresReboot) => _installedDrivers.Add(new DriverInfo { Name = name, Path = path, RequiresReboot = requiresReboot });
            public void AddInstalledCertificate(string thumbprint, string type) => _installedCertificates.Add(new CertificateInfo { Thumbprint = thumbprint, Type = type });
            public void AddCreatedShortcut(string path) => _createdShortcuts.Add(path);
            public void AddFirewallRule(string name) => _firewallRules.Add(name);
            public void AddRegistryEntry(string path) => _registryEntries.Add(path);
            public void AddSystemPath(string path) => _systemPaths.Add(path);
            
            public List<string> GetCreatedDirectories() => new List<string>(_createdDirectories);
            public List<CopiedFileInfo> GetCopiedFiles() => new List<CopiedFileInfo>(_copiedFiles);
            public List<ServiceInfo> GetRegisteredServices() => new List<ServiceInfo>(_registeredServices);
            public List<DriverInfo> GetInstalledDrivers() => new List<DriverInfo>(_installedDrivers);
            public List<CertificateInfo> GetInstalledCertificates() => new List<CertificateInfo>(_installedCertificates);
            public List<string> GetCreatedShortcuts() => new List<string>(_createdShortcuts);
            public List<string> GetFirewallRules() => new List<string>(_firewallRules);
            public List<string> GetRegistryEntries() => new List<string>(_registryEntries);
            public List<string> GetSystemPaths() => new List<string>(_systemPaths);
            
            public class CopiedFileInfo
            {
                public string Path { get; set; }
                public string Hash { get; set; }
            }
            
            public class ServiceInfo
            {
                public string Name { get; set; }
                public IntPtr Handle { get; set; }
            }
            
            public class DriverInfo
            {
                public string Name { get; set; }
                public string Path { get; set; }
                public bool RequiresReboot { get; set; }
            }
            
            public class CertificateInfo
            {
                public string Thumbprint { get; set; }
                public string Type { get; set; }
            }
        }
        
        private class InstallationVerificationResult
        {
            public bool IsValid { get; set; }
            public List<string> BrokenComponents { get; set; } = new List<string>();
        }
        
        private class InstallerLogger
        {
            private readonly string _logFilePath;
            
            public InstallerLogger(string logFilePath)
            {
                _logFilePath = logFilePath;
                Directory.CreateDirectory(Path.GetDirectoryName(logFilePath));
                
                LogInfo($"=== Inicio de registro: {DateTime.Now} ===");
            }
            
            public void LogInfo(string message)
            {
                WriteLog("INFO", message);
                Console.WriteLine($"[INFO] {message}");
            }
            
            public void LogSuccess(string message)
            {
                WriteLog("SUCCESS", message);
                Console.WriteLine($"[SUCCESS] {message}");
            }
            
            public void LogWarning(string message)
            {
                WriteLog("WARNING", message);
                Console.WriteLine($"[WARNING] {message}");
            }
            
            public void LogError(string message, Exception ex = null)
            {
                WriteLog("ERROR", $"{message} {(ex != null ? $"- {ex.Message}" : "")}");
                Console.WriteLine($"[ERROR] {message}");
                if (ex != null)
                {
                    Console.WriteLine($"[ERROR] Detalles: {ex}");
                }
            }
            
            public void LogDebug(string message)
            {
                WriteLog("DEBUG", message);
            }
            
            private void WriteLog(string level, string message)
            {
                try
                {
                    string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}";
                    File.AppendAllLines(_logFilePath, new[] { logEntry });
                }
                catch
                {
                    // Ignorar errores de logging
                }
            }
        }
        
        #endregion
    }
}