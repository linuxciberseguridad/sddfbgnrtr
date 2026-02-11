using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;
using System.Security.Principal;
using Microsoft.Win32;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace BWP.Installer.Engine
{
    public class DriverInstaller : IDisposable
    {
        #region Constantes y estructuras nativas
        
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_HANDLE = 6;
        private const int ERROR_NOT_SUPPORTED = 50;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
        private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
        private const int ERROR_SERVICE_NOT_ACTIVE = 1062;
        private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;
        
        private const int SERVICE_ALL_ACCESS = 0xF01FF;
        private const int SERVICE_KERNEL_DRIVER = 0x00000001;
        private const int SERVICE_FILE_SYSTEM_DRIVER = 0x00000002;
        private const int SERVICE_AUTO_START = 0x00000002;
        private const int SERVICE_DEMAND_START = 0x00000003;
        private const int SERVICE_BOOT_START = 0x00000000;
        private const int SERVICE_SYSTEM_START = 0x00000001;
        private const int SERVICE_ERROR_NORMAL = 0x00000001;
        private const int SERVICE_CONFIG_DESCRIPTION = 1;
        private const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;
        
        private const int SC_MANAGER_ALL_ACCESS = 0xF003F;
        
        private const int SERVICE_CONTROL_STOP = 1;
        private const int SERVICE_STOPPED = 1;
        private const int SERVICE_START_PENDING = 2;
        private const int SERVICE_STOP_PENDING = 3;
        private const int SERVICE_RUNNING = 4;
        
        private const uint DIGCF_PRESENT = 0x00000002;
        private const uint DIGCF_DEVICEINTERFACE = 0x00000010;
        private const uint DIGCF_ALLCLASSES = 0x00000004;
        private const uint SPDRP_HARDWAREID = 0x00000001;
        private const uint SPDRP_SERVICE = 0x00000004;
        
        private const int DIF_INSTALLDEVICE = 0x00000001;
        private const int DIF_REMOVE = 0x00000005;
        private const int DIF_PROPERTYCHANGE = 0x00000012;
        private const int DIF_REGISTER_COINSTALLERS = 0x00000016;
        private const int DIF_INSTALLINTERFACES = 0x00000020;
        
        private const uint DICS_FLAG_GLOBAL = 0x00000001;
        private const uint DICS_FLAG_CONFIGSPECIFIC = 0x00000002;
        private const uint DICS_ENABLE = 0x00000001;
        private const uint DICS_DISABLE = 0x00000002;
        private const uint DICS_START = 0x00000010;
        private const uint DICS_STOP = 0x00000020;
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_STATUS
        {
            public int serviceType;
            public int currentState;
            public int controlsAccepted;
            public int win32ExitCode;
            public int serviceSpecificExitCode;
            public int checkPoint;
            public int waitHint;
        }
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_DESCRIPTION
        {
            public string description;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_FAILURE_ACTIONS
        {
            public int resetPeriod;
            public string rebootMsg;
            public string command;
            public int failureCount;
            public IntPtr actions;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct SC_ACTION
        {
            public int type;
            public int delay;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct GUID
        {
            public uint Data1;
            public ushort Data2;
            public ushort Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Data4;
        }
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, int desiredAccess);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr scManager, string serviceName, int desiredAccess);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr handle);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateService(
            IntPtr scManager,
            string serviceName,
            string displayName,
            int desiredAccess,
            int serviceType,
            int startType,
            int errorControl,
            string binaryPathName,
            string loadOrderGroup,
            IntPtr tagId,
            string dependencies,
            string serviceStartName,
            string password
        );
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool DeleteService(IntPtr service);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr service, int numArgs, string[] args);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr service, int control, ref SERVICE_STATUS status);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr service, ref SERVICE_STATUS status);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig2(IntPtr service, int infoLevel, ref SERVICE_DESCRIPTION info);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ChangeServiceConfig2(IntPtr service, int infoLevel, ref SERVICE_FAILURE_ACTIONS info);
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Wow64DisableWow64FsRedirection(ref IntPtr oldValue);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Wow64RevertWow64FsRedirection(IntPtr oldValue);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, string enumerator, IntPtr hwndParent, uint flags);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(IntPtr classGuid, string enumerator, IntPtr hwndParent, uint flags);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, int memberIndex, IntPtr deviceInfoData);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(int installFunction, IntPtr deviceInfoSet, IntPtr deviceInfoData);
        
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr deviceInfoSet,
            IntPtr deviceInfoData,
            uint property,
            out uint propertyRegDataType,
            byte[] propertyBuffer,
            uint propertyBufferSize,
            out uint requiredSize
        );
        
        [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool UpdateDriverForPlugAndPlayDevices(
            IntPtr hwndParent,
            string hardwareId,
            string fullInfPath,
            uint installFlags,
            ref bool rebootRequired
        );
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);
        
        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }
        
        #endregion
        
        private readonly InstallerLogger _logger;
        private bool _disposed;
        private IntPtr _wow64RedirectionState;
        private bool _isWow64RedirectionDisabled;
        
        public DriverInstaller(InstallerLogger logger = null)
        {
            _logger = logger ?? new InstallerLogger();
        }
        
        #region Métodos públicos de instalación
        
        public DriverInstallResult InstallKernelDriver(string driverPath, string infPath = null, string serviceName = null)
        {
            var result = new DriverInstallResult
            {
                DriverPath = driverPath,
                DriverType = "Kernel"
            };
            
            try
            {
                if (!IsAdministrator())
                {
                    result.ErrorMessage = "Se requieren privilegios de administrador para instalar drivers de kernel";
                    return result;
                }
                
                if (!File.Exists(driverPath))
                {
                    result.ErrorMessage = $"El archivo del driver no existe: {driverPath}";
                    return result;
                }
                
                _logger.LogInfo($"Iniciando instalación de driver de kernel: {Path.GetFileName(driverPath)}");
                
                // Deshabilitar redirección WOW64
                DisableWow64Redirection();
                
                try
                {
                    // 1. Verificar firma digital del driver
                    if (!VerifyDriverSignature(driverPath))
                    {
                        throw new SecurityException("El driver no está correctamente firmado o la firma no es válida");
                    }
                    
                    // 2. Verificar compatibilidad con el sistema
                    if (!IsDriverCompatible(driverPath))
                    {
                        throw new NotSupportedException("El driver no es compatible con esta versión de Windows");
                    }
                    
                    // 3. Copiar driver a system32\drivers
                    string driverFileName = Path.GetFileName(driverPath);
                    string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    string driversPath = Path.Combine(system32Path, "drivers");
                    string targetPath = Path.Combine(driversPath, driverFileName);
                    
                    // Asegurar directorio
                    Directory.CreateDirectory(driversPath);
                    
                    // Copiar archivo
                    File.Copy(driverPath, targetPath, true);
                    result.DriverPath = targetPath;
                    _logger.LogInfo($"Driver copiado a: {targetPath}");
                    
                    // 4. Establecer permisos de seguridad
                    SetDriverFileSecurity(targetPath);
                    
                    // 5. Registrar servicio del driver
                    string driverServiceName = serviceName ?? $"BWP_{Path.GetFileNameWithoutExtension(driverFileName)}";
                    result.ServiceName = driverServiceName;
                    
                    var serviceResult = RegisterDriverService(driverServiceName, targetPath, DriverType.Kernel);
                    
                    if (serviceResult.Success)
                    {
                        result.ServiceHandle = serviceResult.ServiceHandle;
                        
                        // 6. Configurar recuperación automática
                        ConfigureDriverRecovery(driverServiceName);
                        
                        // 7. Iniciar driver
                        var startResult = StartDriverService(driverServiceName);
                        result.Success = startResult.Success;
                        result.RebootRequired = startResult.RebootRequired;
                        
                        if (result.Success)
                        {
                            _logger.LogSuccess($"Driver de kernel instalado y ejecutándose: {driverServiceName}");
                        }
                        else
                        {
                            _logger.LogWarning($"Driver instalado pero no se pudo iniciar: {driverServiceName}");
                        }
                    }
                    else
                    {
                        throw new InvalidOperationException(serviceResult.ErrorMessage);
                    }
                    
                    // 8. Instalar usando INF si se proporciona
                    if (!string.IsNullOrEmpty(infPath) && File.Exists(infPath))
                    {
                        InstallDriverFromInf(infPath, driverServiceName);
                    }
                    
                    // 9. Registrar en el inventario
                    RegisterDriverInInventory(driverServiceName, targetPath, result);
                    
                    result.Success = true;
                    _logger.LogSuccess($"Driver de kernel instalado exitosamente: {driverServiceName}");
                }
                finally
                {
                    // Restaurar redirección WOW64
                    RestoreWow64Redirection();
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando driver de kernel: {ex.Message}", ex);
                
                // Intentar limpieza
                try
                {
                    if (!string.IsNullOrEmpty(result.ServiceName))
                    {
                        UninstallDriver(result.ServiceName);
                    }
                }
                catch { }
            }
            
            return result;
        }
        
        public DriverInstallResult InstallUserModeDriver(string dllPath, string serviceName = null)
        {
            var result = new DriverInstallResult
            {
                DriverPath = dllPath,
                DriverType = "UserMode"
            };
            
            try
            {
                if (!IsAdministrator())
                {
                    result.ErrorMessage = "Se requieren privilegios de administrador para instalar drivers en modo usuario";
                    return result;
                }
                
                if (!File.Exists(dllPath))
                {
                    result.ErrorMessage = $"El archivo DLL no existe: {dllPath}";
                    return result;
                }
                
                _logger.LogInfo($"Iniciando instalación de driver en modo usuario: {Path.GetFileName(dllPath)}");
                
                // Determinar tipo de driver en modo usuario
                string extension = Path.GetExtension(dllPath).ToLowerInvariant();
                string fileName = Path.GetFileNameWithoutExtension(dllPath).ToLowerInvariant();
                
                if (fileName.Contains("filter") || fileName.Contains("monitor") || fileName.Contains("hook"))
                {
                    // Driver de filtro (FileSystem Filter, Registry Filter, Network Filter)
                    result = InstallFilterDriver(dllPath, serviceName);
                }
                else if (extension == ".sys")
                {
                    // Algunos drivers en modo usuario usan .sys
                    result = InstallUserModeServiceDriver(dllPath, serviceName);
                }
                else
                {
                    // Driver genérico en modo usuario
                    result = InstallGenericUserModeDriver(dllPath, serviceName);
                }
                
                if (result.Success)
                {
                    _logger.LogSuccess($"Driver en modo usuario instalado: {result.ServiceName}");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando driver en modo usuario: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public DriverInstallResult InstallFileSystemFilter(string filterPath, string altitude)
        {
            var result = new DriverInstallResult
            {
                DriverPath = filterPath,
                DriverType = "FileSystemFilter"
            };
            
            try
            {
                _logger.LogInfo($"Instalando filtro de sistema de archivos: {Path.GetFileName(filterPath)}");
                
                if (!IsAdministrator())
                {
                    result.ErrorMessage = "Se requieren privilegios de administrador";
                    return result;
                }
                
                string filterName = Path.GetFileNameWithoutExtension(filterPath);
                string serviceName = $"BWP_Filter_{filterName}";
                
                // Copiar a system32\drivers
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string driversPath = Path.Combine(system32Path, "drivers");
                string targetPath = Path.Combine(driversPath, Path.GetFileName(filterPath));
                
                File.Copy(filterPath, targetPath, true);
                
                // Registrar como minifiltro
                RegisterAsMiniFilter(targetPath, serviceName, filterName, altitude);
                
                result.Success = true;
                result.ServiceName = serviceName;
                result.DriverPath = targetPath;
                
                _logger.LogSuccess($"Filtro de sistema de archivos instalado: {serviceName} con altitude {altitude}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando filtro de sistema de archivos: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public DriverInstallResult InstallDriverFromInf(string infPath, string hardwareId = null)
        {
            var result = new DriverInstallResult
            {
                DriverPath = infPath,
                DriverType = "INF"
            };
            
            try
            {
                if (!IsAdministrator())
                {
                    result.ErrorMessage = "Se requieren privilegios de administrador";
                    return result;
                }
                
                if (!File.Exists(infPath))
                {
                    result.ErrorMessage = $"Archivo INF no encontrado: {infPath}";
                    return result;
                }
                
                _logger.LogInfo($"Instalando driver desde INF: {infPath}");
                
                // Obtener HardwareID si no se proporciona
                if (string.IsNullOrEmpty(hardwareId))
                {
                    hardwareId = GetHardwareIdFromInf(infPath);
                }
                
                bool rebootRequired = false;
                
                // Usar UpdateDriverForPlugAndPlayDevices
                if (UpdateDriverForPlugAndPlayDevices(
                    IntPtr.Zero,
                    hardwareId,
                    infPath,
                    0,
                    ref rebootRequired))
                {
                    result.Success = true;
                    result.RebootRequired = rebootRequired;
                    result.ServiceName = GetServiceNameFromInf(infPath);
                    
                    _logger.LogSuccess($"Driver instalado via INF: {infPath}");
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, $"Error instalando driver via INF");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando driver via INF: {ex.Message}", ex);
            }
            
            return result;
        }
        
        #endregion
        
        #region Métodos de desinstalación
        
        public bool UninstallDriver(string driverName)
        {
            try
            {
                _logger.LogInfo($"Desinstalando driver: {driverName}");
                
                if (!IsAdministrator())
                {
                    _logger.LogError("Se requieren privilegios de administrador para desinstalar drivers");
                    return false;
                }
                
                bool success = true;
                
                // 1. Detener servicio
                var stopResult = StopDriverService(driverName);
                if (!stopResult.Success)
                {
                    _logger.LogWarning($"No se pudo detener el servicio {driverName}: {stopResult.ErrorMessage}");
                }
                
                // 2. Eliminar servicio
                var deleteResult = DeleteDriverService(driverName);
                if (!deleteResult.Success && deleteResult.ErrorCode != ERROR_SERVICE_DOES_NOT_EXIST)
                {
                    _logger.LogError($"Error eliminando servicio {driverName}: {deleteResult.ErrorMessage}");
                    success = false;
                }
                
                // 3. Eliminar archivos del driver
                DeleteDriverFiles(driverName);
                
                // 4. Limpiar registro
                CleanDriverRegistryEntries(driverName);
                
                // 5. Eliminar del inventario
                RemoveDriverFromInventory(driverName);
                
                _logger.LogSuccess($"Driver desinstalado: {driverName}");
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error desinstalando driver {driverName}: {ex.Message}", ex);
                return false;
            }
        }
        
        public bool UninstallDriverByPath(string driverPath)
        {
            try
            {
                string fileName = Path.GetFileNameWithoutExtension(driverPath);
                return UninstallDriver($"BWP_{fileName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error desinstalando driver por path: {ex.Message}", ex);
                return false;
            }
        }
        
        #endregion
        
        #region Métodos de gestión de servicios
        
        private ServiceOperationResult RegisterDriverService(string serviceName, string binaryPath, DriverType driverType)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error abriendo administrador de servicios");
                }
                
                // Verificar si ya existe
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                    service = IntPtr.Zero;
                    
                    // Eliminar servicio existente
                    DeleteDriverService(serviceName);
                    Thread.Sleep(500);
                }
                
                // Determinar tipo de servicio
                int serviceType = driverType == DriverType.Kernel ? 
                    SERVICE_KERNEL_DRIVER : SERVICE_FILE_SYSTEM_DRIVER;
                
                // Crear servicio
                service = CreateService(
                    scManager,
                    serviceName,
                    $"BWP Enterprise - {serviceName}",
                    SERVICE_ALL_ACCESS,
                    serviceType,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    binaryPath,
                    null, // loadOrderGroup
                    IntPtr.Zero, // tagId
                    null, // dependencies
                    "LocalSystem",
                    null // password
                );
                
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error creando servicio del driver");
                }
                
                result.Success = true;
                result.ServiceHandle = service;
                result.ServiceName = serviceName;
                
                _logger.LogInfo($"Servicio del driver registrado: {serviceName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.ErrorCode = ex.HResult;
                
                _logger.LogError($"Error registrando servicio del driver: {ex.Message}", ex);
            }
            finally
            {
                if (service != IntPtr.Zero && !result.Success)
                {
                    CloseServiceHandle(service);
                }
                if (scManager != IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                }
            }
            
            return result;
        }
        
        private ServiceOperationResult StartDriverService(string serviceName, int timeoutMilliseconds = 30000)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error abriendo administrador de servicios");
                }
                
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != ERROR_SERVICE_DOES_NOT_EXIST)
                    {
                        throw new Win32Exception(error, "Error abriendo servicio");
                    }
                    result.ErrorMessage = "El servicio no existe";
                    return result;
                }
                
                SERVICE_STATUS status = new SERVICE_STATUS();
                if (!QueryServiceStatus(service, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error consultando estado del servicio");
                }
                
                if (status.currentState == SERVICE_RUNNING)
                {
                    result.Success = true;
                    result.Message = "El servicio ya está en ejecución";
                    return result;
                }
                
                if (!StartService(service, 0, null))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        throw new Win32Exception(error, "Error iniciando servicio");
                    }
                }
                
                // Esperar a que inicie
                Stopwatch stopwatch = Stopwatch.StartNew();
                bool started = false;
                
                while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
                {
                    if (!QueryServiceStatus(service, ref status))
                    {
                        break;
                    }
                    
                    if (status.currentState == SERVICE_RUNNING)
                    {
                        started = true;
                        break;
                    }
                    
                    if (status.currentState == SERVICE_STOPPED)
                    {
                        break;
                    }
                    
                    Thread.Sleep(500);
                }
                
                if (started)
                {
                    result.Success = true;
                    result.Message = "Servicio iniciado exitosamente";
                    
                    _logger.LogInfo($"Servicio iniciado: {serviceName}");
                }
                else
                {
                    result.RebootRequired = true;
                    result.Message = "Se requiere reinicio para iniciar el driver";
                    
                    _logger.LogWarning($"Se requiere reinicio para el driver: {serviceName}");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.ErrorCode = ex.HResult;
                
                _logger.LogError($"Error iniciando servicio {serviceName}: {ex.Message}", ex);
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                }
                if (scManager != IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                }
            }
            
            return result;
        }
        
        private ServiceOperationResult StopDriverService(string serviceName, int timeoutMilliseconds = 30000)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error abriendo administrador de servicios");
                }
                
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_SERVICE_DOES_NOT_EXIST)
                    {
                        result.Success = true;
                        result.Message = "El servicio no existe";
                        return result;
                    }
                    throw new Win32Exception(error, "Error abriendo servicio");
                }
                
                SERVICE_STATUS status = new SERVICE_STATUS();
                if (!QueryServiceStatus(service, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error consultando estado del servicio");
                }
                
                if (status.currentState == SERVICE_STOPPED)
                {
                    result.Success = true;
                    result.Message = "El servicio ya está detenido";
                    return result;
                }
                
                if (!ControlService(service, SERVICE_CONTROL_STOP, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != ERROR_SERVICE_NOT_ACTIVE)
                    {
                        throw new Win32Exception(error, "Error deteniendo servicio");
                    }
                }
                
                // Esperar a que se detenga
                Stopwatch stopwatch = Stopwatch.StartNew();
                bool stopped = false;
                
                while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
                {
                    if (!QueryServiceStatus(service, ref status))
                    {
                        break;
                    }
                    
                    if (status.currentState == SERVICE_STOPPED)
                    {
                        stopped = true;
                        break;
                    }
                    
                    Thread.Sleep(500);
                }
                
                if (stopped)
                {
                    result.Success = true;
                    result.Message = "Servicio detenido exitosamente";
                    
                    _logger.LogInfo($"Servicio detenido: {serviceName}");
                }
                else
                {
                    result.ErrorMessage = "Timeout esperando que el servicio se detenga";
                    
                    // Forzar detención
                    ForceStopDriverService(serviceName);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.ErrorCode = ex.HResult;
                
                _logger.LogError($"Error deteniendo servicio {serviceName}: {ex.Message}", ex);
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                }
                if (scManager != IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                }
            }
            
            return result;
        }
        
        private ServiceOperationResult DeleteDriverService(string serviceName)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error abriendo administrador de servicios");
                }
                
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_SERVICE_DOES_NOT_EXIST)
                    {
                        result.Success = true;
                        result.Message = "El servicio no existe";
                        return result;
                    }
                    throw new Win32Exception(error, "Error abriendo servicio");
                }
                
                if (!DeleteService(service))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Error eliminando servicio");
                }
                
                result.Success = true;
                result.Message = "Servicio eliminado exitosamente";
                
                _logger.LogInfo($"Servicio eliminado: {serviceName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.ErrorCode = ex.HResult;
                
                _logger.LogError($"Error eliminando servicio {serviceName}: {ex.Message}", ex);
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                }
                if (scManager != IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                }
            }
            
            return result;
        }
        
        private void ConfigureDriverRecovery(string serviceName)
        {
            try
            {
                IntPtr scManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                    return;
                    
                IntPtr service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    CloseServiceHandle(scManager);
                    return;
                }
                
                // Configurar acciones de recuperación
                SC_ACTION[] actions = new SC_ACTION[3];
                actions[0].type = 1; // SC_ACTION_RESTART
                actions[0].delay = 5000; // 5 segundos
                actions[1].type = 1; // SC_ACTION_RESTART
                actions[1].delay = 10000; // 10 segundos
                actions[2].type = 1; // SC_ACTION_RESTART
                actions[2].delay = 30000; // 30 segundos
                
                IntPtr actionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SC_ACTION)) * 3);
                try
                {
                    Marshal.StructureToPtr(actions[0], actionsPtr, false);
                    Marshal.StructureToPtr(actions[1], actionsPtr + Marshal.SizeOf(typeof(SC_ACTION)), false);
                    Marshal.StructureToPtr(actions[2], actionsPtr + Marshal.SizeOf(typeof(SC_ACTION)) * 2, false);
                    
                    SERVICE_FAILURE_ACTIONS failureActions = new SERVICE_FAILURE_ACTIONS
                    {
                        resetPeriod = 86400, // 24 horas
                        rebootMsg = null,
                        command = null,
                        failureCount = 3,
                        actions = actionsPtr
                    };
                    
                    ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, ref failureActions);
                    
                    _logger.LogInfo($"Recuperación configurada para driver: {serviceName}");
                }
                finally
                {
                    Marshal.FreeHGlobal(actionsPtr);
                    CloseServiceHandle(service);
                    CloseServiceHandle(scManager);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudo configurar recuperación para driver {serviceName}: {ex.Message}");
            }
        }
        
        #endregion
        
        #region Métodos especializados para diferentes tipos de drivers
        
        private DriverInstallResult InstallFilterDriver(string dllPath, string serviceName)
        {
            var result = new DriverInstallResult
            {
                DriverPath = dllPath,
                DriverType = "Filter"
            };
            
            try
            {
                string fileName = Path.GetFileNameWithoutExtension(dllPath);
                string filterServiceName = serviceName ?? $"BWP_Filter_{fileName}";
                
                // Copiar a system32
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32Path, Path.GetFileName(dllPath));
                
                File.Copy(dllPath, targetPath, true);
                
                // Registrar como servicio
                var serviceResult = RegisterDriverService(filterServiceName, targetPath, DriverType.FileSystem);
                
                if (serviceResult.Success)
                {
                    // Registrar como minifiltro
                    RegisterAsMiniFilter(targetPath, filterServiceName, fileName, "420000");
                    
                    result.Success = true;
                    result.ServiceName = filterServiceName;
                    result.ServiceHandle = serviceResult.ServiceHandle;
                    
                    _logger.LogInfo($"Filtro registrado: {filterServiceName}");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
            }
            
            return result;
        }
        
        private DriverInstallResult InstallUserModeServiceDriver(string driverPath, string serviceName)
        {
            var result = new DriverInstallResult
            {
                DriverPath = driverPath,
                DriverType = "UserModeService"
            };
            
            try
            {
                string fileName = Path.GetFileNameWithoutExtension(driverPath);
                string driverServiceName = serviceName ?? $"BWP_UM_{fileName}";
                
                // Copiar a system32\drivers
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string driversPath = Path.Combine(system32Path, "drivers");
                string targetPath = Path.Combine(driversPath, Path.GetFileName(driverPath));
                
                File.Copy(driverPath, targetPath, true);
                
                // Registrar como servicio
                var serviceResult = RegisterDriverService(driverServiceName, targetPath, DriverType.Kernel);
                
                if (serviceResult.Success)
                {
                    result.Success = true;
                    result.ServiceName = driverServiceName;
                    result.ServiceHandle = serviceResult.ServiceHandle;
                    
                    _logger.LogInfo($"Driver en modo usuario registrado: {driverServiceName}");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
            }
            
            return result;
        }
        
        private DriverInstallResult InstallGenericUserModeDriver(string dllPath, string serviceName)
        {
            var result = new DriverInstallResult
            {
                DriverPath = dllPath,
                DriverType = "UserModeGeneric"
            };
            
            try
            {
                string fileName = Path.GetFileNameWithoutExtension(dllPath);
                string driverServiceName = serviceName ?? $"BWP_UMD_{fileName}";
                
                // Registrar como servicio COM/DLL
                RegisterUserModeDriverDll(dllPath);
                
                result.Success = true;
                result.ServiceName = driverServiceName;
                
                _logger.LogInfo($"Driver genérico en modo usuario registrado: {fileName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
            }
            
            return result;
        }
        
        private void RegisterAsMiniFilter(string filterPath, string serviceName, string filterName, string altitude)
        {
            try
            {
                string registryPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        key.SetValue("Type", 2, RegistryValueKind.DWord); // SERVICE_FILE_SYSTEM_DRIVER
                        key.SetValue("Start", 0, RegistryValueKind.DWord); // SERVICE_BOOT_START
                        key.SetValue("ErrorControl", 1, RegistryValueKind.DWord);
                        key.SetValue("ImagePath", filterPath, RegistryValueKind.ExpandString);
                        key.SetValue("DisplayName", $"BWP {filterName} Filter", RegistryValueKind.String);
                        
                        // Configuración específica de minifiltro
                        using (RegistryKey instancesKey = key.CreateSubKey("Instances"))
                        {
                            if (instancesKey != null)
                            {
                                instancesKey.SetValue("DefaultInstance", $"{serviceName}_Instance", RegistryValueKind.String);
                                
                                using (RegistryKey instanceKey = instancesKey.CreateSubKey($"{serviceName}_Instance"))
                                {
                                    if (instanceKey != null)
                                    {
                                        instanceKey.SetValue("Altitude", altitude, RegistryValueKind.String);
                                        instanceKey.SetValue("Flags", 0, RegistryValueKind.DWord);
                                    }
                                }
                            }
                        }
                        
                        _logger.LogInfo($"Minifiltro registrado: {serviceName} (Altitude: {altitude})");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error registrando minifiltro: {ex.Message}", ex);
                throw;
            }
        }
        
        private void RegisterUserModeDriverDll(string dllPath)
        {
            try
            {
                // Registrar como COM DLL
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "regsvr32.exe",
                    Arguments = $"/s \"{dllPath}\"",
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true
                };
                
                Process process = Process.Start(psi);
                process?.WaitForExit(15000);
                
                if (process?.ExitCode == 0)
                {
                    _logger.LogInfo($"DLL registrada en COM: {Path.GetFileName(dllPath)}");
                }
                else
                {
                    _logger.LogWarning($"Error registrando DLL en COM, código: {process?.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error registrando DLL: {ex.Message}", ex);
                throw;
            }
        }
        
        #endregion
        
        #region Métodos de verificación y validación
        
        private bool VerifyDriverSignature(string driverPath)
        {
            try
            {
                _logger.LogInfo($"Verificando firma digital: {driverPath}");
                
                // Método 1: Usar signtool.exe
                if (File.Exists("signtool.exe"))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "signtool.exe",
                        Arguments = $"verify /pa /q \"{driverPath}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    
                    using (Process process = Process.Start(psi))
                    {
                        process.WaitForExit(5000);
                        if (process.ExitCode == 0)
                        {
                            _logger.LogInfo("Firma verificada con signtool");
                            return true;
                        }
                    }
                }
                
                // Método 2: Usar PowerShell Get-AuthenticodeSignature
                string script = $@"
                    $sig = Get-AuthenticodeSignature '{driverPath}'
                    if ($sig.Status -eq 'Valid') {{ exit 0 }} else {{ exit 1 }}
                ";
                
                ProcessStartInfo psiPs = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using (Process process = Process.Start(psiPs))
                {
                    process.WaitForExit(5000);
                    if (process.ExitCode == 0)
                    {
                        _logger.LogInfo("Firma verificada con PowerShell");
                        return true;
                    }
                }
                
                // Método 3: Verificar características básicas del driver
                FileInfo fileInfo = new FileInfo(driverPath);
                
                // Los drivers firmados por Microsoft suelen tener ciertas propiedades
                if (fileInfo.Length > 0)
                {
                    FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(driverPath);
                    if (!string.IsNullOrEmpty(versionInfo.CompanyName))
                    {
                        _logger.LogInfo($"Driver firmado por: {versionInfo.CompanyName}");
                        return true;
                    }
                }
                
                _logger.LogWarning("No se pudo verificar la firma digital del driver");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error verificando firma: {ex.Message}", ex);
                return false;
            }
        }
        
        private bool IsDriverCompatible(string driverPath)
        {
            try
            {
                var osVersion = Environment.OSVersion;
                var version = osVersion.Version;
                
                // Verificar arquitectura
                bool is64BitSystem = Environment.Is64BitOperatingSystem;
                bool is64BitDriver = Is64BitDriver(driverPath);
                
                if (is64BitSystem && !is64BitDriver)
                {
                    _logger.LogWarning("Driver de 32 bits en sistema de 64 bits");
                    return false;
                }
                
                return true;
            }
            catch
            {
                return true; // Continuar si no se puede determinar
            }
        }
        
        private bool Is64BitDriver(string driverPath)
        {
            try
            {
                using (FileStream fs = new FileStream(driverPath, FileMode.Open, FileAccess.Read))
                using (BinaryReader reader = new BinaryReader(fs))
                {
                    // Leer cabecera PE
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    uint peOffset = reader.ReadUInt32();
                    fs.Seek(peOffset, SeekOrigin.Begin);
                    uint peSignature = reader.ReadUInt32();
                    
                    if (peSignature != 0x00004550) // "PE\0\0"
                        return false;
                    
                    ushort machine = reader.ReadUInt16();
                    
                    // x64 = 0x8664, ARM64 = 0xAA64
                    return machine == 0x8664 || machine == 0xAA64;
                }
            }
            catch
            {
                return false;
            }
        }
        
        private string GetHardwareIdFromInf(string infPath)
        {
            try
            {
                string[] lines = File.ReadAllLines(infPath);
                
                foreach (string line in lines)
                {
                    if (line.Trim().StartsWith("HardwareId", StringComparison.OrdinalIgnoreCase) ||
                        line.Trim().StartsWith("%", StringComparison.OrdinalIgnoreCase))
                    {
                        int equalsIndex = line.IndexOf('=');
                        if (equalsIndex > 0)
                        {
                            string value = line.Substring(equalsIndex + 1).Trim().Trim('"');
                            if (!string.IsNullOrEmpty(value))
                            {
                                return value;
                            }
                        }
                    }
                }
                
                return $"BWP_ENTERPRISE_{Path.GetFileNameWithoutExtension(infPath)}";
            }
            catch
            {
                return "BWP_ENTERPRISE_DEVICE";
            }
        }
        
        private string GetServiceNameFromInf(string infPath)
        {
            try
            {
                string[] lines = File.ReadAllLines(infPath);
                
                foreach (string line in lines)
                {
                    if (line.Trim().StartsWith("ServiceBinary", StringComparison.OrdinalIgnoreCase) ||
                        line.Trim().StartsWith("AddService", StringComparison.OrdinalIgnoreCase))
                    {
                        int equalsIndex = line.IndexOf('=');
                        if (equalsIndex > 0)
                        {
                            string value = line.Substring(0, equalsIndex).Trim();
                            value = value.Replace("AddService", "").Replace("=", "").Trim();
                            if (!string.IsNullOrEmpty(value))
                            {
                                return value;
                            }
                        }
                    }
                }
                
                return $"BWP_{Path.GetFileNameWithoutExtension(infPath)}";
            }
            catch
            {
                return $"BWP_{Path.GetFileNameWithoutExtension(infPath)}";
            }
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        private void DisableWow64Redirection()
        {
            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                _isWow64RedirectionDisabled = Wow64DisableWow64FsRedirection(ref _wow64RedirectionState);
                if (_isWow64RedirectionDisabled)
                {
                    _logger.LogDebug("Redirección WOW64 deshabilitada");
                }
            }
        }
        
        private void RestoreWow64Redirection()
        {
            if (_isWow64RedirectionDisabled && _wow64RedirectionState != IntPtr.Zero)
            {
                Wow64RevertWow64FsRedirection(_wow64RedirectionState);
                _logger.LogDebug("Redirección WOW64 restaurada");
                _isWow64RedirectionDisabled = false;
            }
        }
        
        private void SetDriverFileSecurity(string filePath)
        {
            try
            {
                // Otorgar permisos a SYSTEM y Administradores
                string tempBat = Path.GetTempFileName() + ".bat";
                string commands = $@"
                    @echo off
                    icacls ""{filePath}"" /grant *S-1-5-18:F /grant *S-1-5-32-544:F /grant *S-1-5-32-545:R
                ";
                
                File.WriteAllText(tempBat, commands);
                
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = tempBat,
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                
                Process.Start(psi)?.WaitForExit(5000);
                File.Delete(tempBat);
                
                _logger.LogDebug($"Permisos establecidos para: {filePath}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudieron establecer permisos: {ex.Message}");
            }
        }
        
        private void ForceStopDriverService(string serviceName)
        {
            try
            {
                // Usar sc.exe para forzar detención
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"stop {serviceName}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                Process.Start(psi)?.WaitForExit(5000);
                
                // Si no funciona, usar taskkill
                ProcessStartInfo psiKill = new ProcessStartInfo
                {
                    FileName = "taskkill.exe",
                    Arguments = $"/F /FI ""SERVICES eq {serviceName}""",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                Process.Start(psiKill)?.WaitForExit(3000);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error forzando detención del servicio {serviceName}: {ex.Message}");
            }
        }
        
        private void DeleteDriverFiles(string driverName)
        {
            try
            {
                // Eliminar de system32\drivers
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string driversPath = Path.Combine(system32Path, "drivers");
                
                // Posibles nombres de archivo
                string[] possibleFileNames = {
                    $"{driverName}.sys",
                    $"{driverName.Replace("BWP_", "")}.sys",
                    $"{driverName.Replace("BWP_Filter_", "")}.sys",
                    $"{driverName.Replace("BWP_UM_", "")}.sys",
                    $"{driverName.Replace("BWP_UMD_", "")}.dll"
                };
                
                foreach (string fileName in possibleFileNames)
                {
                    string filePath = Path.Combine(driversPath, fileName);
                    try
                    {
                        if (File.Exists(filePath))
                        {
                            File.SetAttributes(filePath, FileAttributes.Normal);
                            File.Delete(filePath);
                            _logger.LogDebug($"Archivo eliminado: {filePath}");
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error eliminando archivos del driver: {ex.Message}");
            }
        }
        
        private void CleanDriverRegistryEntries(string driverName)
        {
            try
            {
                string[] registryPaths = {
                    $@"SYSTEM\CurrentControlSet\Services\{driverName}",
                    $@"SYSTEM\CurrentControlSet\Services\BWP_{driverName}",
                    $@"SYSTEM\CurrentControlSet\Services\BWP_Filter_{driverName}",
                    $@"SYSTEM\CurrentControlSet\Services\BWP_UM_{driverName}",
                    $@"SYSTEM\CurrentControlSet\Services\BWP_UMD_{driverName}"
                };
                
                foreach (string path in registryPaths)
                {
                    try
                    {
                        Registry.LocalMachine.DeleteSubKeyTree(path, false);
                        _logger.LogDebug($"Clave de registro eliminada: {path}");
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error limpiando registro: {ex.Message}");
            }
        }
        
        private void RegisterDriverInInventory(string serviceName, string driverPath, DriverInstallResult result)
        {
            try
            {
                string registryPath = $@"SOFTWARE\BWP Enterprise\Drivers\{serviceName}";
                
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        key.SetValue("ServiceName", serviceName, RegistryValueKind.String);
                        key.SetValue("DriverPath", driverPath, RegistryValueKind.String);
                        key.SetValue("DriverType", result.DriverType, RegistryValueKind.String);
                        key.SetValue("InstallDate", DateTime.UtcNow.ToString("o"), RegistryValueKind.String);
                        key.SetValue("Status", result.Success ? "Installed" : "Failed", RegistryValueKind.String);
                        key.SetValue("RebootRequired", result.RebootRequired ? 1 : 0, RegistryValueKind.DWord);
                        
                        FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(driverPath);
                        key.SetValue("Version", versionInfo.FileVersion ?? "1.0.0.0", RegistryValueKind.String);
                        key.SetValue("Company", versionInfo.CompanyName ?? "BWP Enterprise", RegistryValueKind.String);
                    }
                }
                
                _logger.LogInfo($"Driver registrado en inventario: {serviceName}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudo registrar driver en inventario: {ex.Message}");
            }
        }
        
        private void RemoveDriverFromInventory(string serviceName)
        {
            try
            {
                string registryPath = $@"SOFTWARE\BWP Enterprise\Drivers\{serviceName}";
                Registry.LocalMachine.DeleteSubKeyTree(registryPath, false);
                
                _logger.LogInfo($"Driver removido del inventario: {serviceName}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error removiendo driver del inventario: {ex.Message}");
            }
        }
        
        private bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        
        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (!_disposed)
            {
                RestoreWow64Redirection();
                _disposed = true;
            }
        }
        
        #endregion
    }
    
    #region Enums y clases de resultado
    
    public enum DriverType
    {
        Kernel,
        FileSystem,
        Filter,
        UserMode,
        UserModeService,
        UserModeGeneric,
        INF
    }
    
    public class DriverInstallResult
    {
        public bool Success { get; set; }
        public bool RebootRequired { get; set; }
        public string DriverPath { get; set; }
        public string ServiceName { get; set; }
        public IntPtr ServiceHandle { get; set; }
        public string DriverType { get; set; }
        public string ErrorMessage { get; set; }
        public Exception Exception { get; set; }
    }
    
    public class ServiceOperationResult
    {
        public bool Success { get; set; }
        public bool RebootRequired { get; set; }
        public string ServiceName { get; set; }
        public IntPtr ServiceHandle { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public int ErrorCode { get; set; }
    }
    
    #endregion
}