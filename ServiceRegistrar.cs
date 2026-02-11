using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Win32;
using System.Security.Principal;

namespace BWP.Installer.Engine
{
    public class ServiceRegistrar
    {
        private const int SERVICE_ALL_ACCESS = 0xF01FF;
        private const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const int SERVICE_AUTO_START = 0x00000002;
        private const int SERVICE_DEMAND_START = 0x00000003;
        private const int SERVICE_ERROR_NORMAL = 0x00000001;
        private const int SERVICE_CONFIG_DESCRIPTION = 1;
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, int desiredAccess);
        
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
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr handle);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr scManager, string serviceName, int desiredAccess);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr service);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr service, int numArgs, string[] args);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr service, int control, ref SERVICE_STATUS status);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig2(IntPtr service, int infoLevel, ref SERVICE_DESCRIPTION info);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig(
            IntPtr service,
            int serviceType,
            int startType,
            int errorControl,
            string binaryPathName,
            string loadOrderGroup,
            IntPtr tagId,
            string dependencies,
            string serviceStartName,
            string password,
            string displayName
        );
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr service, ref SERVICE_STATUS status);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceConfig(
            IntPtr service,
            IntPtr configBuffer,
            int bufferSize,
            out int bytesNeeded
        );
        
        [StructLayout(LayoutKind.Sequential)]
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
        
        public class ServiceRegistrationResult
        {
            public bool Success { get; set; }
            public IntPtr ServiceHandle { get; set; }
            public string ServiceName { get; set; }
            public string ErrorMessage { get; set; }
            public int ErrorCode { get; set; }
        }
        
        public class ServiceOperationResult
        {
            public bool Success { get; set; }
            public string Message { get; set; }
            public int ErrorCode { get; set; }
        }
        
        public ServiceRegistrationResult RegisterService(
            string serviceName,
            string displayName,
            string description,
            string binaryPath,
            ServiceStartType startType,
            ServiceAccount account,
            string[] dependencies = null)
        {
            var result = new ServiceRegistrationResult
            {
                ServiceName = serviceName
            };
            
            if (!IsRunningAsAdministrator())
            {
                result.ErrorMessage = "Se requieren privilegios de administrador para registrar servicios";
                return result;
            }
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.ErrorMessage = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Verificar si el servicio ya existe
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service != IntPtr.Zero)
                {
                    // Servicio ya existe, actualizar configuración
                    CloseServiceHandle(service);
                    return UpdateServiceConfiguration(scManager, serviceName, displayName, description, 
                        binaryPath, startType, account, dependencies);
                }
                
                // Convertir parámetros a valores nativos
                int nativeStartType = ConvertStartType(startType);
                string nativeAccount = ConvertServiceAccount(account);
                
                // Crear el servicio
                service = CreateService(
                    scManager,
                    serviceName,
                    displayName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    nativeStartType,
                    SERVICE_ERROR_NORMAL,
                    binaryPath,
                    null, // loadOrderGroup
                    IntPtr.Zero, // tagId
                    dependencies != null ? string.Join("\0", dependencies) + "\0\0" : null,
                    nativeAccount,
                    null // password
                );
                
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.ErrorMessage = $"Error creando servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Establecer descripción del servicio
                SetServiceDescription(service, description);
                
                // Configurar recuperación del servicio
                ConfigureServiceRecovery(serviceName);
                
                // Configurar permisos del servicio
                ConfigureServicePermissions(serviceName);
                
                result.Success = true;
                result.ServiceHandle = service;
                result.ErrorMessage = "Servicio registrado exitosamente";
                
                // Registrar en el inventario
                RegisterServiceInInventory(serviceName, binaryPath, startType, account);
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Error registrando servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult StartService(string serviceName, int timeoutMilliseconds = 30000)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Verificar estado actual
                SERVICE_STATUS status = new SERVICE_STATUS();
                if (!QueryServiceStatus(service, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error consultando estado del servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Si ya está ejecutándose
                if (status.currentState == 4) // SERVICE_RUNNING
                {
                    result.Success = true;
                    result.Message = "El servicio ya está en ejecución";
                    return result;
                }
                
                // Iniciar servicio
                if (!StartService(service, 0, null))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error iniciando servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Esperar a que el servicio inicie
                Stopwatch stopwatch = Stopwatch.StartNew();
                bool started = false;
                
                while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
                {
                    if (!QueryServiceStatus(service, ref status))
                    {
                        break;
                    }
                    
                    if (status.currentState == 4) // SERVICE_RUNNING
                    {
                        started = true;
                        break;
                    }
                    
                    if (status.currentState == 1) // SERVICE_STOPPED
                    {
                        // El servicio falló al iniciar
                        result.Message = "El servicio falló al iniciar";
                        break;
                    }
                    
                    System.Threading.Thread.Sleep(500);
                }
                
                if (started)
                {
                    result.Success = true;
                    result.Message = "Servicio iniciado exitosamente";
                }
                else
                {
                    result.Message = "Timeout esperando a que el servicio inicie";
                }
            }
            catch (Exception ex)
            {
                result.Message = $"Error iniciando servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult StopService(string serviceName, int timeoutMilliseconds = 30000)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Verificar estado actual
                SERVICE_STATUS status = new SERVICE_STATUS();
                if (!QueryServiceStatus(service, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error consultando estado del servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Si ya está detenido
                if (status.currentState == 1) // SERVICE_STOPPED
                {
                    result.Success = true;
                    result.Message = "El servicio ya está detenido";
                    return result;
                }
                
                // Detener servicio
                if (!ControlService(service, 1, ref status)) // SERVICE_CONTROL_STOP
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error deteniendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Esperar a que el servicio se detenga
                Stopwatch stopwatch = Stopwatch.StartNew();
                bool stopped = false;
                
                while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
                {
                    if (!QueryServiceStatus(service, ref status))
                    {
                        break;
                    }
                    
                    if (status.currentState == 1) // SERVICE_STOPPED
                    {
                        stopped = true;
                        break;
                    }
                    
                    System.Threading.Thread.Sleep(500);
                }
                
                if (stopped)
                {
                    result.Success = true;
                    result.Message = "Servicio detenido exitosamente";
                }
                else
                {
                    result.Message = "Timeout esperando a que el servicio se detenga";
                    
                    // Intentar matar el proceso si hay timeout
                    ForceStopServiceProcess(serviceName);
                }
            }
            catch (Exception ex)
            {
                result.Message = $"Error deteniendo servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult DeleteService(string serviceName)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Primero detener el servicio
                var stopResult = StopService(serviceName);
                if (!stopResult.Success)
                {
                    // Intentar continuar aunque no se pueda detener
                }
                
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Eliminar servicio
                if (!DeleteService(service))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error eliminando servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                result.Success = true;
                result.Message = "Servicio eliminado exitosamente";
                
                // Eliminar del inventario
                RemoveServiceFromInventory(serviceName);
            }
            catch (Exception ex)
            {
                result.Message = $"Error eliminando servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult UpdateService(
            string serviceName,
            string newBinaryPath = null,
            ServiceStartType? newStartType = null,
            ServiceAccount? newAccount = null,
            string newDisplayName = null,
            string newDescription = null)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Actualizar configuración del servicio
                int serviceType = SERVICE_WIN32_OWN_PROCESS;
                int startType = newStartType.HasValue ? ConvertStartType(newStartType.Value) : -1;
                int errorControl = SERVICE_ERROR_NORMAL;
                string account = newAccount.HasValue ? ConvertServiceAccount(newAccount.Value) : null;
                
                if (!ChangeServiceConfig(
                    service,
                    serviceType,
                    startType,
                    errorControl,
                    newBinaryPath,
                    null, // loadOrderGroup
                    IntPtr.Zero, // tagId
                    null, // dependencies
                    account,
                    null, // password
                    newDisplayName))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error actualizando configuración del servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Actualizar descripción si se proporciona
                if (!string.IsNullOrEmpty(newDescription))
                {
                    SetServiceDescription(service, newDescription);
                }
                
                result.Success = true;
                result.Message = "Servicio actualizado exitosamente";
                
                // Actualizar inventario
                UpdateServiceInInventory(serviceName, newBinaryPath, newStartType, newAccount);
            }
            catch (Exception ex)
            {
                result.Message = $"Error actualizando servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult GetServiceStatus(string serviceName)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Consultar estado
                SERVICE_STATUS status = new SERVICE_STATUS();
                if (!QueryServiceStatus(service, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error consultando estado del servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                result.Success = true;
                result.Message = GetServiceStatusDescription(status.currentState);
            }
            catch (Exception ex)
            {
                result.Message = $"Error obteniendo estado del servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        public ServiceOperationResult GetServiceConfiguration(string serviceName)
        {
            var result = new ServiceOperationResult();
            
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir administrador de servicios
                scManager = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo administrador de servicios: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Abrir servicio
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.Message = $"Error abriendo servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Obtener tamaño del buffer necesario
                int bytesNeeded = 0;
                QueryServiceConfig(service, IntPtr.Zero, 0, out bytesNeeded);
                
                // Asignar buffer
                IntPtr buffer = Marshal.AllocHGlobal(bytesNeeded);
                try
                {
                    if (!QueryServiceConfig(service, buffer, bytesNeeded, out bytesNeeded))
                    {
                        int error = Marshal.GetLastWin32Error();
                        result.ErrorCode = error;
                        result.Message = $"Error obteniendo configuración del servicio: {new Win32Exception(error).Message}";
                        return result;
                    }
                    
                    // Aquí se procesaría la estructura QUERY_SERVICE_CONFIG
                    // Por simplicidad, solo devolvemos éxito
                    result.Success = true;
                    result.Message = "Configuración obtenida exitosamente";
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                result.Message = $"Error obteniendo configuración del servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
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
        
        #region Métodos privados
        
        private ServiceRegistrationResult UpdateServiceConfiguration(
            IntPtr scManager,
            string serviceName,
            string displayName,
            string description,
            string binaryPath,
            ServiceStartType startType,
            ServiceAccount account,
            string[] dependencies)
        {
            var result = new ServiceRegistrationResult
            {
                ServiceName = serviceName
            };
            
            IntPtr service = IntPtr.Zero;
            
            try
            {
                // Abrir servicio existente
                service = OpenService(scManager, serviceName, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.ErrorMessage = $"Error abriendo servicio existente: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Detener servicio temporalmente para actualizar
                StopService(serviceName, 15000);
                
                // Actualizar configuración
                int nativeStartType = ConvertStartType(startType);
                string nativeAccount = ConvertServiceAccount(account);
                
                if (!ChangeServiceConfig(
                    service,
                    SERVICE_WIN32_OWN_PROCESS,
                    nativeStartType,
                    SERVICE_ERROR_NORMAL,
                    binaryPath,
                    null, // loadOrderGroup
                    IntPtr.Zero, // tagId
                    dependencies != null ? string.Join("\0", dependencies) + "\0\0" : null,
                    nativeAccount,
                    null, // password
                    displayName))
                {
                    int error = Marshal.GetLastWin32Error();
                    result.ErrorCode = error;
                    result.ErrorMessage = $"Error actualizando servicio: {new Win32Exception(error).Message}";
                    return result;
                }
                
                // Actualizar descripción
                SetServiceDescription(service, description);
                
                // Reconfigurar recuperación
                ConfigureServiceRecovery(serviceName);
                
                result.Success = true;
                result.ServiceHandle = service;
                result.ErrorMessage = "Servicio actualizado exitosamente";
                
                // Actualizar inventario
                UpdateServiceInInventory(serviceName, binaryPath, startType, account);
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Error actualizando servicio: {ex.Message}";
                result.ErrorCode = ex.HResult;
            }
            finally
            {
                if (service != IntPtr.Zero && !result.Success)
                {
                    CloseServiceHandle(service);
                }
            }
            
            return result;
        }
        
        private void SetServiceDescription(IntPtr service, string description)
        {
            try
            {
                SERVICE_DESCRIPTION serviceDesc = new SERVICE_DESCRIPTION
                {
                    description = description
                };
                
                ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, ref serviceDesc);
            }
            catch
            {
                // Ignorar errores al establecer descripción
            }
        }
        
        private void ConfigureServiceRecovery(string serviceName)
        {
            try
            {
                // Configurar acciones de recuperación usando sc.exe
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "sc.exe";
                    process.StartInfo.Arguments = $"failure {serviceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(5000);
                }
            }
            catch (Exception)
            {
                // Ignorar errores en configuración de recuperación
            }
        }
        
        private void ConfigureServicePermissions(string serviceName)
        {
            try
            {
                // Configurar permisos usando sc.exe
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "sc.exe";
                    process.StartInfo.Arguments = $"sdset {serviceName} " +
                        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
                        "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(5000);
                }
            }
            catch (Exception)
            {
                // Ignorar errores en configuración de permisos
            }
        }
        
        private void ForceStopServiceProcess(string serviceName)
        {
            try
            {
                // Encontrar y matar el proceso del servicio
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "taskkill.exe";
                    process.StartInfo.Arguments = $"/F /FI \"SERVICES eq {serviceName}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    process.WaitForExit(5000);
                }
            }
            catch (Exception)
            {
                // Ignorar errores al forzar detención
            }
        }
        
        private void RegisterServiceInInventory(string serviceName, string binaryPath, 
            ServiceStartType startType, ServiceAccount account)
        {
            try
            {
                string registryPath = @"SOFTWARE\BWP Enterprise\Services";
                
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        string serviceKey = Path.Combine(registryPath, serviceName);
                        
                        using (RegistryKey serviceSubKey = Registry.LocalMachine.CreateSubKey(serviceKey))
                        {
                            if (serviceSubKey != null)
                            {
                                serviceSubKey.SetValue("BinaryPath", binaryPath, RegistryValueKind.String);
                                serviceSubKey.SetValue("StartType", startType.ToString(), RegistryValueKind.String);
                                serviceSubKey.SetValue("Account", account.ToString(), RegistryValueKind.String);
                                serviceSubKey.SetValue("InstallationDate", DateTime.UtcNow.ToString("o"), RegistryValueKind.String);
                                serviceSubKey.SetValue("Status", "Registered", RegistryValueKind.String);
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Ignorar errores de registro
            }
        }
        
        private void UpdateServiceInInventory(string serviceName, string binaryPath, 
            ServiceStartType? startType, ServiceAccount? account)
        {
            try
            {
                string registryPath = $@"SOFTWARE\BWP Enterprise\Services\{serviceName}";
                
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key != null)
                    {
                        if (!string.IsNullOrEmpty(binaryPath))
                        {
                            key.SetValue("BinaryPath", binaryPath, RegistryValueKind.String);
                        }
                        
                        if (startType.HasValue)
                        {
                            key.SetValue("StartType", startType.Value.ToString(), RegistryValueKind.String);
                        }
                        
                        if (account.HasValue)
                        {
                            key.SetValue("Account", account.Value.ToString(), RegistryValueKind.String);
                        }
                        
                        key.SetValue("LastUpdated", DateTime.UtcNow.ToString("o"), RegistryValueKind.String);
                    }
                }
            }
            catch (Exception)
            {
                // Ignorar errores de actualización
            }
        }
        
        private void RemoveServiceFromInventory(string serviceName)
        {
            try
            {
                string registryPath = $@"SOFTWARE\BWP Enterprise\Services\{serviceName}";
                Registry.LocalMachine.DeleteSubKeyTree(registryPath, false);
            }
            catch (Exception)
            {
                // Ignorar errores de eliminación
            }
        }
        
        private int ConvertStartType(ServiceStartType startType)
        {
            return startType switch
            {
                ServiceStartType.Auto => SERVICE_AUTO_START,
                ServiceStartType.Manual => SERVICE_DEMAND_START,
                ServiceStartType.Disabled => 0x00000004, // SERVICE_DISABLED
                ServiceStartType.DelayedAuto => 0x00000002, // SERVICE_AUTO_START con retraso
                _ => SERVICE_AUTO_START
            };
        }
        
        private string ConvertServiceAccount(ServiceAccount account)
        {
            return account switch
            {
                ServiceAccount.LocalSystem => "LocalSystem",
                ServiceAccount.LocalService => "NT AUTHORITY\\LocalService",
                ServiceAccount.NetworkService => "NT AUTHORITY\\NetworkService",
                _ => "LocalSystem"
            };
        }
        
        private string GetServiceStatusDescription(int status)
        {
            return status switch
            {
                1 => "Stopped",
                2 => "Start Pending",
                3 => "Stop Pending",
                4 => "Running",
                5 => "Continue Pending",
                6 => "Pause Pending",
                7 => "Paused",
                _ => $"Unknown ({status})"
            };
        }
        
        private bool IsRunningAsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        
        #endregion
        
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
    }
}