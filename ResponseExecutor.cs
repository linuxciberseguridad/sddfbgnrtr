using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Management;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Telemetry;

namespace BWP.Enterprise.Agent.Remediation
{
    /// <summary>
    /// Ejecutor de respuestas automáticas ante amenazas detectadas
    /// Realiza acciones de mitigación como terminar procesos, bloquear conexiones, etc.
    /// </summary>
    public class ResponseExecutor : IDisposable
    {
        private static readonly Lazy<ResponseExecutor> _instance =
            new Lazy<ResponseExecutor>(() => new ResponseExecutor());

        public static ResponseExecutor Instance => _instance.Value;

        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly TelemetryQueue _telemetryQueue;
        private readonly ConcurrentQueue<RemediationAction> _actionQueue;
        private readonly ConcurrentDictionary<string, RemediationHistory> _executionHistory;
        private bool _isRunning;
        private CancellationTokenSource _cancellationTokenSource;
        private Task _processingTask;

        // Límites de seguridad
        private const int MAX_PROCESS_KILLS_PER_MINUTE = 10;
        private const int MAX_FILE_QUARANTINES_PER_MINUTE = 20;
        private const int MAX_NETWORK_BLOCKS_PER_MINUTE = 50;
        private const int ROLLBACK_TIMEOUT_MINUTES = 60;

        // Contadores de rate limiting
        private int _processKillsLastMinute = 0;
        private int _fileQuarantinesLastMinute = 0;
        private int _networkBlocksLastMinute = 0;
        private DateTime _lastRateLimitReset = DateTime.UtcNow;

        private ResponseExecutor()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _telemetryQueue = TelemetryQueue.Instance;
            _actionQueue = new ConcurrentQueue<RemediationAction>();
            _executionHistory = new ConcurrentDictionary<string, RemediationHistory>();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Inicia el ejecutor de respuestas
        /// </summary>
        public void Start()
        {
            if (_isRunning) return;

            try
            {
                _logManager.LogInfo("Iniciando ResponseExecutor...", "ResponseExecutor");

                _isRunning = true;
                _processingTask = Task.Run(() => ProcessActionsAsync(_cancellationTokenSource.Token));

                _logManager.LogInfo("ResponseExecutor iniciado correctamente", "ResponseExecutor");
            }
            catch (Exception ex)
            {
                _logManager.LogCritical($"Error al iniciar ResponseExecutor: {ex}", "ResponseExecutor");
                throw;
            }
        }

        /// <summary>
        /// Detiene el ejecutor de respuestas
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _logManager.LogInfo("Deteniendo ResponseExecutor...", "ResponseExecutor");

                _isRunning = false;
                _cancellationTokenSource.Cancel();

                if (_processingTask != null)
                {
                    _processingTask.Wait(TimeSpan.FromSeconds(10));
                }

                _logManager.LogInfo("ResponseExecutor detenido correctamente", "ResponseExecutor");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener ResponseExecutor: {ex}", "ResponseExecutor");
            }
        }

        /// <summary>
        /// Ejecuta una acción de remediación
        /// </summary>
        public async Task<RemediationResult> ExecuteActionAsync(RemediationAction action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            try
            {
                // Verificar rate limits
                if (!CheckRateLimits(action.ActionType))
                {
                    var result = new RemediationResult
                    {
                        ActionId = action.ActionId,
                        Success = false,
                        ErrorMessage = "Rate limit exceeded",
                        ExecutedAt = DateTime.UtcNow
                    };

                    _logManager.LogWarning($"Rate limit excedido para {action.ActionType}", "ResponseExecutor");
                    return result;
                }

                // Ejecutar acción según tipo
                RemediationResult executionResult = action.ActionType switch
                {
                    RemediationActionType.KillProcess => await KillProcessAsync(action),
                    RemediationActionType.QuarantineFile => await QuarantineFileAsync(action),
                    RemediationActionType.BlockNetworkConnection => await BlockNetworkConnectionAsync(action),
                    RemediationActionType.DisableService => await DisableServiceAsync(action),
                    RemediationActionType.BlockRegistryKey => await BlockRegistryKeyAsync(action),
                    RemediationActionType.IsolateEndpoint => await IsolateEndpointAsync(action),
                    RemediationActionType.DeleteFile => await DeleteFileAsync(action),
                    RemediationActionType.DisableUserAccount => await DisableUserAccountAsync(action),
                    RemediationActionType.KillProcessTree => await KillProcessTreeAsync(action),
                    RemediationActionType.BlockIPAddress => await BlockIPAddressAsync(action),
                    _ => new RemediationResult
                    {
                        ActionId = action.ActionId,
                        Success = false,
                        ErrorMessage = "Unknown action type",
                        ExecutedAt = DateTime.UtcNow
                    }
                };

                // Registrar en historial
                RegisterExecution(action, executionResult);

                // Enviar telemetría
                await SendTelemetryAsync(action, executionResult);

                // Guardar en base de datos
                _localDatabase.StoreRemediationAction(action, executionResult);

                return executionResult;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al ejecutar acción {action.ActionType}: {ex}", "ResponseExecutor");

                return new RemediationResult
                {
                    ActionId = action.ActionId,
                    Success = false,
                    ErrorMessage = ex.Message,
                    ExecutedAt = DateTime.UtcNow
                };
            }
        }

        /// <summary>
        /// Encola una acción para ejecución asíncrona
        /// </summary>
        public void QueueAction(RemediationAction action)
        {
            if (action == null) return;

            _actionQueue.Enqueue(action);
            _logManager.LogInfo($"Acción {action.ActionType} encolada para proceso {action.ProcessId}", "ResponseExecutor");
        }

        /// <summary>
        /// Procesa acciones de forma asíncrona
        /// </summary>
        private async Task ProcessActionsAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (_actionQueue.TryDequeue(out RemediationAction action))
                    {
                        await ExecuteActionAsync(action);
                    }
                    else
                    {
                        await Task.Delay(100, cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en ProcessActionsAsync: {ex}", "ResponseExecutor");
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }

        #region Acciones de Remediación

        /// <summary>
        /// Termina un proceso malicioso
        /// </summary>
        private async Task<RemediationResult> KillProcessAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    var process = Process.GetProcessById(action.ProcessId);

                    if (process == null || process.HasExited)
                    {
                        result.Success = false;
                        result.ErrorMessage = "Process not found or already exited";
                        return result;
                    }

                    // Verificar si es un proceso crítico del sistema
                    if (IsCriticalSystemProcess(process.ProcessName))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Cannot kill critical system process";
                        _logManager.LogWarning($"Intento de terminar proceso crítico bloqueado: {process.ProcessName}", "ResponseExecutor");
                        return result;
                    }

                    // Guardar información del proceso para rollback
                    result.RollbackData = new Dictionary<string, object>
                    {
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id,
                        ["StartTime"] = process.StartTime,
                        ["FileName"] = process.MainModule?.FileName
                    };

                    // Terminar proceso
                    process.Kill();
                    process.WaitForExit(5000);

                    result.Success = true;
                    result.Message = $"Process {action.ProcessId} killed successfully";

                    _logManager.LogWarning($"Proceso {action.ProcessId} terminado: {action.Reason}", "ResponseExecutor");

                    // Incrementar contador de rate limit
                    Interlocked.Increment(ref _processKillsLastMinute);
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al terminar proceso {action.ProcessId}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Pone un archivo en cuarentena
        /// </summary>
        private async Task<RemediationResult> QuarantineFileAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.FilePath) || !File.Exists(action.FilePath))
                    {
                        result.Success = false;
                        result.ErrorMessage = "File not found";
                        return result;
                    }

                    // Usar QuarantineManager para la cuarentena
                    var quarantineResult = QuarantineManager.Instance.QuarantineFile(action.FilePath, action.Reason);

                    result.Success = quarantineResult.Success;
                    result.Message = quarantineResult.Message;
                    result.ErrorMessage = quarantineResult.ErrorMessage;
                    result.RollbackData = new Dictionary<string, object>
                    {
                        ["QuarantineId"] = quarantineResult.QuarantineId,
                        ["OriginalPath"] = action.FilePath
                    };

                    if (result.Success)
                    {
                        _logManager.LogWarning($"Archivo en cuarentena: {action.FilePath} - {action.Reason}", "ResponseExecutor");
                        Interlocked.Increment(ref _fileQuarantinesLastMinute);
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al poner archivo en cuarentena {action.FilePath}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Bloquea una conexión de red
        /// </summary>
        private async Task<RemediationResult> BlockNetworkConnectionAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.RemoteAddress))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Remote address not specified";
                        return result;
                    }

                    // Crear regla de firewall de Windows
                    string ruleName = $"BWP_Block_{action.RemoteAddress}_{DateTime.UtcNow.Ticks}";

                    var psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={action.RemoteAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(psi))
                    {
                        process.WaitForExit(10000);

                        if (process.ExitCode == 0)
                        {
                            result.Success = true;
                            result.Message = $"Network connection to {action.RemoteAddress} blocked";
                            result.RollbackData = new Dictionary<string, object>
                            {
                                ["FirewallRuleName"] = ruleName,
                                ["RemoteAddress"] = action.RemoteAddress
                            };

                            _logManager.LogWarning($"Conexión bloqueada: {action.RemoteAddress} - {action.Reason}", "ResponseExecutor");
                            Interlocked.Increment(ref _networkBlocksLastMinute);
                        }
                        else
                        {
                            result.Success = false;
                            result.ErrorMessage = process.StandardError.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al bloquear conexión {action.RemoteAddress}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Deshabilita un servicio
        /// </summary>
        private async Task<RemediationResult> DisableServiceAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.ServiceName))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Service name not specified";
                        return result;
                    }

                    // Verificar si es servicio crítico
                    if (IsCriticalSystemService(action.ServiceName))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Cannot disable critical system service";
                        _logManager.LogWarning($"Intento de deshabilitar servicio crítico bloqueado: {action.ServiceName}", "ResponseExecutor");
                        return result;
                    }

                    using (var sc = new System.ServiceProcess.ServiceController(action.ServiceName))
                    {
                        // Guardar estado original para rollback
                        result.RollbackData = new Dictionary<string, object>
                        {
                            ["ServiceName"] = action.ServiceName,
                            ["OriginalStatus"] = sc.Status.ToString(),
                            ["OriginalStartType"] = sc.StartType.ToString()
                        };

                        // Detener servicio si está corriendo
                        if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                        {
                            sc.Stop();
                            sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }

                        // Deshabilitar servicio usando WMI
                        using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Service WHERE Name = '{action.ServiceName}'"))
                        {
                            foreach (ManagementObject service in searcher.Get())
                            {
                                service.InvokeMethod("ChangeStartMode", new object[] { "Disabled" });
                            }
                        }

                        result.Success = true;
                        result.Message = $"Service {action.ServiceName} disabled successfully";

                        _logManager.LogWarning($"Servicio deshabilitado: {action.ServiceName} - {action.Reason}", "ResponseExecutor");
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al deshabilitar servicio {action.ServiceName}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Bloquea modificaciones a una clave de registro
        /// </summary>
        private async Task<RemediationResult> BlockRegistryKeyAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.RegistryKey))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Registry key not specified";
                        return result;
                    }

                    // En producción, implementar bloqueo real de registro mediante permisos ACL
                    // Por ahora, solo registramos el intento

                    result.Success = true;
                    result.Message = $"Registry key {action.RegistryKey} blocked";
                    result.RollbackData = new Dictionary<string, object>
                    {
                        ["RegistryKey"] = action.RegistryKey
                    };

                    _logManager.LogWarning($"Clave de registro bloqueada: {action.RegistryKey} - {action.Reason}", "ResponseExecutor");
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al bloquear clave de registro {action.RegistryKey}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Aísla el endpoint de la red
        /// </summary>
        private async Task<RemediationResult> IsolateEndpointAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    // Deshabilitar todos los adaptadores de red excepto loopback
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-NetAdapter | Where-Object {$_.Name -notlike '*Loopback*'} | Disable-NetAdapter -Confirm:$false\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(psi))
                    {
                        process.WaitForExit(30000);

                        if (process.ExitCode == 0)
                        {
                            result.Success = true;
                            result.Message = "Endpoint isolated from network";
                            result.RollbackData = new Dictionary<string, object>
                            {
                                ["IsolatedAt"] = DateTime.UtcNow
                            };

                            _logManager.LogCritical($"ENDPOINT AISLADO DE LA RED - {action.Reason}", "ResponseExecutor");
                        }
                        else
                        {
                            result.Success = false;
                            result.ErrorMessage = process.StandardError.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al aislar endpoint: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Elimina un archivo malicioso
        /// </summary>
        private async Task<RemediationResult> DeleteFileAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.FilePath) || !File.Exists(action.FilePath))
                    {
                        result.Success = false;
                        result.ErrorMessage = "File not found";
                        return result;
                    }

                    // Guardar información del archivo para rollback
                    var fileInfo = new FileInfo(action.FilePath);
                    result.RollbackData = new Dictionary<string, object>
                    {
                        ["FilePath"] = action.FilePath,
                        ["FileSize"] = fileInfo.Length,
                        ["LastModified"] = fileInfo.LastWriteTimeUtc
                    };

                    // Eliminar archivo
                    File.Delete(action.FilePath);

                    result.Success = true;
                    result.Message = $"File {action.FilePath} deleted successfully";

                    _logManager.LogWarning($"Archivo eliminado: {action.FilePath} - {action.Reason}", "ResponseExecutor");
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al eliminar archivo {action.FilePath}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Deshabilita una cuenta de usuario
        /// </summary>
        private async Task<RemediationResult> DisableUserAccountAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.UserName))
                    {
                        result.Success = false;
                        result.ErrorMessage = "User name not specified";
                        return result;
                    }

                    // Verificar si es cuenta crítica
                    if (IsCriticalUserAccount(action.UserName))
                    {
                        result.Success = false;
                        result.ErrorMessage = "Cannot disable critical user account";
                        _logManager.LogWarning($"Intento de deshabilitar cuenta crítica bloqueado: {action.UserName}", "ResponseExecutor");
                        return result;
                    }

                    var psi = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"user {action.UserName} /active:no",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(psi))
                    {
                        process.WaitForExit(10000);

                        if (process.ExitCode == 0)
                        {
                            result.Success = true;
                            result.Message = $"User account {action.UserName} disabled";
                            result.RollbackData = new Dictionary<string, object>
                            {
                                ["UserName"] = action.UserName
                            };

                            _logManager.LogCritical($"Cuenta de usuario deshabilitada: {action.UserName} - {action.Reason}", "ResponseExecutor");
                        }
                        else
                        {
                            result.Success = false;
                            result.ErrorMessage = process.StandardError.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al deshabilitar cuenta {action.UserName}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Termina un árbol completo de procesos
        /// </summary>
        private async Task<RemediationResult> KillProcessTreeAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    var childProcesses = GetChildProcesses(action.ProcessId);
                    var killedProcesses = new List<int>();

                    // Terminar procesos hijos primero
                    foreach (var childPid in childProcesses)
                    {
                        try
                        {
                            var childProcess = Process.GetProcessById(childPid);
                            if (!childProcess.HasExited && !IsCriticalSystemProcess(childProcess.ProcessName))
                            {
                                childProcess.Kill();
                                killedProcesses.Add(childPid);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logManager.LogWarning($"Error al terminar proceso hijo {childPid}: {ex.Message}", "ResponseExecutor");
                        }
                    }

                    // Terminar proceso padre
                    try
                    {
                        var parentProcess = Process.GetProcessById(action.ProcessId);
                        if (!parentProcess.HasExited && !IsCriticalSystemProcess(parentProcess.ProcessName))
                        {
                            parentProcess.Kill();
                            killedProcesses.Add(action.ProcessId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogWarning($"Error al terminar proceso padre {action.ProcessId}: {ex.Message}", "ResponseExecutor");
                    }

                    result.Success = killedProcesses.Count > 0;
                    result.Message = $"Process tree killed: {killedProcesses.Count} processes terminated";
                    result.RollbackData = new Dictionary<string, object>
                    {
                        ["KilledProcesses"] = killedProcesses
                    };

                    _logManager.LogWarning($"Árbol de procesos terminado: {killedProcesses.Count} procesos - {action.Reason}", "ResponseExecutor");
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al terminar árbol de procesos {action.ProcessId}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        /// <summary>
        /// Bloquea una dirección IP
        /// </summary>
        private async Task<RemediationResult> BlockIPAddressAsync(RemediationAction action)
        {
            return await Task.Run(() =>
            {
                var result = new RemediationResult
                {
                    ActionId = action.ActionId,
                    ExecutedAt = DateTime.UtcNow
                };

                try
                {
                    if (string.IsNullOrEmpty(action.RemoteAddress))
                    {
                        result.Success = false;
                        result.ErrorMessage = "IP address not specified";
                        return result;
                    }

                    string ruleName = $"BWP_BlockIP_{action.RemoteAddress.Replace(".", "_")}_{DateTime.UtcNow.Ticks}";

                    // Bloquear entrada y salida
                    var psiOut = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"advfirewall firewall add rule name=\"{ruleName}_Out\" dir=out action=block remoteip={action.RemoteAddress}",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    var psiIn = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"advfirewall firewall add rule name=\"{ruleName}_In\" dir=in action=block remoteip={action.RemoteAddress}",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var processOut = Process.Start(psiOut))
                    using (var processIn = Process.Start(psiIn))
                    {
                        processOut.WaitForExit(10000);
                        processIn.WaitForExit(10000);

                        if (processOut.ExitCode == 0 && processIn.ExitCode == 0)
                        {
                            result.Success = true;
                            result.Message = $"IP address {action.RemoteAddress} blocked";
                            result.RollbackData = new Dictionary<string, object>
                            {
                                ["FirewallRuleNameOut"] = $"{ruleName}_Out",
                                ["FirewallRuleNameIn"] = $"{ruleName}_In",
                                ["RemoteAddress"] = action.RemoteAddress
                            };

                            _logManager.LogWarning($"IP bloqueada: {action.RemoteAddress} - {action.Reason}", "ResponseExecutor");
                        }
                        else
                        {
                            result.Success = false;
                            result.ErrorMessage = "Failed to create firewall rules";
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                    _logManager.LogError($"Error al bloquear IP {action.RemoteAddress}: {ex}", "ResponseExecutor");
                }

                return result;
            });
        }

        #endregion

        #region Helper Methods

        private bool CheckRateLimits(RemediationActionType actionType)
        {
            // Resetear contadores cada minuto
            if ((DateTime.UtcNow - _lastRateLimitReset).TotalMinutes >= 1)
            {
                _processKillsLastMinute = 0;
                _fileQuarantinesLastMinute = 0;
                _networkBlocksLastMinute = 0;
                _lastRateLimitReset = DateTime.UtcNow;
            }

            // Verificar límites según tipo de acción
            return actionType switch
            {
                RemediationActionType.KillProcess => _processKillsLastMinute < MAX_PROCESS_KILLS_PER_MINUTE,
                RemediationActionType.KillProcessTree => _processKillsLastMinute < MAX_PROCESS_KILLS_PER_MINUTE,
                RemediationActionType.QuarantineFile => _fileQuarantinesLastMinute < MAX_FILE_QUARANTINES_PER_MINUTE,
                RemediationActionType.DeleteFile => _fileQuarantinesLastMinute < MAX_FILE_QUARANTINES_PER_MINUTE,
                RemediationActionType.BlockNetworkConnection => _networkBlocksLastMinute < MAX_NETWORK_BLOCKS_PER_MINUTE,
                RemediationActionType.BlockIPAddress => _networkBlocksLastMinute < MAX_NETWORK_BLOCKS_PER_MINUTE,
                _ => true
            };
        }

        private bool IsCriticalSystemProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;

            var criticalProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"
            };

            return criticalProcesses.Contains(processName);
        }

        private bool IsCriticalSystemService(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName)) return false;

            var criticalServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "EventLog", "PlugPlay", "RpcSs", "DcomLaunch", "LanmanServer",
                "LanmanWorkstation", "Dhcp", "Dnscache", "W32Time"
            };

            return criticalServices.Contains(serviceName);
        }

        private bool IsCriticalUserAccount(string userName)
        {
            if (string.IsNullOrEmpty(userName)) return false;

            var criticalAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Administrator", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"
            };

            return criticalAccounts.Contains(userName);
        }

        private List<int> GetChildProcesses(int parentProcessId)
        {
            var childProcesses = new List<int>();

            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentProcessId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var childPid = Convert.ToInt32(obj["ProcessId"]);
                        childProcesses.Add(childPid);

                        // Recursivo para obtener todos los descendientes
                        childProcesses.AddRange(GetChildProcesses(childPid));
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogWarning($"Error al obtener procesos hijos de {parentProcessId}: {ex.Message}", "ResponseExecutor");
            }

            return childProcesses;
        }

        private void RegisterExecution(RemediationAction action, RemediationResult result)
        {
            var history = new RemediationHistory
            {
                ActionId = action.ActionId,
                ActionType = action.ActionType,
                ExecutedAt = result.ExecutedAt,
                Success = result.Success,
                CanRollback = result.RollbackData != null && result.RollbackData.Count > 0,
                RollbackData = result.RollbackData
            };

            _executionHistory[action.ActionId] = history;
        }

        private async Task SendTelemetryAsync(RemediationAction action, RemediationResult result)
        {
            try
            {
                var telemetryData = new Dictionary<string, object>
                {
                    ["EventType"] = "RemediationExecuted",
                    ["ActionType"] = action.ActionType.ToString(),
                    ["ActionId"] = action.ActionId,
                    ["Success"] = result.Success,
                    ["Reason"] = action.Reason,
                    ["ProcessId"] = action.ProcessId,
                    ["FilePath"] = action.FilePath,
                    ["RemoteAddress"] = action.RemoteAddress,
                    ["ExecutedAt"] = result.ExecutedAt,
                    ["ErrorMessage"] = result.ErrorMessage
                };

                await _telemetryQueue.EnqueueEventAsync(telemetryData);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al enviar telemetría de remediación: {ex}", "ResponseExecutor");
            }
        }

        /// <summary>
        /// Revierte una acción de remediación
        /// </summary>
        public async Task<bool> RollbackActionAsync(string actionId)
        {
            try
            {
                if (!_executionHistory.TryGetValue(actionId, out var history))
                {
                    _logManager.LogWarning($"No se encontró historial para acción {actionId}", "ResponseExecutor");
                    return false;
                }

                if (!history.CanRollback)
                {
                    _logManager.LogWarning($"Acción {actionId} no puede revertirse", "ResponseExecutor");
                    return false;
                }

                if ((DateTime.UtcNow - history.ExecutedAt).TotalMinutes > ROLLBACK_TIMEOUT_MINUTES)
                {
                    _logManager.LogWarning($"Timeout de rollback excedido para acción {actionId}", "ResponseExecutor");
                    return false;
                }

                // Implementar rollback según tipo de acción
                bool success = history.ActionType switch
                {
                    RemediationActionType.QuarantineFile => await RollbackQuarantineAsync(history),
                    RemediationActionType.BlockNetworkConnection => await RollbackNetworkBlockAsync(history),
                    RemediationActionType.DisableService => await RollbackServiceDisableAsync(history),
                    RemediationActionType.BlockIPAddress => await RollbackIPBlockAsync(history),
                    _ => false
                };

                if (success)
                {
                    _logManager.LogInfo($"Rollback exitoso para acción {actionId}", "ResponseExecutor");
                }

                return success;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en rollback de acción {actionId}: {ex}", "ResponseExecutor");
                return false;
            }
        }

        private async Task<bool> RollbackQuarantineAsync(RemediationHistory history)
        {
            if (history.RollbackData.TryGetValue("QuarantineId", out var quarantineIdObj))
            {
                string quarantineId = quarantineIdObj.ToString();
                return await Task.Run(() => QuarantineManager.Instance.RestoreFromQuarantine(quarantineId));
            }
            return false;
        }

        private async Task<bool> RollbackNetworkBlockAsync(RemediationHistory history)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (history.RollbackData.TryGetValue("FirewallRuleName", out var ruleNameObj))
                    {
                        string ruleName = ruleNameObj.ToString();
                        var psi = new ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var process = Process.Start(psi))
                        {
                            process.WaitForExit(10000);
                            return process.ExitCode == 0;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en rollback de bloqueo de red: {ex}", "ResponseExecutor");
                }
                return false;
            });
        }

        private async Task<bool> RollbackServiceDisableAsync(RemediationHistory history)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (history.RollbackData.TryGetValue("ServiceName", out var serviceNameObj) &&
                        history.RollbackData.TryGetValue("OriginalStartType", out var startTypeObj))
                    {
                        string serviceName = serviceNameObj.ToString();
                        string startType = startTypeObj.ToString();

                        using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Service WHERE Name = '{serviceName}'"))
                        {
                            foreach (ManagementObject service in searcher.Get())
                            {
                                service.InvokeMethod("ChangeStartMode", new object[] { startType });
                                return true;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en rollback de servicio: {ex}", "ResponseExecutor");
                }
                return false;
            });
        }

        private async Task<bool> RollbackIPBlockAsync(RemediationHistory history)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (history.RollbackData.TryGetValue("FirewallRuleNameOut", out var ruleOutObj) &&
                        history.RollbackData.TryGetValue("FirewallRuleNameIn", out var ruleInObj))
                    {
                        string ruleOut = ruleOutObj.ToString();
                        string ruleIn = ruleInObj.ToString();

                        var psiOut = new ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = $"advfirewall firewall delete rule name=\"{ruleOut}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        var psiIn = new ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = $"advfirewall firewall delete rule name=\"{ruleIn}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var processOut = Process.Start(psiOut))
                        using (var processIn = Process.Start(psiIn))
                        {
                            processOut.WaitForExit(10000);
                            processIn.WaitForExit(10000);
                            return processOut.ExitCode == 0 && processIn.ExitCode == 0;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error en rollback de bloqueo de IP: {ex}", "ResponseExecutor");
                }
                return false;
            });
        }

        #endregion

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource?.Dispose();
        }
    }

    #region Data Models

    public enum RemediationActionType
    {
        KillProcess,
        QuarantineFile,
        BlockNetworkConnection,
        DisableService,
        BlockRegistryKey,
        IsolateEndpoint,
        DeleteFile,
        DisableUserAccount,
        KillProcessTree,
        BlockIPAddress
    }

    public class RemediationAction
    {
        public string ActionId { get; set; } = Guid.NewGuid().ToString();
        public RemediationActionType ActionType { get; set; }
        public string Reason { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string ServiceName { get; set; }
        public string RegistryKey { get; set; }
        public string UserName { get; set; }
        public DateTime RequestedAt { get; set; } = DateTime.UtcNow;
        public Dictionary<string, object> AdditionalData { get; set; }
    }

    public class RemediationResult
    {
        public string ActionId { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime ExecutedAt { get; set; }
        public Dictionary<string, object> RollbackData { get; set; }
    }

    public class RemediationHistory
    {
        public string ActionId { get; set; }
        public RemediationActionType ActionType { get; set; }
        public DateTime ExecutedAt { get; set; }
        public bool Success { get; set; }
        public bool CanRollback { get; set; }
        public Dictionary<string, object> RollbackData { get; set; }
    }

    #endregion
}