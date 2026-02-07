using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;

namespace BWP.Enterprise.Agent.Communication
{
    /// <summary>
    /// Autenticador de dispositivo para BWP Enterprise
    /// Maneja autenticación basada en tokens, certificados y validación de integridad
    /// </summary>
    public sealed class DeviceAuthenticator : IAgentModule, IDeviceAuthenticator
    {
        private static readonly Lazy<DeviceAuthenticator> _instance = 
            new Lazy<DeviceAuthenticator>(() => new DeviceAuthenticator());
        
        public static DeviceAuthenticator Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly CryptoHelper _cryptoHelper;
        
        private DeviceCredentials _currentCredentials;
        private X509Certificate2 _deviceCertificate;
        private AuthenticationStatus _authStatus;
        private DateTime _lastAuthTime;
        private Timer _renewalTimer;
        private bool _isInitialized;
        
        public string ModuleId => "DeviceAuthenticator";
        public string Version => "1.0.0";
        public string Description => "Módulo de autenticación de dispositivo";
        
        private DeviceAuthenticator()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _cryptoHelper = CryptoHelper.Instance;
            _authStatus = AuthenticationStatus.NotAuthenticated;
        }
        
        /// <summary>
        /// Inicializa el autenticador
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando DeviceAuthenticator...", ModuleId);
                
                // Cargar credenciales desde base de datos
                await LoadCredentialsAsync();
                
                // Inicializar certificado del dispositivo
                await InitializeDeviceCertificateAsync();
                
                // Configurar temporizador de renovación
                _renewalTimer = new Timer(RenewCredentialsCallback, null, 
                    TimeSpan.FromHours(1), TimeSpan.FromHours(1));
                
                _isInitialized = true;
                _logManager.LogInfo("DeviceAuthenticator inicializado", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar DeviceAuthenticator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Inicia el autenticador
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
                // Intentar autenticación inicial
                var authResult = await AuthenticateAsync();
                
                if (authResult.IsSuccess)
                {
                    _logManager.LogInfo("DeviceAuthenticator iniciado y autenticado", ModuleId);
                    return ModuleOperationResult.SuccessResult();
                }
                else
                {
                    _logManager.LogWarning($"Autenticación inicial fallida: {authResult.ErrorMessage}", ModuleId);
                    return ModuleOperationResult.ErrorResult($"Autenticación fallida: {authResult.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al iniciar DeviceAuthenticator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Detiene el autenticador
        /// </summary>
        public async Task<ModuleOperationResult> StopAsync()
        {
            try
            {
                _renewalTimer?.Dispose();
                
                // Invalidar credenciales en memoria
                _currentCredentials = null;
                _authStatus = AuthenticationStatus.NotAuthenticated;
                
                _logManager.LogInfo("DeviceAuthenticator detenido", ModuleId);
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al detener DeviceAuthenticator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Autentica el dispositivo con el servidor
        /// </summary>
        public async Task<AuthenticationResult> AuthenticateAsync()
        {
            try
            {
                _logManager.LogInfo("Iniciando autenticación de dispositivo...", ModuleId);
                
                // Verificar si ya hay credenciales válidas
                if (_currentCredentials != null && 
                    _currentCredentials.ExpiresAt > DateTime.UtcNow.AddMinutes(5))
                {
                    _logManager.LogInfo("Credenciales válidas encontradas, autenticación rápida", ModuleId);
                    _authStatus = AuthenticationStatus.Authenticated;
                    _lastAuthTime = DateTime.UtcNow;
                    
                    return AuthenticationResult.Success("Autenticación rápida exitosa");
                }
                
                // Paso 1: Obtener nonce del servidor
                var apiClient = ApiClient.Instance;
                var nonceResponse = await apiClient.GetAuthenticationNonceAsync();
                
                if (!nonceResponse.IsSuccess)
                {
                    return AuthenticationResult.Failed($"Error obteniendo nonce: {nonceResponse.ErrorMessage}");
                }
                
                // Paso 2: Firmar nonce con clave privada del dispositivo
                var signedNonce = await SignDataWithDeviceKeyAsync(nonceResponse.Nonce);
                
                // Paso 3: Enviar autenticación al servidor
                var authRequest = new AuthenticationRequest
                {
                    DeviceId = GetDeviceId(),
                    TenantId = _currentCredentials?.TenantId,
                    Nonce = nonceResponse.Nonce,
                    Signature = signedNonce,
                    Timestamp = DateTime.UtcNow,
                    CertificateThumbprint = _deviceCertificate?.Thumbprint
                };
                
                var authResponse = await apiClient.AuthenticateDeviceAsync(authRequest);
                
                if (!authResponse.IsSuccess)
                {
                    _authStatus = AuthenticationStatus.AuthenticationFailed;
                    _logManager.LogError($"Autenticación fallida: {authResponse.ErrorMessage}", ModuleId);
                    
                    return AuthenticationResult.Failed(authResponse.ErrorMessage);
                }
                
                // Paso 4: Guardar nuevas credenciales
                _currentCredentials = new DeviceCredentials
                {
                    DeviceId = GetDeviceId(),
                    TenantId = authResponse.TenantId,
                    AccessToken = authResponse.AccessToken,
                    RefreshToken = authResponse.RefreshToken,
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddSeconds(authResponse.ExpiresIn),
                    TokenType = authResponse.TokenType,
                    Scope = authResponse.Scope
                };
                
                await SaveCredentialsAsync(_currentCredentials);
                
                _authStatus = AuthenticationStatus.Authenticated;
                _lastAuthTime = DateTime.UtcNow;
                
                _logManager.LogInfo("Autenticación exitosa", ModuleId);
                return AuthenticationResult.Success("Autenticación exitosa");
            }
            catch (Exception ex)
            {
                _authStatus = AuthenticationStatus.AuthenticationFailed;
                _logManager.LogError($"Error en autenticación: {ex}", ModuleId);
                return AuthenticationResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Obtiene credenciales actuales
        /// </summary>
        public async Task<DeviceCredentials> GetCredentialsAsync()
        {
            if (_currentCredentials == null || 
                _currentCredentials.ExpiresAt <= DateTime.UtcNow.AddMinutes(1))
            {
                await RefreshCredentialsAsync();
            }
            
            return _currentCredentials;
        }
        
        /// <summary>
        /// Verifica si el dispositivo está autenticado
        /// </summary>
        public bool IsAuthenticated()
        {
            return _authStatus == AuthenticationStatus.Authenticated &&
                   _currentCredentials != null &&
                   _currentCredentials.ExpiresAt > DateTime.UtcNow.AddMinutes(1);
        }
        
        /// <summary>
        /// Obtiene el estado de autenticación
        /// </summary>
        public AuthenticationStatus GetAuthenticationStatus()
        {
            return _authStatus;
        }
        
        /// <summary>
        /// Firma datos con la clave privada del dispositivo
        /// </summary>
        public async Task<string> SignDataAsync(string data)
        {
            return await SignDataWithDeviceKeyAsync(data);
        }
        
        /// <summary>
        /// Verifica firma con clave pública del servidor
        /// </summary>
        public async Task<bool> VerifyServerSignatureAsync(string data, string signature)
        {
            try
            {
                // Obtener certificado del servidor
                var serverCertificate = await GetServerCertificateAsync();
                
                using (var rsa = serverCertificate.GetRSAPublicKey())
                {
                    var dataBytes = Encoding.UTF8.GetBytes(data);
                    var signatureBytes = Convert.FromBase64String(signature);
                    
                    return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando firma del servidor: {ex}", ModuleId);
                return false;
            }
        }
        
        /// <summary>
        /// Registra nuevo dispositivo en el tenant
        /// </summary>
        public async Task<RegistrationResult> RegisterDeviceAsync(string tenantToken, string deviceName, string groupId = null)
        {
            try
            {
                _logManager.LogInfo("Registrando nuevo dispositivo...", ModuleId);
                
                // Verificar token del tenant
                var tokenValidation = await ValidateTenantTokenAsync(tenantToken);
                if (!tokenValidation.IsValid)
                {
                    return RegistrationResult.Failed($"Token inválido: {tokenValidation.ErrorMessage}");
                }
                
                // Generar par de claves para el dispositivo
                var keyPair = await GenerateDeviceKeyPairAsync();
                
                // Generar CSR (Certificate Signing Request)
                var csr = await GenerateCertificateSigningRequestAsync(deviceName, keyPair);
                
                // Enviar solicitud de registro al servidor
                var registrationRequest = new DeviceRegistrationRequest
                {
                    TenantToken = tenantToken,
                    DeviceId = GetDeviceId(),
                    DeviceName = deviceName,
                    DeviceType = GetDeviceType(),
                    OperatingSystem = Environment.OSVersion.ToString(),
                    GroupId = groupId,
                    Csr = csr,
                    PublicKey = keyPair.PublicKey,
                    HardwareId = GetHardwareId()
                };
                
                var apiClient = ApiClient.Instance;
                var registrationResponse = await apiClient.RegisterDeviceAsync(registrationRequest);
                
                if (!registrationResponse.IsSuccess)
                {
                    return RegistrationResult.Failed($"Registro fallido: {registrationResponse.ErrorMessage}");
                }
                
                // Instalar certificado del dispositivo
                await InstallDeviceCertificateAsync(registrationResponse.Certificate);
                
                // Guardar información del tenant
                var credentials = new DeviceCredentials
                {
                    DeviceId = GetDeviceId(),
                    TenantId = registrationResponse.TenantId,
                    DeviceName = deviceName,
                    GroupId = groupId,
                    RegistrationTime = DateTime.UtcNow
                };
                
                _currentCredentials = credentials;
                await SaveCredentialsAsync(credentials);
                
                _logManager.LogInfo($"Dispositivo registrado exitosamente en tenant: {registrationResponse.TenantId}", ModuleId);
                return RegistrationResult.Success(registrationResponse.TenantId, GetDeviceId());
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en registro de dispositivo: {ex}", ModuleId);
                return RegistrationResult.Failed($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Revoca acceso al dispositivo
        /// </summary>
        public async Task<bool> RevokeDeviceAsync()
        {
            try
            {
                _logManager.LogInfo("Revocando acceso del dispositivo...", ModuleId);
                
                var apiClient = ApiClient.Instance;
                var result = await apiClient.RevokeDeviceAsync(GetDeviceId());
                
                if (result.IsSuccess)
                {
                    // Limpiar credenciales locales
                    await ClearLocalCredentialsAsync();
                    _authStatus = AuthenticationStatus.Revoked;
                    
                    _logManager.LogInfo("Acceso del dispositivo revocado", ModuleId);
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error revocando dispositivo: {ex}", ModuleId);
                return false;
            }
        }
        
        #region Métodos privados
        
        /// <summary>
        /// Carga credenciales desde base de datos
        /// </summary>
        private async Task LoadCredentialsAsync()
        {
            try
            {
                _currentCredentials = await _localDatabase.GetDeviceCredentialsAsync();
                
                if (_currentCredentials != null)
                {
                    _logManager.LogInfo($"Credenciales cargadas para tenant: {_currentCredentials.TenantId}", ModuleId);
                }
                else
                {
                    _logManager.LogInfo("No hay credenciales guardadas", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando credenciales: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Inicializa certificado del dispositivo
        /// </summary>
        private async Task InitializeDeviceCertificateAsync()
        {
            try
            {
                // Buscar certificado en almacén local
                var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                
                var certificates = store.Certificates.Find(
                    X509FindType.FindBySubjectName, 
                    GetDeviceCertificateSubject(),
                    false);
                
                if (certificates.Count > 0)
                {
                    _deviceCertificate = certificates[0];
                    _logManager.LogInfo($"Certificado del dispositivo encontrado: {_deviceCertificate.Thumbprint}", ModuleId);
                }
                else
                {
                    _logManager.LogWarning("Certificado del dispositivo no encontrado", ModuleId);
                }
                
                store.Close();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando certificado: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Refresca credenciales expiradas
        /// </summary>
        private async Task RefreshCredentialsAsync()
        {
            try
            {
                if (_currentCredentials == null || string.IsNullOrEmpty(_currentCredentials.RefreshToken))
                {
                    // Necesita autenticación completa
                    await AuthenticateAsync();
                    return;
                }
                
                _logManager.LogInfo("Refrescando credenciales...", ModuleId);
                
                var refreshRequest = new TokenRefreshRequest
                {
                    DeviceId = GetDeviceId(),
                    RefreshToken = _currentCredentials.RefreshToken,
                    GrantType = "refresh_token"
                };
                
                var apiClient = ApiClient.Instance;
                var refreshResponse = await apiClient.RefreshTokenAsync(refreshRequest);
                
                if (refreshResponse.IsSuccess)
                {
                    _currentCredentials.AccessToken = refreshResponse.AccessToken;
                    _currentCredentials.RefreshToken = refreshResponse.RefreshToken;
                    _currentCredentials.IssuedAt = DateTime.UtcNow;
                    _currentCredentials.ExpiresAt = DateTime.UtcNow.AddSeconds(refreshResponse.ExpiresIn);
                    
                    await SaveCredentialsAsync(_currentCredentials);
                    
                    _logManager.LogInfo("Credenciales refrescadas exitosamente", ModuleId);
                }
                else
                {
                    _logManager.LogWarning($"Error refrescando credenciales: {refreshResponse.ErrorMessage}", ModuleId);
                    
                    // Intentar autenticación completa
                    await AuthenticateAsync();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error refrescando credenciales: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Callback para renovación automática
        /// </summary>
        private async void RenewCredentialsCallback(object state)
        {
            try
            {
                if (_currentCredentials != null && 
                    _currentCredentials.ExpiresAt < DateTime.UtcNow.AddMinutes(30))
                {
                    await RefreshCredentialsAsync();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en renovación automática: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Firma datos con clave del dispositivo
        /// </summary>
        private async Task<string> SignDataWithDeviceKeyAsync(string data)
        {
            try
            {
                if (_deviceCertificate == null || !_deviceCertificate.HasPrivateKey)
                {
                    throw new InvalidOperationException("Certificado del dispositivo no disponible o sin clave privada");
                }
                
                using (var rsa = _deviceCertificate.GetRSAPrivateKey())
                {
                    var dataBytes = Encoding.UTF8.GetBytes(data);
                    var signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    
                    return Convert.ToBase64String(signatureBytes);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error firmando datos: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Guarda credenciales en base de datos
        /// </summary>
        private async Task SaveCredentialsAsync(DeviceCredentials credentials)
        {
            try
            {
                await _localDatabase.SaveDeviceCredentialsAsync(credentials);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando credenciales: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene certificado del servidor
        /// </summary>
        private async Task<X509Certificate2> GetServerCertificateAsync()
        {
            try
            {
                // Buscar en almacén de certificados raíz
                var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                
                // Buscar por nombre del servidor BWP (en producción obtener de configuración)
                var certificates = store.Certificates.Find(
                    X509FindType.FindBySubjectName,
                    "BWP Enterprise Server",
                    false);
                
                store.Close();
                
                if (certificates.Count > 0)
                {
                    return certificates[0];
                }
                
                // Si no está, descargar del servidor
                var apiClient = ApiClient.Instance;
                var certData = await apiClient.GetServerCertificateAsync();
                
                if (!string.IsNullOrEmpty(certData))
                {
                    var certificate = new X509Certificate2(Convert.FromBase64String(certData));
                    
                    // Agregar al almacén de confianza
                    var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                    rootStore.Open(OpenFlags.ReadWrite);
                    rootStore.Add(certificate);
                    rootStore.Close();
                    
                    return certificate;
                }
                
                throw new InvalidOperationException("No se pudo obtener certificado del servidor");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo certificado del servidor: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Valida token del tenant
        /// </summary>
        private async Task<TokenValidationResult> ValidateTenantTokenAsync(string token)
        {
            try
            {
                // Verificar formato básico
                if (string.IsNullOrEmpty(token) || token.Length != 64)
                {
                    return TokenValidationResult.Invalid("Formato de token inválido");
                }
                
                // Verificar con servidor (si hay conexión)
                var apiClient = ApiClient.Instance;
                var validationResult = await apiClient.ValidateTenantTokenAsync(token);
                
                return validationResult.IsSuccess ? 
                    TokenValidationResult.Valid() : 
                    TokenValidationResult.Invalid(validationResult.ErrorMessage);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error validando token: {ex}", ModuleId);
                return TokenValidationResult.Invalid($"Error de validación: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Genera par de claves para el dispositivo
        /// </summary>
        private async Task<DeviceKeyPair> GenerateDeviceKeyPairAsync()
        {
            try
            {
                using (var rsa = RSA.Create(2048))
                {
                    var privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
                    var publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
                    
                    return new DeviceKeyPair
                    {
                        PrivateKey = privateKey,
                        PublicKey = publicKey,
                        Algorithm = "RSA",
                        KeySize = 2048,
                        CreatedAt = DateTime.UtcNow
                    };
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando par de claves: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Genera CSR (Certificate Signing Request)
        /// </summary>
        private async Task<string> GenerateCertificateSigningRequestAsync(string deviceName, DeviceKeyPair keyPair)
        {
            try
            {
                // Crear solicitud de certificado
                var subject = new X500DistinguishedName($"CN={deviceName}, O=BWP Enterprise, C=Global");
                
                var request = new CertificateRequest(
                    subject,
                    RSA.Create(2048),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                
                // Agregar extensiones
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection 
                        { 
                            new Oid("1.3.6.1.5.5.7.3.2") // Client Authentication
                        }, 
                        true));
                
                // Generar CSR
                var csr = request.CreateSigningRequest();
                return Convert.ToBase64String(csr);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando CSR: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Instala certificado del dispositivo
        /// </summary>
        private async Task InstallDeviceCertificateAsync(string certificatePem)
        {
            try
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(certificatePem));
                
                // Agregar al almacén personal
                var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);
                store.Close();
                
                _deviceCertificate = certificate;
                
                _logManager.LogInfo($"Certificado instalado: {certificate.Thumbprint}", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error instalando certificado: {ex}", ModuleId);
                throw;
            }
        }
        
        /// <summary>
        /// Limpia credenciales locales
        /// </summary>
        private async Task ClearLocalCredentialsAsync()
        {
            try
            {
                _currentCredentials = null;
                await _localDatabase.ClearDeviceCredentialsAsync();
                
                _logManager.LogInfo("Credenciales locales limpiadas", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error limpiando credenciales: {ex}", ModuleId);
            }
        }
        
        /// <summary>
        /// Obtiene ID único del dispositivo
        /// </summary>
        private string GetDeviceId()
        {
            // Usar identificadores únicos del sistema
            var machineId = Environment.MachineName.GetHashCode().ToString("X8");
            var volumeId = GetVolumeSerialNumber();
            var cpuId = GetCpuId();
            
            // Combinar y hashear para obtener ID único
            var combined = $"{machineId}:{volumeId}:{cpuId}";
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        
        /// <summary>
        /// Obtiene tipo de dispositivo
        /// </summary>
        private string GetDeviceType()
        {
            return Environment.Is64BitOperatingSystem ? "Windows-x64" : "Windows-x86";
        }
        
        /// <summary>
        /// Obtiene ID de hardware
        /// </summary>
        private string GetHardwareId()
        {
            try
            {
                // Usar múltiples identificadores de hardware
                var identifiers = new List<string>();
                
                // CPU ID
                identifiers.Add(GetCpuId());
                
                // Motherboard serial
                identifiers.Add(GetMotherboardSerial());
                
                // Disk serial
                identifiers.Add(GetDiskSerial());
                
                // MAC address
                identifiers.Add(GetMacAddress());
                
                var combined = string.Join("|", identifiers);
                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return GetDeviceId(); // Fallback al device ID
            }
        }
        
        private string GetVolumeSerialNumber()
        {
            try
            {
                var drive = System.IO.DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.DriveType == DriveType.Fixed);
                return drive?.VolumeSerialNumber.ToString("X8") ?? "00000000";
            }
            catch
            {
                return "00000000";
            }
        }
        
        private string GetCpuId()
        {
            try
            {
                // Implementación simplificada
                return Environment.ProcessorCount.ToString("X4") + 
                       Environment.TickCount.ToString("X8");
            }
            catch
            {
                return "UNKNOWNCPU";
            }
        }
        
        private string GetMotherboardSerial()
        {
            try
            {
                // En producción usar WMI para obtener serial real
                return "MB-" + Guid.NewGuid().ToString("N").Substring(0, 12);
            }
            catch
            {
                return "UNKNOWNMB";
            }
        }
        
        private string GetDiskSerial()
        {
            try
            {
                // Implementación simplificada
                return "DISK-" + DateTime.UtcNow.Ticks.ToString("X");
            }
            catch
            {
                return "UNKNOWNDISK";
            }
        }
        
        private string GetMacAddress()
        {
            try
            {
                var networkInterface = System.Net.NetworkInformation.NetworkInterface
                    .GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && 
                                       n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
                
                return networkInterface?.GetPhysicalAddress().ToString() ?? "00-00-00-00-00-00";
            }
            catch
            {
                return "00-00-00-00-00-00";
            }
        }
        
        private string GetDeviceCertificateSubject()
        {
            var deviceId = GetDeviceId();
            return $"CN=BWP Device {deviceId.Substring(0, 8)}, O=BWP Enterprise, C=Global";
        }
        
        #endregion
        
        #region Métodos de HealthCheck
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var status = new List<string>();
                
                if (!IsAuthenticated())
                    status.Add("No autenticado");
                
                if (_deviceCertificate == null)
                    status.Add("Certificado no disponible");
                else if (_deviceCertificate.NotAfter < DateTime.UtcNow.AddDays(7))
                    status.Add("Certificado próximo a expirar");
                
                if (_currentCredentials?.ExpiresAt < DateTime.UtcNow.AddHours(1))
                    status.Add("Credenciales próximas a expirar");
                
                if (status.Count == 0)
                {
                    return HealthCheckResult.Healthy("DeviceAuthenticator funcionando correctamente");
                }
                
                return HealthCheckResult.Degraded(
                    $"Problemas detectados: {string.Join(", ", status)}",
                    new Dictionary<string, object>
                    {
                        { "AuthStatus", _authStatus.ToString() },
                        { "IsAuthenticated", IsAuthenticated() },
                        { "CertificateValid", _deviceCertificate?.NotAfter > DateTime.UtcNow },
                        { "CredentialsValid", _currentCredentials?.ExpiresAt > DateTime.UtcNow }
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
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public interface IDeviceAuthenticator
    {
        Task<AuthenticationResult> AuthenticateAsync();
        Task<DeviceCredentials> GetCredentialsAsync();
        bool IsAuthenticated();
        Task<bool> VerifyServerSignatureAsync(string data, string signature);
        Task<RegistrationResult> RegisterDeviceAsync(string tenantToken, string deviceName, string groupId = null);
        Task<bool> RevokeDeviceAsync();
    }
    
    public class DeviceCredentials
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string DeviceName { get; set; }
        public string GroupId { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime IssuedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string TokenType { get; set; }
        public string Scope { get; set; }
        public DateTime RegistrationTime { get; set; }
        public DateTime LastAuthentication { get; set; }
        
        public bool IsExpired => ExpiresAt <= DateTime.UtcNow;
        public bool WillExpireSoon => ExpiresAt <= DateTime.UtcNow.AddMinutes(5);
        public TimeSpan RemainingLifetime => ExpiresAt - DateTime.UtcNow;
    }
    
    public class AuthenticationResult
    {
        public bool IsSuccess { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        public string SessionId { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public static AuthenticationResult Success(string message = null)
        {
            return new AuthenticationResult
            {
                IsSuccess = true,
                Timestamp = DateTime.UtcNow,
                Details = new Dictionary<string, object>
                {
                    { "Message", message ?? "Autenticación exitosa" }
                }
            };
        }
        
        public static AuthenticationResult Failed(string errorMessage)
        {
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow,
                Details = new Dictionary<string, object>()
            };
        }
    }
    
    public class RegistrationResult
    {
        public bool IsSuccess { get; set; }
        public string ErrorMessage { get; set; }
        public string TenantId { get; set; }
        public string DeviceId { get; set; }
        public DateTime Timestamp { get; set; }
        
        public static RegistrationResult Success(string tenantId, string deviceId)
        {
            return new RegistrationResult
            {
                IsSuccess = true,
                TenantId = tenantId,
                DeviceId = deviceId,
                Timestamp = DateTime.UtcNow
            };
        }
        
        public static RegistrationResult Failed(string errorMessage)
        {
            return new RegistrationResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class TokenValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; }
        public string TenantId { get; set; }
        public string TenantName { get; set; }
        public DateTime ExpiresAt { get; set; }
        
        public static TokenValidationResult Valid()
        {
            return new TokenValidationResult
            {
                IsValid = true
            };
        }
        
        public static TokenValidationResult Invalid(string errorMessage)
        {
            return new TokenValidationResult
            {
                IsValid = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class DeviceKeyPair
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public string Algorithm { get; set; }
        public int KeySize { get; set; }
        public DateTime CreatedAt { get; set; }
    }
    
    public enum AuthenticationStatus
    {
        NotAuthenticated,
        Authenticating,
        Authenticated,
        AuthenticationFailed,
        Revoked,
        Expired
    }
    
    // Clases para solicitudes/respuestas de API
    public class AuthenticationRequest
    {
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string Nonce { get; set; }
        public string Signature { get; set; }
        public DateTime Timestamp { get; set; }
        public string CertificateThumbprint { get; set; }
    }
    
    public class DeviceRegistrationRequest
    {
        public string TenantToken { get; set; }
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string OperatingSystem { get; set; }
        public string GroupId { get; set; }
        public string Csr { get; set; }
        public string PublicKey { get; set; }
        public string HardwareId { get; set; }
    }
    
    public class TokenRefreshRequest
    {
        public string DeviceId { get; set; }
        public string RefreshToken { get; set; }
        public string GrantType { get; set; }
    }
    
    #endregion
}