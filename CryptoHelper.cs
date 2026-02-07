using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Agent.Utils
{
    /// <summary>
    /// Helper de criptografía para BWP Enterprise
    /// Proporciona funciones de cifrado, hashing y firma digital
    /// </summary>
    public sealed class CryptoHelper
    {
        private static readonly Lazy<CryptoHelper> _instance = 
            new Lazy<CryptoHelper>(() => new CryptoHelper());
        
        public static CryptoHelper Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly RSACryptoServiceProvider _rsaProvider;
        private readonly Aes _aesProvider;
        private readonly RandomNumberGenerator _rng;
        private bool _isInitialized;
        private const int KEY_SIZE = 2048;
        private const int AES_KEY_SIZE = 256;
        private const int AES_BLOCK_SIZE = 128;
        private const int SALT_SIZE = 32;
        private const int ITERATIONS = 10000;
        
        private CryptoHelper()
        {
            _logManager = LogManager.Instance;
            _rsaProvider = new RSACryptoServiceProvider(KEY_SIZE);
            _aesProvider = Aes.Create();
            _aesProvider.KeySize = AES_KEY_SIZE;
            _aesProvider.BlockSize = AES_BLOCK_SIZE;
            _aesProvider.Mode = CipherMode.CBC;
            _aesProvider.Padding = PaddingMode.PKCS7;
            _rng = RandomNumberGenerator.Create();
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el helper de criptografía
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando CryptoHelper...", nameof(CryptoHelper));
                
                // Generar o cargar claves RSA
                await InitializeRsaKeysAsync();
                
                // Generar o cargar clave AES
                await InitializeAesKeyAsync();
                
                _isInitialized = true;
                _logManager.LogInfo("CryptoHelper inicializado", nameof(CryptoHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar CryptoHelper: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        #region Cifrado Simétrico (AES)
        
        /// <summary>
        /// Cifra datos usando AES
        /// </summary>
        public async Task<byte[]> EncryptAesAsync(byte[] data, string key = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                byte[] keyBytes = null;
                byte[] iv = null;
                
                if (string.IsNullOrEmpty(key))
                {
                    // Usar clave interna
                    keyBytes = _aesProvider.Key;
                    iv = _aesProvider.IV;
                }
                else
                {
                    // Derivar clave de la contraseña
                    var keyDerivation = await DeriveKeyFromPasswordAsync(key, SALT_SIZE);
                    keyBytes = keyDerivation.Key;
                    iv = keyDerivation.IV;
                }
                
                using (var aes = Aes.Create())
                {
                    aes.Key = keyBytes;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    
                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        // Escribir IV primero
                        await ms.WriteAsync(iv, 0, iv.Length);
                        
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            await cs.WriteAsync(data, 0, data.Length);
                            cs.FlushFinalBlock();
                        }
                        
                        return ms.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cifrando datos AES: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Descifra datos usando AES
        /// </summary>
        public async Task<byte[]> DecryptAesAsync(byte[] encryptedData, string key = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                using (var ms = new MemoryStream(encryptedData))
                {
                    // Leer IV (primeros 16 bytes)
                    var iv = new byte[16];
                    await ms.ReadAsync(iv, 0, iv.Length);
                    
                    byte[] keyBytes = null;
                    
                    if (string.IsNullOrEmpty(key))
                    {
                        // Usar clave interna
                        keyBytes = _aesProvider.Key;
                    }
                    else
                    {
                        // Derivar clave de la contraseña
                        var keyDerivation = await DeriveKeyFromPasswordAsync(key, SALT_SIZE, iv);
                        keyBytes = keyDerivation.Key;
                    }
                    
                    using (var aes = Aes.Create())
                    {
                        aes.Key = keyBytes;
                        aes.IV = iv;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;
                        
                        using (var decryptor = aes.CreateDecryptor())
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        using (var result = new MemoryStream())
                        {
                            await cs.CopyToAsync(result);
                            return result.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descifrando datos AES: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Cifra texto usando AES
        /// </summary>
        public async Task<string> EncryptTextAsync(string plainText, string key = null)
        {
            var data = Encoding.UTF8.GetBytes(plainText);
            var encrypted = await EncryptAesAsync(data, key);
            return Convert.ToBase64String(encrypted);
        }
        
        /// <summary>
        /// Descifra texto usando AES
        /// </summary>
        public async Task<string> DecryptTextAsync(string encryptedText, string key = null)
        {
            var data = Convert.FromBase64String(encryptedText);
            var decrypted = await DecryptAesAsync(data, key);
            return Encoding.UTF8.GetString(decrypted);
        }
        
        /// <summary>
        /// Cifra archivo usando AES
        /// </summary>
        public async Task EncryptFileAsync(string inputFile, string outputFile, string key = null)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(inputFile);
                var encrypted = await EncryptAesAsync(data, key);
                await File.WriteAllBytesAsync(outputFile, encrypted);
                
                _logManager.LogDebug($"Archivo cifrado: {inputFile} -> {outputFile}", nameof(CryptoHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cifrando archivo {inputFile}: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Descifra archivo usando AES
        /// </summary>
        public async Task DecryptFileAsync(string inputFile, string outputFile, string key = null)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(inputFile);
                var decrypted = await DecryptAesAsync(data, key);
                await File.WriteAllBytesAsync(outputFile, decrypted);
                
                _logManager.LogDebug($"Archivo descifrado: {inputFile} -> {outputFile}", nameof(CryptoHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descifrando archivo {inputFile}: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Genera nueva clave AES
        /// </summary>
        public byte[] GenerateAesKey()
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = AES_KEY_SIZE;
                aes.GenerateKey();
                return aes.Key;
            }
        }
        
        /// <summary>
        /// Genera nuevo IV para AES
        /// </summary>
        public byte[] GenerateAesIv()
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }
        
        #endregion
        
        #region Cifrado Asimétrico (RSA)
        
        /// <summary>
        /// Cifra datos usando RSA
        /// </summary>
        public async Task<byte[]> EncryptRsaAsync(byte[] data, string publicKey = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
                {
                    if (string.IsNullOrEmpty(publicKey))
                    {
                        // Usar clave pública interna
                        rsa.ImportParameters(_rsaProvider.ExportParameters(false));
                    }
                    else
                    {
                        // Usar clave pública proporcionada
                        rsa.FromXmlString(publicKey);
                    }
                    
                    // RSA puede cifrar solo pequeños datos, usar cifrado híbrido
                    var aesKey = GenerateAesKey();
                    var aesIv = GenerateAesIv();
                    
                    // Cifrar datos con AES
                    using (var aes = Aes.Create())
                    {
                        aes.Key = aesKey;
                        aes.IV = aesIv;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;
                        
                        using (var encryptor = aes.CreateEncryptor())
                        using (var ms = new MemoryStream())
                        {
                            // Cifrar datos
                            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                await cs.WriteAsync(data, 0, data.Length);
                                cs.FlushFinalBlock();
                            }
                            
                            var encryptedData = ms.ToArray();
                            
                            // Cifrar clave AES con RSA
                            var keyData = new byte[aesKey.Length + aesIv.Length];
                            Buffer.BlockCopy(aesKey, 0, keyData, 0, aesKey.Length);
                            Buffer.BlockCopy(aesIv, 0, keyData, aesKey.Length, aesIv.Length);
                            
                            var encryptedKey = rsa.Encrypt(keyData, RSAEncryptionPadding.Pkcs1);
                            
                            // Combinar clave cifrada con datos cifrados
                            var result = new byte[4 + encryptedKey.Length + encryptedData.Length];
                            Buffer.BlockCopy(BitConverter.GetBytes(encryptedKey.Length), 0, result, 0, 4);
                            Buffer.BlockCopy(encryptedKey, 0, result, 4, encryptedKey.Length);
                            Buffer.BlockCopy(encryptedData, 0, result, 4 + encryptedKey.Length, encryptedData.Length);
                            
                            return result;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cifrando datos RSA: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Descifra datos usando RSA
        /// </summary>
        public async Task<byte[]> DecryptRsaAsync(byte[] encryptedData, string privateKey = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                // Extraer partes
                var keyLength = BitConverter.ToInt32(encryptedData, 0);
                var encryptedKey = new byte[keyLength];
                Buffer.BlockCopy(encryptedData, 4, encryptedKey, 0, keyLength);
                
                var dataLength = encryptedData.Length - 4 - keyLength;
                var encryptedAesData = new byte[dataLength];
                Buffer.BlockCopy(encryptedData, 4 + keyLength, encryptedAesData, 0, dataLength);
                
                // Descifrar clave AES
                byte[] decryptedKeyData;
                
                using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
                {
                    if (string.IsNullOrEmpty(privateKey))
                    {
                        // Usar clave privada interna
                        rsa.ImportParameters(_rsaProvider.ExportParameters(true));
                    }
                    else
                    {
                        // Usar clave privada proporcionada
                        rsa.FromXmlString(privateKey);
                    }
                    
                    decryptedKeyData = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
                }
                
                // Extraer clave e IV AES
                var aesKey = new byte[AES_KEY_SIZE / 8];
                var aesIv = new byte[16];
                Buffer.BlockCopy(decryptedKeyData, 0, aesKey, 0, aesKey.Length);
                Buffer.BlockCopy(decryptedKeyData, aesKey.Length, aesIv, 0, aesIv.Length);
                
                // Descifrar datos con AES
                using (var aes = Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = aesIv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    
                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(encryptedAesData))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var result = new MemoryStream())
                    {
                        await cs.CopyToAsync(result);
                        return result.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error descifrando datos RSA: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Firma datos usando RSA
        /// </summary>
        public async Task<byte[]> SignDataAsync(byte[] data, string privateKey = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
                {
                    if (string.IsNullOrEmpty(privateKey))
                    {
                        // Usar clave privada interna
                        rsa.ImportParameters(_rsaProvider.ExportParameters(true));
                    }
                    else
                    {
                        // Usar clave privada proporcionada
                        rsa.FromXmlString(privateKey);
                    }
                    
                    // Calcular hash y firmar
                    using (var sha256 = SHA256.Create())
                    {
                        var hash = sha256.ComputeHash(data);
                        return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error firmando datos: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Verifica firma de datos usando RSA
        /// </summary>
        public async Task<bool> VerifySignatureAsync(byte[] data, byte[] signature, string publicKey = null)
        {
            if (!_isInitialized)
                await InitializeAsync();
            
            try
            {
                using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
                {
                    if (string.IsNullOrEmpty(publicKey))
                    {
                        // Usar clave pública interna
                        rsa.ImportParameters(_rsaProvider.ExportParameters(false));
                    }
                    else
                    {
                        // Usar clave pública proporcionada
                        rsa.FromXmlString(publicKey);
                    }
                    
                    // Calcular hash y verificar firma
                    using (var sha256 = SHA256.Create())
                    {
                        var hash = sha256.ComputeHash(data);
                        return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando firma: {ex}", nameof(CryptoHelper));
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene clave pública RSA
        /// </summary>
        public string GetPublicKey()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("CryptoHelper no inicializado");
            
            return _rsaProvider.ToXmlString(false);
        }
        
        /// <summary>
        /// Obtiene clave privada RSA
        /// </summary>
        public string GetPrivateKey()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("CryptoHelper no inicializado");
            
            return _rsaProvider.ToXmlString(true);
        }
        
        /// <summary>
        /// Importa clave pública RSA
        /// </summary>
        public void ImportPublicKey(string publicKeyXml)
        {
            _rsaProvider.FromXmlString(publicKeyXml);
        }
        
        /// <summary>
        /// Importa clave privada RSA
        /// </summary>
        public void ImportPrivateKey(string privateKeyXml)
        {
            _rsaProvider.FromXmlString(privateKeyXml);
        }
        
        #endregion
        
        #region Hashing
        
        /// <summary>
        /// Calcula hash de datos
        /// </summary>
        public string ComputeHash(byte[] data, string algorithm = "SHA256")
        {
            try
            {
                using (var hashAlgorithm = HashAlgorithm.Create(algorithm))
                {
                    var hashBytes = hashAlgorithm.ComputeHash(data);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error calculando hash: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Calcula hash de texto
        /// </summary>
        public string ComputeHash(string text, string algorithm = "SHA256")
        {
            var data = Encoding.UTF8.GetBytes(text);
            return ComputeHash(data, algorithm);
        }
        
        /// <summary>
        /// Calcula hash de archivo
        /// </summary>
        public async Task<string> ComputeFileHashAsync(string filePath, string algorithm = "SHA256")
        {
            try
            {
                using (var stream = File.OpenRead(filePath))
                using (var hashAlgorithm = HashAlgorithm.Create(algorithm))
                {
                    var hashBytes = await hashAlgorithm.ComputeHashAsync(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error calculando hash de archivo {filePath}: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Calcula HMAC
        /// </summary>
        public string ComputeHmac(byte[] data, byte[] key, string algorithm = "SHA256")
        {
            try
            {
                using (var hmac = HMAC.Create($"HMAC{algorithm}"))
                {
                    hmac.Key = key;
                    var hashBytes = hmac.ComputeHash(data);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error calculando HMAC: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Verifica hash
        /// </summary>
        public bool VerifyHash(byte[] data, string expectedHash, string algorithm = "SHA256")
        {
            var actualHash = ComputeHash(data, algorithm);
            return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        
        /// <summary>
        /// Verifica hash de archivo
        /// </summary>
        public async Task<bool> VerifyFileHashAsync(string filePath, string expectedHash, string algorithm = "SHA256")
        {
            var actualHash = await ComputeFileHashAsync(filePath, algorithm);
            return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        
        #endregion
        
        #region Generación de Tokens y Claves
        
        /// <summary>
        /// Genera token aleatorio seguro
        /// </summary>
        public string GenerateSecureToken(int length = 32)
        {
            try
            {
                var bytes = new byte[length];
                _rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes)
                    .Replace("+", "-")
                    .Replace("/", "_")
                    .Replace("=", "");
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando token: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Genera GUID seguro
        /// </summary>
        public string GenerateSecureGuid()
        {
            return Guid.NewGuid().ToString("N") + GenerateSecureToken(8);
        }
        
        /// <summary>
        /// Genera salt aleatorio
        /// </summary>
        public byte[] GenerateSalt(int size = SALT_SIZE)
        {
            var salt = new byte[size];
            _rng.GetBytes(salt);
            return salt;
        }
        
        /// <summary>
        /// Deriva clave de contraseña usando PBKDF2
        /// </summary>
        public async Task<KeyDerivationResult> DeriveKeyFromPasswordAsync(string password, int saltSize = SALT_SIZE, byte[] salt = null)
        {
            try
            {
                salt ??= GenerateSalt(saltSize);
                
                using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
                {
                    var key = deriveBytes.GetBytes(AES_KEY_SIZE / 8);
                    var iv = deriveBytes.GetBytes(16);
                    
                    return new KeyDerivationResult
                    {
                        Key = key,
                        IV = iv,
                        Salt = salt
                    };
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error derivando clave de contraseña: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Genera par de claves RSA
        /// </summary>
        public RsaKeyPair GenerateRsaKeyPair(int keySize = KEY_SIZE)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider(keySize))
                {
                    return new RsaKeyPair
                    {
                        PublicKey = rsa.ToXmlString(false),
                        PrivateKey = rsa.ToXmlString(true),
                        KeySize = keySize,
                        CreatedAt = DateTime.UtcNow
                    };
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error generando par de claves RSA: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        /// <summary>
        /// Convierte bytes a string hexadecimal
        /// </summary>
        public string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
        
        /// <summary>
        /// Convierte string hexadecimal a bytes
        /// </summary>
        public byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                return Array.Empty<byte>();
            
            if (hex.Length % 2 != 0)
                throw new ArgumentException("La cadena hexadecimal debe tener una longitud par");
            
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            
            return bytes;
        }
        
        /// <summary>
        /// Codifica datos a Base64 URL seguro
        /// </summary>
        public string ToBase64UrlSafe(byte[] data)
        {
            return Convert.ToBase64String(data)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
        
        /// <summary>
        /// Decodifica datos desde Base64 URL seguro
        /// </summary>
        public byte[] FromBase64UrlSafe(string base64Url)
        {
            var base64 = base64Url
                .Replace("-", "+")
                .Replace("_", "/");
            
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            
            return Convert.FromBase64String(base64);
        }
        
        /// <summary>
        /// Obtiene información del algoritmo
        /// </summary>
        public CryptoAlgorithmInfo GetAlgorithmInfo(string algorithm)
        {
            return algorithm.ToUpperInvariant() switch
            {
                "AES" => new CryptoAlgorithmInfo
                {
                    Name = "AES",
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = "CBC",
                    Padding = "PKCS7"
                },
                "RSA" => new CryptoAlgorithmInfo
                {
                    Name = "RSA",
                    KeySize = 2048,
                    Mode = "Asymmetric"
                },
                "SHA256" => new CryptoAlgorithmInfo
                {
                    Name = "SHA256",
                    HashSize = 256
                },
                "SHA512" => new CryptoAlgorithmInfo
                {
                    Name = "SHA512",
                    HashSize = 512
                },
                _ => throw new ArgumentException($"Algoritmo no soportado: {algorithm}")
            };
        }
        
        #endregion
        
        #region Métodos privados
        
        /// <summary>
        /// Inicializa claves RSA
        /// </summary>
        private async Task InitializeRsaKeysAsync()
        {
            try
            {
                var rsaKeysPath = GetRsaKeysPath();
                
                if (File.Exists(rsaKeysPath))
                {
                    // Cargar claves desde archivo
                    var keysJson = await File.ReadAllTextAsync(rsaKeysPath);
                    var keys = System.Text.Json.JsonSerializer.Deserialize<RsaKeyPair>(keysJson);
                    
                    _rsaProvider.FromXmlString(keys.PrivateKey);
                    _logManager.LogDebug("Claves RSA cargadas desde archivo", nameof(CryptoHelper));
                }
                else
                {
                    // Generar nuevas claves
                    var keyPair = GenerateRsaKeyPair();
                    
                    // Guardar claves
                    var keysJson = System.Text.Json.JsonSerializer.Serialize(keyPair, 
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    
                    await File.WriteAllTextAsync(rsaKeysPath, keysJson);
                    
                    // Importar al provider
                    _rsaProvider.FromXmlString(keyPair.PrivateKey);
                    
                    _logManager.LogDebug("Nuevas claves RSA generadas y guardadas", nameof(CryptoHelper));
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando claves RSA: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Inicializa clave AES
        /// </summary>
        private async Task InitializeAesKeyAsync()
        {
            try
            {
                var aesKeyPath = GetAesKeyPath();
                
                if (File.Exists(aesKeyPath))
                {
                    // Cargar clave desde archivo
                    var keyData = await File.ReadAllBytesAsync(aesKeyPath);
                    var decryptedKey = await DecryptKeyWithRsaAsync(keyData);
                    
                    _aesProvider.Key = decryptedKey.Take(AES_KEY_SIZE / 8).ToArray();
                    _aesProvider.IV = decryptedKey.Skip(AES_KEY_SIZE / 8).Take(16).ToArray();
                    
                    _logManager.LogDebug("Clave AES cargada desde archivo", nameof(CryptoHelper));
                }
                else
                {
                    // Generar nueva clave
                    _aesProvider.GenerateKey();
                    _aesProvider.GenerateIV();
                    
                    // Guardar clave cifrada con RSA
                    var keyData = new byte[_aesProvider.Key.Length + _aesProvider.IV.Length];
                    Buffer.BlockCopy(_aesProvider.Key, 0, keyData, 0, _aesProvider.Key.Length);
                    Buffer.BlockCopy(_aesProvider.IV, 0, keyData, _aesProvider.Key.Length, _aesProvider.IV.Length);
                    
                    var encryptedKey = await EncryptKeyWithRsaAsync(keyData);
                    await File.WriteAllBytesAsync(aesKeyPath, encryptedKey);
                    
                    _logManager.LogDebug("Nueva clave AES generada y guardada", nameof(CryptoHelper));
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error inicializando clave AES: {ex}", nameof(CryptoHelper));
                throw;
            }
        }
        
        /// <summary>
        /// Cifra clave con RSA
        /// </summary>
        private async Task<byte[]> EncryptKeyWithRsaAsync(byte[] keyData)
        {
            using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
            {
                rsa.ImportParameters(_rsaProvider.ExportParameters(false));
                return rsa.Encrypt(keyData, RSAEncryptionPadding.Pkcs1);
            }
        }
        
        /// <summary>
        /// Descifra clave con RSA
        /// </summary>
        private async Task<byte[]> DecryptKeyWithRsaAsync(byte[] encryptedKey)
        {
            using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
            {
                rsa.ImportParameters(_rsaProvider.ExportParameters(true));
                return rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
            }
        }
        
        /// <summary>
        /// Obtiene ruta de archivo de claves RSA
        /// </summary>
        private string GetRsaKeysPath()
        {
            var configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BWP Enterprise", "Crypto");
            Directory.CreateDirectory(configDir);
            return Path.Combine(configDir, "rsa_keys.json");
        }
        
        /// <summary>
        /// Obtiene ruta de archivo de clave AES
        /// </summary>
        private string GetAesKeyPath()
        {
            var configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BWP Enterprise", "Crypto");
            Directory.CreateDirectory(configDir);
            return Path.Combine(configDir, "aes_key.bin");
        }
        
        #endregion
        
        #region Métodos de HealthCheck
        
        /// <summary>
        /// Verifica salud del sistema criptográfico
        /// </summary>
        public async Task<CryptoHealthCheck> CheckHealthAsync()
        {
            try
            {
                var checks = new List<string>();
                
                // Verificar inicialización
                if (!_isInitialized)
                    checks.Add("No inicializado");
                
                // Verificar claves RSA
                try
                {
                    var publicParams = _rsaProvider.ExportParameters(false);
                    if (publicParams.Modulus == null || publicParams.Exponent == null)
                        checks.Add("Clave pública RSA inválida");
                    
                    var privateParams = _rsaProvider.ExportParameters(true);
                    if (privateParams.D == null)
                        checks.Add("Clave privada RSA inválida");
                }
                catch
                {
                    checks.Add("Error exportando parámetros RSA");
                }
                
                // Verificar clave AES
                if (_aesProvider.Key == null || _aesProvider.Key.Length != AES_KEY_SIZE / 8)
                    checks.Add("Clave AES inválida");
                
                if (_aesProvider.IV == null || _aesProvider.IV.Length != 16)
                    checks.Add("IV AES inválido");
                
                // Prueba de cifrado/descifrado
                try
                {
                    var testData = Encoding.UTF8.GetBytes("Test de salud criptográfica");
                    var encrypted = await EncryptAesAsync(testData);
                    var decrypted = await DecryptAesAsync(encrypted);
                    
                    if (!testData.SequenceEqual(decrypted))
                        checks.Add("Prueba de cifrado/descifrado falló");
                }
                catch (Exception ex)
                {
                    checks.Add($"Prueba de cifrado falló: {ex.Message}");
                }
                
                // Prueba de firma/verificación
                try
                {
                    var testData = Encoding.UTF8.GetBytes("Test de firma");
                    var signature = await SignDataAsync(testData);
                    var verified = await VerifySignatureAsync(testData, signature);
                    
                    if (!verified)
                        checks.Add("Prueba de firma/verificación falló");
                }
                catch (Exception ex)
                {
                    checks.Add($"Prueba de firma falló: {ex.Message}");
                }
                
                var isHealthy = checks.Count == 0;
                
                return new CryptoHealthCheck
                {
                    IsHealthy = isHealthy,
                    Checks = checks,
                    Timestamp = DateTime.UtcNow,
                    AlgorithmInfo = new Dictionary<string, object>
                    {
                        { "RSA_KeySize", KEY_SIZE },
                        { "AES_KeySize", AES_KEY_SIZE },
                        { "AES_BlockSize", AES_BLOCK_SIZE },
                        { "IsInitialized", _isInitialized },
                        { "HasPublicKey", _rsaProvider.PublicOnly },
                        { "HasPrivateKey", !_rsaProvider.PublicOnly }
                    }
                };
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en health check criptográfico: {ex}", nameof(CryptoHelper));
                return CryptoHealthCheck.Error($"Error: {ex.Message}");
            }
        }
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public class KeyDerivationResult
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        public byte[] Salt { get; set; }
    }
    
    public class RsaKeyPair
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public int KeySize { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsed { get; set; }
    }
    
    public class CryptoAlgorithmInfo
    {
        public string Name { get; set; }
        public int KeySize { get; set; }
        public int BlockSize { get; set; }
        public int HashSize { get; set; }
        public string Mode { get; set; }
        public string Padding { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        
        public CryptoAlgorithmInfo()
        {
            Parameters = new Dictionary<string, object>();
        }
    }
    
    public class CryptoHealthCheck
    {
        public bool IsHealthy { get; set; }
        public List<string> Checks { get; set; }
        public DateTime Timestamp { get; set; }
        public Dictionary<string, object> AlgorithmInfo { get; set; }
        public string Error { get; set; }
        
        public CryptoHealthCheck()
        {
            Checks = new List<string>();
            AlgorithmInfo = new Dictionary<string, object>();
        }
        
        public static CryptoHealthCheck Error(string errorMessage)
        {
            return new CryptoHealthCheck
            {
                IsHealthy = false,
                Error = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    #endregion
}