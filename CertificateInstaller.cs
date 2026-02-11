using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace BWP.Installer.Engine
{
    public class CertificateInstaller : IDisposable
    {
        // Constantes de almacenes de certificados
        private const string CERT_STORE_ROOT = "Root";
        private const string CERT_STORE_TRUSTED_PUBLISHER = "TrustedPublisher";
        private const string CERT_STORE_CA = "CertificateAuthority";
        private const string CERT_STORE_MY = "My";
        private const string CERT_STORE_AUTH_ROOT = "AuthRoot";
        
        // Constantes de APIs nativas
        private const uint CERT_STORE_PROV_SYSTEM = 10;
        private const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x20000;
        private const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        private const uint CERT_STORE_CREATE_NEW_FLAG = 0x00002000;
        private const uint CERT_FIND_SHA1_HASH = 0x00010000;
        private const uint CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001;
        private const uint CERT_STORE_ADD_ALWAYS = 4;
        private const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
        
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CertOpenStore(
            IntPtr storeProvider,
            uint encodingType,
            IntPtr cryptProv,
            uint flags,
            string pvPara
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertCloseStore(
            IntPtr storeHandle,
            uint flags
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertCreateCertificateContext(
            uint encodingType,
            byte[] certData,
            uint certDataLength
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertAddCertificateContextToStore(
            IntPtr storeHandle,
            IntPtr certContext,
            uint addDisposition,
            out IntPtr storeContext
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertFindCertificateInStore(
            IntPtr storeHandle,
            uint encodingType,
            uint findFlags,
            uint findType,
            IntPtr findPara,
            IntPtr prevCertContext
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertFreeCertificateContext(IntPtr certContext);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptAcquireContext(
            out IntPtr cryptProvHandle,
            string containerName,
            string providerName,
            uint providerType,
            uint flags
        );
        
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptReleaseContext(IntPtr cryptProvHandle, uint flags);
        
        private readonly InstallerLogger _logger;
        private bool _disposed;
        
        public CertificateInstaller(InstallerLogger logger = null)
        {
            _logger = logger ?? new InstallerLogger();
        }
        
        #region Métodos principales de instalación
        
        public CertificateInstallResult InstallRootCertificate(byte[] certificateData, string password = null)
        {
            var result = new CertificateInstallResult();
            
            try
            {
                _logger.LogInfo("Iniciando instalación de certificado raíz...");
                
                // Validar datos del certificado
                if (certificateData == null || certificateData.Length == 0)
                {
                    throw new ArgumentException("Los datos del certificado no pueden estar vacíos");
                }
                
                X509Certificate2 certificate;
                
                // Cargar certificado
                if (!string.IsNullOrEmpty(password))
                {
                    certificate = new X509Certificate2(certificateData, password, 
                        X509KeyStorageFlags.MachineKeySet | 
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);
                }
                else
                {
                    certificate = new X509Certificate2(certificateData);
                }
                
                // Validar que sea un certificado raíz
                if (!IsRootCertificate(certificate))
                {
                    throw new InvalidOperationException("El certificado no es una CA raíz válida");
                }
                
                // Verificar si ya está instalado
                if (IsCertificateInstalled(certificate.Thumbprint, StoreName.Root))
                {
                    _logger.LogWarning($"Certificado raíz ya instalado: {certificate.Thumbprint}");
                    result.Success = true;
                    result.CertificateThumbprint = certificate.Thumbprint;
                    result.Message = "Certificado ya estaba instalado";
                    return result;
                }
                
                // Instalar en almacén Root
                InstallToCertificateStore(certificate, StoreName.Root);
                
                // Instalar en almacén TrustedPublisher
                InstallToCertificateStore(certificate, StoreName.TrustedPublisher);
                
                // Instalar en almacén CertificateAuthority
                InstallToCertificateStore(certificate, StoreName.CertificateAuthority);
                
                // Instalar en almacén AuthRoot
                InstallToCertificateStore(certificate, StoreName.AuthRoot);
                
                // Configurar confianza completa
                ConfigureCertificateTrust(certificate);
                
                // Verificar instalación
                if (!VerifyCertificateInstallation(certificate.Thumbprint))
                {
                    throw new InvalidOperationException("La verificación de instalación del certificado falló");
                }
                
                result.Success = true;
                result.CertificateThumbprint = certificate.Thumbprint;
                result.Message = "Certificado raíz instalado exitosamente";
                
                _logger.LogSuccess($"Certificado raíz instalado: {certificate.Thumbprint}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando certificado raíz: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public CertificateInstallResult InstallClientCertificate(byte[] certificateData, byte[] privateKeyData = null, string password = null)
        {
            var result = new CertificateInstallResult();
            
            try
            {
                _logger.LogInfo("Iniciando instalación de certificado cliente...");
                
                if (certificateData == null || certificateData.Length == 0)
                {
                    throw new ArgumentException("Los datos del certificado no pueden estar vacíos");
                }
                
                X509Certificate2 certificate;
                
                if (privateKeyData != null && privateKeyData.Length > 0)
                {
                    // Combinar certificado y clave privada
                    byte[] combinedData = CombineCertificateAndPrivateKey(certificateData, privateKeyData);
                    
                    certificate = new X509Certificate2(combinedData, password,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);
                }
                else
                {
                    certificate = new X509Certificate2(certificateData, password,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet);
                }
                
                // Validar que sea un certificado de cliente
                if (!IsClientCertificate(certificate))
                {
                    throw new InvalidOperationException("El certificado no es un certificado de cliente válido");
                }
                
                // Verificar si ya está instalado
                if (IsCertificateInstalled(certificate.Thumbprint, StoreName.My))
                {
                    _logger.LogWarning($"Certificado cliente ya instalado: {certificate.Thumbprint}");
                    result.Success = true;
                    result.CertificateThumbprint = certificate.Thumbprint;
                    result.Message = "Certificado ya estaba instalado";
                    return result;
                }
                
                // Instalar en almacén My
                InstallToCertificateStore(certificate, StoreName.My);
                
                // Configurar permisos de clave privada
                if (certificate.HasPrivateKey)
                {
                    ConfigurePrivateKeyPermissions(certificate);
                }
                
                // Configurar para autenticación cliente
                ConfigureForClientAuthentication(certificate);
                
                result.Success = true;
                result.CertificateThumbprint = certificate.Thumbprint;
                result.Message = "Certificado cliente instalado exitosamente";
                
                _logger.LogSuccess($"Certificado cliente instalado: {certificate.Thumbprint}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando certificado cliente: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public CertificateInstallResult InstallCertificateFromFile(string filePath, string password = null)
        {
            var result = new CertificateInstallResult();
            
            try
            {
                _logger.LogInfo($"Instalando certificado desde archivo: {filePath}");
                
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"Archivo de certificado no encontrado: {filePath}");
                }
                
                // Determinar tipo de archivo por extensión
                string extension = Path.GetExtension(filePath).ToLowerInvariant();
                byte[] fileData = File.ReadAllBytes(filePath);
                
                switch (extension)
                {
                    case ".pfx":
                    case ".p12":
                        return InstallPFXCertificate(fileData, password);
                        
                    case ".cer":
                    case ".crt":
                        return InstallCERTCertificate(fileData);
                        
                    case ".p7b":
                    case ".p7c":
                        return InstallPKCS7Certificate(fileData);
                        
                    default:
                        throw new NotSupportedException($"Formato de certificado no soportado: {extension}");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando certificado desde archivo: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public CertificateInstallResult InstallPFXCertificate(byte[] pfxData, string password = null)
        {
            var result = new CertificateInstallResult();
            
            try
            {
                _logger.LogInfo("Instalando certificado PFX...");
                
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                
                try
                {
                    certificates.Import(pfxData, password, 
                        X509KeyStorageFlags.MachineKeySet | 
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);
                }
                catch (CryptographicException ex)
                {
                    // Intentar con diferentes flags si falla
                    certificates.Import(pfxData, password, 
                        X509KeyStorageFlags.MachineKeySet | 
                        X509KeyStorageFlags.PersistKeySet);
                }
                
                int installedCount = 0;
                List<string> thumbprints = new List<string>();
                
                foreach (X509Certificate2 certificate in certificates)
                {
                    try
                    {
                        // Determinar tipo de certificado
                        if (IsRootCertificate(certificate))
                        {
                            var rootResult = InstallRootCertificate(certificate.Export(X509ContentType.Cert));
                            if (rootResult.Success)
                            {
                                installedCount++;
                                thumbprints.Add(certificate.Thumbprint);
                            }
                        }
                        else if (IsClientCertificate(certificate))
                        {
                            var clientResult = InstallClientCertificate(
                                certificate.Export(X509ContentType.Cert),
                                certificate.HasPrivateKey ? certificate.Export(X509ContentType.Pfx) : null);
                            
                            if (clientResult.Success)
                            {
                                installedCount++;
                                thumbprints.Add(certificate.Thumbprint);
                            }
                        }
                        else
                        {
                            // Instalar como certificado intermedio
                            InstallToCertificateStore(certificate, StoreName.CertificateAuthority);
                            installedCount++;
                            thumbprints.Add(certificate.Thumbprint);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error instalando certificado individual: {ex.Message}");
                    }
                    finally
                    {
                        certificate.Dispose();
                    }
                }
                
                result.Success = installedCount > 0;
                result.CertificateThumbprint = thumbprints.Count > 0 ? string.Join(";", thumbprints) : null;
                result.Message = $"Instalados {installedCount} certificados de {certificates.Count}";
                
                _logger.LogInfo($"Instalación PFX completada: {result.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error instalando certificado PFX: {ex.Message}", ex);
            }
            
            return result;
        }
        
        #endregion
        
        #region Métodos de verificación y validación
        
        public bool VerifyCertificateInstallation(string thumbprint, StoreName? specificStore = null)
        {
            try
            {
                if (specificStore.HasValue)
                {
                    return IsCertificateInstalled(thumbprint, specificStore.Value);
                }
                else
                {
                    // Verificar en todos los almacenes relevantes
                    StoreName[] storesToCheck = { 
                        StoreName.Root, 
                        StoreName.TrustedPublisher, 
                        StoreName.CertificateAuthority,
                        StoreName.My,
                        StoreName.AuthRoot
                    };
                    
                    foreach (var store in storesToCheck)
                    {
                        if (IsCertificateInstalled(thumbprint, store))
                        {
                            return true;
                        }
                    }
                    
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error verificando instalación de certificado: {ex.Message}", ex);
                return false;
            }
        }
        
        public CertificateValidationResult ValidateCertificate(X509Certificate2 certificate)
        {
            var result = new CertificateValidationResult();
            
            try
            {
                result.Thumbprint = certificate.Thumbprint;
                result.Subject = certificate.Subject;
                result.Issuer = certificate.Issuer;
                result.NotBefore = certificate.NotBefore;
                result.NotAfter = certificate.NotAfter;
                
                // Verificar validez temporal
                DateTime now = DateTime.Now;
                if (now < certificate.NotBefore)
                {
                    result.IsValid = false;
                    result.Errors.Add("El certificado aún no es válido");
                }
                else if (now > certificate.NotAfter)
                {
                    result.IsValid = false;
                    result.Errors.Add("El certificado ha expirado");
                }
                else
                {
                    result.IsValid = true;
                }
                
                // Verificar firma
                try
                {
                    certificate.Verify();
                    result.SignatureValid = true;
                }
                catch (CryptographicException ex)
                {
                    result.SignatureValid = false;
                    result.Errors.Add($"Firma inválida: {ex.Message}");
                }
                
                // Verificar uso de clave
                result.KeyUsage = GetKeyUsage(certificate);
                result.EnhancedKeyUsage = GetEnhancedKeyUsage(certificate);
                
                // Verificar cadena de confianza
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                
                if (chain.Build(certificate))
                {
                    result.ChainValid = true;
                    result.ChainStatus = chain.ChainStatus.Select(s => s.StatusInformation).ToList();
                }
                else
                {
                    result.ChainValid = false;
                    result.ChainStatus = chain.ChainStatus.Select(s => s.StatusInformation).ToList();
                    result.Errors.Add("La cadena de certificados no es válida");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Error validando certificado: {ex.Message}");
                
                _logger.LogError($"Error validando certificado: {ex.Message}", ex);
            }
            
            return result;
        }
        
        #endregion
        
        #region Métodos de desinstalación
        
        public CertificateUninstallResult UninstallCertificate(string thumbprint)
        {
            var result = new CertificateUninstallResult();
            
            try
            {
                _logger.LogInfo($"Desinstalando certificado: {thumbprint}");
                
                List<string> removedFrom = new List<string>();
                StoreName[] storesToClean = { 
                    StoreName.Root, 
                    StoreName.TrustedPublisher, 
                    StoreName.CertificateAuthority,
                    StoreName.My,
                    StoreName.AuthRoot,
                    StoreName.TrustedPeople,
                    StoreName.AddressBook
                };
                
                foreach (var storeName in storesToClean)
                {
                    try
                    {
                        if (RemoveCertificateFromStore(thumbprint, storeName))
                        {
                            removedFrom.Add(storeName.ToString());
                            _logger.LogInfo($"Certificado removido de {storeName}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error removiendo certificado de {storeName}: {ex.Message}");
                    }
                }
                
                // Limpiar entradas del registro
                CleanRegistryCertificateEntries(thumbprint);
                
                result.Success = removedFrom.Count > 0;
                result.RemovedFromStores = removedFrom;
                result.Message = $"Certificado removido de {removedFrom.Count} almacenes";
                
                _logger.LogSuccess($"Desinstalación completada: {result.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error desinstalando certificado: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public CertificateUninstallResult UninstallAllBWPEnterpriseCertificates()
        {
            var result = new CertificateUninstallResult();
            
            try
            {
                _logger.LogInfo("Desinstalando todos los certificados de BWP Enterprise...");
                
                List<string> removedCertificates = new List<string>();
                StoreName[] storesToCheck = { 
                    StoreName.Root, 
                    StoreName.TrustedPublisher, 
                    StoreName.CertificateAuthority,
                    StoreName.My
                };
                
                foreach (var storeName in storesToCheck)
                {
                    try
                    {
                        using (X509Store store = new X509Store(storeName, StoreLocation.LocalMachine))
                        {
                            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                            
                            foreach (X509Certificate2 certificate in store.Certificates)
                            {
                                if (IsBWPEnterpriseCertificate(certificate))
                                {
                                    try
                                    {
                                        store.Remove(certificate);
                                        removedCertificates.Add($"{certificate.Thumbprint} ({storeName})");
                                        _logger.LogInfo($"Removido: {certificate.Thumbprint} de {storeName}");
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogWarning($"Error removiendo certificado {certificate.Thumbprint}: {ex.Message}");
                                    }
                                }
                            }
                            
                            store.Close();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error accediendo al almacén {storeName}: {ex.Message}");
                    }
                }
                
                result.Success = removedCertificates.Count > 0;
                result.RemovedCertificates = removedCertificates;
                result.Message = $"Removidos {removedCertificates.Count} certificados";
                
                _logger.LogSuccess($"Desinstalación masiva completada: {result.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                
                _logger.LogError($"Error desinstalando certificados: {ex.Message}", ex);
            }
            
            return result;
        }
        
        #endregion
        
        #region Métodos de gestión de almacenes
        
        public List<CertificateInfo> ListCertificatesInStore(StoreName storeName, StoreLocation storeLocation = StoreLocation.LocalMachine)
        {
            var certificates = new List<CertificateInfo>();
            
            try
            {
                using (X509Store store = new X509Store(storeName, storeLocation))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    
                    foreach (X509Certificate2 certificate in store.Certificates)
                    {
                        var info = new CertificateInfo
                        {
                            Thumbprint = certificate.Thumbprint,
                            Subject = certificate.Subject,
                            Issuer = certificate.Issuer,
                            NotBefore = certificate.NotBefore,
                            NotAfter = certificate.NotAfter,
                            HasPrivateKey = certificate.HasPrivateKey,
                            SerialNumber = certificate.SerialNumber,
                            SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName,
                            Version = certificate.Version
                        };
                        
                        certificates.Add(info);
                    }
                    
                    store.Close();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error listando certificados en {storeName}: {ex.Message}", ex);
            }
            
            return certificates;
        }
        
        public bool BackupCertificateStore(StoreName storeName, string backupPath)
        {
            try
            {
                _logger.LogInfo($"Respaldando almacén {storeName} a {backupPath}");
                
                using (X509Store store = new X509Store(storeName, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    
                    X509Certificate2Collection certificates = store.Certificates;
                    
                    using (FileStream fs = new FileStream(backupPath, FileMode.Create, FileAccess.Write))
                    {
                        foreach (X509Certificate2 certificate in certificates)
                        {
                            byte[] certData = certificate.Export(X509ContentType.Cert);
                            fs.Write(certData, 0, certData.Length);
                            
                            // Separador entre certificados
                            fs.WriteByte(0x1E); // Record Separator
                        }
                    }
                    
                    store.Close();
                }
                
                _logger.LogSuccess($"Respaldo completado: {backupPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error respaldando almacén {storeName}: {ex.Message}", ex);
                return false;
            }
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        private bool IsRootCertificate(X509Certificate2 certificate)
        {
            try
            {
                bool isCA = false;
                bool isSelfSigned = false;
                
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension is X509BasicConstraintsExtension basicConstraints)
                    {
                        isCA = basicConstraints.CertificateAuthority;
                    }
                }
                
                // Verificar que sea auto-firmado
                isSelfSigned = certificate.SubjectName.RawData.SequenceEqual(
                    certificate.IssuerName.RawData);
                
                return isCA && isSelfSigned;
            }
            catch
            {
                return false;
            }
        }
        
        private bool IsClientCertificate(X509Certificate2 certificate)
        {
            try
            {
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension is X509EnhancedKeyUsageExtension enhancedUsage)
                    {
                        foreach (Oid oid in enhancedUsage.EnhancedKeyUsages)
                        {
                            if (oid.Value == "1.3.6.1.5.5.7.3.2" || // Client Authentication
                                oid.Value == "1.3.6.1.4.1.311.10.3.4") // EFS Recovery
                            {
                                return true;
                            }
                        }
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private bool IsBWPEnterpriseCertificate(X509Certificate2 certificate)
        {
            try
            {
                // Verificar por sujeto o emisor
                string subject = certificate.Subject.ToUpperInvariant();
                string issuer = certificate.Issuer.ToUpperInvariant();
                
                return subject.Contains("BWP") || 
                       subject.Contains("ENTERPRISE") ||
                       issuer.Contains("BWP") || 
                       issuer.Contains("ENTERPRISE") ||
                       subject.Contains("BWPENTERPRISE") ||
                       issuer.Contains("BWPENTERPRISE");
            }
            catch
            {
                return false;
            }
        }
        
        private bool IsCertificateInstalled(string thumbprint, StoreName storeName)
        {
            try
            {
                using (X509Store store = new X509Store(storeName, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    
                    X509Certificate2Collection certs = store.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        thumbprint,
                        false);
                    
                    bool found = certs.Count > 0;
                    
                    // Limpiar colección
                    foreach (var cert in certs)
                    {
                        cert.Dispose();
                    }
                    
                    store.Close();
                    
                    return found;
                }
            }
            catch
            {
                return false;
            }
        }
        
        private void InstallToCertificateStore(X509Certificate2 certificate, StoreName storeName)
        {
            X509Store store = null;
            
            try
            {
                store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                
                X509Certificate2Collection existingCerts = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    certificate.Thumbprint,
                    false);
                
                if (existingCerts.Count == 0)
                {
                    store.Add(certificate);
                    _logger.LogInfo($"Certificado agregado al almacén {storeName}: {certificate.Thumbprint}");
                }
                else
                {
                    _logger.LogInfo($"Certificado ya existe en almacén {storeName}: {certificate.Thumbprint}");
                    
                    // Limpiar colección
                    foreach (var cert in existingCerts)
                    {
                        cert.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error agregando certificado al almacén {storeName}: {ex.Message}", ex);
                throw;
            }
            finally
            {
                store?.Close();
            }
        }
        
        private bool RemoveCertificateFromStore(string thumbprint, StoreName storeName)
        {
            try
            {
                using (X509Store store = new X509Store(storeName, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadWrite);
                    
                    X509Certificate2Collection certs = store.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        thumbprint,
                        false);
                    
                    if (certs.Count > 0)
                    {
                        store.RemoveRange(certs);
                        
                        // Limpiar colección
                        foreach (var cert in certs)
                        {
                            cert.Dispose();
                        }
                        
                        return true;
                    }
                    
                    store.Close();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error removiendo certificado de {storeName}: {ex.Message}");
            }
            
            return false;
        }
        
        private void ConfigureCertificateTrust(X509Certificate2 certificate)
        {
            try
            {
                // Configurar para confianza completa
                using (RegistryKey policyKey = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainPolicy\Config"))
                {
                    if (policyKey != null)
                    {
                        policyKey.SetValue(certificate.Thumbprint, "1", RegistryValueKind.String);
                    }
                }
                
                // Configurar para SSL/TLS
                using (RegistryKey sslKey = Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\TrustedCertificateStore"))
                {
                    if (sslKey != null)
                    {
                        sslKey.SetValue(certificate.Thumbprint, "1", RegistryValueKind.String);
                    }
                }
                
                _logger.LogInfo($"Confianza configurada para certificado: {certificate.Thumbprint}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudo configurar confianza completa del certificado: {ex.Message}");
            }
        }
        
        private void ConfigurePrivateKeyPermissions(X509Certificate2 certificate)
        {
            try
            {
                if (!certificate.HasPrivateKey)
                    return;
                    
                // Obtener nombre del contenedor de claves
                string keyContainerName = certificate.PrivateKey?.KeyExchangeAlgorithm ?? 
                                         certificate.PrivateKey?.SignatureAlgorithm ?? 
                                         "Unknown";
                
                // Configurar permisos usando icacls (simplificado)
                string tempBat = Path.GetTempFileName() + ".bat";
                string commands = $@"
                    @echo off
                    setlocal
                    
                    echo Configurando permisos de clave privada...
                    
                    REM Otorgar permisos a SYSTEM
                    icacls ""%ALLUSERSPROFILE%\Microsoft\Crypto\RSA\MachineKeys"" /grant *S-1-5-18:(OI)(CI)F
                    
                    REM Otorgar permisos a Administradores
                    icacls ""%ALLUSERSPROFILE%\Microsoft\Crypto\RSA\MachineKeys"" /grant *S-1-5-32-544:(OI)(CI)F
                    
                    endlocal
                ";
                
                File.WriteAllText(tempBat, commands);
                
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = tempBat,
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                
                Process.Start(psi)?.WaitForExit(10000);
                File.Delete(tempBat);
                
                _logger.LogInfo($"Permisos de clave privada configurados para: {certificate.Thumbprint}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudieron configurar permisos de clave privada: {ex.Message}");
            }
        }
        
        private void ConfigureForClientAuthentication(X509Certificate2 certificate)
        {
            try
            {
                // Configurar para autenticación Schannel
                using (RegistryKey clientAuthKey = Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\ClientAuth\Certificates\" + certificate.Thumbprint))
                {
                    if (clientAuthKey != null)
                    {
                        clientAuthKey.SetValue("CertificateBlob", certificate.RawData, RegistryValueKind.Binary);
                    }
                }
                
                _logger.LogInfo($"Certificado configurado para autenticación cliente: {certificate.Thumbprint}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudo configurar certificado para autenticación cliente: {ex.Message}");
            }
        }
        
        private void CleanRegistryCertificateEntries(string thumbprint)
        {
            try
            {
                string[] registryPaths = {
                    @"SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\" + thumbprint,
                    @"SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Certificates\" + thumbprint,
                    @"SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\" + thumbprint,
                    @"SOFTWARE\Microsoft\SystemCertificates\My\Certificates\" + thumbprint,
                    @"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainPolicy\Config",
                    @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\TrustedCertificateStore",
                    @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\ClientAuth\Certificates\" + thumbprint
                };
                
                foreach (var path in registryPaths)
                {
                    try
                    {
                        Registry.LocalMachine.DeleteSubKeyTree(path, false);
                    }
                    catch
                    {
                        // Ignorar si la clave no existe
                    }
                }
                
                _logger.LogInfo($"Entradas del registro limpiadas para certificado: {thumbprint}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudieron limpiar todas las entradas del registro: {ex.Message}");
            }
        }
        
        private byte[] CombineCertificateAndPrivateKey(byte[] certificateData, byte[] privateKeyData)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // Escribir certificado
                ms.Write(certificateData, 0, certificateData.Length);
                
                // Separador
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x42); // B
                ms.WriteByte(0x45); // E
                ms.WriteByte(0x47); // G
                ms.WriteByte(0x49); // I
                ms.WriteByte(0x4E); // N
                ms.WriteByte(0x20); // Space
                ms.WriteByte(0x50); // P
                ms.WriteByte(0x52); // R
                ms.WriteByte(0x49); // I
                ms.WriteByte(0x56); // V
                ms.WriteByte(0x41); // A
                ms.WriteByte(0x54); // T
                ms.WriteByte(0x45); // E
                ms.WriteByte(0x20); // Space
                ms.WriteByte(0x4B); // K
                ms.WriteByte(0x45); // E
                ms.WriteByte(0x59); // Y
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x2D); // Hyphen
                ms.WriteByte(0x0A); // Newline
                
                // Escribir clave privada
                ms.Write(privateKeyData, 0, privateKeyData.Length);
                
                return ms.ToArray();
            }
        }
        
        private CertificateInstallResult InstallCERTCertificate(byte[] certData)
        {
            try
            {
                X509Certificate2 certificate = new X509Certificate2(certData);
                
                if (IsRootCertificate(certificate))
                {
                    return InstallRootCertificate(certData);
                }
                else
                {
                    // Instalar como certificado intermedio
                    InstallToCertificateStore(certificate, StoreName.CertificateAuthority);
                    
                    return new CertificateInstallResult
                    {
                        Success = true,
                        CertificateThumbprint = certificate.Thumbprint,
                        Message = "Certificado intermedio instalado"
                    };
                }
            }
            catch (Exception ex)
            {
                return new CertificateInstallResult
                {
                    Success = false,
                    ErrorMessage = ex.Message,
                    Exception = ex
                };
            }
        }
        
        private CertificateInstallResult InstallPKCS7Certificate(byte[] p7bData)
        {
            try
            {
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                certificates.Import(p7bData);
                
                int installedCount = 0;
                List<string> thumbprints = new List<string>();
                
                foreach (X509Certificate2 certificate in certificates)
                {
                    try
                    {
                        if (IsRootCertificate(certificate))
                        {
                            var result = InstallRootCertificate(certificate.Export(X509ContentType.Cert));
                            if (result.Success)
                            {
                                installedCount++;
                                thumbprints.Add(certificate.Thumbprint);
                            }
                        }
                        else
                        {
                            InstallToCertificateStore(certificate, StoreName.CertificateAuthority);
                            installedCount++;
                            thumbprints.Add(certificate.Thumbprint);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error instalando certificado PKCS7: {ex.Message}");
                    }
                }
                
                return new CertificateInstallResult
                {
                    Success = installedCount > 0,
                    CertificateThumbprint = thumbprints.Count > 0 ? string.Join(";", thumbprints) : null,
                    Message = $"Instalados {installedCount} certificados de {certificates.Count}"
                };
            }
            catch (Exception ex)
            {
                return new CertificateInstallResult
                {
                    Success = false,
                    ErrorMessage = ex.Message,
                    Exception = ex
                };
            }
        }
        
        private string GetKeyUsage(X509Certificate2 certificate)
        {
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension is X509KeyUsageExtension keyUsage)
                {
                    return keyUsage.KeyUsages.ToString();
                }
            }
            
            return "No especificado";
        }
        
        private List<string> GetEnhancedKeyUsage(X509Certificate2 certificate)
        {
            List<string> usages = new List<string>();
            
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension enhancedUsage)
                {
                    foreach (Oid oid in enhancedUsage.EnhancedKeyUsages)
                    {
                        usages.Add(oid.FriendlyName ?? oid.Value);
                    }
                }
            }
            
            return usages;
        }
        
        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
            }
        }
        
        #endregion
    }
    
    #region Clases de resultado
    
    public class CertificateInstallResult
    {
        public bool Success { get; set; }
        public string CertificateThumbprint { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public Exception Exception { get; set; }
    }
    
    public class CertificateUninstallResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public Exception Exception { get; set; }
        public List<string> RemovedFromStores { get; set; } = new List<string>();
        public List<string> RemovedCertificates { get; set; } = new List<string>();
    }
    
    public class CertificateValidationResult
    {
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsValid { get; set; }
        public bool SignatureValid { get; set; }
        public bool ChainValid { get; set; }
        public string KeyUsage { get; set; }
        public List<string> EnhancedKeyUsage { get; set; } = new List<string>();
        public List<string> ChainStatus { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();
    }
    
    public class CertificateInfo
    {
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool HasPrivateKey { get; set; }
        public string SerialNumber { get; set; }
        public string SignatureAlgorithm { get; set; }
        public int Version { get; set; }
    }
    
    #endregion
}