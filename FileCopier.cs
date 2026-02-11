using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BWP.Installer.Engine
{
    public class FileCopier : IDisposable
    {
        #region Constantes
        
        private const int MAX_RETRY_ATTEMPTS = 5;
        private const int RETRY_DELAY_MS = 1000;
        private const int BUFFER_SIZE = 81920; // 80KB buffer para copia
        private const long MAX_SINGLE_FILE_SIZE = 2L * 1024 * 1024 * 1024; // 2GB
        private const long WARNING_DISK_SPACE_MULTIPLIER = 2; // Espacio requerido = tamaño * 2
        private const string BACKUP_DIRECTORY = "BWP_Backups";
        private const string TEMP_FILE_PREFIX = "BWP_TEMP_";
        private const int HASH_VERIFICATION_CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks para hash
        
        #endregion
        
        #region Campos privados
        
        private readonly InstallerLogger _logger;
        private readonly SHA256 _sha256;
        private readonly List<string> _temporaryFiles;
        private bool _disposed;
        
        #endregion
        
        #region Constructor
        
        public FileCopier(InstallerLogger logger = null)
        {
            _logger = logger ?? new InstallerLogger();
            _sha256 = SHA256.Create();
            _temporaryFiles = new List<string>();
        }
        
        #endregion
        
        #region Clases públicas
        
        public class CopyResult
        {
            public bool Success { get; set; }
            public string SourcePath { get; set; }
            public string DestinationPath { get; set; }
            public long FileSize { get; set; }
            public string FileHash { get; set; }
            public DateTime StartTime { get; set; }
            public DateTime EndTime { get; set; }
            public TimeSpan Duration => EndTime - StartTime;
            public string ErrorMessage { get; set; }
            public Exception Exception { get; set; }
            public List<string> Warnings { get; set; } = new List<string>();
            public CopyMethod Method { get; set; }
            public bool RequiresRestart { get; set; }
            public string BackupPath { get; set; }
        }
        
        public class DirectoryCopyResult
        {
            public bool Success { get; set; }
            public string SourceDirectory { get; set; }
            public string DestinationDirectory { get; set; }
            public int TotalFiles { get; set; }
            public int SuccessfulFiles { get; set; }
            public int FailedFiles { get; set; }
            public long TotalBytes { get; set; }
            public long CopiedBytes { get; set; }
            public DateTime StartTime { get; set; }
            public DateTime EndTime { get; set; }
            public TimeSpan Duration => EndTime - StartTime;
            public List<CopyResult> FileResults { get; set; } = new List<CopyResult>();
            public List<string> Errors { get; set; } = new List<string>();
            public List<string> Warnings { get; set; } = new List<string>();
        }
        
        public class CopyOptions
        {
            public bool OverwriteExisting { get; set; } = true;
            public bool VerifyAfterCopy { get; set; } = true;
            public bool SetPermissions { get; set; } = true;
            public bool CreateBackup { get; set; } = true;
            public bool PreserveTimestamps { get; set; } = true;
            public bool PreserveAttributes { get; set; } = true;
            public bool LogDetailedInfo { get; set; } = false;
            public bool UseBufferedCopy { get; set; } = true;
            public bool ValidateSource { get; set; } = true;
            public bool CalculateHash { get; set; } = true;
            public int RetryCount { get; set; } = MAX_RETRY_ATTEMPTS;
            public int RetryDelay { get; set; } = RETRY_DELAY_MS;
            public int BufferSize { get; set; } = BUFFER_SIZE;
            public FileSecuritySettings SecuritySettings { get; set; } = new FileSecuritySettings();
            public CopyPriority Priority { get; set; } = CopyPriority.Normal;
            public CopyMethod PreferredMethod { get; set; } = CopyMethod.Automatic;
        }
        
        public class FileSecuritySettings
        {
            public bool InheritPermissions { get; set; } = true;
            public FileSystemRights UserRights { get; set; } = FileSystemRights.ReadAndExecute;
            public FileSystemRights AdminRights { get; set; } = FileSystemRights.FullControl;
            public FileSystemRights SystemRights { get; set; } = FileSystemRights.FullControl;
            public FileSystemRights ServiceRights { get; set; } = FileSystemRights.Read | FileSystemRights.Execute;
            public InheritanceFlags Inheritance { get; set; } = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            public PropagationFlags Propagation { get; set; } = PropagationFlags.None;
            public AccessControlType ControlType { get; set; } = AccessControlType.Allow;
        }
        
        public enum CopyMethod
        {
            Automatic,
            FileCopy,
            BufferedStream,
            MemoryMapped,
            SymbolicLink,
            HardLink
        }
        
        public enum CopyPriority
        {
            Low,
            Normal,
            High,
            Critical
        }
        
        #endregion
        
        #region Métodos públicos principales
        
        public CopyResult CopyFile(string sourcePath, string destinationPath, CopyOptions options = null)
        {
            var result = new CopyResult
            {
                SourcePath = sourcePath,
                DestinationPath = destinationPath,
                StartTime = DateTime.Now,
                Method = CopyMethod.Automatic
            };
            
            if (options == null)
            {
                options = new CopyOptions();
            }
            
            try
            {
                _logger.LogInfo($"Iniciando copia: {sourcePath} -> {destinationPath}");
                
                // 1. Validaciones previas
                if (!ValidatePreCopyConditions(sourcePath, destinationPath, options, result))
                {
                    result.EndTime = DateTime.Now;
                    return result;
                }
                
                // 2. Verificar espacio en disco
                if (!CheckDiskSpace(sourcePath, destinationPath, result))
                {
                    result.ErrorMessage = "Espacio insuficiente en disco";
                    result.EndTime = DateTime.Now;
                    return result;
                }
                
                // 3. Crear backup si existe y está configurado
                if (options.CreateBackup && File.Exists(destinationPath))
                {
                    result.BackupPath = CreateBackup(destinationPath, result);
                }
                
                // 4. Determinar método de copia óptimo
                CopyMethod selectedMethod = DetermineOptimalCopyMethod(sourcePath, destinationPath, options);
                result.Method = selectedMethod;
                
                // 5. Ejecutar copia con reintentos
                bool copySuccess = false;
                Exception lastException = null;
                
                for (int attempt = 0; attempt < options.RetryCount && !copySuccess; attempt++)
                {
                    if (attempt > 0)
                    {
                        _logger.LogWarning($"Reintento {attempt + 1}/{options.RetryCount} para {Path.GetFileName(sourcePath)}");
                        Thread.Sleep(options.RetryDelay * (attempt + 1)); // Espera progresiva
                    }
                    
                    try
                    {
                        switch (selectedMethod)
                        {
                            case CopyMethod.FileCopy:
                                PerformFileCopy(sourcePath, destinationPath, options, result);
                                break;
                            case CopyMethod.BufferedStream:
                                PerformBufferedCopy(sourcePath, destinationPath, options, result);
                                break;
                            case CopyMethod.MemoryMapped:
                                PerformMemoryMappedCopy(sourcePath, destinationPath, options, result);
                                break;
                            case CopyMethod.SymbolicLink:
                                PerformSymbolicLink(sourcePath, destinationPath, result);
                                break;
                            case CopyMethod.HardLink:
                                PerformHardLink(sourcePath, destinationPath, result);
                                break;
                            default:
                                PerformIntelligentCopy(sourcePath, destinationPath, options, result);
                                break;
                        }
                        
                        copySuccess = true;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                        result.Warnings.Add($"Intento {attempt + 1} falló: {ex.Message}");
                        
                        if (attempt == options.RetryCount - 1)
                        {
                            result.Exception = ex;
                            result.ErrorMessage = $"Error después de {options.RetryCount} intentos: {ex.Message}";
                        }
                    }
                }
                
                if (!copySuccess)
                {
                    result.Success = false;
                    result.EndTime = DateTime.Now;
                    return result;
                }
                
                // 6. Verificar copia
                if (options.VerifyAfterCopy)
                {
                    if (!VerifyFileCopy(sourcePath, destinationPath, options, result))
                    {
                        result.Success = false;
                        result.ErrorMessage = "La verificación de la copia falló";
                        result.EndTime = DateTime.Now;
                        
                        // Intentar restaurar backup
                        if (!string.IsNullOrEmpty(result.BackupPath))
                        {
                            RestoreFromBackup(result.BackupPath, destinationPath);
                        }
                        
                        return result;
                    }
                }
                
                // 7. Preservar atributos y timestamps
                if (options.PreserveTimestamps || options.PreserveAttributes)
                {
                    PreserveFileMetadata(sourcePath, destinationPath, options);
                }
                
                // 8. Establecer permisos
                if (options.SetPermissions)
                {
                    SetFilePermissions(destinationPath, options.SecuritySettings, result);
                }
                
                // 9. Calcular hash
                if (options.CalculateHash)
                {
                    result.FileHash = CalculateFileHash(destinationPath);
                }
                
                // 10. Registrar en el sistema
                RegisterFileInSystem(destinationPath, result);
                
                result.Success = true;
                result.EndTime = DateTime.Now;
                
                string speed = result.FileSize > 0 
                    ? $"{result.FileSize / (1024 * 1024) / result.Duration.TotalSeconds:F2} MB/s" 
                    : "N/A";
                
                _logger.LogSuccess($"Archivo copiado: {Path.GetFileName(destinationPath)} " +
                    $"({result.FileSize / 1024:N0} KB en {result.Duration.TotalSeconds:F2}s, {speed})");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Exception = ex;
                result.EndTime = DateTime.Now;
                
                _logger.LogError($"Error copiando archivo {sourcePath}: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public async Task<CopyResult> CopyFileAsync(string sourcePath, string destinationPath, CopyOptions options = null)
        {
            return await Task.Run(() => CopyFile(sourcePath, destinationPath, options));
        }
        
        public DirectoryCopyResult CopyDirectory(string sourceDir, string destinationDir, CopyOptions options = null)
        {
            var result = new DirectoryCopyResult
            {
                SourceDirectory = sourceDir,
                DestinationDirectory = destinationDir,
                StartTime = DateTime.Now
            };
            
            if (options == null)
            {
                options = new CopyOptions();
            }
            
            try
            {
                _logger.LogInfo($"Iniciando copia de directorio: {sourceDir} -> {destinationDir}");
                
                // Validar directorio fuente
                if (!Directory.Exists(sourceDir))
                {
                    result.Errors.Add($"El directorio fuente no existe: {sourceDir}");
                    result.Success = false;
                    result.EndTime = DateTime.Now;
                    return result;
                }
                
                // Crear directorio destino
                Directory.CreateDirectory(destinationDir);
                
                // Obtener todos los archivos
                string[] allFiles = Directory.GetFiles(sourceDir, "*.*", SearchOption.AllDirectories);
                result.TotalFiles = allFiles.Length;
                
                _logger.LogInfo($"Encontrados {result.TotalFiles} archivos para copiar");
                
                // Configurar paralelismo según prioridad
                ParallelOptions parallelOptions = new ParallelOptions();
                
                switch (options.Priority)
                {
                    case CopyPriority.Low:
                        parallelOptions.MaxDegreeOfParallelism = 1;
                        break;
                    case CopyPriority.Normal:
                        parallelOptions.MaxDegreeOfParallelism = Environment.ProcessorCount / 2;
                        break;
                    case CopyPriority.High:
                        parallelOptions.MaxDegreeOfParallelism = Environment.ProcessorCount;
                        break;
                    case CopyPriority.Critical:
                        parallelOptions.MaxDegreeOfParallelism = Environment.ProcessorCount * 2;
                        break;
                }
                
                // Copiar archivos en paralelo
                Parallel.ForEach(allFiles, parallelOptions, (file) =>
                {
                    try
                    {
                        string relativePath = GetRelativePath(file, sourceDir);
                        string destFile = Path.Combine(destinationDir, relativePath);
                        
                        // Crear subdirectorio si no existe
                        string destSubDir = Path.GetDirectoryName(destFile);
                        if (!Directory.Exists(destSubDir))
                        {
                            Directory.CreateDirectory(destSubDir);
                        }
                        
                        // Copiar archivo
                        var fileResult = CopyFile(file, destFile, options);
                        
                        lock (result.FileResults)
                        {
                            result.FileResults.Add(fileResult);
                            
                            if (fileResult.Success)
                            {
                                result.SuccessfulFiles++;
                                result.CopiedBytes += fileResult.FileSize;
                                
                                if (options.LogDetailedInfo)
                                {
                                    _logger.LogDebug($"  ✓ {relativePath}");
                                }
                            }
                            else
                            {
                                result.FailedFiles++;
                                result.Errors.Add($"{relativePath}: {fileResult.ErrorMessage}");
                                
                                if (options.LogDetailedInfo)
                                {
                                    _logger.LogWarning($"  ✗ {relativePath}: {fileResult.ErrorMessage}");
                                }
                            }
                        }
                        
                        Interlocked.Add(ref result.TotalBytes, new FileInfo(file).Length);
                    }
                    catch (Exception ex)
                    {
                        lock (result)
                        {
                            result.FailedFiles++;
                            result.Errors.Add($"{file}: {ex.Message}");
                        }
                        
                        _logger.LogWarning($"Error copiando {file}: {ex.Message}");
                    }
                });
                
                // Copiar estructura de directorios vacíos
                CopyEmptyDirectoryStructure(sourceDir, destinationDir, options);
                
                // Establecer permisos en el directorio raíz
                if (options.SetPermissions)
                {
                    SetDirectoryPermissions(destinationDir, options.SecuritySettings);
                }
                
                result.Success = result.FailedFiles == 0;
                result.EndTime = DateTime.Now;
                
                _logger.LogSuccess($"Directorio copiado: {result.SuccessfulFiles}/{result.TotalFiles} archivos, " +
                    $"{result.CopiedBytes / (1024 * 1024):N0} MB en {result.Duration.TotalSeconds:F2}s");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add($"Error general: {ex.Message}");
                result.EndTime = DateTime.Now;
                
                _logger.LogError($"Error copiando directorio: {ex.Message}", ex);
            }
            
            return result;
        }
        
        public async Task<DirectoryCopyResult> CopyDirectoryAsync(string sourceDir, string destinationDir, CopyOptions options = null)
        {
            return await Task.Run(() => CopyDirectory(sourceDir, destinationDir, options));
        }
        
        #endregion
        
        #region Métodos de copia especializados
        
        private void PerformFileCopy(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            if (options.OverwriteExisting && File.Exists(destinationPath))
            {
                File.Copy(sourcePath, destinationPath, true);
            }
            else
            {
                File.Copy(sourcePath, destinationPath, false);
            }
            
            result.FileSize = new FileInfo(sourcePath).Length;
        }
        
        private void PerformBufferedCopy(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            using (FileStream sourceStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, options.BufferSize))
            using (FileStream destStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, options.BufferSize))
            {
                byte[] buffer = new byte[options.BufferSize];
                int bytesRead;
                long totalBytes = 0;
                
                while ((bytesRead = sourceStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    destStream.Write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
                
                result.FileSize = totalBytes;
            }
        }
        
        private unsafe void PerformMemoryMappedCopy(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            // Implementación simplificada - en producción usaría MemoryMappedFile
            PerformBufferedCopy(sourcePath, destinationPath, options, result);
        }
        
        private void PerformSymbolicLink(string sourcePath, string destinationPath, CopyResult result)
        {
            // Crear enlace simbólico
            if (!CreateSymbolicLink(destinationPath, sourcePath, 0))
            {
                throw new InvalidOperationException("No se pudo crear el enlace simbólico");
            }
            
            result.FileSize = new FileInfo(sourcePath).Length;
            result.Warnings.Add("Se creó un enlace simbólico en lugar de copiar el archivo");
        }
        
        private void PerformHardLink(string sourcePath, string destinationPath, CopyResult result)
        {
            // Crear enlace físico
            if (!CreateHardLink(destinationPath, sourcePath, IntPtr.Zero))
            {
                throw new InvalidOperationException("No se pudo crear el enlace físico");
            }
            
            result.FileSize = new FileInfo(sourcePath).Length;
            result.Warnings.Add("Se creó un enlace físico en lugar de copiar el archivo");
        }
        
        private void PerformIntelligentCopy(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            // Usar el método más apropiado según el contexto
            if (options.UseBufferedCopy)
            {
                PerformBufferedCopy(sourcePath, destinationPath, options, result);
            }
            else
            {
                PerformFileCopy(sourcePath, destinationPath, options, result);
            }
        }
        
        #endregion
        
        #region Métodos de validación y verificación
        
        private bool ValidatePreCopyConditions(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            try
            {
                // Verificar que el archivo fuente existe
                if (!File.Exists(sourcePath))
                {
                    result.ErrorMessage = $"El archivo fuente no existe: {sourcePath}";
                    return false;
                }
                
                // Verificar tamaño máximo
                FileInfo sourceInfo = new FileInfo(sourcePath);
                if (sourceInfo.Length > MAX_SINGLE_FILE_SIZE)
                {
                    result.Warnings.Add($"Archivo muy grande: {sourceInfo.Length / (1024 * 1024):N0} MB");
                }
                
                result.FileSize = sourceInfo.Length;
                
                // Verificar permisos de lectura
                if (options.ValidateSource)
                {
                    try
                    {
                        using (FileStream fs = File.OpenRead(sourcePath))
                        {
                            // Solo verificar acceso
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        result.ErrorMessage = $"Sin permisos de lectura para: {sourcePath}";
                        return false;
                    }
                    catch (IOException ex)
                    {
                        result.ErrorMessage = $"El archivo está en uso: {sourcePath}";
                        result.RequiresRestart = true;
                        _logger.LogWarning($"Archivo en uso, puede requerir reinicio: {sourcePath}");
                        return false;
                    }
                }
                
                // Verificar permisos de escritura en destino
                string directory = Path.GetDirectoryName(destinationPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    try
                    {
                        if (!Directory.Exists(directory))
                        {
                            Directory.CreateDirectory(directory);
                        }
                        
                        string testFile = Path.Combine(directory, $"{TEMP_FILE_PREFIX}{Guid.NewGuid():N}.tmp");
                        File.WriteAllText(testFile, "test");
                        File.Delete(testFile);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        result.ErrorMessage = $"Sin permisos de escritura en: {directory}";
                        return false;
                    }
                }
                
                return true;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Error en validación previa: {ex.Message}";
                return false;
            }
        }
        
        private bool VerifyFileCopy(string sourcePath, string destinationPath, CopyOptions options, CopyResult result)
        {
            try
            {
                // Verificar existencia
                if (!File.Exists(destinationPath))
                {
                    _logger.LogError($"El archivo destino no existe: {destinationPath}");
                    return false;
                }
                
                // Verificar tamaño
                FileInfo sourceInfo = new FileInfo(sourcePath);
                FileInfo destInfo = new FileInfo(destinationPath);
                
                if (sourceInfo.Length != destInfo.Length)
                {
                    _logger.LogError($"Tamaño incorrecto: origen={sourceInfo.Length:N0}, destino={destInfo.Length:N0}");
                    return false;
                }
                
                // Verificar hash
                string sourceHash = CalculateFileHash(sourcePath);
                string destHash = CalculateFileHash(destinationPath);
                
                if (sourceHash != destHash)
                {
                    _logger.LogError($"Hash incorrecto para: {destinationPath}");
                    _logger.LogDebug($"  Esperado: {sourceHash}");
                    _logger.LogDebug($"  Obtenido: {destHash}");
                    return false;
                }
                
                result.FileHash = destHash;
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error verificando copia: {ex.Message}", ex);
                return false;
            }
        }
        
        #endregion
        
        #region Métodos de utilidad
        
        private CopyMethod DetermineOptimalCopyMethod(string sourcePath, string destinationPath, CopyOptions options)
        {
            if (options.PreferredMethod != CopyMethod.Automatic)
            {
                return options.PreferredMethod;
            }
            
            FileInfo sourceInfo = new FileInfo(sourcePath);
            
            // Archivos muy grandes > 500MB
            if (sourceInfo.Length > 500 * 1024 * 1024)
            {
                return CopyMethod.BufferedStream;
            }
            
            // Archivos pequeños < 1MB
            if (sourceInfo.Length < 1024 * 1024)
            {
                return CopyMethod.FileCopy;
            }
            
            // Por defecto
            return CopyMethod.BufferedStream;
        }
        
        private bool CheckDiskSpace(string sourcePath, string destinationPath, CopyResult result)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(sourcePath);
                long requiredSpace = fileInfo.Length * WARNING_DISK_SPACE_MULTIPLIER;
                
                string drive = Path.GetPathRoot(destinationPath);
                DriveInfo driveInfo = new DriveInfo(drive);
                
                if (driveInfo.AvailableFreeSpace < requiredSpace)
                {
                    _logger.LogWarning($"Espacio bajo en {drive}: {driveInfo.AvailableFreeSpace / (1024 * 1024):N0} MB disponible, " +
                        $"{requiredSpace / (1024 * 1024):N0} MB recomendado");
                    
                    if (driveInfo.AvailableFreeSpace < fileInfo.Length)
                    {
                        return false;
                    }
                }
                
                return true;
            }
            catch
            {
                return true;
            }
        }
        
        private string CreateBackup(string filePath, CopyResult result)
        {
            try
            {
                string directory = Path.GetDirectoryName(filePath);
                string backupDir = Path.Combine(directory, BACKUP_DIRECTORY);
                Directory.CreateDirectory(backupDir);
                
                string fileName = Path.GetFileName(filePath);
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string backupPath = Path.Combine(backupDir, $"{fileName}.backup_{timestamp}");
                
                File.Copy(filePath, backupPath, true);
                
                // Limpiar backups antiguos (más de 5)
                CleanOldBackups(backupDir, fileName);
                
                _logger.LogDebug($"Backup creado: {backupPath}");
                return backupPath;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"No se pudo crear backup: {ex.Message}");
                result.Warnings.Add($"No se pudo crear backup: {ex.Message}");
                return null;
            }
        }
        
        private void CleanOldBackups(string backupDir, string fileNamePattern)
        {
            try
            {
                var backupFiles = Directory.GetFiles(backupDir, $"{fileNamePattern}.backup_*")
                    .OrderByDescending(f => f)
                    .ToList();
                
                if (backupFiles.Count > 5)
                {
                    foreach (var oldFile in backupFiles.Skip(5))
                    {
                        File.Delete(oldFile);
                        _logger.LogDebug($"Backup antiguo eliminado: {oldFile}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error limpiando backups: {ex.Message}");
            }
        }
        
        private void RestoreFromBackup(string backupPath, string destinationPath)
        {
            try
            {
                if (File.Exists(backupPath))
                {
                    File.Copy(backupPath, destinationPath, true);
                    _logger.LogInfo($"Backup restaurado: {destinationPath}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error restaurando backup: {ex.Message}", ex);
            }
        }
        
        private void PreserveFileMetadata(string sourcePath, string destinationPath, CopyOptions options)
        {
            try
            {
                FileInfo sourceInfo = new FileInfo(sourcePath);
                FileInfo destInfo = new FileInfo(destinationPath);
                
                if (options.PreserveTimestamps)
                {
                    destInfo.CreationTime = sourceInfo.CreationTime;
                    destInfo.LastWriteTime = sourceInfo.LastWriteTime;
                    destInfo.LastAccessTime = sourceInfo.LastAccessTime;
                }
                
                if (options.PreserveAttributes)
                {
                    destInfo.Attributes = sourceInfo.Attributes;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error preservando metadatos: {ex.Message}");
            }
        }
        
        private void SetFilePermissions(string filePath, FileSecuritySettings settings, CopyResult result)
        {
            try
            {
                FileSecurity fileSecurity = new FileSecurity();
                
                // SYSTEM
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    settings.SystemRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                // Administradores
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    settings.AdminRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                // Usuarios
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    settings.UserRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                // Servicio
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.ServiceSid, null),
                    settings.ServiceRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                File.SetAccessControl(filePath, fileSecurity);
                _logger.LogDebug($"Permisos establecidos: {filePath}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error estableciendo permisos: {ex.Message}");
                result.Warnings.Add($"No se pudieron establecer permisos: {ex.Message}");
            }
        }
        
        private void SetDirectoryPermissions(string directoryPath, FileSecuritySettings settings)
        {
            try
            {
                DirectorySecurity dirSecurity = new DirectorySecurity();
                
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    settings.SystemRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    settings.AdminRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    settings.UserRights,
                    settings.Inheritance,
                    settings.Propagation,
                    settings.ControlType
                ));
                
                Directory.SetAccessControl(directoryPath, dirSecurity);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error estableciendo permisos de directorio: {ex.Message}");
            }
        }
        
        private void CopyEmptyDirectoryStructure(string sourceDir, string destinationDir, CopyOptions options)
        {
            try
            {
                foreach (string dir in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
                {
                    if (IsDirectoryEmpty(dir))
                    {
                        string relativePath = GetRelativePath(dir, sourceDir);
                        string destDirPath = Path.Combine(destinationDir, relativePath);
                        
                        if (!Directory.Exists(destDirPath))
                        {
                            Directory.CreateDirectory(destDirPath);
                            
                            if (options.SetPermissions)
                            {
                                SetDirectoryPermissions(destDirPath, options.SecuritySettings);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error copiando directorios vacíos: {ex.Message}");
            }
        }
        
        private bool IsDirectoryEmpty(string directory)
        {
            try
            {
                return Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Length == 0;
            }
            catch
            {
                return false;
            }
        }
        
        private string GetRelativePath(string fullPath, string basePath)
        {
            if (!basePath.EndsWith(Path.DirectorySeparatorChar.ToString()))
            {
                basePath += Path.DirectorySeparatorChar;
            }
            
            Uri pathUri = new Uri(fullPath);
            Uri baseUri = new Uri(basePath);
            
            return Uri.UnescapeDataString(baseUri.MakeRelativeUri(pathUri).ToString()
                .Replace('/', Path.DirectorySeparatorChar));
        }
        
        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = _sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error calculando hash: {ex.Message}");
                return string.Empty;
            }
        }
        
        private void RegisterFileInSystem(string filePath, CopyResult result)
        {
            try
            {
                string registryPath = $@"SOFTWARE\BWP Enterprise\FileRegistry\{Guid.NewGuid():N}";
                
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        key.SetValue("Path", filePath, RegistryValueKind.String);
                        key.SetValue("Size", result.FileSize, RegistryValueKind.QWord);
                        key.SetValue("Hash", result.FileHash ?? "", RegistryValueKind.String);
                        key.SetValue("InstallDate", DateTime.UtcNow.ToString("o"), RegistryValueKind.String);
                        key.SetValue("Source", result.SourcePath, RegistryValueKind.String);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error registrando archivo: {ex.Message}");
            }
        }
        
        public bool CleanupFailedCopy(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                    _logger.LogDebug($"Archivo eliminado: {path}");
                    return true;
                }
                else if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                    _logger.LogDebug($"Directorio eliminado: {path}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error en limpieza: {ex.Message}");
            }
            
            return false;
        }
        
        public void CleanupTemporaryFiles()
        {
            foreach (string tempFile in _temporaryFiles.ToList())
            {
                try
                {
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                        _logger.LogDebug($"Archivo temporal eliminado: {tempFile}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Error eliminando archivo temporal {tempFile}: {ex.Message}");
                }
            }
            
            _temporaryFiles.Clear();
        }
        
        #endregion
        
        #region P/Invoke
        
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
        
        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (!_disposed)
            {
                _sha256?.Dispose();
                CleanupTemporaryFiles();
                _disposed = true;
            }
        }
        
        #endregion
    }
    
    #region Logger simplificado
    
    public class InstallerLogger
    {
        public void LogInfo(string message) => Debug.WriteLine($"[INFO] {message}");
        public void LogSuccess(string message) => Debug.WriteLine($"[SUCCESS] {message}");
        public void LogWarning(string message) => Debug.WriteLine($"[WARNING] {message}");
        public void LogError(string message, Exception ex = null) => Debug.WriteLine($"[ERROR] {message}");
        public void LogDebug(string message) => Debug.WriteLine($"[DEBUG] {message}");
    }
    
    #endregion
}