using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Utils;

namespace BWP.Enterprise.Agent.Remediation
{
    /// <summary>
    /// Administrador de cuarentena de archivos maliciosos
    /// Cifra archivos, mantiene metadatos y permite restauración segura
    /// </summary>
    public class QuarantineManager : IDisposable



    {
        private static readonly Lazy<QuarantineManager> _instance =
            new Lazy<QuarantineManager>(() => new QuarantineManager());

        public static QuarantineManager Instance => _instance.Value;

        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly CryptoHelper _cryptoHelper;
        private readonly ConcurrentDictionary<string, QuarantineEntry> _quarantineIndex;
        private readonly string _quarantineDirectory;
        private readonly string _metadataFile;
        private readonly Timer _cleanupTimer;
        private readonly object _lockObject = new object();

        // Configuración
        private const int MAX_QUARANTINE_SIZE_GB = 10;
        private const int MAX_FILE_SIZE_MB = 500;
        private const int RETENTION_DAYS = 30;
        private const int CLEANUP_INTERVAL_HOURS = 24;

        private QuarantineManager()
        {
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _cryptoHelper = CryptoHelper.Instance;
            _quarantineIndex = new ConcurrentDictionary<string, QuarantineEntry>();

            // Configurar directorio de cuarentena
            string basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BWPEnterprise", "Quarantine"
            );

            _quarantineDirectory = basePath;
            _metadataFile = Path.Combine(basePath, "quarantine_index.dat");

            // Crear directorio si no existe
            if (!Directory.Exists(_quarantineDirectory))
            {
                Directory.CreateDirectory(_quarantineDirectory);
                
                // Establecer permisos restrictivos
                SetRestrictivePermissions(_quarantineDirectory);
            }

            // Cargar índice de cuarentena
            LoadQuarantineIndex();

            // Iniciar timer de limpieza
            _cleanupTimer = new Timer(
                CleanupTimerCallback,
                null,
                TimeSpan.FromHours(1),
                TimeSpan.FromHours(CLEANUP_INTERVAL_HOURS)
            );
        }

        /// <summary>
        /// Pone un archivo en cuarentena
        /// </summary>
        public QuarantineResult QuarantineFile(string filePath, string reason)
        {
            var result = new QuarantineResult();

            try
            {
                // Validaciones
                if (string.IsNullOrEmpty(filePath))
                {
                    result.Success = false;
                    result.ErrorMessage = "File path is null or empty";
                    return result;
                }

                if (!File.Exists(filePath))
                {
                    result.Success = false;
                    result.ErrorMessage = "File not found";
                    return result;
                }

                // Verificar tamaño del archivo
                var fileInfo = new FileInfo(filePath);
                long fileSizeMB = fileInfo.Length / (1024 * 1024);

                if (fileSizeMB > MAX_FILE_SIZE_MB)
                {
                    result.Success = false;
                    result.ErrorMessage = $"File exceeds maximum size ({MAX_FILE_SIZE_MB}MB)";
                    _logManager.LogWarning($"Archivo demasiado grande para cuarentena: {filePath} ({fileSizeMB}MB)", "QuarantineManager");
                    return result;
                }

                // Verificar espacio disponible en cuarentena
                if (!HasSufficientSpace(fileInfo.Length))
                {
                    result.Success = false;
                    result.ErrorMessage = "Insufficient quarantine space";
                    _logManager.LogWarning("Espacio insuficiente en cuarentena", "QuarantineManager");
                    return result;
                }

                lock (_lockObject)
                {
                    // Generar ID único para cuarentena
                    string quarantineId = GenerateQuarantineId();
                    string quarantinePath = Path.Combine(_quarantineDirectory, quarantineId + ".qtn");
                    string metadataPath = Path.Combine(_quarantineDirectory, quarantineId + ".meta");

                    // Calcular hash del archivo original
                    string fileHash = _cryptoHelper.CalculateFileHash(filePath, HashAlgorithmType.SHA256);

                    // Crear entrada de metadatos
                    var entry = new QuarantineEntry
                    {
                        QuarantineId = quarantineId,
                        OriginalPath = filePath,
                        OriginalFileName = Path.GetFileName(filePath),
                        QuarantinePath = quarantinePath,
                        FileHash = fileHash,
                        FileSize = fileInfo.Length,
                        QuarantinedAt = DateTime.UtcNow,
                        Reason = reason,
                        OriginalCreationTime = fileInfo.CreationTimeUtc,
                        OriginalLastWriteTime = fileInfo.LastWriteTimeUtc,
                        OriginalLastAccessTime = fileInfo.LastAccessTimeUtc,
                        FileAttributes = fileInfo.Attributes,
                        CanRestore = true
                    };

                    try
                    {
                        // Leer archivo original
                        byte[] fileData = File.ReadAllBytes(filePath);

                        // Cifrar archivo
                        byte[] encryptedData = _cryptoHelper.EncryptData(
                            fileData,
                            GetQuarantineEncryptionKey(),
                            out byte[] iv
                        );

                        // Guardar IV en metadatos
                        entry.EncryptionIV = Convert.ToBase64String(iv);

                        // Escribir archivo cifrado
                        File.WriteAllBytes(quarantinePath, encryptedData);

                        // Guardar metadatos
                        string metadataJson = JsonConvert.SerializeObject(entry, Formatting.Indented);
                        File.WriteAllText(metadataPath, metadataJson);

                        // Eliminar archivo original
                        File.Delete(filePath);

                        // Agregar al índice
                        _quarantineIndex[quarantineId] = entry;

                        // Guardar índice actualizado
                        SaveQuarantineIndex();

                        // Guardar en base de datos
                        _localDatabase.StoreQuarantineEntry(entry);

                        result.Success = true;
                        result.QuarantineId = quarantineId;
                        result.Message = $"File quarantined successfully: {quarantineId}";

                        _logManager.LogWarning(
                            $"Archivo en cuarentena: {filePath} -> {quarantineId} | Razón: {reason}",
                            "QuarantineManager"
                        );
                    }
                    catch (Exception ex)
                    {
                        // Limpiar archivos parciales en caso de error
                        if (File.Exists(quarantinePath))
                            File.Delete(quarantinePath);
                        
                        if (File.Exists(metadataPath))
                            File.Delete(metadataPath);

                        throw;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _logManager.LogError($"Error al poner archivo en cuarentena {filePath}: {ex}", "QuarantineManager");
            }

            return result;
        }

        /// <summary>
        /// Restaura un archivo desde cuarentena
        /// </summary>
        public bool RestoreFromQuarantine(string quarantineId)
        {
            try
            {
                if (!_quarantineIndex.TryGetValue(quarantineId, out var entry))
                {
                    _logManager.LogWarning($"Entrada de cuarentena no encontrada: {quarantineId}", "QuarantineManager");
                    return false;
                }

                if (!entry.CanRestore)
                {
                    _logManager.LogWarning($"Archivo no puede ser restaurado: {quarantineId}", "QuarantineManager");
                    return false;
                }

                lock (_lockObject)
                {
                    string quarantinePath = entry.QuarantinePath;
                    string metadataPath = Path.Combine(_quarantineDirectory, quarantineId + ".meta");

                    if (!File.Exists(quarantinePath))
                    {
                        _logManager.LogError($"Archivo de cuarentena no encontrado: {quarantinePath}", "QuarantineManager");
                        return false;
                    }

                    try
                    {
                        // Leer archivo cifrado
                        byte[] encryptedData = File.ReadAllBytes(quarantinePath);

                        // Descifrar archivo
                        byte[] iv = Convert.FromBase64String(entry.EncryptionIV);
                        byte[] decryptedData = _cryptoHelper.DecryptData(
                            encryptedData,
                            GetQuarantineEncryptionKey(),
                            iv
                        );

                        // Verificar hash
                        string restoredHash = _cryptoHelper.CalculateDataHash(decryptedData, HashAlgorithmType.SHA256);
                        if (restoredHash != entry.FileHash)
                        {
                            _logManager.LogCritical(
                                $"HASH MISMATCH al restaurar {quarantineId}: esperado {entry.FileHash}, obtenido {restoredHash}",
                                "QuarantineManager"
                            );
                            return false;
                        }

                        // Crear directorio si no existe
                        string directory = Path.GetDirectoryName(entry.OriginalPath);
                        if (!Directory.Exists(directory))
                        {
                            Directory.CreateDirectory(directory);
                        }

                        // Restaurar archivo
                        File.WriteAllBytes(entry.OriginalPath, decryptedData);

                        // Restaurar atributos del archivo
                        var fileInfo = new FileInfo(entry.OriginalPath);
                        fileInfo.CreationTimeUtc = entry.OriginalCreationTime;
                        fileInfo.LastWriteTimeUtc = entry.OriginalLastWriteTime;
                        fileInfo.LastAccessTimeUtc = entry.OriginalLastAccessTime;
                        fileInfo.Attributes = entry.FileAttributes;

                        // Eliminar archivos de cuarentena
                        File.Delete(quarantinePath);
                        if (File.Exists(metadataPath))
                            File.Delete(metadataPath);

                        // Actualizar entrada
                        entry.RestoredAt = DateTime.UtcNow;
                        entry.CanRestore = false;

                        // Remover del índice
                        _quarantineIndex.TryRemove(quarantineId, out _);

                        // Guardar índice actualizado
                        SaveQuarantineIndex();

                        // Actualizar base de datos
                        _localDatabase.UpdateQuarantineEntry(entry);

                        _logManager.LogInfo(
                            $"Archivo restaurado desde cuarentena: {quarantineId} -> {entry.OriginalPath}",
                            "QuarantineManager"
                        );

                        return true;
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error al restaurar archivo {quarantineId}: {ex}", "QuarantineManager");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en RestoreFromQuarantine {quarantineId}: {ex}", "QuarantineManager");
                return false;
            }
        }

        /// <summary>
        /// Elimina permanentemente un archivo de cuarentena
        /// </summary>
        public bool DeleteFromQuarantine(string quarantineId)
        {
            try
            {
                if (!_quarantineIndex.TryGetValue(quarantineId, out var entry))
                {
                    _logManager.LogWarning($"Entrada de cuarentena no encontrada: {quarantineId}", "QuarantineManager");
                    return false;
                }

                lock (_lockObject)
                {
                    string quarantinePath = entry.QuarantinePath;
                    string metadataPath = Path.Combine(_quarantineDirectory, quarantineId + ".meta");

                    // Eliminar archivos
                    if (File.Exists(quarantinePath))
                        File.Delete(quarantinePath);

                    if (File.Exists(metadataPath))
                        File.Delete(metadataPath);

                    // Actualizar entrada
                    entry.DeletedAt = DateTime.UtcNow;
                    entry.CanRestore = false;

                    // Remover del índice
                    _quarantineIndex.TryRemove(quarantineId, out _);

                    // Guardar índice actualizado
                    SaveQuarantineIndex();

                    // Actualizar base de datos
                    _localDatabase.UpdateQuarantineEntry(entry);

                    _logManager.LogInfo(
                        $"Archivo eliminado permanentemente de cuarentena: {quarantineId}",
                        "QuarantineManager"
                    );

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al eliminar de cuarentena {quarantineId}: {ex}", "QuarantineManager");
                return false;
            }
        }

        /// <summary>
        /// Obtiene información de un archivo en cuarentena
        /// </summary>
        public QuarantineEntry GetQuarantineInfo(string quarantineId)
        {
            _quarantineIndex.TryGetValue(quarantineId, out var entry);
            return entry;
        }

        /// <summary>
        /// Lista todos los archivos en cuarentena
        /// </summary>
        public List<QuarantineEntry> ListQuarantinedFiles()
        {
            return _quarantineIndex.Values.OrderByDescending(e => e.QuarantinedAt).ToList();
        }

        /// <summary>
        /// Obtiene estadísticas de cuarentena
        /// </summary>
        public QuarantineStatistics GetStatistics()
        {
            var entries = _quarantineIndex.Values.ToList();

            return new QuarantineStatistics
            {
                TotalFiles = entries.Count,
                TotalSizeBytes = entries.Sum(e => e.FileSize),
                OldestQuarantineDate = entries.Any() ? entries.Min(e => e.QuarantinedAt) : DateTime.MinValue,
                NewestQuarantineDate = entries.Any() ? entries.Max(e => e.QuarantinedAt) : DateTime.MinValue,
                FilesCanRestore = entries.Count(e => e.CanRestore),
                QuarantineDirectoryPath = _quarantineDirectory
            };
        }

        /// <summary>
        /// Exporta archivo de cuarentena para análisis (sin descifrar)
        /// </summary>
        public bool ExportQuarantineFile(string quarantineId, string exportPath)
        {
            try
            {
                if (!_quarantineIndex.TryGetValue(quarantineId, out var entry))
                {
                    _logManager.LogWarning($"Entrada de cuarentena no encontrada: {quarantineId}", "QuarantineManager");
                    return false;
                }

                string quarantinePath = entry.QuarantinePath;
                if (!File.Exists(quarantinePath))
                {
                    _logManager.LogError($"Archivo de cuarentena no encontrado: {quarantinePath}", "QuarantineManager");
                    return false;
                }

                // Copiar archivo cifrado (para análisis externo)
                File.Copy(quarantinePath, exportPath, true);

                _logManager.LogInfo($"Archivo de cuarentena exportado: {quarantineId} -> {exportPath}", "QuarantineManager");
                return true;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al exportar archivo de cuarentena {quarantineId}: {ex}", "QuarantineManager");
                return false;
            }
        }

        #region Helper Methods

        private string GenerateQuarantineId()
        {
            return $"QTN_{DateTime.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid().ToString("N").Substring(0, 8)}";
        }

        private byte[] GetQuarantineEncryptionKey()
        {
            // En producción, usar clave derivada de certificado del sistema
            // Por ahora, usar clave generada en instalación
            string keyMaterial = $"{Environment.MachineName}_BWP_QUARANTINE_KEY";
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(keyMaterial));
            }
        }

        private bool HasSufficientSpace(long requiredBytes)
        {
            try
            {
                // Obtener tamaño actual de cuarentena
                long currentSize = _quarantineIndex.Values.Sum(e => e.FileSize);
                long maxSizeBytes = (long)MAX_QUARANTINE_SIZE_GB * 1024 * 1024 * 1024;

                return (currentSize + requiredBytes) <= maxSizeBytes;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al verificar espacio de cuarentena: {ex}", "QuarantineManager");
                return false;
            }
        }

        private void SetRestrictivePermissions(string path)
        {
            try
            {
                // En producción, establecer permisos ACL restrictivos
                // Solo SYSTEM y Administrators
                var dirInfo = new DirectoryInfo(path);
                dirInfo.Attributes = FileAttributes.Directory | FileAttributes.Hidden | FileAttributes.System;
            }
            catch (Exception ex)
            {
                _logManager.LogWarning($"No se pudieron establecer permisos restrictivos en {path}: {ex.Message}", "QuarantineManager");
            }
        }

        private void LoadQuarantineIndex()
        {
            try
            {
                if (File.Exists(_metadataFile))
                {
                    string json = File.ReadAllText(_metadataFile);
                    var entries = JsonConvert.DeserializeObject<List<QuarantineEntry>>(json);

                    if (entries != null)
                    {
                        foreach (var entry in entries.Where(e => e.CanRestore))
                        {
                            _quarantineIndex[entry.QuarantineId] = entry;
                        }

                        _logManager.LogInfo($"Índice de cuarentena cargado: {_quarantineIndex.Count} entradas", "QuarantineManager");
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar índice de cuarentena: {ex}", "QuarantineManager");
            }
        }

        private void SaveQuarantineIndex()
        {
            try
            {
                var entries = _quarantineIndex.Values.ToList();
                string json = JsonConvert.SerializeObject(entries, Formatting.Indented);
                File.WriteAllText(_metadataFile, json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al guardar índice de cuarentena: {ex}", "QuarantineManager");
            }
        }

        private void CleanupTimerCallback(object state)
        {
            try
            {
                _logManager.LogInfo("Iniciando limpieza de cuarentena...", "QuarantineManager");

                int deletedCount = 0;
                var cutoffDate = DateTime.UtcNow.AddDays(-RETENTION_DAYS);

                var entriesToDelete = _quarantineIndex.Values
                    .Where(e => e.QuarantinedAt < cutoffDate)
                    .Select(e => e.QuarantineId)
                    .ToList();

                foreach (var quarantineId in entriesToDelete)
                {
                    if (DeleteFromQuarantine(quarantineId))
                    {
                        deletedCount++;
                    }
                }

                if (deletedCount > 0)
                {
                    _logManager.LogInfo(
                        $"Limpieza de cuarentena completada: {deletedCount} archivos eliminados (> {RETENTION_DAYS} días)",
                        "QuarantineManager"
                    );
                }

                // Limpiar archivos huérfanos (sin entrada en índice)
                CleanupOrphanedFiles();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en limpieza de cuarentena: {ex}", "QuarantineManager");
            }
        }

        private void CleanupOrphanedFiles()
        {
            try
            {
                var quarantineFiles = Directory.GetFiles(_quarantineDirectory, "*.qtn");
                int orphanedCount = 0;

                foreach (var file in quarantineFiles)
                {
                    string fileName = Path.GetFileNameWithoutExtension(file);
                    
                    if (!_quarantineIndex.ContainsKey(fileName))
                    {
                        // Archivo huérfano, eliminar
                        File.Delete(file);
                        
                        string metaFile = Path.ChangeExtension(file, ".meta");
                        if (File.Exists(metaFile))
                            File.Delete(metaFile);

                        orphanedCount++;
                    }
                }

                if (orphanedCount > 0)
                {
                    _logManager.LogInfo(
                        $"Archivos huérfanos eliminados de cuarentena: {orphanedCount}",
                        "QuarantineManager"
                    );
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al limpiar archivos huérfanos: {ex}", "QuarantineManager");
            }
        }

        /// <summary>
        /// Verifica la integridad de todos los archivos en cuarentena
        /// </summary>
        public async Task<QuarantineIntegrityReport> VerifyIntegrityAsync()
        {
            var report = new QuarantineIntegrityReport
            {
                VerificationStarted = DateTime.UtcNow,
                TotalFiles = _quarantineIndex.Count
            };

            await Task.Run(() =>
            {
                foreach (var entry in _quarantineIndex.Values)
                {
                    try
                    {
                        if (!File.Exists(entry.QuarantinePath))
                        {
                            report.MissingFiles.Add(entry.QuarantineId);
                            continue;
                        }

                        // Leer archivo cifrado
                        byte[] encryptedData = File.ReadAllBytes(entry.QuarantinePath);

                        // Descifrar
                        byte[] iv = Convert.FromBase64String(entry.EncryptionIV);
                        byte[] decryptedData = _cryptoHelper.DecryptData(
                            encryptedData,
                            GetQuarantineEncryptionKey(),
                            iv
                        );

                        // Verificar hash
                        string currentHash = _cryptoHelper.CalculateDataHash(decryptedData, HashAlgorithmType.SHA256);

                        if (currentHash != entry.FileHash)
                        {
                            report.CorruptedFiles.Add(entry.QuarantineId);
                        }
                        else
                        {
                            report.IntactFiles++;
                        }
                    }
                    catch (Exception ex)
                    {
                        report.ErrorFiles.Add(entry.QuarantineId, ex.Message);
                    }
                }

                report.VerificationCompleted = DateTime.UtcNow;
                report.Duration = report.VerificationCompleted - report.VerificationStarted;
            });

            _logManager.LogInfo(
                $"Verificación de integridad completada: {report.IntactFiles}/{report.TotalFiles} OK, " +
                $"{report.CorruptedFiles.Count} corruptos, {report.MissingFiles.Count} faltantes",
                "QuarantineManager"
            );

            return report;
        }

        /// <summary>
        /// Busca archivos en cuarentena por criterios
        /// </summary>
        public List<QuarantineEntry> SearchQuarantine(QuarantineSearchCriteria criteria)
        {
            var results = _quarantineIndex.Values.AsEnumerable();

            if (!string.IsNullOrEmpty(criteria.FileName))
            {
                results = results.Where(e => 
                    e.OriginalFileName.Contains(criteria.FileName, StringComparison.OrdinalIgnoreCase)
                );
            }

            if (!string.IsNullOrEmpty(criteria.FilePath))
            {
                results = results.Where(e => 
                    e.OriginalPath.Contains(criteria.FilePath, StringComparison.OrdinalIgnoreCase)
                );
            }

            if (!string.IsNullOrEmpty(criteria.FileHash))
            {
                results = results.Where(e => 
                    e.FileHash.Equals(criteria.FileHash, StringComparison.OrdinalIgnoreCase)
                );
            }

            if (criteria.QuarantinedAfter.HasValue)
            {
                results = results.Where(e => e.QuarantinedAt >= criteria.QuarantinedAfter.Value);
            }

            if (criteria.QuarantinedBefore.HasValue)
            {
                results = results.Where(e => e.QuarantinedAt <= criteria.QuarantinedBefore.Value);
            }

            if (criteria.MinFileSize.HasValue)
            {
                results = results.Where(e => e.FileSize >= criteria.MinFileSize.Value);
            }

            if (criteria.MaxFileSize.HasValue)
            {
                results = results.Where(e => e.FileSize <= criteria.MaxFileSize.Value);
            }

            if (criteria.CanRestoreOnly)
            {
                results = results.Where(e => e.CanRestore);
            }

            return results.OrderByDescending(e => e.QuarantinedAt).ToList();
        }

        #endregion

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
            SaveQuarantineIndex();
        }
    }

    #region Data Models

    public class QuarantineResult
    {
        public bool Success { get; set; }
        public string QuarantineId { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class QuarantineEntry
    {
        public string QuarantineId { get; set; }
        public string OriginalPath { get; set; }
        public string OriginalFileName { get; set; }
        public string QuarantinePath { get; set; }
        public string FileHash { get; set; }
        public long FileSize { get; set; }
        public DateTime QuarantinedAt { get; set; }
        public string Reason { get; set; }
        public DateTime OriginalCreationTime { get; set; }
        public DateTime OriginalLastWriteTime { get; set; }
        public DateTime OriginalLastAccessTime { get; set; }
        public FileAttributes FileAttributes { get; set; }
        public string EncryptionIV { get; set; }
        public bool CanRestore { get; set; }
        public DateTime? RestoredAt { get; set; }
        public DateTime? DeletedAt { get; set; }
    }

    public class QuarantineStatistics
    {
        public int TotalFiles { get; set; }
        public long TotalSizeBytes { get; set; }
        public DateTime OldestQuarantineDate { get; set; }
        public DateTime NewestQuarantineDate { get; set; }
        public int FilesCanRestore { get; set; }
        public string QuarantineDirectoryPath { get; set; }

        public double TotalSizeMB => TotalSizeBytes / (1024.0 * 1024.0);
        public double TotalSizeGB => TotalSizeBytes / (1024.0 * 1024.0 * 1024.0);
    }

    public class QuarantineIntegrityReport
    {
        public DateTime VerificationStarted { get; set; }
        public DateTime VerificationCompleted { get; set; }
        public TimeSpan Duration { get; set; }
        public int TotalFiles { get; set; }
        public int IntactFiles { get; set; }
        public List<string> CorruptedFiles { get; set; } = new List<string>();
        public List<string> MissingFiles { get; set; } = new List<string>();
        public Dictionary<string, string> ErrorFiles { get; set; } = new Dictionary<string, string>();

        public bool AllFilesIntact => CorruptedFiles.Count == 0 && MissingFiles.Count == 0 && ErrorFiles.Count == 0;
        public double IntegrityPercentage => TotalFiles > 0 ? (IntactFiles * 100.0 / TotalFiles) : 100.0;
    }

    public class QuarantineSearchCriteria
    {
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public string FileHash { get; set; }
        public DateTime? QuarantinedAfter { get; set; }
        public DateTime? QuarantinedBefore { get; set; }
        public long? MinFileSize { get; set; }
        public long? MaxFileSize { get; set; }
        public bool CanRestoreOnly { get; set; }
    }

    #endregion
}