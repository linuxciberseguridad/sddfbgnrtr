#pragma once
#include <windows.h>
#include <fltuser.h>
#include <string>
#include <functional>
#include <memory>

namespace BWP {
namespace Enterprise {
namespace Drivers {

// Forward declarations
struct FileOperationInfo;

// Callback definitions
typedef std::function<void(DWORD ProcessId, const std::wstring& FilePath, 
                          DWORD Operation, PVOID Context)> FileOperationCallback_t;

/// <summary>
/// Driver de sistema de archivos para monitoreo en tiempo real
/// Detecta operaciones de archivos: creación, modificación, eliminación
/// </summary>
class FileSystemDriver {
public:
    FileSystemDriver();
    ~FileSystemDriver();

    // Operaciones de archivo
    enum FileOperation {
        FILE_CREATE = 1,
        FILE_READ = 2,
        FILE_WRITE = 3,
        FILE_DELETE = 4,
        FILE_RENAME = 5,
        FILE_SET_INFO = 6,
        FILE_SET_SECURITY = 7
    };

    // Inicialización y limpieza
    bool Initialize();
    void Cleanup();

    // Registro de callbacks
    void RegisterFileOperationCallback(FileOperationCallback_t callback, PVOID context = nullptr);
    
    // Callbacks específicos
    void RegisterFileCreateCallback(std::function<void(DWORD, const std::wstring&, PVOID)> callback, PVOID context = nullptr);
    void RegisterFileDeleteCallback(std::function<void(DWORD, const std::wstring&, PVOID)> callback, PVOID context = nullptr);
    void RegisterFileRenameCallback(std::function<void(DWORD, const std::wstring&, const std::wstring&, PVOID)> callback, PVOID context = nullptr);
    void RegisterFileWriteCallback(std::function<void(DWORD, const std::wstring&, DWORD, PVOID)> callback, PVOID context = nullptr);

    // Control del driver
    bool StartMonitoring();
    bool StopMonitoring();
    bool IsMonitoring() const;

    // Configuración
    void AddMonitorPath(const std::wstring& path);
    void RemoveMonitorPath(const std::wstring& path);
    void ClearMonitorPaths();
    std::vector<std::wstring> GetMonitorPaths() const;

    // Filtrado
    void SetMinFileSizeFilter(DWORD minSizeBytes);
    void SetFileExtensionFilter(const std::vector<std::wstring>& extensions);
    void SetProcessFilter(const std::vector<DWORD>& processIds);

    // Utilidades
    static bool FileExists(const std::wstring& path);
    static std::wstring GetFileOwner(const std::wstring& path);
    static FILETIME GetFileCreationTime(const std::wstring& path);
    static FILETIME GetFileLastWriteTime(const std::wstring& path);
    static DWORD GetFileSize(const std::wstring& path);
    static std::wstring CalculateFileHash(const std::wstring& path);
    static bool IsFileEncrypted(const std::wstring& path);
    static bool IsFileHidden(const std::wstring& path);
    static bool IsFileSystemFile(const std::wstring& path);

    // Estadísticas
    struct Statistics {
        DWORD FilesCreated;
        DWORD FilesDeleted;
        DWORD FilesModified;
        DWORD FilesRenamed;
        DWORD FilesRead;
        DWORD AccessDenied;
        DWORD CallbacksProcessed;
        DWORD Errors;
        FILETIME StartTime;
        FILETIME LastEventTime;
    };

    Statistics GetStatistics() const;

private:
    // Variables miembro
    HANDLE m_hPort;
    HANDLE m_hCompletion;
    HANDLE m_hDriver;
    bool m_isInitialized;
    bool m_isMonitoring;
    mutable CRITICAL_SECTION m_csLock;

    // Callbacks
    FileOperationCallback_t m_fileOperationCallback;
    PVOID m_fileOperationContext;
    
    std::function<void(DWORD, const std::wstring&, PVOID)> m_fileCreateCallback;
    PVOID m_fileCreateContext;
    
    std::function<void(DWORD, const std::wstring&, PVOID)> m_fileDeleteCallback;
    PVOID m_fileDeleteContext;
    
    std::function<void(DWORD, const std::wstring&, const std::wstring&, PVOID)> m_fileRenameCallback;
    PVOID m_fileRenameContext;
    
    std::function<void(DWORD, const std::wstring&, DWORD, PVOID)> m_fileWriteCallback;
    PVOID m_fileWriteContext;

    // Configuración
    std::vector<std::wstring> m_monitorPaths;
    DWORD m_minFileSize;
    std::vector<std::wstring> m_fileExtensions;
    std::vector<DWORD> m_processFilter;

    // Estadísticas
    Statistics m_stats;

    // Hilo de procesamiento
    HANDLE m_hWorkerThread;
    static DWORD WINAPI WorkerThreadProc(LPVOID lpParameter);
    DWORD WorkerThread();

    // Manejo de mensajes
    bool ProcessMessage(const void* message, DWORD messageSize);
    void HandleFileCreate(const void* message);
    void HandleFileDelete(const void* message);
    void HandleFileRename(const void* message);
    void HandleFileWrite(const void* message);
    void HandleFileRead(const void* message);
    void HandleFileSetInfo(const void* message);

    // Helpers de comunicación con driver
    bool ConnectToDriver();
    bool DisconnectFromDriver();
    bool SendControlCode(DWORD controlCode, void* input = nullptr, DWORD inputSize = 0,
                        void* output = nullptr, DWORD outputSize = 0);

    // Helpers de instalación
    bool InstallDriver();
    bool UninstallDriver();
    bool LoadDriver();
    bool UnloadDriver();
    bool IsDriverLoaded() const;

    // Filtrado de eventos
    bool ShouldProcessEvent(DWORD processId, const std::wstring& filePath, DWORD operation) const;
    bool IsPathMonitored(const std::wstring& filePath) const;
    bool IsExtensionAllowed(const std::wstring& filePath) const;
    bool IsProcessAllowed(DWORD processId) const;
    bool IsFileSizeRelevant(DWORD fileSize) const;

    // Registro de eventos
    void LogError(const wchar_t* format, ...) const;
    void LogInfo(const wchar_t* format, ...) const;
    void LogDebug(const wchar_t* format, ...) const;

    // Prevención de copia
    FileSystemDriver(const FileSystemDriver&) = delete;
    FileSystemDriver& operator=(const FileSystemDriver&) = delete;
};

/// <summary>
/// Información de operación de archivo
/// </summary>
struct FileOperationInfo {
    DWORD ProcessId;
    std::wstring ProcessName;
    std::wstring FilePath;
    std::wstring NewFilePath; // Para renombrado
    DWORD Operation;
    DWORD DesiredAccess;
    DWORD ShareMode;
    DWORD CreationDisposition;
    DWORD FlagsAndAttributes;
    HANDLE FileHandle;
    FILETIME OperationTime;
    DWORD FileSize;
    std::wstring FileOwner;
    std::wstring FileHash;
    bool AccessGranted;
    DWORD ResultStatus;
};

/// <summary>
/// Mensajes del driver de sistema de archivos
/// </summary>
#pragma pack(push, 1)
struct FileCreateMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR FilePath[1024];
    DWORD DesiredAccess;
    DWORD ShareMode;
    DWORD CreationDisposition;
    DWORD FlagsAndAttributes;
    HANDLE FileHandle;
    FILETIME OperationTime;
};

struct FileDeleteMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR FilePath[1024];
    DWORD DeleteFlags;
    FILETIME OperationTime;
};

struct FileRenameMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR OldFilePath[1024];
    WCHAR NewFilePath[1024];
    DWORD RenameFlags;
    FILETIME OperationTime;
};

struct FileWriteMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR FilePath[1024];
    HANDLE FileHandle;
    DWORD Offset;
    DWORD Length;
    FILETIME OperationTime;
};

struct FileReadMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR FilePath[1024];
    HANDLE FileHandle;
    DWORD Offset;
    DWORD Length;
    FILETIME OperationTime;
};
#pragma pack(pop)

} // namespace Drivers
} // namespace Enterprise
} // namespace BWP