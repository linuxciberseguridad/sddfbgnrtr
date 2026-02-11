#include "pch.h"
#include "FileSystemDriver.h"
#include <windows.h>
#include <fltuser.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>

#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace BWP {
namespace Enterprise {
namespace Drivers {

// Constantes
constexpr wchar_t DRIVER_NAME[] = L"BWPFileSystemMonitor";
constexpr wchar_t DRIVER_DISPLAY_NAME[] = L"BWP Enterprise File System Monitor Driver";
constexpr wchar_t DRIVER_PATH[] = L"%SystemRoot%\\System32\\drivers\\BWPFileMon.sys";
constexpr DWORD DRIVER_CONTROL_ADD_PATH = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_REMOVE_PATH = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_START = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_STOP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD MESSAGE_BUFFER_SIZE = 8192;

FileSystemDriver::FileSystemDriver() :
    m_hPort(nullptr),
    m_hCompletion(nullptr),
    m_hDriver(INVALID_HANDLE_VALUE),
    m_isInitialized(false),
    m_isMonitoring(false),
    m_hWorkerThread(nullptr),
    m_minFileSize(0)
{
    InitializeCriticalSection(&m_csLock);
    ZeroMemory(&m_stats, sizeof(m_stats));
    GetSystemTimeAsFileTime(&m_stats.StartTime);
    m_stats.LastEventTime = m_stats.StartTime;
}

FileSystemDriver::~FileSystemDriver()
{
    Cleanup();
    DeleteCriticalSection(&m_csLock);
}

bool FileSystemDriver::Initialize()
{
    EnterCriticalSection(&m_csLock);

    if (m_isInitialized)
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }

    try
    {
        LogInfo(L"Inicializando FileSystemDriver...");

        // 1. Instalar driver si no está instalado
        if (!IsDriverLoaded())
        {
            if (!InstallDriver())
            {
                LogError(L"No se pudo instalar el driver");
                LeaveCriticalSection(&m_csLock);
                return false;
            }
        }

        // 2. Cargar driver
        if (!LoadDriver())
        {
            LogError(L"No se pudo cargar el driver");
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // 3. Conectar al driver
        if (!ConnectToDriver())
        {
            LogError(L"No se pudo conectar al driver");
            UnloadDriver();
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // 4. Configurar paths de monitoreo por defecto
        AddDefaultMonitorPaths();

        m_isInitialized = true;
        LogInfo(L"FileSystemDriver inicializado exitosamente");

        LeaveCriticalSection(&m_csLock);
        return true;
    }
    catch (...)
    {
        LogError(L"Excepción durante inicialización");
        LeaveCriticalSection(&m_csLock);
        return false;
    }
}

void FileSystemDriver::Cleanup()
{
    EnterCriticalSection(&m_csLock);

    try
    {
        if (m_isMonitoring)
        {
            StopMonitoring();
        }

        if (m_isInitialized)
        {
            DisconnectFromDriver();
            UnloadDriver();
            m_isInitialized = false;
        }

        if (m_hWorkerThread)
        {
            CloseHandle(m_hWorkerThread);
            m_hWorkerThread = nullptr;
        }

        ClearMonitorPaths();
        LogInfo(L"FileSystemDriver limpiado");
    }
    catch (...)
    {
        LogError(L"Excepción durante limpieza");
    }

    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RegisterFileOperationCallback(FileOperationCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_fileOperationCallback = callback;
    m_fileOperationContext = context;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RegisterFileCreateCallback(
    std::function<void(DWORD, const std::wstring&, PVOID)> callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_fileCreateCallback = callback;
    m_fileCreateContext = context;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RegisterFileDeleteCallback(
    std::function<void(DWORD, const std::wstring&, PVOID)> callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_fileDeleteCallback = callback;
    m_fileDeleteContext = context;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RegisterFileRenameCallback(
    std::function<void(DWORD, const std::wstring&, const std::wstring&, PVOID)> callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_fileRenameCallback = callback;
    m_fileRenameContext = context;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RegisterFileWriteCallback(
    std::function<void(DWORD, const std::wstring&, DWORD, PVOID)> callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_fileWriteCallback = callback;
    m_fileWriteContext = context;
    LeaveCriticalSection(&m_csLock);
}

bool FileSystemDriver::StartMonitoring()
{
    EnterCriticalSection(&m_csLock);

    if (!m_isInitialized || m_isMonitoring)
    {
        LeaveCriticalSection(&m_csLock);
        return false;
    }

    try
    {
        // Enviar comando de inicio al driver
        if (!SendControlCode(DRIVER_CONTROL_START))
        {
            LogError(L"No se pudo iniciar monitoreo en el driver");
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // Enviar paths de monitoreo al driver
        for (const auto& path : m_monitorPaths)
        {
            SendControlCode(DRIVER_CONTROL_ADD_PATH, (void*)path.c_str(), 
                          (DWORD)(path.length() + 1) * sizeof(wchar_t));
        }

        // Crear hilo de trabajo
        m_hWorkerThread = CreateThread(
            nullptr,
            0,
            WorkerThreadProc,
            this,
            0,
            nullptr
        );

        if (!m_hWorkerThread)
        {
            LogError(L"No se pudo crear hilo de trabajo. Error: %lu", GetLastError());
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        m_isMonitoring = true;
        LogInfo(L"Monitoreo de sistema de archivos iniciado");

        LeaveCriticalSection(&m_csLock);
        return true;
    }
    catch (...)
    {
        LogError(L"Excepción al iniciar monitoreo");
        LeaveCriticalSection(&m_csLock);
        return false;
    }
}

bool FileSystemDriver::StopMonitoring()
{
    EnterCriticalSection(&m_csLock);

    if (!m_isMonitoring)
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }

    try
    {
        m_isMonitoring = false;

        // Enviar comando de parada al driver
        SendControlCode(DRIVER_CONTROL_STOP);

        // Esperar a que termine el hilo de trabajo
        if (m_hWorkerThread)
        {
            WaitForSingleObject(m_hWorkerThread, 5000);
            CloseHandle(m_hWorkerThread);
            m_hWorkerThread = nullptr;
        }

        LogInfo(L"Monitoreo de sistema de archivos detenido");

        LeaveCriticalSection(&m_csLock);
        return true;
    }
    catch (...)
    {
        LogError(L"Excepción al detener monitoreo");
        LeaveCriticalSection(&m_csLock);
        return false;
    }
}

bool FileSystemDriver::IsMonitoring() const
{
    return m_isMonitoring;
}

void FileSystemDriver::AddMonitorPath(const std::wstring& path)
{
    EnterCriticalSection(&m_csLock);
    
    // Verificar si ya existe
    auto it = std::find(m_monitorPaths.begin(), m_monitorPaths.end(), path);
    if (it == m_monitorPaths.end())
    {
        m_monitorPaths.push_back(path);
        
        // Si estamos monitoreando, enviar al driver
        if (m_isMonitoring && m_isInitialized)
        {
            SendControlCode(DRIVER_CONTROL_ADD_PATH, (void*)path.c_str(), 
                          (DWORD)(path.length() + 1) * sizeof(wchar_t));
        }
        
        LogInfo(L"Path agregado para monitoreo: %ls", path.c_str());
    }
    
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::RemoveMonitorPath(const std::wstring& path)
{
    EnterCriticalSection(&m_csLock);
    
    auto it = std::find(m_monitorPaths.begin(), m_monitorPaths.end(), path);
    if (it != m_monitorPaths.end())
    {
        m_monitorPaths.erase(it);
        
        // Si estamos monitoreando, enviar al driver
        if (m_isMonitoring && m_isInitialized)
        {
            SendControlCode(DRIVER_CONTROL_REMOVE_PATH, (void*)path.c_str(), 
                          (DWORD)(path.length() + 1) * sizeof(wchar_t));
        }
        
        LogInfo(L"Path removido del monitoreo: %ls", path.c_str());
    }
    
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::ClearMonitorPaths()
{
    EnterCriticalSection(&m_csLock);
    
    // Remover todos los paths del driver si estamos monitoreando
    if (m_isMonitoring && m_isInitialized)
    {
        for (const auto& path : m_monitorPaths)
        {
            SendControlCode(DRIVER_CONTROL_REMOVE_PATH, (void*)path.c_str(), 
                          (DWORD)(path.length() + 1) * sizeof(wchar_t));
        }
    }
    
    m_monitorPaths.clear();
    LeaveCriticalSection(&m_csLock);
}

std::vector<std::wstring> FileSystemDriver::GetMonitorPaths() const
{
    EnterCriticalSection(&m_csLock);
    std::vector<std::wstring> paths = m_monitorPaths;
    LeaveCriticalSection(&m_csLock);
    return paths;
}

void FileSystemDriver::SetMinFileSizeFilter(DWORD minSizeBytes)
{
    EnterCriticalSection(&m_csLock);
    m_minFileSize = minSizeBytes;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::SetFileExtensionFilter(const std::vector<std::wstring>& extensions)
{
    EnterCriticalSection(&m_csLock);
    m_fileExtensions = extensions;
    LeaveCriticalSection(&m_csLock);
}

void FileSystemDriver::SetProcessFilter(const std::vector<DWORD>& processIds)
{
    EnterCriticalSection(&m_csLock);
    m_processFilter = processIds;
    LeaveCriticalSection(&m_csLock);
}

bool FileSystemDriver::FileExists(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring FileSystemDriver::GetFileOwner(const std::wstring& path)
{
    std::wstring owner;
    
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD dwError = GetNamedSecurityInfoW(
        path.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &pSD
    );
    
    if (dwError == ERROR_SUCCESS && pSD)
    {
        PSID pOwner = nullptr;
        BOOL bOwnerDefaulted = FALSE;
        
        if (GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted) && pOwner)
        {
            LPWSTR sidString = nullptr;
            if (ConvertSidToStringSidW(pOwner, &sidString))
            {
                owner = sidString;
                LocalFree(sidString);
            }
        }
        
        LocalFree(pSD);
    }
    
    return owner;
}

FILETIME FileSystemDriver::GetFileCreationTime(const std::wstring& path)
{
    FILETIME creationTime = {0};
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile != INVALID_HANDLE_VALUE)
    {
        FILETIME ftCreate, ftAccess, ftWrite;
        if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
        {
            creationTime = ftCreate;
        }
        CloseHandle(hFile);
    }
    
    return creationTime;
}

FILETIME FileSystemDriver::GetFileLastWriteTime(const std::wstring& path)
{
    FILETIME lastWriteTime = {0};
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile != INVALID_HANDLE_VALUE)
    {
        FILETIME ftCreate, ftAccess, ftWrite;
        if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
        {
            lastWriteTime = ftWrite;
        }
        CloseHandle(hFile);
    }
    
    return lastWriteTime;
}

DWORD FileSystemDriver::GetFileSize(const std::wstring& path)
{
    DWORD fileSize = 0;
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile != INVALID_HANDLE_VALUE)
    {
        fileSize = GetFileSize(hFile, nullptr);
        CloseHandle(hFile);
    }
    
    return fileSize;
}

std::wstring FileSystemDriver::CalculateFileHash(const std::wstring& path)
{
    std::wstring hash;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE)
        return hash;
    
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return hash;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return hash;
    }
    
    BYTE buffer[4096];
    DWORD bytesRead = 0;
    
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
    {
        if (!CryptHashData(hHash, buffer, bytesRead, 0))
            break;
    }
    
    DWORD hashSize = 0;
    DWORD hashSizeSize = sizeof(hashSize);
    
    if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0))
    {
        std::vector<BYTE> hashBytes(hashSize);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0))
        {
            std::wstringstream ss;
            ss << std::hex << std::setfill(L'0');
            for (BYTE b : hashBytes)
            {
                ss << std::setw(2) << static_cast<int>(b);
            }
            hash = ss.str();
        }
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    
    return hash;
}

bool FileSystemDriver::IsFileEncrypted(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return false;
    
    return (attrs & FILE_ATTRIBUTE_ENCRYPTED) != 0;
}

bool FileSystemDriver::IsFileHidden(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return false;
    
    return (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
}

bool FileSystemDriver::IsFileSystemFile(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return false;
    
    return (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
}

FileSystemDriver::Statistics FileSystemDriver::GetStatistics() const
{
    EnterCriticalSection(&m_csLock);
    Statistics stats = m_stats;
    LeaveCriticalSection(&m_csLock);
    return stats;
}

// Hilo de trabajo
DWORD WINAPI FileSystemDriver::WorkerThreadProc(LPVOID lpParameter)
{
    FileSystemDriver* pDriver = reinterpret_cast<FileSystemDriver*>(lpParameter);
    return pDriver->WorkerThread();
}

DWORD FileSystemDriver::WorkerThread()
{
    LogInfo(L"Hilo de trabajo de FileSystemDriver iniciado");

    while (m_isMonitoring)
    {
        try
        {
            // Leer mensajes del puerto de filtro
            BYTE buffer[MESSAGE_BUFFER_SIZE];
            DWORD bytesReturned = 0;
            HRESULT hr = FilterGetMessage(
                m_hPort,
                reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer),
                MESSAGE_BUFFER_SIZE,
                nullptr
            );

            if (SUCCEEDED(hr))
            {
                ProcessMessage(buffer, bytesReturned);
                InterlockedIncrement(&m_stats.CallbacksProcessed);
                GetSystemTimeAsFileTime(&m_stats.LastEventTime);
            }
            else if (hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                LogError(L"Error leyendo mensajes del filtro: 0x%08X", hr);
                Sleep(100);
            }
            else
            {
                Sleep(10); // No hay mensajes, dormir brevemente
            }
        }
        catch (...)
        {
            LogError(L"Excepción en hilo de trabajo");
            Sleep(100);
        }
    }

    LogInfo(L"Hilo de trabajo de FileSystemDriver terminado");
    return 0;
}

bool FileSystemDriver::ProcessMessage(const void* message, DWORD messageSize)
{
    if (!message || messageSize < sizeof(FILTER_MESSAGE_HEADER))
        return false;

    auto header = reinterpret_cast<const FILTER_MESSAGE_HEADER*>(message);
    
    // Determinar tipo de mensaje basado en el tamaño
    switch (header->ReplyLength)
    {
    case sizeof(FileCreateMessage):
        HandleFileCreate(message);
        break;
    case sizeof(FileDeleteMessage):
        HandleFileDelete(message);
        break;
    case sizeof(FileRenameMessage):
        HandleFileRename(message);
        break;
    case sizeof(FileWriteMessage):
        HandleFileWrite(message);
        break;
    case sizeof(FileReadMessage):
        HandleFileRead(message);
        break;
    default:
        LogDebug(L"Mensaje desconocido del driver: tamaño %lu", header->ReplyLength);
        break;
    }

    return true;
}

void FileSystemDriver::HandleFileCreate(const void* message)
{
    auto msg = reinterpret_cast<const FileCreateMessage*>(message);
    
    std::wstring filePath(msg->FilePath);
    std::wstring processName(msg->ProcessName);
    
    // Verificar si debemos procesar este evento
    if (!ShouldProcessEvent(msg->ProcessId, filePath, FILE_CREATE))
        return;
    
    EnterCriticalSection(&m_csLock);
    
    // Callback general
    if (m_fileOperationCallback)
    {
        try
        {
            m_fileOperationCallback(
                msg->ProcessId,
                filePath,
                FILE_CREATE,
                m_fileOperationContext
            );
        }
        catch (...) {}
    }
    
    // Callback específico
    if (m_fileCreateCallback)
    {
        try
        {
            m_fileCreateCallback(
                msg->ProcessId,
                filePath,
                m_fileCreateContext
            );
        }
        catch (...) {}
    }
    
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.FilesCreated);
    LogDebug(L"Archivo creado: PID=%lu, Path=%ls", 
        msg->ProcessId, filePath.c_str());
}

void FileSystemDriver::HandleFileDelete(const void* message)
{
    auto msg = reinterpret_cast<const FileDeleteMessage*>(message);
    
    std::wstring filePath(msg->FilePath);
    std::wstring processName(msg->ProcessName);
    
    if (!ShouldProcessEvent(msg->ProcessId, filePath, FILE_DELETE))
        return;
    
    EnterCriticalSection(&m_csLock);
    
    if (m_fileOperationCallback)
    {
        try
        {
            m_fileOperationCallback(
                msg->ProcessId,
                filePath,
                FILE_DELETE,
                m_fileOperationContext
            );
        }
        catch (...) {}
    }
    
    if (m_fileDeleteCallback)
    {
        try
        {
            m_fileDeleteCallback(
                msg->ProcessId,
                filePath,
                m_fileDeleteContext
            );
        }
        catch (...) {}
    }
    
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.FilesDeleted);
    LogDebug(L"Archivo eliminado: PID=%lu, Path=%ls", 
        msg->ProcessId, filePath.c_str());
}

void FileSystemDriver::HandleFileRename(const void* message)
{
    auto msg = reinterpret_cast<const FileRenameMessage*>(message);
    
    std::wstring oldPath(msg->OldFilePath);
    std::wstring newPath(msg->NewFilePath);
    std::wstring processName(msg->ProcessName);
    
    // Verificar ambos paths
    if (!ShouldProcessEvent(msg->ProcessId, oldPath, FILE_RENAME) &&
        !ShouldProcessEvent(msg->ProcessId, newPath, FILE_RENAME))
        return;
    
    EnterCriticalSection(&m_csLock);
    
    if (m_fileOperationCallback)
    {
        try
        {
            m_fileOperationCallback(
                msg->ProcessId,
                oldPath,
                FILE_RENAME,
                m_fileOperationContext
            );
        }
        catch (...) {}
    }
    
    if (m_fileRenameCallback)
    {
        try
        {
            m_fileRenameCallback(
                msg->ProcessId,
                oldPath,
                newPath,
                m_fileRenameContext
            );
        }
        catch (...) {}
    }
    
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.FilesRenamed);
    LogDebug(L"Archivo renombrado: PID=%lu, Old=%ls, New=%ls", 
        msg->ProcessId, oldPath.c_str(), newPath.c_str());
}

void FileSystemDriver::HandleFileWrite(const void* message)
{
    auto msg = reinterpret_cast<const FileWriteMessage*>(message);
    
    std::wstring filePath(msg->FilePath);
    std::wstring processName(msg->ProcessName);
    
    if (!ShouldProcessEvent(msg->ProcessId, filePath, FILE_WRITE))
        return;
    
    EnterCriticalSection(&m_csLock);
    
    if (m_fileOperationCallback)
    {
        try
        {
            m_fileOperationCallback(
                msg->ProcessId,
                filePath,
                FILE_WRITE,
                m_fileOperationContext
            );
        }
        catch (...) {}
    }
    
    if (m_fileWriteCallback)
    {
        try
        {
            m_fileWriteCallback(
                msg->ProcessId,
                filePath,
                msg->Length,
                m_fileWriteContext
            );
        }
        catch (...) {}
    }
    
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.FilesModified);
    LogDebug(L"Archivo escrito: PID=%lu, Path=%ls, Bytes=%lu", 
        msg->ProcessId, filePath.c_str(), msg->Length);
}

void FileSystemDriver::HandleFileRead(const void* message)
{
    auto msg = reinterpret_cast<const FileReadMessage*>(message);
    
    std::wstring filePath(msg->FilePath);
    std::wstring processName(msg->ProcessName);
    
    if (!ShouldProcessEvent(msg->ProcessId, filePath, FILE_READ))
        return;
    
    EnterCriticalSection(&m_csLock);
    
    if (m_fileOperationCallback)
    {
        try
        {
            m_fileOperationCallback(
                msg->ProcessId,
                filePath,
                FILE_READ,
                m_fileOperationContext
            );
        }
        catch (...) {}
    }
    
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.FilesRead);
    LogDebug(L"Archivo leído: PID=%lu, Path=%ls, Bytes=%lu", 
        msg->ProcessId, filePath.c_str(), msg->Length);
}

void FileSystemDriver::AddDefaultMonitorPaths()
{
    // Directorios críticos del sistema
    std::vector<std::wstring> defaultPaths = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\Users",
        L"C:\\ProgramData"
    };

    for (const auto& path : defaultPaths)
    {
        AddMonitorPath(path);
    }
}

bool FileSystemDriver::ConnectToDriver()
{
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\BWPFileSystemPort",
        0,
        nullptr,
        0,
        nullptr,
        &m_hPort
    );

    if (FAILED(hr))
    {
        LogError(L"No se pudo conectar al puerto del filtro: 0x%08X", hr);
        return false;
    }

    // Crear puerto de finalización
    m_hCompletion = CreateIoCompletionPort(
        m_hPort,
        nullptr,
        0,
        1
    );

    if (!m_hCompletion)
    {
        LogError(L"No se pudo crear puerto de finalización: %lu", GetLastError());
        CloseHandle(m_hPort);
        m_hPort = nullptr;
        return false;
    }

    return true;
}

bool FileSystemDriver::DisconnectFromDriver()
{
    if (m_hCompletion)
    {
        CloseHandle(m_hCompletion);
        m_hCompletion = nullptr;
    }

    if (m_hPort)
    {
        CloseHandle(m_hPort);
        m_hPort = nullptr;
    }

    if (m_hDriver != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hDriver);
        m_hDriver = INVALID_HANDLE_VALUE;
    }

    return true;
}

bool FileSystemDriver::SendControlCode(DWORD controlCode, void* input, DWORD inputSize,
                                      void* output, DWORD outputSize)
{
    if (m_hDriver == INVALID_HANDLE_VALUE)
    {
        // Abrir handle al driver
        m_hDriver = CreateFileW(
            L"\\\\.\\BWPFileSystemMonitor",
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (m_hDriver == INVALID_HANDLE_VALUE)
        {
            LogError(L"No se pudo abrir handle al driver: %lu", GetLastError());
            return false;
        }
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        m_hDriver,
        controlCode,
        input,
        inputSize,
        output,
        outputSize,
        &bytesReturned,
        nullptr
    );

    if (!result)
    {
        LogError(L"Error enviando código de control al driver: %lu", GetLastError());
        return false;
    }

    return true;
}

bool FileSystemDriver::InstallDriver()
{
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS
    );

    if (!hSCManager)
    {
        LogError(L"No se pudo abrir Service Control Manager: %lu", GetLastError());
        return false;
    }

    bool success = false;
    SC_HANDLE hService = nullptr;

    try
    {
        // Verificar si el servicio ya existe
        hService = OpenServiceW(
            hSCManager,
            DRIVER_NAME,
            SERVICE_ALL_ACCESS
        );

        if (hService)
        {
            // Servicio ya existe
            LogInfo(L"Driver ya instalado");
            success = true;
        }
        else
        {
            // Crear nuevo servicio
            hService = CreateServiceW(
                hSCManager,
                DRIVER_NAME,
                DRIVER_DISPLAY_NAME,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                DRIVER_PATH,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            );

            if (hService)
            {
                LogInfo(L"Driver instalado exitosamente");
                success = true;
            }
            else
            {
                LogError(L"No se pudo instalar el driver: %lu", GetLastError());
            }
        }
    }
    catch (...)
    {
        LogError(L"Excepción durante instalación del driver");
    }

    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);

    return success;
}

bool FileSystemDriver::UninstallDriver()
{
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS
    );

    if (!hSCManager)
    {
        return false;
    }

    bool success = false;
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        DRIVER_NAME,
        SERVICE_ALL_ACCESS
    );

    if (hService)
    {
        // Detener servicio si está ejecutándose
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);

        // Eliminar servicio
        if (DeleteService(hService))
        {
            LogInfo(L"Driver desinstalado exitosamente");
            success = true;
        }
        else
        {
            LogError(L"No se pudo desinstalar el driver: %lu", GetLastError());
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return success;
}

bool FileSystemDriver::LoadDriver()
{
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS
    );

    if (!hSCManager)
    {
        return false;
    }

    bool success = false;
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        DRIVER_NAME,
        SERVICE_ALL_ACCESS
    );

    if (hService)
    {
        if (StartServiceW(hService, 0, nullptr))
        {
            LogInfo(L"Driver cargado exitosamente");
            success = true;
        }
        else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        {
            LogInfo(L"Driver ya está ejecutándose");
            success = true;
        }
        else
        {
            LogError(L"No se pudo cargar el driver: %lu", GetLastError());
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return success;
}

bool FileSystemDriver::UnloadDriver()
{
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS
    );

    if (!hSCManager)
    {
        return false;
    }

    bool success = false;
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        DRIVER_NAME,
        SERVICE_ALL_ACCESS
    );

    if (hService)
    {
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status))
        {
            LogInfo(L"Driver descargado exitosamente");
            success = true;
        }
        else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
        {
            LogInfo(L"Driver no estaba ejecutándose");
            success = true;
        }
        else
        {
            LogError(L"No se pudo descargar el driver: %lu", GetLastError());
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return success;
}

bool FileSystemDriver::IsDriverLoaded() const
{
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT
    );

    if (!hSCManager)
    {
        return false;
    }

    bool loaded = false;
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        DRIVER_NAME,
        SERVICE_QUERY_STATUS
    );

    if (hService)
    {
        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;

        if (QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp),
            sizeof(ssp),
            &bytesNeeded))
        {
            loaded = (ssp.dwCurrentState != SERVICE_STOPPED);
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return loaded;
}

bool FileSystemDriver::ShouldProcessEvent(DWORD processId, const std::wstring& filePath, DWORD operation) const
{
    // Verificar path monitoreado
    if (!IsPathMonitored(filePath))
        return false;

    // Verificar extensión de archivo
    if (!IsExtensionAllowed(filePath))
        return false;

    // Verificar filtro de proceso
    if (!IsProcessAllowed(processId))
        return false;

    // Verificar tamaño mínimo de archivo (si aplica)
    if (operation == FILE_WRITE || operation == FILE_CREATE)
    {
        if (!IsFileSizeRelevant(GetFileSize(filePath)))
            return false;
    }

    return true;
}

bool FileSystemDriver::IsPathMonitored(const std::wstring& filePath) const
{
    EnterCriticalSection(&m_csLock);
    
    // Si no hay paths configurados, monitorear todo
    if (m_monitorPaths.empty())
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }
    
    // Verificar si el path está dentro de algún path monitoreado
    for (const auto& monitorPath : m_monitorPaths)
    {
        // Comparación case-insensitive
        if (_wcsnicmp(filePath.c_str(), monitorPath.c_str(), monitorPath.length()) == 0)
        {
            LeaveCriticalSection(&m_csLock);
            return true;
        }
    }
    
    LeaveCriticalSection(&m_csLock);
    return false;
}

bool FileSystemDriver::IsExtensionAllowed(const std::wstring& filePath) const
{
    EnterCriticalSection(&m_csLock);
    
    // Si no hay extensiones configuradas, permitir todo
    if (m_fileExtensions.empty())
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }
    
    // Extraer extensión del archivo
    size_t dotPos = filePath.find_last_of(L'.');
    if (dotPos == std::wstring::npos)
    {
        LeaveCriticalSection(&m_csLock);
        return false; // Sin extensión
    }
    
    std::wstring extension = filePath.substr(dotPos);
    
    // Convertir a minúsculas para comparación
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    
    // Verificar si la extensión está en la lista
    for (const auto& allowedExt : m_fileExtensions)
    {
        std::wstring allowedExtLower = allowedExt;
        std::transform(allowedExtLower.begin(), allowedExtLower.end(), allowedExtLower.begin(), ::towlower);
        
        if (extension == allowedExtLower)
        {
            LeaveCriticalSection(&m_csLock);
            return true;
        }
    }
    
    LeaveCriticalSection(&m_csLock);
    return false;
}

bool FileSystemDriver::IsProcessAllowed(DWORD processId) const
{
    EnterCriticalSection(&m_csLock);
    
    // Si no hay filtro de procesos, permitir todo
    if (m_processFilter.empty())
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }
    
    // Verificar si el proceso está en la lista
    bool allowed = std::find(m_processFilter.begin(), m_processFilter.end(), processId) != m_processFilter.end();
    
    LeaveCriticalSection(&m_csLock);
    return allowed;
}

bool FileSystemDriver::IsFileSizeRelevant(DWORD fileSize) const
{
    EnterCriticalSection(&m_csLock);
    bool relevant = (m_minFileSize == 0 || fileSize >= m_minFileSize);
    LeaveCriticalSection(&m_csLock);
    return relevant;
}

void FileSystemDriver::LogError(const wchar_t* format, ...) const
{
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP FileSystemDriver ERROR] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
}

void FileSystemDriver::LogInfo(const wchar_t* format, ...) const
{
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP FileSystemDriver INFO] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
}

void FileSystemDriver::LogDebug(const wchar_t* format, ...) const
{
#ifdef _DEBUG
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP FileSystemDriver DEBUG] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
#endif
}

} // namespace Drivers
} // namespace Enterprise
} // namespace BWP