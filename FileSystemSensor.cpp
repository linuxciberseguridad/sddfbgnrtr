#include "pch.h"
#include "FileSystemSensor.h"
#include "FileSystemDriver.h"
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <atomic>
#include <memory>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")

namespace BWP {
namespace Enterprise {
namespace Sensors {

// Constantes
constexpr DWORD MONITORING_INTERVAL_MS = 100;
constexpr size_t MAX_EVENT_QUEUE_SIZE = 10000;
constexpr size_t MAX_FILE_HASH_CACHE = 1000;

// Estructuras de datos
struct FileOperationInfo {
    std::wstring filePath;
    std::wstring processName;
    DWORD processId;
    std::wstring userName;
    std::wstring operationType; // CREATE, DELETE, MODIFY, RENAME
    std::wstring oldFilePath;   // Para operaciones RENAME
    LARGE_INTEGER fileSize;
    FILETIME creationTime;
    FILETIME lastAccessTime;
    FILETIME lastWriteTime;
    std::string fileHash;       // SHA256 del archivo
    DWORD fileAttributes;
    bool isDirectory;
};

struct FileSystemEvent {
    EventType eventType;
    FileOperationInfo fileInfo;
    FILETIME eventTime;
    std::wstring sourceModule;
};

// Variables globales
std::atomic<bool> g_monitoringActive{false};
std::thread g_monitoringThread;
std::mutex g_eventQueueMutex;
std::queue<FileSystemEvent> g_eventQueue;
std::mutex g_fileHashCacheMutex;
std::map<std::wstring, std::pair<std::string, FILETIME>> g_fileHashCache;
FileSystemDriver* g_fileSystemDriver = nullptr;
std::atomic<size_t> g_totalEventsProcessed{0};
std::atomic<size_t> g_totalEventsDropped{0};
std::vector<std::wstring> g_monitoredPaths;
std::vector<std::wstring> g_excludedPaths;

// Callbacks del driver de sistema de archivos
VOID FileCreateCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR FilePath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::FILE_CREATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = FilePath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"CREATE";
        
        // Obtener información adicional del archivo
        GetFileInfo(FilePath, event.fileInfo);
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Calcular hash del archivo (si es pequeño y no binario)
        if (ShouldCalculateHash(event.fileInfo)) {
            event.fileInfo.fileHash = CalculateFileHash(FilePath);
            
            // Cachear hash
            {
                std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
                g_fileHashCache[FilePath] = std::make_pair(
                    event.fileInfo.fileHash, 
                    event.fileInfo.lastWriteTime
                );
                
                // Limitar tamaño del caché
                if (g_fileHashCache.size() > MAX_FILE_HASH_CACHE) {
                    g_fileHashCache.erase(g_fileHashCache.begin());
                }
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID FileDeleteCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR FilePath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::FILE_DELETED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = FilePath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"DELETE";
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar hash en caché
        {
            std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
            auto it = g_fileHashCache.find(FilePath);
            if (it != g_fileHashCache.end()) {
                event.fileInfo.fileHash = it->second.first;
                g_fileHashCache.erase(it);
            }
        }
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID FileModifyCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR FilePath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::FILE_MODIFIED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = FilePath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"MODIFY";
        
        // Obtener información adicional del archivo
        GetFileInfo(FilePath, event.fileInfo);
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Calcular nuevo hash si es necesario
        if (ShouldCalculateHash(event.fileInfo)) {
            std::string newHash = CalculateFileHash(FilePath);
            
            // Comparar con hash anterior en caché
            std::string oldHash;
            {
                std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
                auto it = g_fileHashCache.find(FilePath);
                if (it != g_fileHashCache.end()) {
                    oldHash = it->second.first;
                    
                    // Actualizar caché si el archivo cambió
                    if (newHash != oldHash) {
                        it->second.first = newHash;
                        it->second.second = event.fileInfo.lastWriteTime;
                        event.fileInfo.fileHash = newHash;
                    } else {
                        event.fileInfo.fileHash = oldHash;
                    }
                } else {
                    // Guardar nuevo hash en caché
                    g_fileHashCache[FilePath] = std::make_pair(
                        newHash,
                        event.fileInfo.lastWriteTime
                    );
                    event.fileInfo.fileHash = newHash;
                }
            }
            
            // Si el hash cambió, podría ser importante
            if (!oldHash.empty() && newHash != oldHash) {
                event.eventType = EventType::FILE_HASH_CHANGED;
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID FileRenameCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR OldFilePath,
    _In_ PWSTR NewFilePath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::FILE_RENAMED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = NewFilePath;
        event.fileInfo.oldFilePath = OldFilePath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"RENAME";
        
        // Obtener información adicional del archivo
        GetFileInfo(NewFilePath, event.fileInfo);
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Mover hash en caché
        {
            std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
            auto it = g_fileHashCache.find(OldFilePath);
            if (it != g_fileHashCache.end()) {
                g_fileHashCache[NewFilePath] = it->second;
                g_fileHashCache.erase(it);
                event.fileInfo.fileHash = g_fileHashCache[NewFilePath].first;
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID DirectoryCreateCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR DirectoryPath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::DIRECTORY_CREATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = DirectoryPath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"DIR_CREATE";
        event.fileInfo.isDirectory = true;
        
        // Obtener información del directorio
        GetFileInfo(DirectoryPath, event.fileInfo);
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID DirectoryDeleteCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR DirectoryPath,
    _In_ PWSTR ProcessName,
    _In_ PVOID Context
) {
    try {
        FileSystemEvent event;
        event.eventType = EventType::DIRECTORY_DELETED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"FileSystemDriver";
        
        event.fileInfo.filePath = DirectoryPath;
        event.fileInfo.processName = ProcessName;
        event.fileInfo.processId = ProcessId;
        event.fileInfo.operationType = L"DIR_DELETE";
        event.fileInfo.isDirectory = true;
        
        // Obtener información del usuario
        event.fileInfo.userName = GetProcessUserName(ProcessId);
        
        // Verificar si debemos excluir este evento
        if (ShouldExcludeEvent(event)) {
            return;
        }
        
        // Eliminar todos los hashes de archivos en este directorio del caché
        {
            std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
            std::vector<std::wstring> toRemove;
            
            for (const auto& kvp : g_fileHashCache) {
                if (kvp.first.find(DirectoryPath) == 0) {
                    toRemove.push_back(kvp.first);
                }
            }
            
            for (const auto& path : toRemove) {
                g_fileHashCache.erase(path);
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

// Funciones de utilidad
bool GetFileInfo(const std::wstring& filePath, FileOperationInfo& fileInfo) {
    WIN32_FILE_ATTRIBUTE_DATA fileAttrData;
    
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileAttrData)) {
        fileInfo.fileSize.LowPart = fileAttrData.nFileSizeLow;
        fileInfo.fileSize.HighPart = fileAttrData.nFileSizeHigh;
        fileInfo.creationTime = fileAttrData.ftCreationTime;
        fileInfo.lastAccessTime = fileAttrData.ftLastAccessTime;
        fileInfo.lastWriteTime = fileAttrData.ftLastWriteTime;
        fileInfo.fileAttributes = fileAttrData.dwFileAttributes;
        fileInfo.isDirectory = (fileAttrData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        
        return true;
    }
    
    return false;
}

std::wstring GetProcessUserName(DWORD processId) {
    std::wstring userName;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    
    if (hProcess) {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            DWORD tokenInfoLength = 0;
            GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLength);
            
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(tokenInfoLength);
                if (GetTokenInformation(hToken, TokenUser, buffer.data(), tokenInfoLength, &tokenInfoLength)) {
                    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
                    
                    // Convertir SID a nombre de usuario
                    wchar_t userNameBuffer[256];
                    wchar_t domainNameBuffer[256];
                    DWORD userNameSize = 256;
                    DWORD domainNameSize = 256;
                    SID_NAME_USE sidType;
                    
                    if (LookupAccountSidW(nullptr, pTokenUser->User.Sid,
                        userNameBuffer, &userNameSize,
                        domainNameBuffer, &domainNameSize, &sidType)) {
                        userName = std::wstring(domainNameBuffer) + L"\\" + userNameBuffer;
                    }
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    }
    
    return userName;
}

bool ShouldCalculateHash(const FileOperationInfo& fileInfo) {
    // No calcular hash para directorios
    if (fileInfo.isDirectory) {
        return false;
    }
    
    // No calcular hash para archivos muy grandes (>10MB)
    if (fileInfo.fileSize.QuadPart > 10 * 1024 * 1024) {
        return false;
    }
    
    // Calcular hash solo para ciertas extensiones
    static const std::vector<std::wstring> hashExtensions = {
        L".exe", L".dll", L".sys", L".ps1", L".vbs", L".js", L".bat", L".cmd"
    };
    
    std::wstring filePathLower = fileInfo.filePath;
    std::transform(filePathLower.begin(), filePathLower.end(), 
                   filePathLower.begin(), ::towlower);
    
    for (const auto& ext : hashExtensions) {
        if (filePathLower.length() >= ext.length() &&
            filePathLower.compare(filePathLower.length() - ext.length(), ext.length(), ext) == 0) {
            return true;
        }
    }
    
    return false;
}

std::string CalculateFileHash(const std::wstring& filePath) {
    // Implementación simplificada - usar CryptoAPI o CNG en producción
    std::ifstream file(filePath, std::ios::binary);
    if (file) {
        // Calcular SHA256
        // Código omitido por brevedad
        return "sha256_placeholder";
    }
    return "";
}

bool ShouldExcludeEvent(const FileSystemEvent& event) {
    std::wstring filePathLower = event.fileInfo.filePath;
    std::transform(filePathLower.begin(), filePathLower.end(), 
                   filePathLower.begin(), ::towlower);
    
    // Excluir rutas del sistema y temporales
    static const std::vector<std::wstring> systemPaths = {
        L"c:\\windows\\", L"c:\\programdata\\", L"c:\\program files\\",
        L"c:\\program files (x86)\\", L"c:\\users\\", L"\\temp\\",
        L"\\tmp\\", L"\\appdata\\local\\temp\\", L"\\recycler\\",
        L"\\$recycle.bin\\"
    };
    
    for (const auto& systemPath : systemPaths) {
        if (filePathLower.find(systemPath) == 0) {
            return true;
        }
    }
    
    // Excluir extensiones específicas
    static const std::vector<std::wstring> excludedExtensions = {
        L".log", L".tmp", L".temp", L".cache", L".db", L".db-wal",
        L".db-shm", L".journal"
    };
    
    for (const auto& ext : excludedExtensions) {
        if (filePathLower.length() >= ext.length() &&
            filePathLower.compare(filePathLower.length() - ext.length(), ext.length(), ext) == 0) {
            return true;
        }
    }
    
    return false;
}

void EnqueueEvent(const FileSystemEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (g_eventQueue.size() < MAX_EVENT_QUEUE_SIZE) {
        g_eventQueue.push(event);
        g_totalEventsProcessed++;
    } else {
        g_totalEventsDropped++;
    }
}

bool DequeueEvent(FileSystemEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (!g_eventQueue.empty()) {
        event = g_eventQueue.front();
        g_eventQueue.pop();
        return true;
    }
    
    return false;
}

// Configuración de rutas monitoreadas
void AddMonitoredPath(const std::wstring& path) {
    g_monitoredPaths.push_back(path);
}

void AddExcludedPath(const std::wstring& path) {
    g_excludedPaths.push_back(path);
}

bool IsPathMonitored(const std::wstring& filePath) {
    // Si no hay rutas monitoreadas específicas, monitorear todo
    if (g_monitoredPaths.empty()) {
        return true;
    }
    
    for (const auto& monitoredPath : g_monitoredPaths) {
        if (filePath.find(monitoredPath) == 0) {
            return true;
        }
    }
    
    return false;
}

bool IsPathExcluded(const std::wstring& filePath) {
    for (const auto& excludedPath : g_excludedPaths) {
        if (filePath.find(excludedPath) == 0) {
            return true;
        }
    }
    
    return false;
}

// Función de monitoreo principal
void MonitoringThread() {
    while (g_monitoringActive) {
        try {
            // Procesar eventos en cola
            ProcessQueuedEvents();
            
            // Realizar escaneo periódico de archivos críticos
            PerformPeriodicScan();
            
            // Limpiar caché de hashes antiguos
            CleanupHashCache();
            
            // Dormir para evitar uso excesivo de CPU
            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }
        catch (...) {
            // Continuar monitoreo después de error
        }
    }
}

void ProcessQueuedEvents() {
    FileSystemEvent event;
    while (DequeueEvent(event)) {
        try {
            // Formatear evento para C#
            FormatAndSendEvent(event);
        }
        catch (...) {
            // Continuar con siguiente evento
        }
    }
}

void FormatAndSendEvent(const FileSystemEvent& event) {
    std::wstring jsonEvent = FormatEventToJson(event);
    SendEventToManagedCode(jsonEvent);
}

std::wstring FormatEventToJson(const FileSystemEvent& event) {
    // Formatear tiempo
    SYSTEMTIME sysTime;
    FileTimeToSystemTime(&event.eventTime, &sysTime);
    
    wchar_t timeBuffer[64];
    swprintf_s(timeBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    // Formatear tamaño del archivo
    wchar_t sizeBuffer[32];
    swprintf_s(sizeBuffer, L"%lld", event.fileInfo.fileSize.QuadPart);
    
    // Crear JSON
    std::wstring json = L"{";
    json += L"\"eventType\":\"" + std::to_wstring(static_cast<int>(event.eventType)) + L"\",";
    json += L"\"timestamp\":\"" + std::wstring(timeBuffer) + L"\",";
    json += L"\"source\":\"" + event.sourceModule + L"\",";
    json += L"\"filePath\":\"" + EscapeJsonString(event.fileInfo.filePath) + L"\",";
    
    if (!event.fileInfo.oldFilePath.empty()) {
        json += L"\"oldFilePath\":\"" + EscapeJsonString(event.fileInfo.oldFilePath) + L"\",";
    }
    
    json += L"\"processName\":\"" + EscapeJsonString(event.fileInfo.processName) + L"\",";
    json += L"\"processId\":" + std::to_wstring(event.fileInfo.processId) + L",";
    json += L"\"userName\":\"" + EscapeJsonString(event.fileInfo.userName) + L"\",";
    json += L"\"operationType\":\"" + event.fileInfo.operationType + L"\",";
    json += L"\"fileSize\":" + std::wstring(sizeBuffer) + L",";
    json += L"\"isDirectory\":" + std::wstring(event.fileInfo.isDirectory ? L"true" : L"false") + L",";
    json += L"\"fileAttributes\":" + std::to_wstring(event.fileInfo.fileAttributes) + L",";
    
    if (!event.fileInfo.fileHash.empty()) {
        json += L"\"fileHash\":\"" + std::wstring(event.fileInfo.fileHash.begin(), 
                                                event.fileInfo.fileHash.end()) + L"\",";
    }
    
    // Formatear tiempos del archivo
    wchar_t creationTimeBuffer[64], lastWriteBuffer[64];
    FileTimeToSystemTime(&event.fileInfo.creationTime, &sysTime);
    swprintf_s(creationTimeBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    FileTimeToSystemTime(&event.fileInfo.lastWriteTime, &sysTime);
    swprintf_s(lastWriteBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    json += L"\"creationTime\":\"" + std::wstring(creationTimeBuffer) + L"\",";
    json += L"\"lastWriteTime\":\"" + std::wstring(lastWriteBuffer) + L"\"";
    
    json += L"}";
    
    return json;
}

std::wstring EscapeJsonString(const std::wstring& input) {
    std::wstring output;
    output.reserve(input.length());
    
    for (wchar_t c : input) {
        switch (c) {
            case L'\"': output += L"\\\""; break;
            case L'\\': output += L"\\\\"; break;
            case L'\b': output += L"\\b"; break;
            case L'\f': output += L"\\f"; break;
            case L'\n': output += L"\\n"; break;
            case L'\r': output += L"\\r"; break;
            case L'\t': output += L"\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    output += c;
                } else {
                    wchar_t hex[7];
                    swprintf_s(hex, L"\\u%04x", c);
                    output += hex;
                }
                break;
        }
    }
    
    return output;
}

void PerformPeriodicScan() {
    static DWORD lastScanTick = GetTickCount();
    DWORD currentTick = GetTickCount();
    
    // Escanear cada 5 minutos
    if (currentTick - lastScanTick > 300000) {
        lastScanTick = currentTick;
        
        // Escanear archivos críticos del sistema
        ScanCriticalFiles();
        
        // Verificar integridad de archivos importantes
        CheckFileIntegrity();
        
        // Reportar estadísticas
        ReportStatistics();
    }
}

void ScanCriticalFiles() {
    // Rutas críticas a monitorear
    static const std::vector<std::wstring> criticalPaths = {
        L"C:\\Windows\\System32\\",
        L"C:\\Windows\\SysWOW64\\",
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\",
        L"C:\\Users\\",
        L"C:\\ProgramData\\"
    };
    
    for (const auto& path : criticalPaths) {
        ScanDirectoryForChanges(path);
    }
}

void ScanDirectoryForChanges(const std::wstring& directoryPath) {
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = directoryPath + L"*";
    
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    do {
        if (wcscmp(findData.cFileName, L".") == 0 || 
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        
        std::wstring fullPath = directoryPath + findData.cFileName;
        
        // Verificar si es directorio
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursivamente escanear subdirectorios
            ScanDirectoryForChanges(fullPath + L"\\");
        } else {
            // Verificar archivo
            CheckFileForChanges(fullPath, findData);
        }
    } while (FindNextFileW(hFind, &findData) != 0);
    
    FindClose(hFind);
}

void CheckFileForChanges(const std::wstring& filePath, const WIN32_FIND_DATAW& findData) {
    // Verificar solo archivos ejecutables y DLLs
    std::wstring filePathLower = filePath;
    std::transform(filePathLower.begin(), filePathLower.end(), 
                   filePathLower.begin(), ::towlower);
    
    static const std::vector<std::wstring> executableExtensions = {
        L".exe", L".dll", L".sys", L".ocx", L".cpl", L".drv"
    };
    
    bool isExecutable = false;
    for (const auto& ext : executableExtensions) {
        if (filePathLower.length() >= ext.length() &&
            filePathLower.compare(filePathLower.length() - ext.length(), ext.length(), ext) == 0) {
            isExecutable = true;
            break;
        }
    }
    
    if (!isExecutable) {
        return;
    }
    
    // Verificar si el archivo ha cambiado desde el último escaneo
    {
        std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
        auto it = g_fileHashCache.find(filePath);
        
        if (it != g_fileHashCache.end()) {
            // Comparar tiempos de modificación
            if (CompareFileTime(&findData.ftLastWriteTime, &it->second.second) > 0) {
                // Archivo modificado
                GenerateFileChangeEvent(filePath, L"Periodic scan detected modification");
            }
        } else {
            // Nuevo archivo encontrado en escaneo
            GenerateFileChangeEvent(filePath, L"Periodic scan detected new file");
        }
    }
}

void CheckFileIntegrity() {
    // Verificar integridad de archivos del sistema importantes
    static const std::vector<std::wstring> systemFiles = {
        L"C:\\Windows\\System32\\kernel32.dll",
        L"C:\\Windows\\System32\\ntdll.dll",
        L"C:\\Windows\\System32\\user32.dll",
        L"C:\\Windows\\System32\\advapi32.dll",
        L"C:\\Windows\\System32\\lsass.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        L"C:\\Windows\\System32\\services.exe",
        L"C:\\Windows\\System32\\winlogon.exe"
    };
    
    for (const auto& filePath : systemFiles) {
        VerifySystemFileIntegrity(filePath);
    }
}

void VerifySystemFileIntegrity(const std::wstring& filePath) {
    // Calcular hash actual
    std::string currentHash = CalculateFileHash(filePath);
    
    // Comparar con hash conocido (en producción, usar base de datos de firmas)
    static std::map<std::wstring, std::string> knownHashes = {
        {L"C:\\Windows\\System32\\kernel32.dll", "known_hash_kernel32"},
        {L"C:\\Windows\\System32\\ntdll.dll", "known_hash_ntdll"}
    };
    
    auto it = knownHashes.find(filePath);
    if (it != knownHashes.end() && currentHash != it->second) {
        GenerateIntegrityAlert(filePath, currentHash, it->second);
    }
}

void GenerateFileChangeEvent(const std::wstring& filePath, const std::wstring& reason) {
    FileSystemEvent event;
    event.eventType = EventType::FILE_SUSPICIOUS_CHANGE;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"FileSystemSensor";
    
    event.fileInfo.filePath = filePath;
    event.fileInfo.operationType = L"PERIODIC_SCAN";
    
    // Obtener información del archivo
    GetFileInfo(filePath, event.fileInfo);
    
    // Formatear evento con razón
    std::wstring json = FormatEventToJson(event);
    
    // Insertar razón
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        json.insert(pos, L",\"scanReason\":\"" + EscapeJsonString(reason) + L"\"");
    }
    
    // Enviar evento
    SendSuspiciousEventToManagedCode(json);
}

void GenerateIntegrityAlert(const std::wstring& filePath, 
                           const std::string& currentHash, 
                           const std::string& expectedHash) {
    FileSystemEvent event;
    event.eventType = EventType::FILE_INTEGRITY_VIOLATION;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"FileSystemSensor";
    
    event.fileInfo.filePath = filePath;
    event.fileInfo.operationType = L"INTEGRITY_CHECK";
    event.fileInfo.fileHash = currentHash;
    
    // Formatear alerta
    std::wstring json = FormatEventToJson(event);
    
    // Insertar información de hash
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring hashInfo = L",\"integrityCheck\":{";
        hashInfo += L"\"currentHash\":\"" + 
                   std::wstring(currentHash.begin(), currentHash.end()) + L"\",";
        hashInfo += L"\"expectedHash\":\"" + 
                   std::wstring(expectedHash.begin(), expectedHash.end()) + L"\"";
        hashInfo += L"}";
        
        json.insert(pos, hashInfo);
    }
    
    // Enviar alerta
    SendIntegrityAlertToManagedCode(json);
}

void CleanupHashCache() {
    static DWORD lastCleanupTick = GetTickCount();
    DWORD currentTick = GetTickCount();
    
    // Limpiar cada hora
    if (currentTick - lastCleanupTick > 3600000) {
        lastCleanupTick = currentTick;
        
        std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
        
        std::vector<std::wstring> toRemove;
        FILETIME currentTime;
        GetSystemTimeAsFileTime(&currentTime);
        
        for (const auto& kvp : g_fileHashCache) {
            // Eliminar entradas con más de 24 horas
            ULARGE_INTEGER cacheTime, nowTime;
            cacheTime.LowPart = kvp.second.second.dwLowDateTime;
            cacheTime.HighPart = kvp.second.second.dwHighDateTime;
            nowTime.LowPart = currentTime.dwLowDateTime;
            nowTime.HighPart = currentTime.dwHighDateTime;
            
            // 24 horas en unidades de 100-nanosegundos
            const ULONGLONG twentyFourHours = 24ULL * 60ULL * 60ULL * 10000000ULL;
            
            if (nowTime.QuadPart - cacheTime.QuadPart > twentyFourHours) {
                toRemove.push_back(kvp.first);
            }
        }
        
        for (const auto& path : toRemove) {
            g_fileHashCache.erase(path);
        }
    }
}

void ReportStatistics() {
    size_t processed = g_totalEventsProcessed.load();
    size_t dropped = g_totalEventsDropped.load();
    size_t cacheSize = 0;
    
    {
        std::lock_guard<std::mutex> lock(g_fileHashCacheMutex);
        cacheSize = g_fileHashCache.size();
    }
    
    wchar_t statsBuffer[256];
    swprintf_s(statsBuffer, 
        L"{\"type\":\"FileSystemSensorStats\",\"processed\":%zu,\"dropped\":%zu,\"hashCacheSize\":%zu}",
        processed, dropped, cacheSize);
    
    SendStatisticsToManagedCode(statsBuffer);
}

// Funciones de inicialización/limpieza
bool InitializeFileSystemSensor() {
    try {
        // Inicializar driver de sistema de archivos
        g_fileSystemDriver = new FileSystemDriver();
        if (!g_fileSystemDriver->Initialize()) {
            delete g_fileSystemDriver;
            g_fileSystemDriver = nullptr;
            return false;
        }
        
        // Registrar callbacks
        g_fileSystemDriver->RegisterFileCreateCallback(FileCreateCallback, nullptr);
        g_fileSystemDriver->RegisterFileDeleteCallback(FileDeleteCallback, nullptr);
        g_fileSystemDriver->RegisterFileModifyCallback(FileModifyCallback, nullptr);
        g_fileSystemDriver->RegisterFileRenameCallback(FileRenameCallback, nullptr);
        g_fileSystemDriver->RegisterDirectoryCreateCallback(DirectoryCreateCallback, nullptr);
        g_fileSystemDriver->RegisterDirectoryDeleteCallback(DirectoryDeleteCallback, nullptr);
        
        // Configurar rutas monitoreadas (por defecto)
        AddMonitoredPath(L"C:\\"); // Monitorear todo por defecto
        
        // Configurar rutas excluidas
        AddExcludedPath(L"C:\\Windows\\Temp\\");
        AddExcludedPath(L"C:\\Users\\");
        
        // Iniciar monitoreo
        g_monitoringActive = true;
        g_monitoringThread = std::thread(MonitoringThread);
        
        return true;
    }
    catch (...) {
        return false;
    }
}

void CleanupFileSystemSensor() {
    try {
        // Detener monitoreo
        g_monitoringActive = false;
        
        if (g_monitoringThread.joinable()) {
            g_monitoringThread.join();
        }
        
        // Limpiar driver
        if (g_fileSystemDriver) {
            g_fileSystemDriver->Cleanup();
            delete g_fileSystemDriver;
            g_fileSystemDriver = nullptr;
        }
        
        // Limpiar colas y cachés
        {
            std::lock_guard<std::mutex> lock1(g_eventQueueMutex);
            std::queue<FileSystemEvent> emptyQueue;
            std::swap(g_eventQueue, emptyQueue);
        }
        
        {
            std::lock_guard<std::mutex> lock2(g_fileHashCacheMutex);
            g_fileHashCache.clear();
        }
        
        g_monitoredPaths.clear();
        g_excludedPaths.clear();
    }
    catch (...) {
        // Ignorar errores durante limpieza
    }
}

// Exportaciones para C#
extern "C" __declspec(dllexport) bool __stdcall StartFileSystemMonitoring() {
    return InitializeFileSystemSensor();
}

extern "C" __declspec(dllexport) void __stdcall StopFileSystemMonitoring() {
    CleanupFileSystemSensor();
}

extern "C" __declspec(dllexport) void __stdcall AddMonitoredPathExport(const wchar_t* path) {
    AddMonitoredPath(path);
}

extern "C" __declspec(dllexport) void __stdcall AddExcludedPathExport(const wchar_t* path) {
    AddExcludedPath(path);
}

extern "C" __declspec(dllexport) size_t __stdcall GetFileSystemEventCount() {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    return g_eventQueue.size();
}

extern "C" __declspec(dllexport) bool __stdcall GetFileSystemEvent(wchar_t* buffer, size_t bufferSize) {
    FileSystemEvent event;
    if (DequeueEvent(event)) {
        std::wstring jsonEvent = FormatEventToJson(event);
        
        if (jsonEvent.length() < bufferSize) {
            wcscpy_s(buffer, bufferSize, jsonEvent.c_str());
            return true;
        }
    }
    
    return false;
}

} // namespace Sensors
} // namespace Enterprise
} // namespace BWP