#include "pch.h"
#include "ProcessSensor.h"
#include "ProcessDriver.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <securitybaseapi.h>
#include <sddl.h>
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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace BWP {
namespace Enterprise {
namespace Sensors {

// Constantes
constexpr DWORD MONITORING_INTERVAL_MS = 100;
constexpr size_t MAX_EVENT_QUEUE_SIZE = 10000;
constexpr int PROCESS_HASH_SAMPLE_RATE = 10; // Calcular hash cada 10 procesos

// Estructuras de datos
struct ProcessInfo {
    DWORD processId;
    DWORD parentProcessId;
    std::wstring processName;
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring userSid;
    std::wstring integrityLevel;
    FILETIME creationTime;
    FILETIME exitTime;
    SIZE_T workingSetSize;
    DWORD sessionId;
    bool isElevated;
    std::string processHash; // SHA256 del ejecutable
};

struct ProcessEvent {
    EventType eventType;
    ProcessInfo processInfo;
    FILETIME eventTime;
    std::wstring sourceModule;
};

// Variables globales
std::atomic<bool> g_monitoringActive{false};
std::thread g_monitoringThread;
std::mutex g_eventQueueMutex;
std::queue<ProcessEvent> g_eventQueue;
std::mutex g_processCacheMutex;
std::map<DWORD, ProcessInfo> g_processCache;
ProcessDriver* g_processDriver = nullptr;
std::atomic<size_t> g_totalEventsProcessed{0};
std::atomic<size_t> g_totalEventsDropped{0};

// Callback del driver de procesos
VOID ProcessCreateCallback(
    _In_ DWORD ProcessId,
    _In_ DWORD ParentProcessId,
    _In_ HANDLE CreatingThreadId,
    _In_ PVOID Context
) {
    try {
        ProcessEvent event;
        event.eventType = EventType::PROCESS_CREATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessDriver";
        
        // Obtener información detallada del proceso
        if (GetProcessInfo(ProcessId, event.processInfo)) {
            event.processInfo.processId = ProcessId;
            event.processInfo.parentProcessId = ParentProcessId;
            
            // Calcular hash del ejecutable (muestreado)
            if (ProcessId % PROCESS_HASH_SAMPLE_RATE == 0) {
                event.processInfo.processHash = CalculateProcessHash(ProcessId);
            }
            
            // Cachear información del proceso
            {
                std::lock_guard<std::mutex> lock(g_processCacheMutex);
                g_processCache[ProcessId] = event.processInfo;
            }
            
            // Encolar evento
            EnqueueEvent(event);
        }
    }
    catch (...) {
        // Log error interno
    }
}

VOID ProcessTerminateCallback(
    _In_ DWORD ProcessId,
    _In_ PVOID Context
) {
    try {
        ProcessEvent event;
        event.eventType = EventType::PROCESS_TERMINATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessDriver";
        
        // Obtener información del caché
        {
            std::lock_guard<std::mutex> lock(g_processCacheMutex);
            auto it = g_processCache.find(ProcessId);
            if (it != g_processCache.end()) {
                event.processInfo = it->second;
                event.processInfo.processId = ProcessId;
                GetSystemTimeAsFileTime(&event.processInfo.exitTime);
                
                // Eliminar del caché
                g_processCache.erase(it);
            } else {
                // Si no está en caché, obtener información básica
                event.processInfo.processId = ProcessId;
                wchar_t processName[MAX_PATH] = {0};
                if (GetProcessName(ProcessId, processName, MAX_PATH)) {
                    event.processInfo.processName = processName;
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

VOID ThreadCreateCallback(
    _In_ DWORD ThreadId,
    _In_ DWORD ProcessId,
    _In_ PVOID Context
) {
    try {
        ProcessEvent event;
        event.eventType = EventType::THREAD_CREATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessDriver";
        
        // Obtener información del proceso padre
        event.processInfo.processId = ProcessId;
        {
            std::lock_guard<std::mutex> lock(g_processCacheMutex);
            auto it = g_processCache.find(ProcessId);
            if (it != g_processCache.end()) {
                event.processInfo = it->second;
            } else {
                GetProcessInfo(ProcessId, event.processInfo);
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID ThreadTerminateCallback(
    _In_ DWORD ThreadId,
    _In_ DWORD ProcessId,
    _In_ PVOID Context
) {
    try {
        ProcessEvent event;
        event.eventType = EventType::THREAD_TERMINATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessDriver";
        
        event.processInfo.processId = ProcessId;
        {
            std::lock_guard<std::mutex> lock(g_processCacheMutex);
            auto it = g_processCache.find(ProcessId);
            if (it != g_processCache.end()) {
                event.processInfo = it->second;
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID ImageLoadCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ImagePath,
    _In_ PVOID Context
) {
    try {
        ProcessEvent event;
        event.eventType = EventType::IMAGE_LOADED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessDriver";
        
        event.processInfo.processId = ProcessId;
        event.processInfo.imagePath = ImagePath;
        
        {
            std::lock_guard<std::mutex> lock(g_processCacheMutex);
            auto it = g_processCache.find(ProcessId);
            if (it != g_processCache.end()) {
                event.processInfo.processName = it->second.processName;
                event.processInfo.userSid = it->second.userSid;
            }
        }
        
        // Calcular hash de la imagen cargada
        event.processInfo.processHash = CalculateFileHash(ImagePath);
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

// Funciones de utilidad
bool GetProcessInfo(DWORD processId, ProcessInfo& processInfo) {
    bool success = false;
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId
    );
    
    if (hProcess != nullptr && hProcess != INVALID_HANDLE_VALUE) {
        try {
            // Nombre del proceso
            wchar_t processName[MAX_PATH] = {0};
            if (GetProcessImageFileNameW(hProcess, processName, MAX_PATH)) {
                processInfo.processName = ExtractFileName(processName);
                processInfo.imagePath = processName;
            }
            
            // Línea de comandos
            processInfo.commandLine = GetProcessCommandLine(processId);
            
            // Información de usuario e integridad
            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                processInfo.userSid = GetTokenUserSid(hToken);
                processInfo.integrityLevel = GetTokenIntegrityLevel(hToken);
                processInfo.isElevated = IsTokenElevated(hToken);
                CloseHandle(hToken);
            }
            
            // Tiempos de creación
            FILETIME createTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                processInfo.creationTime = createTime;
            }
            
            // Memoria
            PROCESS_MEMORY_COUNTERS_EX pmc;
            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                processInfo.workingSetSize = pmc.WorkingSetSize;
            }
            
            // Session ID
            DWORD sessionId;
            if (ProcessIdToSessionId(processId, &sessionId)) {
                processInfo.sessionId = sessionId;
            }
            
            // Parent Process ID
            processInfo.parentProcessId = GetParentProcessId(processId);
            
            success = true;
        }
        catch (...) {
            // Fallback a información básica
        }
        
        CloseHandle(hProcess);
    }
    
    return success;
}

std::wstring GetProcessCommandLine(DWORD processId) {
    std::wstring commandLine;
    
    // Usar NtQueryInformationProcess para obtener línea de comandos
    // Implementación simplificada - en producción usar PEB reading
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        // Leer PEB para obtener parámetros
        // Código omitido por brevedad
        CloseHandle(hProcess);
    }
    
    return commandLine;
}

std::wstring GetTokenUserSid(HANDLE hToken) {
    std::wstring sidString;
    
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLength);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer(tokenInfoLength);
        if (GetTokenInformation(hToken, TokenUser, buffer.data(), tokenInfoLength, &tokenInfoLength)) {
            PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidStr)) {
                sidString = sidStr;
                LocalFree(sidStr);
            }
        }
    }
    
    return sidString;
}

std::wstring GetTokenIntegrityLevel(HANDLE hToken) {
    std::wstring integrityLevel = L"Unknown";
    
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &tokenInfoLength);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer(tokenInfoLength);
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buffer.data(), tokenInfoLength, &tokenInfoLength)) {
            PTOKEN_MANDATORY_LABEL pTokenIntegrity = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());
            DWORD integrity = *GetSidSubAuthority(pTokenIntegrity->Label.Sid, 
                (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTokenIntegrity->Label.Sid) - 1));
            
            if (integrity >= SECURITY_MANDATORY_SYSTEM_RID) {
                integrityLevel = L"System";
            } else if (integrity >= SECURITY_MANDATORY_HIGH_RID) {
                integrityLevel = L"High";
            } else if (integrity >= SECURITY_MANDATORY_MEDIUM_RID) {
                integrityLevel = L"Medium";
            } else if (integrity >= SECURITY_MANDATORY_LOW_RID) {
                integrityLevel = L"Low";
            } else {
                integrityLevel = L"Untrusted";
            }
        }
    }
    
    return integrityLevel;
}

bool IsTokenElevated(HANDLE hToken) {
    TOKEN_ELEVATION elevation;
    DWORD returnLength;
    
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &returnLength)) {
        return elevation.TokenIsElevated != 0;
    }
    
    return false;
}

DWORD GetParentProcessId(DWORD processId) {
    DWORD parentPid = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == processId) {
                    parentPid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return parentPid;
}

std::wstring ExtractFileName(const std::wstring& fullPath) {
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return fullPath.substr(pos + 1);
    }
    return fullPath;
}

bool GetProcessName(DWORD processId, wchar_t* buffer, DWORD bufferSize) {
    bool success = false;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    
    if (hProcess) {
        if (GetProcessImageFileNameW(hProcess, buffer, bufferSize)) {
            success = true;
        }
        CloseHandle(hProcess);
    }
    
    return success;
}

std::string CalculateProcessHash(DWORD processId) {
    std::string hash;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
    if (hProcess) {
        wchar_t imagePath[MAX_PATH] = {0};
        if (GetProcessImageFileNameW(hProcess, imagePath, MAX_PATH)) {
            hash = CalculateFileHash(imagePath);
        }
        CloseHandle(hProcess);
    }
    
    return hash;
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

void EnqueueEvent(const ProcessEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (g_eventQueue.size() < MAX_EVENT_QUEUE_SIZE) {
        g_eventQueue.push(event);
        g_totalEventsProcessed++;
    } else {
        g_totalEventsDropped++;
    }
}

bool DequeueEvent(ProcessEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (!g_eventQueue.empty()) {
        event = g_eventQueue.front();
        g_eventQueue.pop();
        return true;
    }
    
    return false;
}

// Función de monitoreo principal
void MonitoringThread() {
    // Enumerar procesos existentes al inicio
    EnumerateExistingProcesses();
    
    while (g_monitoringActive) {
        try {
            // Procesar eventos en cola
            ProcessQueuedEvents();
            
            // Realizar escaneo periódico de procesos
            PerformPeriodicScan();
            
            // Dormir para evitar uso excesivo de CPU
            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }
        catch (...) {
            // Continuar monitoreo después de error
        }
    }
}

void EnumerateExistingProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            ProcessEvent event;
            event.eventType = EventType::PROCESS_EXISTING;
            GetSystemTimeAsFileTime(&event.eventTime);
            event.sourceModule = L"ProcessSensor";
            
            event.processInfo.processId = pe32.th32ProcessID;
            event.processInfo.parentProcessId = pe32.th32ParentProcessID;
            event.processInfo.processName = pe32.szExeFile;
            
            // Obtener información adicional
            GetProcessInfo(pe32.th32ProcessID, event.processInfo);
            
            // Cachear
            {
                std::lock_guard<std::mutex> lock(g_processCacheMutex);
                g_processCache[pe32.th32ProcessID] = event.processInfo;
            }
            
            // Encolar
            EnqueueEvent(event);
            
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

void ProcessQueuedEvents() {
    ProcessEvent event;
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

void FormatAndSendEvent(const ProcessEvent& event) {
    // Convertir a formato JSON para enviar a C#
    std::wstring jsonEvent = FormatEventToJson(event);
    
    // Enviar a través del bridge C++/CLI
    SendEventToManagedCode(jsonEvent);
}

std::wstring FormatEventToJson(const ProcessEvent& event) {
    // Formatear tiempo
    SYSTEMTIME sysTime;
    FileTimeToSystemTime(&event.eventTime, &sysTime);
    
    wchar_t timeBuffer[64];
    swprintf_s(timeBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    // Crear JSON
    std::wstring json = L"{";
    json += L"\"eventType\":\"" + std::to_wstring(static_cast<int>(event.eventType)) + L"\",";
    json += L"\"timestamp\":\"" + std::wstring(timeBuffer) + L"\",";
    json += L"\"source\":\"" + event.sourceModule + L"\",";
    json += L"\"processId\":" + std::to_wstring(event.processInfo.processId) + L",";
    json += L"\"parentProcessId\":" + std::to_wstring(event.processInfo.parentProcessId) + L",";
    json += L"\"processName\":\"" + EscapeJsonString(event.processInfo.processName) + L"\",";
    json += L"\"imagePath\":\"" + EscapeJsonString(event.processInfo.imagePath) + L"\",";
    json += L"\"commandLine\":\"" + EscapeJsonString(event.processInfo.commandLine) + L"\",";
    json += L"\"userSid\":\"" + EscapeJsonString(event.processInfo.userSid) + L"\",";
    json += L"\"integrityLevel\":\"" + EscapeJsonString(event.processInfo.integrityLevel) + L"\",";
    json += L"\"isElevated\":" + std::wstring(event.processInfo.isElevated ? L"true" : L"false") + L",";
    json += L"\"sessionId\":" + std::to_wstring(event.processInfo.sessionId) + L",";
    json += L"\"workingSetSize\":" + std::to_wstring(event.processInfo.workingSetSize) + L",";
    json += L"\"processHash\":\"" + std::wstring(event.processInfo.processHash.begin(), event.processInfo.processHash.end()) + L"\"";
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
                    // Escapar Unicode
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
    
    // Escanear cada 60 segundos
    if (currentTick - lastScanTick > 60000) {
        lastScanTick = currentTick;
        
        // Verificar procesos zombis no detectados
        CleanupProcessCache();
        
        // Verificar procesos con comportamiento sospechoso
        DetectSuspiciousProcesses();
        
        // Reportar estadísticas
        ReportStatistics();
    }
}

void CleanupProcessCache() {
    std::vector<DWORD> processesToRemove;
    
    {
        std::lock_guard<std::mutex> lock(g_processCacheMutex);
        
        for (const auto& kvp : g_processCache) {
            DWORD processId = kvp.first;
            
            // Verificar si el proceso aún existe
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (hProcess) {
                DWORD exitCode;
                if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    processesToRemove.push_back(processId);
                }
                CloseHandle(hProcess);
            } else {
                // Proceso ya no existe
                processesToRemove.push_back(processId);
            }
        }
        
        // Eliminar procesos muertos del caché
        for (DWORD pid : processesToRemove) {
            g_processCache.erase(pid);
        }
    }
    
    // Generar eventos de terminación para procesos no detectados
    for (DWORD pid : processesToRemove) {
        ProcessEvent event;
        event.eventType = EventType::PROCESS_TERMINATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"ProcessSensor";
        event.processInfo.processId = pid;
        
        EnqueueEvent(event);
    }
}

void DetectSuspiciousProcesses() {
    // Detectar procesos sospechosos basados en heurísticas
    std::lock_guard<std::mutex> lock(g_processCacheMutex);
    
    for (const auto& kvp : g_processCache) {
        const ProcessInfo& procInfo = kvp.second;
        
        // Heurística 1: Procesos sin path de imagen válido
        if (procInfo.imagePath.empty() || procInfo.imagePath.find(L"\\") == std::wstring::npos) {
            GenerateSuspiciousEvent(procInfo, L"Process without valid image path");
        }
        
        // Heurística 2: Procesos con integridad baja pero privilegios elevados
        if (procInfo.integrityLevel == L"Low" && procInfo.isElevated) {
            GenerateSuspiciousEvent(procInfo, L"Low integrity process with elevated privileges");
        }
        
        // Heurística 3: Procesos con nombres sospechosos
        if (IsSuspiciousProcessName(procInfo.processName)) {
            GenerateSuspiciousEvent(procInfo, L"Suspicious process name");
        }
        
        // Heurística 4: Procesos con commandline inusual
        if (IsSuspiciousCommandLine(procInfo.commandLine)) {
            GenerateSuspiciousEvent(procInfo, L"Suspicious command line");
        }
    }
}

bool IsSuspiciousProcessName(const std::wstring& processName) {
    // Lista de nombres sospechosos (simplificada)
    static const std::vector<std::wstring> suspiciousNames = {
        L"mimikatz.exe", L"procdump.exe", L"psexec.exe", L"nc.exe", 
        L"powershell.exe", L"cmd.exe", L"wscript.exe", L"cscript.exe",
        L"rundll32.exe", L"regsvr32.exe", L"mshta.exe", L"bitsadmin.exe"
    };
    
    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    
    for (const auto& suspicious : suspiciousNames) {
        if (lowerName.find(suspicious) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IsSuspiciousCommandLine(const std::wstring& commandLine) {
    if (commandLine.empty()) return false;
    
    std::wstring lowerCmd = commandLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);
    
    // Patrones sospechosos
    static const std::vector<std::wstring> suspiciousPatterns = {
        L"-enc ", L"-e ", L"iex(", L"invoke-expression",
        L"downloadstring", L"frombase64string", L"shellcode",
        L"meterpreter", L"payload", L"obfuscated",
        L"powershell -window hidden", L"powershell -w hidden",
        L"bypass", L"executionpolicy", L"noprofile"
    };
    
    for (const auto& pattern : suspiciousPatterns) {
        if (lowerCmd.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

void GenerateSuspiciousEvent(const ProcessInfo& procInfo, const std::wstring& reason) {
    ProcessEvent event;
    event.eventType = EventType::PROCESS_SUSPICIOUS;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"ProcessSensor";
    event.processInfo = procInfo;
    
    // Añadir razón al JSON
    std::wstring json = FormatEventToJson(event);
    
    // Insertar razón
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        json.insert(pos, L",\"suspicionReason\":\"" + EscapeJsonString(reason) + L"\"");
    }
    
    // Enviar evento
    SendSuspiciousEventToManagedCode(json);
}

void ReportStatistics() {
    // Reportar estadísticas de monitoreo
    size_t processed = g_totalEventsProcessed.load();
    size_t dropped = g_totalEventsDropped.load();
    size_t cacheSize = 0;
    
    {
        std::lock_guard<std::mutex> lock(g_processCacheMutex);
        cacheSize = g_processCache.size();
    }
    
    // Enviar estadísticas
    wchar_t statsBuffer[256];
    swprintf_s(statsBuffer, 
        L"{\"type\":\"ProcessSensorStats\",\"processed\":%zu,\"dropped\":%zu,\"cacheSize\":%zu}",
        processed, dropped, cacheSize);
    
    SendStatisticsToManagedCode(statsBuffer);
}

// Funciones de inicialización/limpieza
bool InitializeProcessSensor() {
    try {
        // Inicializar driver de procesos
        g_processDriver = new ProcessDriver();
        if (!g_processDriver->Initialize()) {
            delete g_processDriver;
            g_processDriver = nullptr;
            return false;
        }
        
        // Registrar callbacks
        g_processDriver->RegisterProcessCreateCallback(ProcessCreateCallback, nullptr);
        g_processDriver->RegisterProcessTerminateCallback(ProcessTerminateCallback, nullptr);
        g_processDriver->RegisterThreadCreateCallback(ThreadCreateCallback, nullptr);
        g_processDriver->RegisterThreadTerminateCallback(ThreadTerminateCallback, nullptr);
        g_processDriver->RegisterImageLoadCallback(ImageLoadCallback, nullptr);
        
        // Iniciar monitoreo
        g_monitoringActive = true;
        g_monitoringThread = std::thread(MonitoringThread);
        
        return true;
    }
    catch (...) {
        return false;
    }
}

void CleanupProcessSensor() {
    try {
        // Detener monitoreo
        g_monitoringActive = false;
        
        if (g_monitoringThread.joinable()) {
            g_monitoringThread.join();
        }
        
        // Limpiar driver
        if (g_processDriver) {
            g_processDriver->Cleanup();
            delete g_processDriver;
            g_processDriver = nullptr;
        }
        
        // Limpiar colas y cachés
        {
            std::lock_guard<std::mutex> lock1(g_eventQueueMutex);
            std::queue<ProcessEvent> emptyQueue;
            std::swap(g_eventQueue, emptyQueue);
        }
        
        {
            std::lock_guard<std::mutex> lock2(g_processCacheMutex);
            g_processCache.clear();
        }
    }
    catch (...) {
        // Ignorar errores durante limpieza
    }
}

// Funciones para obtener estadísticas
size_t GetProcessedEventsCount() {
    return g_totalEventsProcessed.load();
}

size_t GetDroppedEventsCount() {
    return g_totalEventsDropped.load();
}

size_t GetCachedProcessesCount() {
    std::lock_guard<std::mutex> lock(g_processCacheMutex);
    return g_processCache.size();
}

// Exportaciones para C# (usando C++/CLI)
extern "C" __declspec(dllexport) bool __stdcall StartProcessMonitoring() {
    return InitializeProcessSensor();
}

extern "C" __declspec(dllexport) void __stdcall StopProcessMonitoring() {
    CleanupProcessSensor();
}

extern "C" __declspec(dllexport) size_t __stdcall GetProcessEventCount() {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    return g_eventQueue.size();
}

extern "C" __declspec(dllexport) bool __stdcall GetProcessEvent(wchar_t* buffer, size_t bufferSize) {
    ProcessEvent event;
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