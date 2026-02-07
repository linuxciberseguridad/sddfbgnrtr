#include "pch.h"
#include "RegistrySensor.h"
#include "RegistryDriver.h"
#include <windows.h>
#include <winreg.h>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <atomic>
#include <memory>
#include <vector>
#include <map>
#include <sstream>

namespace BWP {
namespace Enterprise {
namespace Sensors {

// Constantes
constexpr DWORD MONITORING_INTERVAL_MS = 100;
constexpr size_t MAX_EVENT_QUEUE_SIZE = 10000;
constexpr size_t MAX_REGISTRY_CACHE = 5000;

// Tipos de operaciones de registro
enum RegistryOperation {
    REG_CREATE_KEY = 1,
    REG_DELETE_KEY = 2,
    REG_SET_VALUE = 3,
    REG_DELETE_VALUE = 4,
    REG_RENAME_KEY = 5
};

// Estructuras de datos
struct RegistryChangeInfo {
    DWORD processId;
    std::wstring processName;
    std::wstring registryPath;
    std::wstring valueName;
    std::wstring oldValueData;
    std::wstring newValueData;
    DWORD valueType; // REG_SZ, REG_DWORD, etc.
    RegistryOperation operation;
    std::wstring userName;
    bool isSystemKey;
    bool isAutoRun; // Para detección de persistencia
};

struct RegistryEvent {
    EventType eventType;
    RegistryChangeInfo registryInfo;
    FILETIME eventTime;
    std::wstring sourceModule;
};

// Variables globales
std::atomic<bool> g_monitoringActive{false};
std::thread g_monitoringThread;
std::mutex g_eventQueueMutex;
std::queue<RegistryEvent> g_eventQueue;
std::mutex g_registryCacheMutex;
std::map<std::wstring, RegistryChangeInfo> g_registryCache; // Path -> último estado
RegistryDriver* g_registryDriver = nullptr;
std::atomic<size_t> g_totalEventsProcessed{0};
std::atomic<size_t> g_totalEventsDropped{0};
std::vector<std::wstring> g_monitoredKeys;
std::vector<std::wstring> g_sensitiveKeys;

// Callbacks del driver de registro
VOID RegistryCreateKeyCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR KeyPath,
    _In_ PVOID Context
) {
    try {
        RegistryEvent event;
        event.eventType = EventType::REGISTRY_KEY_CREATED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"RegistryDriver";
        
        event.registryInfo.processId = ProcessId;
        event.registryInfo.processName = ProcessName;
        event.registryInfo.registryPath = KeyPath;
        event.registryInfo.operation = REG_CREATE_KEY;
        event.registryInfo.userName = GetProcessUserName(ProcessId);
        event.registryInfo.isSystemKey = IsSystemRegistryKey(KeyPath);
        event.registryInfo.isAutoRun = IsAutoRunKey(KeyPath);
        
        // Verificar si es una clave sensible
        if (IsSensitiveRegistryKey(KeyPath)) {
            GenerateSensitiveRegistryEvent(event, L"Sensitive registry key creation");
        }
        
        // Cachear cambio
        {
            std::lock_guard<std::mutex> lock(g_registryCacheMutex);
            g_registryCache[KeyPath] = event.registryInfo;
            
            // Limitar tamaño del caché
            if (g_registryCache.size() > MAX_REGISTRY_CACHE) {
                g_registryCache.erase(g_registryCache.begin());
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID RegistryDeleteKeyCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR KeyPath,
    _In_ PVOID Context
) {
    try {
        RegistryEvent event;
        event.eventType = EventType::REGISTRY_KEY_DELETED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"RegistryDriver";
        
        event.registryInfo.processId = ProcessId;
        event.registryInfo.processName = ProcessName;
        event.registryInfo.registryPath = KeyPath;
        event.registryInfo.operation = REG_DELETE_KEY;
        event.registryInfo.userName = GetProcessUserName(ProcessId);
        event.registryInfo.isSystemKey = IsSystemRegistryKey(KeyPath);
        
        // Eliminar del caché
        {
            std::lock_guard<std::mutex> lock(g_registryCacheMutex);
            g_registryCache.erase(KeyPath);
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID RegistrySetValueCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR KeyPath,
    _In_ PWSTR ValueName,
    _In_ PWSTR ValueData,
    _In_ DWORD ValueType,
    _In_ PVOID Context
) {
    try {
        RegistryEvent event;
        event.eventType = EventType::REGISTRY_VALUE_SET;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"RegistryDriver";
        
        event.registryInfo.processId = ProcessId;
        event.registryInfo.processName = ProcessName;
        event.registryInfo.registryPath = KeyPath;
        event.registryInfo.valueName = ValueName;
        event.registryInfo.newValueData = ValueData;
        event.registryInfo.valueType = ValueType;
        event.registryInfo.operation = REG_SET_VALUE;
        event.registryInfo.userName = GetProcessUserName(ProcessId);
        event.registryInfo.isSystemKey = IsSystemRegistryKey(KeyPath);
        event.registryInfo.isAutoRun = IsAutoRunKey(KeyPath);
        
        // Obtener valor anterior del caché
        {
            std::lock_guard<std::mutex> lock(g_registryCacheMutex);
            auto it = g_registryCache.find(KeyPath);
            if (it != g_registryCache.end() && it->second.valueName == ValueName) {
                event.registryInfo.oldValueData = it->second.newValueData;
            }
            
            // Actualizar caché
            g_registryCache[KeyPath] = event.registryInfo;
        }
        
        // Verificar si es cambio sospechoso
        if (IsSuspiciousRegistryChange(event.registryInfo)) {
            GenerateSuspiciousRegistryEvent(event);
        }
        
        // Verificar persistencia maliciosa
        if (IsMaliciousPersistence(event.registryInfo)) {
            GeneratePersistenceAlert(event);
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID RegistryDeleteValueCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR KeyPath,
    _In_ PWSTR ValueName,
    _In_ PVOID Context
) {
    try {
        RegistryEvent event;
        event.eventType = EventType::REGISTRY_VALUE_DELETED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"RegistryDriver";
        
        event.registryInfo.processId = ProcessId;
        event.registryInfo.processName = ProcessName;
        event.registryInfo.registryPath = KeyPath;
        event.registryInfo.valueName = ValueName;
        event.registryInfo.operation = REG_DELETE_VALUE;
        event.registryInfo.userName = GetProcessUserName(ProcessId);
        event.registryInfo.isSystemKey = IsSystemRegistryKey(KeyPath);
        
        // Eliminar del caché
        {
            std::lock_guard<std::mutex> lock(g_registryCacheMutex);
            auto it = g_registryCache.find(KeyPath);
            if (it != g_registryCache.end() && it->second.valueName == ValueName) {
                g_registryCache.erase(it);
            }
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID RegistryRenameKeyCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR OldKeyPath,
    _In_ PWSTR NewKeyPath,
    _In_ PVOID Context
) {
    try {
        RegistryEvent event;
        event.eventType = EventType::REGISTRY_KEY_RENAMED;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"RegistryDriver";
        
        event.registryInfo.processId = ProcessId;
        event.registryInfo.processName = ProcessName;
        event.registryInfo.registryPath = NewKeyPath;
        event.registryInfo.oldValueData = OldKeyPath; // Reutilizando campo para old path
        event.registryInfo.operation = REG_RENAME_KEY;
        event.registryInfo.userName = GetProcessUserName(ProcessId);
        event.registryInfo.isSystemKey = IsSystemRegistryKey(NewKeyPath);
        
        // Actualizar caché
        {
            std::lock_guard<std::mutex> lock(g_registryCacheMutex);
            auto it = g_registryCache.find(OldKeyPath);
            if (it != g_registryCache.end()) {
                RegistryChangeInfo info = it->second;
                info.registryPath = NewKeyPath;
                g_registryCache[NewKeyPath] = info;
                g_registryCache.erase(it);
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

bool IsSystemRegistryKey(const std::wstring& keyPath) {
    static const std::vector<std::wstring> systemKeyPrefixes = {
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\",
        L"HKEY_USERS\\.DEFAULT\\",
        L"HKEY_CURRENT_CONFIG\\"
    };
    
    std::wstring upperPath = keyPath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::towupper);
    
    for (const auto& prefix : systemKeyPrefixes) {
        if (upperPath.find(prefix) == 0) {
            return true;
        }
    }
    
    return false;
}

bool IsAutoRunKey(const std::wstring& keyPath) {
    static const std::vector<std::wstring> autoRunKeys = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
        L"SOFTWARE\\Classes\\Exefile\\Shell\\Open\\Command"
    };
    
    std::wstring upperPath = keyPath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::towupper);
    
    for (const auto& autoRunKey : autoRunKeys) {
        std::wstring upperAutoRun = autoRunKey;
        std::transform(upperAutoRun.begin(), upperAutoRun.end(), upperAutoRun.begin(), ::towupper);
        
        if (upperPath.find(upperAutoRun) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IsSensitiveRegistryKey(const std::wstring& keyPath) {
    static const std::vector<std::wstring> sensitiveKeys = {
        // Credenciales y autenticación
        L"SECURITY\\Policy\\Secrets",
        L"SECURITY\\Policy\\Accounts",
        L"SAM\\Domains\\Account\\Users",
        
        // Configuración de seguridad
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        
        // Firewall y red
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        
        // UAC y permisos
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        
        // Defensa antimalware
        L"SOFTWARE\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Microsoft\\Antimalware",
        
        // Task Scheduler
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
    };
    
    std::wstring upperPath = keyPath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::towupper);
    
    for (const auto& sensitiveKey : sensitiveKeys) {
        std::wstring upperSensitive = sensitiveKey;
        std::transform(upperSensitive.begin(), upperSensitive.end(), upperSensitive.begin(), ::towupper);
        
        if (upperPath.find(upperSensitive) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IsSuspiciousRegistryChange(const RegistryChangeInfo& regInfo) {
    // Heurística 1: Cambios a claves de auto-inicio
    if (regInfo.isAutoRun && regInfo.operation == REG_SET_VALUE) {
        return true;
    }
    
    // Heurística 2: Cambios por procesos no privilegiados a claves del sistema
    if (regInfo.isSystemKey && !IsPrivilegedProcess(regInfo.processName)) {
        return true;
    }
    
    // Heurística 3: Valores con datos sospechosos
    if (ContainsSuspiciousData(regInfo.newValueData)) {
        return true;
    }
    
    // Heurística 4: Nombres de valores sospechosos
    if (ContainsSuspiciousValueName(regInfo.valueName)) {
        return true;
    }
    
    // Heurística 5: Cambios frecuentes a la misma clave
    if (IsFrequentRegistryChange(regInfo.registryPath)) {
        return true;
    }
    
    return false;
}

bool IsPrivilegedProcess(const std::wstring& processName) {
    static const std::vector<std::wstring> privilegedProcesses = {
        L"services.exe", L"svchost.exe", L"lsass.exe", L"winlogon.exe",
        L"explorer.exe", L"csrss.exe", L"smss.exe", L"wininit.exe",
        L"spoolsv.exe", L"taskhost.exe", L"dwm.exe"
    };
    
    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    
    for (const auto& proc : privilegedProcesses) {
        if (lowerName == proc) {
            return true;
        }
    }
    
    return false;
}

bool ContainsSuspiciousData(const std::wstring& valueData) {
    if (valueData.empty()) {
        return false;
    }
    
    std::wstring lowerData = valueData;
    std::transform(lowerData.begin(), lowerData.end(), lowerData.begin(), ::towlower);
    
    // Patrones de malware/exploits
    static const std::vector<std::wstring> suspiciousPatterns = {
        L"powershell", L"cmd.exe", L"wscript", L"cscript", L"mshta",
        L"rundll32", L"regsvr32", L"bitsadmin", L"certutil",
        L"-enc", L"-e", L"iex", L"invoke-expression",
        L"frombase64", L"downloadstring", L"webclient",
        L"shellcode", L"meterpreter", L"reverse_tcp",
        L"javascript:", L"vbscript:", L"data:text/html"
    };
    
    for (const auto& pattern : suspiciousPatterns) {
        if (lowerData.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool ContainsSuspiciousValueName(const std::wstring& valueName) {
    if (valueName.empty()) {
        return false;
    }
    
    std::wstring lowerName = valueName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    
    // Nombres comúnmente usados por malware
    static const std::vector<std::wstring> suspiciousNames = {
        L"update", L"windowsupdate", L"securityupdate", L"microsoftupdate",
        L"javaupdate", L"adobeupdate", L"flashupdate", L"chromeupdate",
        L"firefoxupdate", L"skypeupdate", L"teamviewerupdate",
        L"svc", L"service", L"loader", L"injector", L"payload",
        L"backdoor", L"rat", L"bot", L"miner", L"keylogger",
        L"persistence", L"startup", L"autostart", L"runonce"
    };
    
    for (const auto& name : suspiciousNames) {
        if (lowerName.find(name) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IsFrequentRegistryChange(const std::wstring& keyPath) {
    static std::map<std::wstring, std::pair<DWORD, FILETIME>> changeHistory;
    static std::mutex historyMutex;
    
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);
    
    std::lock_guard<std::mutex> lock(historyMutex);
    
    auto it = changeHistory.find(keyPath);
    if (it == changeHistory.end()) {
        changeHistory[keyPath] = std::make_pair(1, currentTime);
        return false;
    }
    
    // Calcular tiempo desde último cambio
    ULARGE_INTEGER lastTime, nowTime;
    lastTime.LowPart = it->second.second.dwLowDateTime;
    lastTime.HighPart = it->second.second.dwHighDateTime;
    nowTime.LowPart = currentTime.dwLowDateTime;
    nowTime.HighPart = currentTime.dwHighDateTime;
    
    const ULONGLONG oneMinute = 60ULL * 10000000ULL; // 1 minuto en unidades de 100ns
    
    if (nowTime.QuadPart - lastTime.QuadPart < oneMinute) {
        // Misma clave cambiada en menos de 1 minuto
        it->second.first++;
        it->second.second = currentTime;
        
        // Si más de 3 cambios en 1 minuto, sospechoso
        return it->second.first > 3;
    } else {
        // Resetear contador
        it->second.first = 1;
        it->second.second = currentTime;
        return false;
    }
}

bool IsMaliciousPersistence(const RegistryChangeInfo& regInfo) {
    if (!regInfo.isAutoRun || regInfo.operation != REG_SET_VALUE) {
        return false;
    }
    
    // Verificar si el valor apunta a un ejecutable sospechoso
    std::wstring lowerValue = regInfo.newValueData;
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::towlower);
    
    // Patrones de persistencia maliciosa
    if (lowerValue.find(L".exe") == std::wstring::npos &&
        lowerValue.find(L".dll") == std::wstring::npos &&
        lowerValue.find(L".vbs") == std::wstring::npos &&
        lowerValue.find(L".js") == std::wstring::npos &&
        lowerValue.find(L".ps1") == std::wstring::npos) {
        return false;
    }
    
    // Verificar si es un proceso conocido del sistema
    if (IsKnownSystemProcess(regInfo.newValueData)) {
        return false;
    }
    
    // Verificar si está en ubicación temporal o sospechosa
    if (IsSuspiciousLocation(regInfo.newValueData)) {
        return true;
    }
    
    // Verificar si usa técnicas de ofuscación
    if (ContainsObfuscation(regInfo.newValueData)) {
        return true;
    }
    
    return false;
}

bool IsKnownSystemProcess(const std::wstring& filePath) {
    static const std::vector<std::wstring> systemPaths = {
        L"c:\\windows\\system32\\",
        L"c:\\windows\\syswow64\\",
        L"c:\\program files\\",
        L"c:\\program files (x86)\\",
        L"c:\\windows\\"
    };
    
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    for (const auto& sysPath : systemPaths) {
        if (lowerPath.find(sysPath) == 0) {
            return true;
        }
    }
    
    return false;
}

bool IsSuspiciousLocation(const std::wstring& filePath) {
    static const std::vector<std::wstring> suspiciousLocations = {
        L"temp\\", L"tmp\\", L"appdata\\local\\temp\\",
        L"downloads\\", L"desktop\\", L"documents\\",
        L"recycler\\", L"$recycle.bin\\",
        L"appdata\\roaming\\", L"appdata\\local\\"
    };
    
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    for (const auto& location : suspiciousLocations) {
        if (lowerPath.find(location) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool ContainsObfuscation(const std::wstring& valueData) {
    if (valueData.empty()) {
        return false;
    }
    
    std::wstring lowerData = valueData;
    std::transform(lowerData.begin(), lowerData.end(), lowerData.begin(), ::towlower);
    
    // Técnicas de ofuscación comunes
    if (lowerData.find(L"frombase64") != std::wstring::npos ||
        lowerData.find(L"iex") != std::wstring::npos ||
        lowerData.find(L"invoke-expression") != std::wstring::npos ||
        lowerData.find(L"-enc") != std::wstring::npos ||
        lowerData.find(L"decode") != std::wstring::npos ||
        lowerData.find(L"decompress") != std::wstring::npos) {
        return true;
    }
    
    // Muchos caracteres especiales o codificación
    int specialCharCount = 0;
    int totalChars = 0;
    
    for (wchar_t c : lowerData) {
        totalChars++;
        if (!iswalnum(c) && c != L'\\' && c != L':' && c != L'.' && c != L' ' && c != L'-' && c != L'_') {
            specialCharCount++;
        }
    }
    
    if (totalChars > 0 && (float)specialCharCount / totalChars > 0.3f) {
        return true; // Más del 30% caracteres especiales
    }
    
    return false;
}

void GenerateSensitiveRegistryEvent(const RegistryEvent& originalEvent, const std::wstring& reason) {
    RegistryEvent event = originalEvent;
    event.eventType = EventType::SENSITIVE_REGISTRY_ACCESS;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring sensitiveInfo = L",\"sensitivityReason\":\"" + EscapeJsonString(reason) + L"\"";
        json.insert(pos, sensitiveInfo);
    }
    
    SendSensitiveEventToManagedCode(json);
}

void GenerateSuspiciousRegistryEvent(const RegistryEvent& originalEvent) {
    RegistryEvent event = originalEvent;
    event.eventType = EventType::SUSPICIOUS_REGISTRY_CHANGE;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring suspicionInfo = L",\"suspicionReason\":\"";
        
        if (event.registryInfo.isAutoRun) {
            suspicionInfo += L"Auto-run registry key modification";
        } else if (event.registryInfo.isSystemKey && !IsPrivilegedProcess(event.registryInfo.processName)) {
            suspicionInfo += L"Non-privileged process modifying system key";
        } else if (ContainsSuspiciousData(event.registryInfo.newValueData)) {
            suspicionInfo += L"Suspicious data in registry value";
        } else if (ContainsSuspiciousValueName(event.registryInfo.valueName)) {
            suspicionInfo += L"Suspicious registry value name";
        } else {
            suspicionInfo += L"Frequent registry modifications";
        }
        
        suspicionInfo += L"\"";
        json.insert(pos, suspicionInfo);
    }
    
    SendSuspiciousEventToManagedCode(json);
}

void GeneratePersistenceAlert(const RegistryEvent& originalEvent) {
    RegistryEvent event = originalEvent;
    event.eventType = EventType::MALICIOUS_PERSISTENCE;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring persistenceInfo = L",\"persistenceDetails\":{";
        persistenceInfo += L"\"technique\":\"Registry Auto-run\",";
        persistenceInfo += L"\"target\":\"" + EscapeJsonString(event.registryInfo.registryPath) + L"\",";
        persistenceInfo += L"\"executablePath\":\"" + EscapeJsonString(event.registryInfo.newValueData) + L"\",";
        persistenceInfo += L"\"riskLevel\":\"High\"";
        persistenceInfo += L"}";
        json.insert(pos, persistenceInfo);
    }
    
    SendPersistenceAlertToManagedCode(json);
}

void EnqueueEvent(const RegistryEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (g_eventQueue.size() < MAX_EVENT_QUEUE_SIZE) {
        g_eventQueue.push(event);
        g_totalEventsProcessed++;
    } else {
        g_totalEventsDropped++;
    }
}

bool DequeueEvent(RegistryEvent& event) {
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
    // Enumerar claves de auto-inicio al inicio
    EnumerateAutoRunKeys();
    
    while (g_monitoringActive) {
        try {
            // Procesar eventos en cola
            ProcessQueuedEvents();
            
            // Realizar escaneo periódico
            PerformPeriodicScan();
            
            // Dormir para evitar uso excesivo de CPU
            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }
        catch (...) {
            // Continuar monitoreo después de error
        }
    }
}

void EnumerateAutoRunKeys() {
    // Enumerar claves de auto-inicio comunes
    static const std::vector<std::wstring> autoRunLocations = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    
    HKEY hKey;
    for (const auto& location : autoRunLocations) {
        std::wstring fullPath = L"HKEY_LOCAL_MACHINE\\" + location;
        
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, location.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[256];
            DWORD valueNameSize = 256;
            BYTE valueData[1024];
            DWORD valueDataSize = 1024;
            DWORD valueType;
            
            while (RegEnumValueW(hKey, index, valueName, &valueNameSize, 
                                nullptr, &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
                
                RegistryEvent event;
                event.eventType = EventType::REGISTRY_AUTORUN_EXISTING;
                GetSystemTimeAsFileTime(&event.eventTime);
                event.sourceModule = L"RegistrySensor";
                
                event.registryInfo.registryPath = fullPath;
                event.registryInfo.valueName = valueName;
                event.registryInfo.isAutoRun = true;
                event.registryInfo.isSystemKey = true;
                
                // Convertir datos según tipo
                if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                    event.registryInfo.newValueData = reinterpret_cast<wchar_t*>(valueData);
                } else if (valueType == REG_DWORD) {
                    DWORD dwValue = *reinterpret_cast<DWORD*>(valueData);
                    event.registryInfo.newValueData = std::to_wstring(dwValue);
                }
                
                event.registryInfo.valueType = valueType;
                
                // Cachear
                {
                    std::lock_guard<std::mutex> lock(g_registryCacheMutex);
                    g_registryCache[fullPath + L"\\" + valueName] = event.registryInfo;
                }
                
                // Encolar
                EnqueueEvent(event);
                
                // Resetear buffers
                index++;
                valueNameSize = 256;
                valueDataSize = 1024;
            }
            
            RegCloseKey(hKey);
        }
    }
}

void ProcessQueuedEvents() {
    RegistryEvent event;
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

void FormatAndSendEvent(const RegistryEvent& event) {
    std::wstring jsonEvent = FormatEventToJson(event);
    SendEventToManagedCode(jsonEvent);
}

std::wstring FormatEventToJson(const RegistryEvent& event) {
    SYSTEMTIME sysTime;
    FileTimeToSystemTime(&event.eventTime, &sysTime);
    
    wchar_t timeBuffer[64];
    swprintf_s(timeBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    std::wstring json = L"{";
    json += L"\"eventType\":\"" + std::to_wstring(static_cast<int>(event.eventType)) + L"\",";
    json += L"\"timestamp\":\"" + std::wstring(timeBuffer) + L"\",";
    json += L"\"source\":\"" + event.sourceModule + L"\",";
    json += L"\"processId\":" + std::to_wstring(event.registryInfo.processId) + L",";
    json += L"\"processName\":\"" + EscapeJsonString(event.registryInfo.processName) + L"\",";
    json += L"\"registryPath\":\"" + EscapeJsonString(event.registryInfo.registryPath) + L"\",";
    
    if (!event.registryInfo.valueName.empty()) {
        json += L"\"valueName\":\"" + EscapeJsonString(event.registryInfo.valueName) + L"\",";
    }
    
    if (!event.registryInfo.newValueData.empty()) {
        json += L"\"newValueData\":\"" + EscapeJsonString(event.registryInfo.newValueData) + L"\",";
    }
    
    if (!event.registryInfo.oldValueData.empty()) {
        json += L"\"oldValueData\":\"" + EscapeJsonString(event.registryInfo.oldValueData) + L"\",";
    }
    
    json += L"\"operation\":" + std::to_wstring(static_cast<int>(event.registryInfo.operation)) + L",";
    json += L"\"valueType\":" + std::to_wstring(event.registryInfo.valueType) + L",";
    json += L"\"userName\":\"" + EscapeJsonString(event.registryInfo.userName) + L"\",";
    json += L"\"isSystemKey\":" + std::wstring(event.registryInfo.isSystemKey ? L"true" : L"false") + L",";
    json += L"\"isAutoRun\":" + std::wstring(event.registryInfo.isAutoRun ? L"true" : L"false");
    
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
        
        // Verificar integridad de claves críticas
        CheckCriticalRegistryKeys();
        
        // Detectar nuevas entradas de auto-inicio
        DetectNewAutoRunEntries();
        
        // Reportar estadísticas
        ReportStatistics();
    }
}

void CheckCriticalRegistryKeys() {
    // Claves críticas para verificar integridad
    static const std::vector<std::wstring> criticalKeys = {
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    };
    
    for (const auto& keyPath : criticalKeys) {
        VerifyRegistryKeyIntegrity(keyPath);
    }
}

void VerifyRegistryKeyIntegrity(const std::wstring& keyPath) {
    HKEY hKey;
    size_t pos = keyPath.find(L'\\');
    if (pos == std::wstring::npos) {
        return;
    }
    
    std::wstring rootKey = keyPath.substr(0, pos);
    std::wstring subKey = keyPath.substr(pos + 1);
    
    HKEY hRootKey = GetRootKeyFromString(rootKey);
    if (!hRootKey) {
        return;
    }
    
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Verificar permisos
        CheckRegistryKeyPermissions(hKey, keyPath);
        
        // Verificar valores
        CheckRegistryKeyValues(hKey, keyPath);
        
        RegCloseKey(hKey);
    } else {
        // Clave no existe o no se puede acceder
        GenerateRegistryIntegrityAlert(keyPath, L"Registry key missing or inaccessible");
    }
}

HKEY GetRootKeyFromString(const std::wstring& rootKey) {
    if (rootKey == L"HKEY_LOCAL_MACHINE") return HKEY_LOCAL_MACHINE;
    if (rootKey == L"HKEY_CURRENT_USER") return HKEY_CURRENT_USER;
    if (rootKey == L"HKEY_CLASSES_ROOT") return HKEY_CLASSES_ROOT;
    if (rootKey == L"HKEY_CURRENT_CONFIG") return HKEY_CURRENT_CONFIG;
    if (rootKey == L"HKEY_USERS") return HKEY_USERS;
    return nullptr;
}

void CheckRegistryKeyPermissions(HKEY hKey, const std::wstring& keyPath) {
    // Verificar permisos usando GetNamedSecurityInfo
    // Implementación simplificada
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD dwError = GetNamedSecurityInfoW(keyPath.c_str(), SE_REGISTRY_KEY,
                                         OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                         nullptr, nullptr, nullptr, nullptr, &pSD);
    
    if (dwError == ERROR_SUCCESS && pSD) {
        // Analizar permisos (simplificado)
        BOOL bDaclPresent = FALSE;
        BOOL bDaclDefaulted = FALSE;
        PACL pDacl = nullptr;
        
        if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
            if (!bDaclPresent || pDacl == nullptr) {
                // Sin DACL - permisos abiertos
                GenerateRegistryIntegrityAlert(keyPath, L"No DACL present - open permissions");
            }
        }
        
        LocalFree(pSD);
    }
}

void CheckRegistryKeyValues(HKEY hKey, const std::wstring& keyPath) {
    DWORD index = 0;
    wchar_t valueName[256];
    DWORD valueNameSize = 256;
    
    while (RegEnumValueW(hKey, index, valueName, &valueNameSize, 
                        nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        
        // Verificar valores sospechosos
        std::wstring fullValuePath = keyPath + L"\\" + valueName;
        if (ContainsSuspiciousValueName(valueName)) {
            GenerateRegistryIntegrityAlert(fullValuePath, L"Suspicious value name detected");
        }
        
        index++;
        valueNameSize = 256;
    }
}

void DetectNewAutoRunEntries() {
    // Comparar con caché para detectar nuevas entradas
    std::lock_guard<std::mutex> lock(g_registryCacheMutex);
    
    // Escanear claves de auto-inicio actuales
    // (Implementación similar a EnumerateAutoRunKeys pero comparando con caché)
    // Código omitido por brevedad
}

void GenerateRegistryIntegrityAlert(const std::wstring& keyPath, const std::wstring& reason) {
    RegistryEvent event;
    event.eventType = EventType::REGISTRY_INTEGRITY_ALERT;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"RegistrySensor";
    
    event.registryInfo.registryPath = keyPath;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring integrityInfo = L",\"integrityIssue\":\"" + EscapeJsonString(reason) + L"\"";
        json.insert(pos, integrityInfo);
    }
    
    SendIntegrityAlertToManagedCode(json);
}

void ReportStatistics() {
    size_t processed = g_totalEventsProcessed.load();
    size_t dropped = g_totalEventsDropped.load();
    size_t cacheSize = 0;
    
    {
        std::lock_guard<std::mutex> lock(g_registryCacheMutex);
        cacheSize = g_registryCache.size();
    }
    
    wchar_t statsBuffer[256];
    swprintf_s(statsBuffer, 
        L"{\"type\":\"RegistrySensorStats\",\"processed\":%zu,\"dropped\":%zu,\"cacheSize\":%zu}",
        processed, dropped, cacheSize);
    
    SendStatisticsToManagedCode(statsBuffer);
}

// Funciones de inicialización/limpieza
bool InitializeRegistrySensor() {
    try {
        // Inicializar driver de registro
        g_registryDriver = new RegistryDriver();
        if (!g_registryDriver->Initialize()) {
            delete g_registryDriver;
            g_registryDriver = nullptr;
            return false;
        }
        
        // Registrar callbacks
        g_registryDriver->RegistryCreateKeyCallback(RegistryCreateKeyCallback, nullptr);
        g_registryDriver->RegistryDeleteKeyCallback(RegistryDeleteKeyCallback, nullptr);
        g_registryDriver->RegistrySetValueCallback(RegistrySetValueCallback, nullptr);
        g_registryDriver->RegistryDeleteValueCallback(RegistryDeleteValueCallback, nullptr);
        g_registryDriver->RegistryRenameKeyCallback(RegistryRenameKeyCallback, nullptr);
        
        // Configurar claves sensibles a monitorear
        ConfigureSensitiveKeys();
        
        // Iniciar monitoreo
        g_monitoringActive = true;
        g_monitoringThread = std::thread(MonitoringThread);
        
        return true;
    }
    catch (...) {
        return false;
    }
}

void ConfigureSensitiveKeys() {
    // Agregar claves sensibles para monitoreo especial
    g_sensitiveKeys = {
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"HKEY_LOCAL_MACHINE\\SAM",
        L"HKEY_LOCAL_MACHINE\\SECURITY",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    };
}

void CleanupRegistrySensor() {
    try {
        // Detener monitoreo
        g_monitoringActive = false;
        
        if (g_monitoringThread.joinable()) {
            g_monitoringThread.join();
        }
        
        // Limpiar driver
        if (g_registryDriver) {
            g_registryDriver->Cleanup();
            delete g_registryDriver;
            g_registryDriver = nullptr;
        }
        
        // Limpiar colas y cachés
        {
            std::lock_guard<std::mutex> lock1(g_eventQueueMutex);
            std::queue<RegistryEvent> emptyQueue;
            std::swap(g_eventQueue, emptyQueue);
        }
        
        {
            std::lock_guard<std::mutex> lock2(g_registryCacheMutex);
            g_registryCache.clear();
        }
        
        g_monitoredKeys.clear();
        g_sensitiveKeys.clear();
    }
    catch (...) {
        // Ignorar errores durante limpieza
    }
}

// Exportaciones para C#
extern "C" __declspec(dllexport) bool __stdcall StartRegistryMonitoring() {
    return InitializeRegistrySensor();
}

extern "C" __declspec(dllexport) void __stdcall StopRegistryMonitoring() {
    CleanupRegistrySensor();
}

extern "C" __declspec(dllexport) size_t __stdcall GetRegistryEventCount() {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    return g_eventQueue.size();
}

extern "C" __declspec(dllexport) bool __stdcall GetRegistryEvent(wchar_t* buffer, size_t bufferSize) {
    RegistryEvent event;
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