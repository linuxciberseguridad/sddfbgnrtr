#include "pch.h"
#include "NetworkSensor.h"
#include "NetworkDriver.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wininet.h>
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
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

namespace BWP {
namespace Enterprise {
namespace Sensors {

// Constantes
constexpr DWORD MONITORING_INTERVAL_MS = 100;
constexpr size_t MAX_EVENT_QUEUE_SIZE = 10000;
constexpr DWORD DNS_CACHE_SIZE = 1000;

// Estructuras de datos
struct NetworkConnectionInfo {
    DWORD processId;
    std::wstring processName;
    std::wstring localAddress;
    USHORT localPort;
    std::wstring remoteAddress;
    USHORT remotePort;
    ULONG protocol; // TCP=6, UDP=17
    ULONG state;    // Para TCP: ESTABLISHED=1, LISTENING=2, etc.
    FILETIME connectionTime;
    ULONGLONG bytesSent;
    ULONGLONG bytesReceived;
    std::wstring userName;
    bool isOutbound;
    std::wstring dnsName; // Resolución DNS si está disponible
};

struct DNSQueryInfo {
    std::wstring queryName;
    std::wstring resolvedAddress;
    DWORD processId;
    std::wstring processName;
    FILETIME queryTime;
    USHORT queryType; // A=1, AAAA=28, CNAME=5, etc.
};

struct NetworkEvent {
    EventType eventType;
    union {
        NetworkConnectionInfo connectionInfo;
        DNSQueryInfo dnsInfo;
    };
    FILETIME eventTime;
    std::wstring sourceModule;
};

// Variables globales
std::atomic<bool> g_monitoringActive{false};
std::thread g_monitoringThread;
std::mutex g_eventQueueMutex;
std::queue<NetworkEvent> g_eventQueue;
std::mutex g_connectionCacheMutex;
std::map<ULONG_PTR, NetworkConnectionInfo> g_connectionCache; // Key: Connection ID
std::mutex g_dnsCacheMutex;
std::map<std::wstring, std::wstring> g_dnsCache; // DNS name -> IP
NetworkDriver* g_networkDriver = nullptr;
std::atomic<size_t> g_totalEventsProcessed{0};
std::atomic<size_t> g_totalEventsDropped{0};

// Callbacks del driver de red
VOID TcpConnectCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PWSTR RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ ULONG State,
    _In_ PVOID Context
) {
    try {
        NetworkEvent event;
        event.eventType = EventType::TCP_CONNECTION;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"NetworkDriver";
        
        event.connectionInfo.processId = ProcessId;
        event.connectionInfo.processName = ProcessName;
        event.connectionInfo.localAddress = LocalAddress;
        event.connectionInfo.localPort = LocalPort;
        event.connectionInfo.remoteAddress = RemoteAddress;
        event.connectionInfo.remotePort = RemotePort;
        event.connectionInfo.protocol = 6; // TCP
        event.connectionInfo.state = State;
        event.connectionInfo.isOutbound = (State == 1); // ESTABLISHED generalmente es outbound
        
        GetSystemTimeAsFileTime(&event.connectionInfo.connectionTime);
        event.connectionInfo.userName = GetProcessUserName(ProcessId);
        
        // Intentar resolver DNS para dirección remota
        if (!event.connectionInfo.remoteAddress.empty() && 
            event.connectionInfo.remoteAddress != L"0.0.0.0" &&
            event.connectionInfo.remoteAddress != L"::") {
            event.connectionInfo.dnsName = ResolveDNS(event.connectionInfo.remoteAddress);
        }
        
        // Cachear conexión
        ULONG_PTR connectionId = GenerateConnectionId(event.connectionInfo);
        {
            std::lock_guard<std::mutex> lock(g_connectionCacheMutex);
            g_connectionCache[connectionId] = event.connectionInfo;
        }
        
        // Verificar si es conexión sospechosa
        if (IsSuspiciousConnection(event.connectionInfo)) {
            GenerateSuspiciousConnectionEvent(event);
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID UdpActivityCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PWSTR RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ PVOID Context
) {
    try {
        NetworkEvent event;
        event.eventType = EventType::UDP_ACTIVITY;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"NetworkDriver";
        
        event.connectionInfo.processId = ProcessId;
        event.connectionInfo.processName = ProcessName;
        event.connectionInfo.localAddress = LocalAddress;
        event.connectionInfo.localPort = LocalPort;
        event.connectionInfo.remoteAddress = RemoteAddress;
        event.connectionInfo.remotePort = RemotePort;
        event.connectionInfo.protocol = 17; // UDP
        event.connectionInfo.isOutbound = true; // UDP generalmente es outbound
        
        GetSystemTimeAsFileTime(&event.connectionInfo.connectionTime);
        event.connectionInfo.userName = GetProcessUserName(ProcessId);
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID DnsQueryCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR QueryName,
    _In_ PWSTR ResolvedAddress,
    _In_ USHORT QueryType,
    _In_ PVOID Context
) {
    try {
        NetworkEvent event;
        event.eventType = EventType::DNS_QUERY;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"NetworkDriver";
        
        event.dnsInfo.processId = ProcessId;
        event.dnsInfo.processName = ProcessName;
        event.dnsInfo.queryName = QueryName;
        event.dnsInfo.resolvedAddress = ResolvedAddress;
        event.dnsInfo.queryType = QueryType;
        GetSystemTimeAsFileTime(&event.dnsInfo.queryTime);
        
        // Cachear resolución DNS
        if (!event.dnsInfo.queryName.empty() && !event.dnsInfo.resolvedAddress.empty()) {
            std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
            g_dnsCache[event.dnsInfo.queryName] = event.dnsInfo.resolvedAddress;
            
            // Limitar tamaño del caché
            if (g_dnsCache.size() > DNS_CACHE_SIZE) {
                g_dnsCache.erase(g_dnsCache.begin());
            }
        }
        
        // Verificar si es consulta DNS sospechosa
        if (IsSuspiciousDnsQuery(event.dnsInfo)) {
            GenerateSuspiciousDnsEvent(event);
        }
        
        // Encolar evento
        EnqueueEvent(event);
    }
    catch (...) {
        // Log error interno
    }
}

VOID DataTransferCallback(
    _In_ DWORD ProcessId,
    _In_ PWSTR ProcessName,
    _In_ PWSTR RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ ULONGLONG BytesSent,
    _In_ ULONGLONG BytesReceived,
    _In_ PVOID Context
) {
    try {
        NetworkEvent event;
        event.eventType = EventType::DATA_TRANSFER;
        GetSystemTimeAsFileTime(&event.eventTime);
        event.sourceModule = L"NetworkDriver";
        
        event.connectionInfo.processId = ProcessId;
        event.connectionInfo.processName = ProcessName;
        event.connectionInfo.remoteAddress = RemoteAddress;
        event.connectionInfo.remotePort = RemotePort;
        event.connectionInfo.bytesSent = BytesSent;
        event.connectionInfo.bytesReceived = BytesReceived;
        
        // Actualizar caché de conexiones
        UpdateConnectionStats(ProcessId, RemoteAddress, RemotePort, BytesSent, BytesReceived);
        
        // Verificar transferencia sospechosa
        if (IsSuspiciousDataTransfer(BytesSent, BytesReceived)) {
            GenerateSuspiciousDataTransferEvent(event);
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

std::wstring ResolveDNS(const std::wstring& ipAddress) {
    // Primero verificar caché
    {
        std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
        for (const auto& kvp : g_dnsCache) {
            if (kvp.second == ipAddress) {
                return kvp.first;
            }
        }
    }
    
    // Intentar resolución inversa
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
        sockaddr_in sa;
        sa.sin_family = AF_INET;
        InetPtonW(AF_INET, ipAddress.c_str(), &sa.sin_addr);
        
        wchar_t hostname[NI_MAXHOST];
        if (getnameinfo((sockaddr*)&sa, sizeof(sa), 
                       (PWSTR)hostname, NI_MAXHOST, 
                       nullptr, 0, 0) == 0) {
            std::wstring result = hostname;
            WSACleanup();
            
            // Cachear resultado
            {
                std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
                g_dnsCache[result] = ipAddress;
            }
            
            return result;
        }
        WSACleanup();
    }
    
    return L"";
}

ULONG_PTR GenerateConnectionId(const NetworkConnectionInfo& conn) {
    // Generar ID único basado en conexión
    std::wstringstream ss;
    ss << conn.processId << L"_" 
       << conn.localAddress << L":" << conn.localPort << L"_"
       << conn.remoteAddress << L":" << conn.remotePort << L"_"
       << conn.protocol;
    
    std::hash<std::wstring> hasher;
    return hasher(ss.str());
}

bool IsSuspiciousConnection(const NetworkConnectionInfo& conn) {
    // Heurística 1: Conexiones a puertos conocidos sospechosos
    static const std::vector<USHORT> suspiciousPorts = {
        4444,  // Meterpreter
        5555,  // Android ADB
        6666, 6667, 6668, 6669,  // IRC
        31337, // Back Orifice
        12345, 12346, // NetBus
        20034, // NetBus Pro
        27374, // SubSeven
        54320, // Back Orifice 2000
        65506   // PhatBot
    };
    
    for (USHORT port : suspiciousPorts) {
        if (conn.remotePort == port) {
            return true;
        }
    }
    
    // Heurística 2: Conexiones a IPs en rangos sospechosos
    if (IsSuspiciousIP(conn.remoteAddress)) {
        return true;
    }
    
    // Heurística 3: Conexiones desde procesos no comunes a puertos no estándar
    if (IsUnusualProcessForNetwork(conn.processName) && conn.remotePort > 1024) {
        return true;
    }
    
    return false;
}

bool IsSuspiciousIP(const std::wstring& ipAddress) {
    // Lista de IPs/rangos sospechosos (simplificada)
    static const std::vector<std::wstring> suspiciousRanges = {
        L"10.", L"192.168.", L"172.16.", L"172.17.", L"172.18.", L"172.19.",
        L"172.20.", L"172.21.", L"172.22.", L"172.23.", L"172.24.", L"172.25.",
        L"172.26.", L"172.27.", L"172.28.", L"172.29.", L"172.30.", L"172.31."
    };
    
    // No marcar IPs internas como sospechosas (a menos que sea tráfico saliente anómalo)
    for (const auto& range : suspiciousRanges) {
        if (ipAddress.find(range) == 0) {
            return false; // IP interna, no sospechosa por sí sola
        }
    }
    
    // Verificar si es IP reservada o bogon
    if (ipAddress == L"0.0.0.0" || ipAddress == L"127.0.0.1" || 
        ipAddress == L"::" || ipAddress == L"::1") {
        return false;
    }
    
    return false;
}

bool IsUnusualProcessForNetwork(const std::wstring& processName) {
    // Lista de procesos que normalmente no hacen conexiones de red
    static const std::vector<std::wstring> unusualProcesses = {
        L"notepad.exe", L"calc.exe", L"mspaint.exe", L"wordpad.exe",
        L"explorer.exe", L"svchost.exe", L"services.exe", L"lsass.exe",
        L"winlogon.exe", L"csrss.exe", L"smss.exe"
    };
    
    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    
    for (const auto& proc : unusualProcesses) {
        if (lowerName == proc) {
            return true;
        }
    }
    
    return false;
}

bool IsSuspiciousDnsQuery(const DNSQueryInfo& dnsInfo) {
    // Heurística 1: Nombres de dominio sospechosos
    static const std::vector<std::wstring> suspiciousDomains = {
        L"pastebin.com", L"github.com", L"bitbucket.org",
        L"dropbox.com", L"drive.google.com", L"mega.nz",
        L"telegram.org", L"discord.com", L"slack.com",
        L"commandandcontrol", L"c2server", L"malware",
        L"exploit", L"payload", L"backdoor"
    };
    
    std::wstring lowerQuery = dnsInfo.queryName;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::towlower);
    
    for (const auto& domain : suspiciousDomains) {
        if (lowerQuery.find(domain) != std::wstring::npos) {
            return true;
        }
    }
    
    // Heurística 2: Dominios DGA-like (Generated Domain Names)
    if (IsDGADomain(lowerQuery)) {
        return true;
    }
    
    // Heurística 3: Consultas TXT o tipos inusuales
    if (dnsInfo.queryType == 16 || dnsInfo.queryType == 999) { // TXT o tipo personalizado
        return true;
    }
    
    return false;
}

bool IsDGADomain(const std::wstring& domain) {
    // Detección simplificada de dominios generados por algoritmos
    // Características: largos, con muchos números y guiones, sin sentido
    
    if (domain.length() > 30) {
        return true;
    }
    
    int digitCount = 0;
    int hyphenCount = 0;
    
    for (wchar_t c : domain) {
        if (iswdigit(c)) digitCount++;
        if (c == L'-') hyphenCount++;
    }
    
    // Si tiene muchos dígitos o guiones, podría ser DGA
    if (digitCount > 5 || hyphenCount > 3) {
        return true;
    }
    
    return false;
}

bool IsSuspiciousDataTransfer(ULONGLONG bytesSent, ULONGLONG bytesReceived) {
    // Heurística: Transferencias grandes o asimétricas
    const ULONGLONG LARGE_TRANSFER = 10 * 1024 * 1024; // 10MB
    const ULONGLONG ASYMMETRIC_RATIO = 10; // 10:1 ratio
    
    if (bytesSent > LARGE_TRANSFER || bytesReceived > LARGE_TRANSFER) {
        return true;
    }
    
    if (bytesSent > 0 && bytesReceived > 0) {
        ULONGLONG ratio = (bytesSent > bytesReceived) ? 
                         bytesSent / bytesReceived : 
                         bytesReceived / bytesSent;
        
        if (ratio > ASYMMETRIC_RATIO) {
            return true;
        }
    }
    
    return false;
}

void UpdateConnectionStats(DWORD processId, const std::wstring& remoteAddress, 
                          USHORT remotePort, ULONGLONG bytesSent, ULONGLONG bytesReceived) {
    std::lock_guard<std::mutex> lock(g_connectionCacheMutex);
    
    for (auto& kvp : g_connectionCache) {
        if (kvp.second.processId == processId &&
            kvp.second.remoteAddress == remoteAddress &&
            kvp.second.remotePort == remotePort) {
            kvp.second.bytesSent += bytesSent;
            kvp.second.bytesReceived += bytesReceived;
            break;
        }
    }
}

void GenerateSuspiciousConnectionEvent(const NetworkEvent& originalEvent) {
    NetworkEvent event = originalEvent;
    event.eventType = EventType::SUSPICIOUS_CONNECTION;
    
    // Añadir información adicional
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring suspicionInfo = L",\"suspicionReason\":\"";
        
        if (IsSuspiciousPort(event.connectionInfo.remotePort)) {
            suspicionInfo += L"Suspicious port " + std::to_wstring(event.connectionInfo.remotePort);
        } else if (IsSuspiciousIP(event.connectionInfo.remoteAddress)) {
            suspicionInfo += L"Suspicious IP range";
        } else if (IsUnusualProcessForNetwork(event.connectionInfo.processName)) {
            suspicionInfo += L"Unusual process making network connection";
        }
        
        suspicionInfo += L"\"";
        json.insert(pos, suspicionInfo);
    }
    
    SendSuspiciousEventToManagedCode(json);
}

void GenerateSuspiciousDnsEvent(const NetworkEvent& originalEvent) {
    NetworkEvent event = originalEvent;
    event.eventType = EventType::SUSPICIOUS_DNS;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring suspicionInfo = L",\"suspicionReason\":\"";
        
        if (IsDGADomain(event.dnsInfo.queryName)) {
            suspicionInfo += L"Possible DGA domain";
        } else {
            suspicionInfo += L"Suspicious domain name";
        }
        
        suspicionInfo += L"\"";
        json.insert(pos, suspicionInfo);
    }
    
    SendSuspiciousEventToManagedCode(json);
}

void GenerateSuspiciousDataTransferEvent(const NetworkEvent& originalEvent) {
    NetworkEvent event = originalEvent;
    event.eventType = EventType::SUSPICIOUS_DATA_TRANSFER;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring transferInfo = L",\"transferAnalysis\":{";
        transferInfo += L"\"bytesSent\":" + std::to_wstring(event.connectionInfo.bytesSent) + L",";
        transferInfo += L"\"bytesReceived\":" + std::to_wstring(event.connectionInfo.bytesReceived) + L",";
        
        if (event.connectionInfo.bytesSent > 10 * 1024 * 1024) {
            transferInfo += L"\"reason\":\"Large data transfer\"";
        } else {
            transferInfo += L"\"reason\":\"Asymmetric data transfer\"";
        }
        
        transferInfo += L"}";
        json.insert(pos, transferInfo);
    }
    
    SendSuspiciousEventToManagedCode(json);
}

void EnqueueEvent(const NetworkEvent& event) {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    
    if (g_eventQueue.size() < MAX_EVENT_QUEUE_SIZE) {
        g_eventQueue.push(event);
        g_totalEventsProcessed++;
    } else {
        g_totalEventsDropped++;
    }
}

bool DequeueEvent(NetworkEvent& event) {
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
    // Enumerar conexiones existentes al inicio
    EnumerateExistingConnections();
    
    while (g_monitoringActive) {
        try {
            // Procesar eventos en cola
            ProcessQueuedEvents();
            
            // Realizar escaneo periódico
            PerformPeriodicScan();
            
            // Limpiar cachés
            CleanupCaches();
            
            // Dormir para evitar uso excesivo de CPU
            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }
        catch (...) {
            // Continuar monitoreo después de error
        }
    }
}

void EnumerateExistingConnections() {
    // Usar GetExtendedTcpTable y GetExtendedUdpTable para enumerar conexiones existentes
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    DWORD dwSize = 0;
    
    // TCP connections
    if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, 
                           TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pTcpTable) {
            if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, 
                                   TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
                    
                    NetworkEvent event;
                    event.eventType = EventType::TCP_CONNECTION_EXISTING;
                    GetSystemTimeAsFileTime(&event.eventTime);
                    event.sourceModule = L"NetworkSensor";
                    
                    event.connectionInfo.processId = row.dwOwningPid;
                    event.connectionInfo.localAddress = FormatIPAddress(row.dwLocalAddr);
                    event.connectionInfo.localPort = ntohs((u_short)row.dwLocalPort);
                    event.connectionInfo.remoteAddress = FormatIPAddress(row.dwRemoteAddr);
                    event.connectionInfo.remotePort = ntohs((u_short)row.dwRemotePort);
                    event.connectionInfo.protocol = 6;
                    event.connectionInfo.state = row.dwState;
                    
                    // Obtener nombre del proceso
                    wchar_t processName[MAX_PATH] = {0};
                    if (GetProcessName(row.dwOwningPid, processName, MAX_PATH)) {
                        event.connectionInfo.processName = processName;
                    }
                    
                    // Cachear conexión
                    ULONG_PTR connectionId = GenerateConnectionId(event.connectionInfo);
                    {
                        std::lock_guard<std::mutex> lock(g_connectionCacheMutex);
                        g_connectionCache[connectionId] = event.connectionInfo;
                    }
                    
                    // Encolar evento
                    EnqueueEvent(event);
                }
            }
            free(pTcpTable);
        }
    }
    
    // Similar para UDP (código omitido por brevedad)
}

std::wstring FormatIPAddress(DWORD ip) {
    IN_ADDR addr;
    addr.S_un.S_addr = ip;
    
    wchar_t ipBuffer[16];
    InetNtopW(AF_INET, &addr, ipBuffer, 16);
    
    return std::wstring(ipBuffer);
}

void ProcessQueuedEvents() {
    NetworkEvent event;
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

void FormatAndSendEvent(const NetworkEvent& event) {
    std::wstring jsonEvent = FormatEventToJson(event);
    SendEventToManagedCode(jsonEvent);
}

std::wstring FormatEventToJson(const NetworkEvent& event) {
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
    
    if (event.eventType == EventType::TCP_CONNECTION || 
        event.eventType == EventType::UDP_ACTIVITY ||
        event.eventType == EventType::DATA_TRANSFER ||
        event.eventType == EventType::SUSPICIOUS_CONNECTION ||
        event.eventType == EventType::SUSPICIOUS_DATA_TRANSFER ||
        event.eventType == EventType::TCP_CONNECTION_EXISTING) {
        
        // Formato para eventos de conexión
        json += L"\"processId\":" + std::to_wstring(event.connectionInfo.processId) + L",";
        json += L"\"processName\":\"" + EscapeJsonString(event.connectionInfo.processName) + L"\",";
        json += L"\"localAddress\":\"" + EscapeJsonString(event.connectionInfo.localAddress) + L"\",";
        json += L"\"localPort\":" + std::to_wstring(event.connectionInfo.localPort) + L",";
        json += L"\"remoteAddress\":\"" + EscapeJsonString(event.connectionInfo.remoteAddress) + L"\",";
        json += L"\"remotePort\":" + std::to_wstring(event.connectionInfo.remotePort) + L",";
        json += L"\"protocol\":" + std::to_wstring(event.connectionInfo.protocol) + L",";
        json += L"\"state\":" + std::to_wstring(event.connectionInfo.state) + L",";
        json += L"\"isOutbound\":" + std::wstring(event.connectionInfo.isOutbound ? L"true" : L"false") + L",";
        json += L"\"userName\":\"" + EscapeJsonString(event.connectionInfo.userName) + L"\",";
        
        if (!event.connectionInfo.dnsName.empty()) {
            json += L"\"dnsName\":\"" + EscapeJsonString(event.connectionInfo.dnsName) + L"\",";
        }
        
        if (event.connectionInfo.bytesSent > 0 || event.connectionInfo.bytesReceived > 0) {
            json += L"\"bytesSent\":" + std::to_wstring(event.connectionInfo.bytesSent) + L",";
            json += L"\"bytesReceived\":" + std::to_wstring(event.connectionInfo.bytesReceived) + L",";
        }
        
    } else if (event.eventType == EventType::DNS_QUERY || 
               event.eventType == EventType::SUSPICIOUS_DNS) {
        
        // Formato para eventos DNS
        json += L"\"processId\":" + std::to_wstring(event.dnsInfo.processId) + L",";
        json += L"\"processName\":\"" + EscapeJsonString(event.dnsInfo.processName) + L"\",";
        json += L"\"queryName\":\"" + EscapeJsonString(event.dnsInfo.queryName) + L"\",";
        json += L"\"resolvedAddress\":\"" + EscapeJsonString(event.dnsInfo.resolvedAddress) + L"\",";
        json += L"\"queryType\":" + std::to_wstring(event.dnsInfo.queryType) + L",";
    }
    
    // Eliminar última coma si existe
    if (json.back() == L',') {
        json.pop_back();
    }
    
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
    
    // Escanear cada 2 minutos
    if (currentTick - lastScanTick > 120000) {
        lastScanTick = currentTick;
        
        // Verificar conexiones anómalas
        CheckForAnomalousConnections();
        
        // Verificar DNS poisoning
        CheckDnsCacheConsistency();
        
        // Reportar estadísticas
        ReportStatistics();
    }
}

void CheckForAnomalousConnections() {
    std::lock_guard<std::mutex> lock(g_connectionCacheMutex);
    
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);
    
    for (const auto& kvp : g_connectionCache) {
        const NetworkConnectionInfo& conn = kvp.second;
        
        // Verificar conexiones de larga duración (> 1 hora)
        ULARGE_INTEGER connTime, nowTime;
        connTime.LowPart = conn.connectionTime.dwLowDateTime;
        connTime.HighPart = conn.connectionTime.dwHighDateTime;
        nowTime.LowPart = currentTime.dwLowDateTime;
        nowTime.HighPart = currentTime.dwHighDateTime;
        
        const ULONGLONG oneHour = 3600ULL * 10000000ULL; // 1 hora en unidades de 100ns
        
        if (nowTime.QuadPart - connTime.QuadPart > oneHour) {
            GenerateLongConnectionEvent(conn);
        }
        
        // Verificar conexiones con mucho tráfico
        if (conn.bytesSent > 100 * 1024 * 1024 || // 100MB enviados
            conn.bytesReceived > 100 * 1024 * 1024) { // 100MB recibidos
            GenerateHighTrafficEvent(conn);
        }
    }
}

void CheckDnsCacheConsistency() {
    // Verificar inconsistencias en el caché DNS
    std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
    
    // Verificar múltiples IPs para el mismo dominio (posible DNS poisoning)
    std::map<std::wstring, std::vector<std::wstring>> domainToIPs;
    
    for (const auto& kvp : g_dnsCache) {
        domainToIPs[kvp.second].push_back(kvp.first);
    }
    
    for (const auto& kvp : domainToIPs) {
        if (kvp.second.size() > 3) { // Más de 3 dominios apuntando a misma IP
            GenerateDnsPoisoningAlert(kvp.first, kvp.second);
        }
    }
}

void CleanupCaches() {
    static DWORD lastCleanupTick = GetTickCount();
    DWORD currentTick = GetTickCount();
    
    // Limpiar cada 5 minutos
    if (currentTick - lastCleanupTick > 300000) {
        lastCleanupTick = currentTick;
        
        // Limpiar caché de conexiones antiguas (> 24 horas)
        {
            std::lock_guard<std::mutex> lock(g_connectionCacheMutex);
            FILETIME currentTime;
            GetSystemTimeAsFileTime(&currentTime);
            
            std::vector<ULONG_PTR> toRemove;
            
            for (const auto& kvp : g_connectionCache) {
                ULARGE_INTEGER connTime, nowTime;
                connTime.LowPart = kvp.second.connectionTime.dwLowDateTime;
                connTime.HighPart = kvp.second.connectionTime.dwHighDateTime;
                nowTime.LowPart = currentTime.dwLowDateTime;
                nowTime.HighPart = currentTime.dwHighDateTime;
                
                const ULONGLONG twentyFourHours = 24ULL * 3600ULL * 10000000ULL;
                
                if (nowTime.QuadPart - connTime.QuadPart > twentyFourHours) {
                    toRemove.push_back(kvp.first);
                }
            }
            
            for (ULONG_PTR id : toRemove) {
                g_connectionCache.erase(id);
            }
        }
        
        // Limpiar caché DNS antiguo (> 1 hora)
        {
            // Implementación simplificada
            // En producción, guardar timestamp con cada entrada
        }
    }
}

void GenerateLongConnectionEvent(const NetworkConnectionInfo& conn) {
    NetworkEvent event;
    event.eventType = EventType::LONG_CONNECTION;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"NetworkSensor";
    event.connectionInfo = conn;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring durationInfo = L",\"durationHours\":1"; // Simplificado
        json.insert(pos, durationInfo);
    }
    
    SendAnomalyEventToManagedCode(json);
}

void GenerateHighTrafficEvent(const NetworkConnectionInfo& conn) {
    NetworkEvent event;
    event.eventType = EventType::HIGH_TRAFFIC;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"NetworkSensor";
    event.connectionInfo = conn;
    
    std::wstring json = FormatEventToJson(event);
    
    size_t pos = json.rfind(L'}');
    if (pos != std::wstring::npos) {
        std::wstring trafficInfo = L",\"trafficAnalysis\":{";
        trafficInfo += L"\"totalBytes\":" + std::to_wstring(conn.bytesSent + conn.bytesReceived) + L",";
        trafficInfo += L"\"reason\":\"High volume data transfer\"";
        trafficInfo += L"}";
        json.insert(pos, trafficInfo);
    }
    
    SendAnomalyEventToManagedCode(json);
}

void GenerateDnsPoisoningAlert(const std::wstring& ip, const std::vector<std::wstring>& domains) {
    NetworkEvent event;
    event.eventType = EventType::DNS_POISONING_SUSPECTED;
    GetSystemTimeAsFileTime(&event.eventTime);
    event.sourceModule = L"NetworkSensor";
    
    std::wstring json = L"{";
    json += L"\"eventType\":\"" + std::to_wstring(static_cast<int>(EventType::DNS_POISONING_SUSPECTED)) + L"\",";
    
    SYSTEMTIME sysTime;
    FileTimeToSystemTime(&event.eventTime, &sysTime);
    wchar_t timeBuffer[64];
    swprintf_s(timeBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        sysTime.wYear, sysTime.wMonth, sysTime.wDay,
        sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
        sysTime.wMilliseconds);
    
    json += L"\"timestamp\":\"" + std::wstring(timeBuffer) + L"\",";
    json += L"\"source\":\"NetworkSensor\",";
    json += L"\"suspectedIP\":\"" + EscapeJsonString(ip) + L"\",";
    json += L"\"domainCount\":" + std::to_wstring(domains.size()) + L",";
    json += L"\"domains\":[";
    
    for (size_t i = 0; i < domains.size(); i++) {
        json += L"\"" + EscapeJsonString(domains[i]) + L"\"";
        if (i < domains.size() - 1) {
            json += L",";
        }
    }
    
    json += L"],";
    json += L"\"reason\":\"Multiple domains resolving to same IP, possible DNS poisoning\"";
    json += L"}";
    
    SendDnsAlertToManagedCode(json);
}

void ReportStatistics() {
    size_t processed = g_totalEventsProcessed.load();
    size_t dropped = g_totalEventsDropped.load();
    size_t connCacheSize = 0;
    size_t dnsCacheSize = 0;
    
    {
        std::lock_guard<std::mutex> lock1(g_connectionCacheMutex);
        connCacheSize = g_connectionCache.size();
    }
    
    {
        std::lock_guard<std::mutex> lock2(g_dnsCacheMutex);
        dnsCacheSize = g_dnsCache.size();
    }
    
    wchar_t statsBuffer[256];
    swprintf_s(statsBuffer, 
        L"{\"type\":\"NetworkSensorStats\",\"processed\":%zu,\"dropped\":%zu,\"connectionCache\":%zu,\"dnsCache\":%zu}",
        processed, dropped, connCacheSize, dnsCacheSize);
    
    SendStatisticsToManagedCode(statsBuffer);
}

// Funciones de inicialización/limpieza
bool InitializeNetworkSensor() {
    try {
        // Inicializar Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
        
        // Inicializar driver de red
        g_networkDriver = new NetworkDriver();
        if (!g_networkDriver->Initialize()) {
            delete g_networkDriver;
            g_networkDriver = nullptr;
            WSACleanup();
            return false;
        }
        
        // Registrar callbacks
        g_networkDriver->RegisterTcpConnectCallback(TcpConnectCallback, nullptr);
        g_networkDriver->RegisterUdpActivityCallback(UdpActivityCallback, nullptr);
        g_networkDriver->RegisterDnsQueryCallback(DnsQueryCallback, nullptr);
        g_networkDriver->RegisterDataTransferCallback(DataTransferCallback, nullptr);
        
        // Iniciar monitoreo
        g_monitoringActive = true;
        g_monitoringThread = std::thread(MonitoringThread);
        
        return true;
    }
    catch (...) {
        return false;
    }
}

void CleanupNetworkSensor() {
    try {
        // Detener monitoreo
        g_monitoringActive = false;
        
        if (g_monitoringThread.joinable()) {
            g_monitoringThread.join();
        }
        
        // Limpiar driver
        if (g_networkDriver) {
            g_networkDriver->Cleanup();
            delete g_networkDriver;
            g_networkDriver = nullptr;
        }
        
        // Limpiar Winsock
        WSACleanup();
        
        // Limpiar colas y cachés
        {
            std::lock_guard<std::mutex> lock1(g_eventQueueMutex);
            std::queue<NetworkEvent> emptyQueue;
            std::swap(g_eventQueue, emptyQueue);
        }
        
        {
            std::lock_guard<std::mutex> lock2(g_connectionCacheMutex);
            g_connectionCache.clear();
        }
        
        {
            std::lock_guard<std::mutex> lock3(g_dnsCacheMutex);
            g_dnsCache.clear();
        }
    }
    catch (...) {
        // Ignorar errores durante limpieza
    }
}

// Exportaciones para C#
extern "C" __declspec(dllexport) bool __stdcall StartNetworkMonitoring() {
    return InitializeNetworkSensor();
}

extern "C" __declspec(dllexport) void __stdcall StopNetworkMonitoring() {
    CleanupNetworkSensor();
}

extern "C" __declspec(dllexport) size_t __stdcall GetNetworkEventCount() {
    std::lock_guard<std::mutex> lock(g_eventQueueMutex);
    return g_eventQueue.size();
}

extern "C" __declspec(dllexport) bool __stdcall GetNetworkEvent(wchar_t* buffer, size_t bufferSize) {
    NetworkEvent event;
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