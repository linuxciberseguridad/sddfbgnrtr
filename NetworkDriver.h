#pragma once
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <functional>
#include <memory>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace BWP {
namespace Enterprise {
namespace Drivers {

// Forward declarations
struct NetworkConnectionInfo;
struct DnsQueryInfo;

// Callback definitions
typedef std::function<void(const NetworkConnectionInfo&, PVOID)> NetworkConnectionCallback_t;
typedef std::function<void(const DnsQueryInfo&, PVOID)> DnsQueryCallback_t;
typedef std::function<void(DWORD ProcessId, const std::wstring& Hostname, 
                          USHORT Port, DWORD Protocol, PVOID)> RawPacketCallback_t;

/// <summary>
/// Driver de red para monitoreo de conexiones y tráfico de red
/// Detecta conexiones TCP/UDP, consultas DNS y actividad de red sospechosa
/// </summary>
class NetworkDriver {
public:
    NetworkDriver();
    ~NetworkDriver();

    // Tipos de protocolo
    enum ProtocolType {
        PROTOCOL_TCP = 6,
        PROTOCOL_UDP = 17,
        PROTOCOL_ICMP = 1,
        PROTOCOL_ANY = 0
    };

    // Tipos de dirección
    enum AddressType {
        ADDRESS_IPV4 = AF_INET,
        ADDRESS_IPV6 = AF_INET6
    };

    // Estados de conexión
    enum ConnectionState {
        STATE_ESTABLISHED = 1,
        STATE_LISTENING = 2,
        STATE_SYN_SENT = 3,
        STATE_SYN_RECEIVED = 4,
        STATE_FIN_WAIT = 5,
        STATE_CLOSED = 6
    };

    // Inicialización y limpieza
    bool Initialize();
    void Cleanup();

    // Registro de callbacks
    void RegisterConnectionCallback(NetworkConnectionCallback_t callback, PVOID context = nullptr);
    void RegisterDnsQueryCallback(DnsQueryCallback_t callback, PVOID context = nullptr);
    void RegisterPacketCallback(RawPacketCallback_t callback, PVOID context = nullptr);
    
    // Callbacks específicos
    void RegisterTcpConnectionCallback(std::function<void(const NetworkConnectionInfo&, PVOID)> callback, PVOID context = nullptr);
    void RegisterUdpConnectionCallback(std::function<void(const NetworkConnectionInfo&, PVOID)> callback, PVOID context = nullptr);
    void RegisterOutboundConnectionCallback(std::function<void(const NetworkConnectionInfo&, PVOID)> callback, PVOID context = nullptr);
    void RegisterInboundConnectionCallback(std::function<void(const NetworkConnectionInfo&, PVOID)> callback, PVOID context = nullptr);

    // Control del driver
    bool StartMonitoring();
    bool StopMonitoring();
    bool IsMonitoring() const;

    // Configuración
    void AddAllowedPort(USHORT port, ProtocolType protocol = PROTOCOL_ANY);
    void AddBlockedPort(USHORT port, ProtocolType protocol = PROTOCOL_ANY);
    void AddAllowedIp(const std::wstring& ipAddress);
    void AddBlockedIp(const std::wstring& ipAddress);
    void AddSuspiciousDomain(const std::wstring& domain);
    
    void ClearFilters();
    void SetMaxConnectionsPerProcess(DWORD maxConnections);

    // Información del sistema
    std::vector<NetworkConnectionInfo> GetActiveConnections() const;
    std::vector<NetworkConnectionInfo> GetConnectionsByProcess(DWORD processId) const;
    std::vector<NetworkConnectionInfo> GetConnectionsByIp(const std::wstring& ipAddress) const;
    std::vector<DnsQueryInfo> GetRecentDnsQueries(DWORD maxQueries = 100) const;

    // Utilidades de red
    static std::wstring IpToString(const void* ipAddress, AddressType type);
    static std::wstring GetHostnameByIp(const std::wstring& ipAddress);
    static std::wstring GetCountryByIp(const std::wstring& ipAddress);
    static bool IsPrivateIp(const std::wstring& ipAddress);
    static bool IsSuspiciousIp(const std::wstring& ipAddress);
    static USHORT GetPortFromConnection(const NetworkConnectionInfo& connection);
    static DWORD GetProcessIdFromConnection(const NetworkConnectionInfo& connection);

    // Análisis de tráfico
    static bool IsDataExfiltration(const NetworkConnectionInfo& connection, DWORD dataSize);
    static bool IsPortScanning(const std::vector<NetworkConnectionInfo>& connections);
    static bool IsDnsTunneling(const DnsQueryInfo& dnsQuery);
    static bool IsEncryptedTraffic(const NetworkConnectionInfo& connection);

    // Bloqueo de conexiones
    bool BlockConnection(const NetworkConnectionInfo& connection);
    bool BlockProcessConnections(DWORD processId);
    bool BlockIpAddress(const std::wstring& ipAddress);
    bool UnblockConnection(const NetworkConnectionInfo& connection);
    
    // Estadísticas
    struct Statistics {
        DWORD TcpConnections;
        DWORD UdpConnections;
        DWORD DnsQueries;
        DWORD PacketsProcessed;
        DWORD ConnectionsBlocked;
        DWORD ConnectionsAllowed;
        DWORD SuspiciousConnections;
        DWORD Errors;
        FILETIME StartTime;
        FILETIME LastEventTime;
        DWORD TotalBytesSent;
        DWORD TotalBytesReceived;
    };

    Statistics GetStatistics() const;

private:
    // Variables miembro
    HANDLE m_hDevice;
    HANDLE m_hCompletionPort;
    bool m_isInitialized;
    bool m_isMonitoring;
    mutable CRITICAL_SECTION m_csLock;

    // Callbacks
    NetworkConnectionCallback_t m_connectionCallback;
    PVOID m_connectionContext;
    
    DnsQueryCallback_t m_dnsQueryCallback;
    PVOID m_dnsQueryContext;
    
    RawPacketCallback_t m_packetCallback;
    PVOID m_packetContext;
    
    std::function<void(const NetworkConnectionInfo&, PVOID)> m_tcpConnectionCallback;
    PVOID m_tcpConnectionContext;
    
    std::function<void(const NetworkConnectionInfo&, PVOID)> m_udpConnectionCallback;
    PVOID m_udpConnectionContext;
    
    std::function<void(const NetworkConnectionInfo&, PVOID)> m_outboundCallback;
    PVOID m_outboundContext;
    
    std::function<void(const NetworkConnectionInfo&, PVOID)> m_inboundCallback;
    PVOID m_inboundContext;

    // Configuración y filtros
    std::vector<std::pair<USHORT, ProtocolType>> m_allowedPorts;
    std::vector<std::pair<USHORT, ProtocolType>> m_blockedPorts;
    std::vector<std::wstring> m_allowedIps;
    std::vector<std::wstring> m_blockedIps;
    std::vector<std::wstring> m_suspiciousDomains;
    DWORD m_maxConnectionsPerProcess;

    // Cache de información
    mutable std::vector<NetworkConnectionInfo> m_connectionCache;
    mutable std::vector<DnsQueryInfo> m_dnsCache;
    mutable FILETIME m_lastCacheUpdate;

    // Estadísticas
    Statistics m_stats;

    // Hilos de procesamiento
    HANDLE m_hWorkerThread;
    HANDLE m_hPacketThread;
    static DWORD WINAPI WorkerThreadProc(LPVOID lpParameter);
    static DWORD WINAPI PacketThreadProc(LPVOID lpParameter);
    DWORD WorkerThread();
    DWORD PacketThread();

    // Helpers de driver
    bool InstallDriver();
    bool UninstallDriver();
    bool LoadDriver();
    bool UnloadDriver();
    bool IsDriverLoaded() const;
    bool ConnectToDriver();
    bool DisconnectFromDriver();
    bool SendIoControl(DWORD controlCode, void* input = nullptr, DWORD inputSize = 0,
                      void* output = nullptr, DWORD outputSize = 0);

    // Procesamiento de eventos
    void HandleConnectionEvent(const void* data, DWORD size);
    void HandleDnsEvent(const void* data, DWORD size);
    void HandlePacketEvent(const void* data, DWORD size);
    
    // Filtrado
    bool ShouldAllowConnection(const NetworkConnectionInfo& connection) const;
    bool ShouldBlockConnection(const NetworkConnectionInfo& connection) const;
    bool IsPortAllowed(USHORT port, ProtocolType protocol) const;
    bool IsPortBlocked(USHORT port, ProtocolType protocol) const;
    bool IsIpAllowed(const std::wstring& ipAddress) const;
    bool IsIpBlocked(const std::wstring& ipAddress) const;
    bool IsSuspiciousDomain(const std::wstring& domain) const;
    bool CheckConnectionLimit(DWORD processId) const;

    // Actualización de cache
    void UpdateConnectionCache();
    void UpdateDnsCache();
    bool IsCacheValid() const;

    // Utilidades
    static bool InitializeWinsock();
    static void CleanupWinsock();
    static std::wstring GetProcessName(DWORD processId);
    static DWORD GetParentProcessId(DWORD processId);

    // Registro de eventos
    void LogError(const wchar_t* format, ...) const;
    void LogInfo(const wchar_t* format, ...) const;
    void LogDebug(const wchar_t* format, ...) const;

    // Prevención de copia
    NetworkDriver(const NetworkDriver&) = delete;
    NetworkDriver& operator=(const NetworkDriver&) = delete;
};

/// <summary>
/// Información de conexión de red
/// </summary>
struct NetworkConnectionInfo {
    DWORD ProcessId;
    std::wstring ProcessName;
    std::wstring LocalAddress;
    std::wstring RemoteAddress;
    USHORT LocalPort;
    USHORT RemotePort;
    DWORD Protocol; // TCP=6, UDP=17
    ConnectionState State;
    FILETIME ConnectionTime;
    FILETIME LastActivity;
    DWORD BytesSent;
    DWORD BytesReceived;
    DWORD PacketsSent;
    DWORD PacketsReceived;
    bool IsOutbound;
    bool IsEncrypted;
    std::wstring CountryCode;
    std::wstring Hostname;
    std::wstring ServiceName; // Ej: HTTP, HTTPS, DNS, etc.
    DWORD ConnectionId;
    HANDLE ConnectionHandle;
};

/// <summary>
/// Información de consulta DNS
/// </summary>
struct DnsQueryInfo {
    DWORD ProcessId;
    std::wstring ProcessName;
    std::wstring QueryName;
    std::wstring ResponseIp;
    DWORD QueryType; // A=1, AAAA=28, CNAME=5, etc.
    FILETIME QueryTime;
    DWORD ResponseTimeMs;
    bool IsCached;
    bool IsBlocked;
    std::wstring ServerIp;
    USHORT ServerPort;
    DWORD ResponseCode; // 0=NoError, 2=ServFail, 3=NXDomain, etc.
    std::vector<std::wstring> AdditionalRecords;
};

/// <summary>
/// Información de paquete de red
/// </summary>
struct PacketInfo {
    DWORD ProcessId;
    std::wstring SourceIp;
    std::wstring DestinationIp;
    USHORT SourcePort;
    USHORT DestinationPort;
    DWORD Protocol;
    DWORD PacketSize;
    FILETIME Timestamp;
    std::vector<BYTE> PacketData;
    bool IsOutbound;
    bool IsMalicious;
    DWORD Flags;
};

/// <summary>
/// Mensajes del driver de red
/// </summary>
#pragma pack(push, 1)
struct ConnectionEventMessage {
    DWORD EventType; // 1=Create, 2=Close, 3=Send, 4=Receive
    DWORD ProcessId;
    WCHAR ProcessName[260];
    BYTE LocalAddress[16]; // IPv4 o IPv6
    BYTE RemoteAddress[16];
    USHORT LocalPort;
    USHORT RemotePort;
    DWORD Protocol;
    DWORD State;
    FILETIME EventTime;
    DWORD DataSize;
    DWORD ConnectionId;
};

struct DnsEventMessage {
    DWORD ProcessId;
    WCHAR ProcessName[260];
    WCHAR QueryName[256];
    BYTE ResponseAddress[16];
    DWORD QueryType;
    FILETIME QueryTime;
    DWORD ResponseTime;
    BOOL IsCached;
    WCHAR ServerIp[46];
    USHORT ServerPort;
    DWORD ResponseCode;
};

struct PacketEventMessage {
    DWORD ProcessId;
    BYTE SourceAddress[16];
    BYTE DestinationAddress[16];
    USHORT SourcePort;
    USHORT DestinationPort;
    DWORD Protocol;
    DWORD PacketSize;
    FILETIME Timestamp;
    DWORD Flags;
    // Los datos del paquete siguen después de la estructura
};
#pragma pack(pop)

} // namespace Drivers
} // namespace Enterprise
} // namespace BWP