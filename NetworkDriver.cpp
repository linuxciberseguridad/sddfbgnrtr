#include "pch.h"
#include "NetworkDriver.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <fwpmu.h>
#include <fwpsk.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <thread>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")

namespace BWP {
namespace Enterprise {
namespace Drivers {

// Constantes
constexpr wchar_t DRIVER_NAME[] = L"BWPNetworkMonitor";
constexpr wchar_t DRIVER_DISPLAY_NAME[] = L"BWP Enterprise Network Monitor Driver";
constexpr wchar_t DRIVER_PATH[] = L"%SystemRoot%\\System32\\drivers\\BWPNetMon.sys";
constexpr DWORD DRIVER_CONTROL_START = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_STOP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_ADD_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_REMOVE_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_BLOCK_IP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_UNBLOCK_IP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD EVENT_BUFFER_SIZE = 65536;
constexpr DWORD MAX_CACHE_SIZE = 10000;
constexpr DWORD CACHE_TTL_MS = 60000;

// Constructor
NetworkDriver::NetworkDriver() :
    m_hDevice(INVALID_HANDLE_VALUE),
    m_hCompletionPort(nullptr),
    m_isInitialized(false),
    m_isMonitoring(false),
    m_hWorkerThread(nullptr),
    m_hPacketThread(nullptr),
    m_policyManager(nullptr),
    m_apiClient(nullptr)
{
    InitializeCriticalSection(&m_csLock);
    ZeroMemory(&m_stats, sizeof(m_stats));
    GetSystemTimeAsFileTime(&m_stats.StartTime);
    m_stats.LastEventTime = m_stats.StartTime;
    ZeroMemory(&m_lastCacheUpdate, sizeof(m_lastCacheUpdate));
}

// Destructor
NetworkDriver::~NetworkDriver()
{
    Cleanup();
    DeleteCriticalSection(&m_csLock);
}

// Inicialización CON integración con PolicyManager
bool NetworkDriver::Initialize(PolicyManagerInterface* policyManager, ApiClientInterface* apiClient)
{
    EnterCriticalSection(&m_csLock);

    if (m_isInitialized)
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }

    try
    {
        LogInfo(L"Inicializando NetworkDriver...");

        // Guardar referencias a interfaces
        m_policyManager = policyManager;
        m_apiClient = apiClient;

        // 1. Inicializar Winsock
        if (!InitializeWinsock())
        {
            LogError(L"No se pudo inicializar Winsock");
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // 2. Instalar driver si no está instalado
        if (!IsDriverLoaded())
        {
            if (!InstallDriver())
            {
                LogError(L"No se pudo instalar el driver");
                LeaveCriticalSection(&m_csLock);
                return false;
            }
        }

        // 3. Cargar driver
        if (!LoadDriver())
        {
            LogError(L"No se pudo cargar el driver");
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // 4. Conectar al driver
        if (!ConnectToDriver())
        {
            LogError(L"No se pudo conectar al driver");
            UnloadDriver();
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        // 5. NO configurar filtros hardcodeados - se cargarán desde PolicyManager
        LogInfo(L"Esperando configuración desde PolicyManager...");

        m_isInitialized = true;
        LogInfo(L"NetworkDriver inicializado exitosamente");

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

// Método para aplicar configuración desde PolicyManager
bool NetworkDriver::ApplyPolicyConfiguration(const NetworkPolicyConfig& config)
{
    EnterCriticalSection(&m_csLock);
    
    try
    {
        LogInfo(L"Aplicando configuración de política de red...");
        
        // Limpiar filtros anteriores
        ClearFilters();
        
        // Aplicar IPs bloqueadas desde política
        for (const auto& ip : config.BlockedIps)
        {
            AddBlockedIp(ip);
        }
        
        // Aplicar puertos bloqueados desde política
        for (const auto& portInfo : config.BlockedPorts)
        {
            AddBlockedPort(portInfo.Port, static_cast<ProtocolType>(portInfo.Protocol));
        }
        
        // Aplicar dominios sospechosos desde política
        for (const auto& domain : config.SuspiciousDomains)
        {
            AddSuspiciousDomain(domain);
        }
        
        // Configurar límites de comportamiento
        m_maxConnectionsPerProcess = config.MaxConnectionsPerProcess;
        
        // Configurar umbrales de detección
        m_dataExfiltrationThreshold = config.DataExfiltrationThresholdMB * 1024 * 1024;
        m_portScanThreshold = config.PortScanThreshold;
        
        LogInfo(L"Configuración de política aplicada: %lu IPs, %lu puertos, %lu dominios",
               config.BlockedIps.size(), config.BlockedPorts.size(), config.SuspiciousDomains.size());
        
        LeaveCriticalSection(&m_csLock);
        return true;
    }
    catch (...)
    {
        LogError(L"Excepción aplicando configuración de política");
        LeaveCriticalSection(&m_csLock);
        return false;
    }
}

// Método para consultar inteligencia de amenazas en la nube
bool NetworkDriver::CheckCloudThreatIntelligence(const std::wstring& ipAddress, const std::wstring& domain)
{
    if (!m_apiClient)
        return false;
    
    try
    {
        // Consultar API de inteligencia de amenazas
        ThreatIntelligenceRequest request;
        request.IpAddress = ipAddress;
        request.Domain = domain;
        request.Timestamp = GetCurrentTimestamp();
        
        // Esto sería una llamada real a tu API cloud
        // ThreatIntelligenceResponse response = m_apiClient->QueryThreatIntel(request);
        
        // Por ahora, simulamos respuesta
        bool isMalicious = false;
        
        // Si la API responde que es malicioso
        if (isMalicious)
        {
            LogInfo(L"Inteligencia de amenazas: %ls identificado como malicioso", 
                   ipAddress.empty() ? domain.c_str() : ipAddress.c_str());
            return true;
        }
        
        return false;
    }
    catch (...)
    {
        LogError(L"Excepción consultando inteligencia de amenazas");
        return false;
    }
}

// Método para verificar IP con múltiples fuentes
bool NetworkDriver::IsSuspiciousIp(const std::wstring& ipAddress)
{
    // 1. Verificar en lista local (desde PolicyManager)
    {
        std::shared_lock lock(m_dataMutex);
        auto it = std::find_if(m_blockedIps.begin(), m_blockedIps.end(),
            [&ipAddress](const IpFilter& filter) {
                return filter.Matches(ipAddress);
            });
        
        if (it != m_blockedIps.end())
        {
            LogDebug(L"IP %ls encontrada en lista local de bloqueo", ipAddress.c_str());
            return true;
        }
    }
    
    // 2. Verificar si es IP privada (no maliciosa por defecto, solo información)
    if (IsPrivateIp(ipAddress))
    {
        return false; // IPs privadas no son sospechosas por sí mismas
    }
    
    // 3. Consultar inteligencia de amenazas en la nube (si está configurado)
    if (m_apiClient && m_checkCloudIntel)
    {
        if (CheckCloudThreatIntelligence(ipAddress, L""))
        {
            // Agregar a cache local para futuras consultas
            AddBlockedIp(ipAddress);
            return true;
        }
    }
    
    // 4. Verificar comportamiento anómalo (si tenemos datos históricos)
    if (IsAnomalousBehavior(ipAddress))
    {
        LogWarning(L"Comportamiento anómalo detectado para IP: %ls", ipAddress.c_str());
        return true;
    }
    
    return false;
}

// Método mejorado para detección de DNS tunneling
bool NetworkDriver::IsDnsTunneling(const DnsQueryInfo& dnsQuery)
{
    // Usar modelo ML si está disponible
    if (m_mlEngine && m_mlEngine->IsModelLoaded("dns_tunneling"))
    {
        try
        {
            // Preparar características para el modelo
            std::vector<float> features = ExtractDnsFeatures(dnsQuery);
            
            // Ejecutar inferencia
            float probability = m_mlEngine->Predict("dns_tunneling", features);
            
            if (probability > 0.8f) // Umbral configurable
            {
                LogWarning(L"DNS tunneling detectado por ML (probabilidad: %.2f): %ls", 
                          probability, dnsQuery.QueryName.c_str());
                return true;
            }
        }
        catch (...)
        {
            LogError(L"Error en inferencia ML para DNS tunneling");
        }
    }
    
    // Fallback a detección heurística si ML no está disponible
    return DetectDnsTunnelingHeuristic(dnsQuery);
}

// Extraer características para modelo ML
std::vector<float> NetworkDriver::ExtractDnsFeatures(const DnsQueryInfo& dnsQuery)
{
    std::vector<float> features;
    
    // 1. Longitud del nombre de dominio (normalizada)
    features.push_back(static_cast<float>(dnsQuery.QueryName.length()) / 253.0f);
    
    // 2. Número de subdominios
    size_t dotCount = std::count(dnsQuery.QueryName.begin(), dnsQuery.QueryName.end(), L'.');
    features.push_back(static_cast<float>(dotCount) / 10.0f);
    
    // 3. Entropía del nombre de dominio
    features.push_back(CalculateEntropy(dnsQuery.QueryName));
    
    // 4. Proporción de caracteres alfanuméricos
    size_t alnumCount = 0;
    for (wchar_t c : dnsQuery.QueryName)
    {
        if (iswalnum(c)) alnumCount++;
    }
    features.push_back(static_cast<float>(alnumCount) / dnsQuery.QueryName.length());
    
    // 5. Tipo de consulta (codificada one-hot)
    // features.push_back(dnsQuery.QueryType == 16 ? 1.0f : 0.0f); // TXT
    // features.push_back(dnsQuery.QueryType == 1 ? 1.0f : 0.0f);  // A
    // ... etc
    
    // 6. Tiempo de respuesta
    features.push_back(static_cast<float>(dnsQuery.ResponseTimeMs) / 1000.0f);
    
    // 7. Frecuencia de consultas (si tenemos tracking)
    float queryFrequency = GetQueryFrequency(dnsQuery.QueryName);
    features.push_back(queryFrequency);
    
    return features;
}

// Detección heurística de DNS tunneling
bool NetworkDriver::DetectDnsTunnelingHeuristic(const DnsQueryInfo& dnsQuery)
{
    // Umbrales configurables desde política
    constexpr size_t MAX_DOMAIN_LENGTH = 253;
    constexpr size_t MAX_SUBDOMAINS = 8;
    constexpr float MIN_ENTROPY_THRESHOLD = 4.5f;
    
    // 1. Longitud excesiva
    if (dnsQuery.QueryName.length() > MAX_DOMAIN_LENGTH)
    {
        LogDebug(L"DNS: Longitud excesiva (%lu): %ls", 
                dnsQuery.QueryName.length(), dnsQuery.QueryName.c_str());
        return true;
    }
    
    // 2. Demasiados subdominios
    size_t dotCount = std::count(dnsQuery.QueryName.begin(), dnsQuery.QueryName.end(), L'.');
    if (dotCount > MAX_SUBDOMAINS)
    {
        LogDebug(L"DNS: Demasiados subdominios (%lu): %ls", dotCount, dnsQuery.QueryName.c_str());
        return true;
    }
    
    // 3. Entropía alta (posible datos codificados)
    float entropy = CalculateEntropy(dnsQuery.QueryName);
    if (entropy > MIN_ENTROPY_THRESHOLD)
    {
        LogDebug(L"DNS: Entropía alta (%.2f): %ls", entropy, dnsQuery.QueryName.c_str());
        return true;
    }
    
    // 4. Tipo de consulta inusual para tráfico normal
    if (dnsQuery.QueryType == 10 ||  // NULL
        dnsQuery.QueryType == 255)   // ANY (usado en ataques de amplificación)
    {
        LogDebug(L"DNS: Tipo de consulta inusual (%lu): %ls", 
                dnsQuery.QueryType, dnsQuery.QueryName.c_str());
        return true;
    }
    
    // 5. Patrones de caracteres de codificación
    if (ContainsEncodingPatterns(dnsQuery.QueryName))
    {
        LogDebug(L"DNS: Patrones de codificación detectados: %ls", dnsQuery.QueryName.c_str());
        return true;
    }
    
    return false;
}

// Calcular entropía de Shannon
float NetworkDriver::CalculateEntropy(const std::wstring& str)
{
    if (str.empty()) return 0.0f;
    
    std::map<wchar_t, size_t> frequency;
    for (wchar_t c : str)
    {
        frequency[c]++;
    }
    
    float entropy = 0.0f;
    float length = static_cast<float>(str.length());
    
    for (const auto& [ch, count] : frequency)
    {
        float probability = static_cast<float>(count) / length;
        entropy -= probability * log2f(probability);
    }
    
    return entropy;
}

// Verificar patrones de codificación
bool NetworkDriver::ContainsEncodingPatterns(const std::wstring& str)
{
    // Caracteres comunes en codificación Base64
    static const std::wstring base64Chars = 
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    // Verificar proporción de caracteres Base64
    size_t base64Count = 0;
    for (wchar_t c : str)
    {
        if (base64Chars.find(c) != std::wstring::npos)
        {
            base64Count++;
        }
    }
    
    float base64Ratio = static_cast<float>(base64Count) / str.length();
    
    // Umbral configurable (80% caracteres Base64 es sospechoso)
    return base64Ratio > 0.8f;
}

// Método para integración con ML Engine
void NetworkDriver::SetMLEngine(MLEngineInterface* mlEngine)
{
    m_mlEngine = mlEngine;
    
    if (mlEngine)
    {
        LogInfo(L"Motor ML configurado para NetworkDriver");
        
        // Cargar modelos específicos para red
        // mlEngine->LoadModel("dns_tunneling", L"models/dns_tunneling.onnx");
        // mlEngine->LoadModel("network_anomaly", L"models/network_anomaly.onnx");
    }
}

// Método para análisis de tráfico con ML
bool NetworkDriver::AnalyzeTrafficWithML(const NetworkConnectionInfo& connection)
{
    if (!m_mlEngine || !m_mlEngine->IsModelLoaded("network_anomaly"))
        return false;
    
    try
    {
        // Extraer características de la conexión
        std::vector<float> features = ExtractTrafficFeatures(connection);
        
        // Ejecutar inferencia
        float anomalyScore = m_mlEngine->Predict("network_anomaly", features);
        
        // Umbral configurable
        constexpr float ANOMALY_THRESHOLD = 0.7f;
        
        if (anomalyScore > ANOMALY_THRESHOLD)
        {
            LogWarning(L"Anomalía de red detectada por ML (score: %.2f): %ls:%hu -> %ls:%hu",
                      anomalyScore,
                      connection.LocalAddress.c_str(), connection.LocalPort,
                      connection.RemoteAddress.c_str(), connection.RemotePort);
            
            // Reportar anomalía a la nube
            ReportAnomalyToCloud(connection, anomalyScore);
            
            return true;
        }
    }
    catch (...)
    {
        LogError(L"Error en análisis ML de tráfico");
    }
    
    return false;
}

// Extraer características para modelo de anomalías de red
std::vector<float> NetworkDriver::ExtractTrafficFeatures(const NetworkConnectionInfo& connection)
{
    std::vector<float> features;
    
    // 1. Duración de la conexión (si está disponible)
    if (connection.ConnectionTime.dwHighDateTime != 0)
    {
        ULONGLONG connectionDuration = CalculateDuration(connection.ConnectionTime);
        features.push_back(static_cast<float>(connectionDuration) / 36000000000.0f); // Normalizar a horas
    }
    
    // 2. Volumen de datos (normalizado)
    float totalBytes = static_cast<float>(connection.BytesSent + connection.BytesReceived);
    features.push_back(log2f(totalBytes + 1.0f) / 30.0f); // log-scale normalization
    
    // 3. Ratio upload/download
    if (connection.BytesReceived > 0)
    {
        float ratio = static_cast<float>(connection.BytesSent) / connection.BytesReceived;
        features.push_back(ratio / 10.0f);
    }
    else
    {
        features.push_back(10.0f); // Solo upload
    }
    
    // 4. Puerto destino (codificado)
    features.push_back(static_cast<float>(connection.RemotePort) / 65535.0f);
    
    // 5. Es tráfico encriptado
    features.push_back(connection.IsEncrypted ? 1.0f : 0.0f);
    
    // 6. Es IP privada
    features.push_back(IsPrivateIp(connection.RemoteAddress) ? 1.0f : 0.0f);
    
    // 7. Frecuencia de conexiones a esta IP (si tenemos tracking)
    float connectionFrequency = GetConnectionFrequency(connection.RemoteAddress);
    features.push_back(connectionFrequency);
    
    // 8. Hora del día (para detectar actividad en horas no laborales)
    SYSTEMTIME st;
    GetLocalTime(&st);
    float hourOfDay = static_cast<float>(st.wHour) / 24.0f;
    features.push_back(hourOfDay);
    
    return features;
}

// Método para reportar anomalías a la nube
void NetworkDriver::ReportAnomalyToCloud(const NetworkConnectionInfo& connection, float anomalyScore)
{
    if (!m_apiClient)
        return;
    
    try
    {
        AnomalyReport report;
        report.Timestamp = GetCurrentTimestamp();
        report.SourceProcessId = connection.ProcessId;
        report.SourceProcessName = connection.ProcessName;
        report.LocalAddress = connection.LocalAddress;
        report.RemoteAddress = connection.RemoteAddress;
        report.LocalPort = connection.LocalPort;
        report.RemotePort = connection.RemotePort;
        report.Protocol = connection.Protocol;
        report.AnomalyScore = anomalyScore;
        report.BytesSent = connection.BytesSent;
        report.BytesReceived = connection.BytesReceived;
        report.IsEncrypted = connection.IsEncrypted;
        
        // Enviar reporte asíncronamente
        // m_apiClient->SendAnomalyReport(report);
        
        LogInfo(L"Reporte de anomalía preparado para envío a la nube");
    }
    catch (...)
    {
        LogError(L"Error preparando reporte de anomalía");
    }
}

// Método para actualización dinámica de políticas
void NetworkDriver::UpdateDynamicPolicies()
{
    if (!m_policyManager)
        return;
    
    try
    {
        // Solicitar actualización de políticas
        NetworkPolicyUpdate update = m_policyManager->GetNetworkPolicyUpdate();
        
        if (update.HasChanges)
        {
            LogInfo(L"Actualizando políticas de red dinámicamente...");
            
            EnterCriticalSection(&m_csLock);
            
            // Aplicar nuevas reglas
            for (const auto& ip : update.NewBlockedIps)
            {
                if (std::find(m_blockedIps.begin(), m_blockedIps.end(), ip) == m_blockedIps.end())
                {
                    AddBlockedIp(ip);
                    LogDebug(L"Nueva IP bloqueada: %ls", ip.c_str());
                }
            }
            
            // Remover reglas eliminadas
            for (const auto& ip : update.RemovedIps)
            {
                RemoveBlockedIp(ip);
                LogDebug(L"IP desbloqueada: %ls", ip.c_str());
            }
            
            // Actualizar configuración de comportamiento
            m_maxConnectionsPerProcess = update.MaxConnectionsPerProcess;
            m_dataExfiltrationThreshold = update.DataExfiltrationThresholdMB * 1024 * 1024;
            
            LeaveCriticalSection(&m_csLock);
            
            LogInfo(L"Políticas de red actualizadas: %lu nuevas, %lu removidas",
                   update.NewBlockedIps.size(), update.RemovedIps.size());
        }
    }
    catch (...)
    {
        LogError(L"Error actualizando políticas dinámicas");
    }
}

// Método mejorado para detección de exfiltración
bool NetworkDriver::IsDataExfiltration(const NetworkConnectionInfo& connection)
{
    // 1. Verificar umbral de tamaño
    if (connection.BytesSent < m_dataExfiltrationThreshold)
        return false;
    
    // 2. Verificar si es tráfico encriptado (más sospechoso)
    bool isEncrypted = connection.IsEncrypted;
    
    // 3. Verificar destino
    bool isSuspiciousDestination = false;
    
    // a. IP en lista negra
    if (IsSuspiciousIp(connection.RemoteAddress))
        isSuspiciousDestination = true;
    
    // b. Dominio sospechoso (si tenemos resolución DNS)
    if (!connection.Hostname.empty())
    {
        if (IsSuspiciousDomain(connection.Hostname))
            isSuspiciousDestination = true;
    }
    
    // c. País de alto riesgo (si tenemos geolocalización)
    std::wstring countryCode = GetCountryCode(connection.RemoteAddress);
    if (IsHighRiskCountry(countryCode))
        isSuspiciousDestination = true;
    
    // 4. Verificar patrón temporal (ej: grandes transferencias en horario no laboral)
    bool isAnomalousTime = IsAnomalousTransferTime();
    
    // 5. Combinar señales
    int signalCount = 0;
    if (isEncrypted) signalCount++;
    if (isSuspiciousDestination) signalCount++;
    if (isAnomalousTime) signalCount++;
    
    // Requerir múltiples señales para reducir falsos positivos
    return signalCount >= 2;
}

// Método para verificar país de riesgo
bool NetworkDriver::IsHighRiskCountry(const std::wstring& countryCode)
{
    // Esta lista debería cargarse desde PolicyManager
    static const std::vector<std::wstring> highRiskCountries = {
        L"CN", L"RU", L"IR", L"KP", L"SY"
    };
    
    return std::find(highRiskCountries.begin(), highRiskCountries.end(), countryCode) 
           != highRiskCountries.end();
}

// Método para obtener código de país (simplificado)
std::wstring NetworkDriver::GetCountryCode(const std::wstring& ipAddress)
{
    // En producción, usar servicio de geolocalización o base de datos local
    // Por ahora, retornar marcador de posición
    
    if (IsPrivateIp(ipAddress))
        return L"PRIVATE";
    
    // Simulación: basado en rangos de IP conocidos
    // Esto es solo para demostración
    
    return L"UNKNOWN";
}

// Método para verificar hora anómala de transferencia
bool NetworkDriver::IsAnomalousTransferTime()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // Horario laboral típico: 9 AM - 6 PM, Lunes a Viernes
    bool isWorkHour = (st.wHour >= 9 && st.wHour < 18);
    bool isWeekday = (st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5);
    
    // Transferencias grandes fuera de horario laboral son más sospechosas
    return !(isWorkHour && isWeekday);
}

// Interfaz para PolicyManager
class PolicyManagerInterface {
public:
    virtual NetworkPolicyConfig GetNetworkPolicy() = 0;
    virtual NetworkPolicyUpdate GetNetworkPolicyUpdate() = 0;
    virtual void ReportNetworkEvent(const NetworkEvent& event) = 0;
};

// Interfaz para ApiClient
class ApiClientInterface {
public:
    virtual bool SendTelemetry(const TelemetryData& data) = 0;
    virtual ThreatIntelligenceResponse QueryThreatIntel(const ThreatIntelligenceRequest& request) = 0;
    virtual bool SendAnomalyReport(const AnomalyReport& report) = 0;
};

// Interfaz para ML Engine
class MLEngineInterface {
public:
    virtual bool LoadModel(const std::string& modelName, const std::wstring& modelPath) = 0;
    virtual bool IsModelLoaded(const std::string& modelName) = 0;
    virtual float Predict(const std::string& modelName, const std::vector<float>& features) = 0;
};

// Estructuras de datos
struct NetworkPolicyConfig {
    std::vector<std::wstring> BlockedIps;
    std::vector<PortFilter> BlockedPorts;
    std::vector<std::wstring> SuspiciousDomains;
    DWORD MaxConnectionsPerProcess;
    DWORD DataExfiltrationThresholdMB;
    DWORD PortScanThreshold;
    bool EnableCloudThreatIntel;
    bool EnableMLAnalysis;
};

struct NetworkPolicyUpdate {
    bool HasChanges;
    std::vector<std::wstring> NewBlockedIps;
    std::vector<std::wstring> RemovedIps;
    DWORD MaxConnectionsPerProcess;
    DWORD DataExfiltrationThresholdMB;
};

struct ThreatIntelligenceRequest {
    std::wstring IpAddress;
    std::wstring Domain;
    FILETIME Timestamp;
};

struct AnomalyReport {
    FILETIME Timestamp;
    DWORD SourceProcessId;
    std::wstring SourceProcessName;
    std::wstring LocalAddress;
    std::wstring RemoteAddress;
    USHORT LocalPort;
    USHORT RemotePort;
    DWORD Protocol;
    float AnomalyScore;
    ULONGLONG BytesSent;
    ULONGLONG BytesReceived;
    bool IsEncrypted;
};

// Clase para filtros de IP (soporta CIDR)
class IpFilter {
private:
    std::wstring m_ip;
    int m_prefixLength;
    
public:
    IpFilter(const std::wstring& ipCidr) {
        size_t slashPos = ipCidr.find(L'/');
        if (slashPos != std::wstring::npos) {
            m_ip = ipCidr.substr(0, slashPos);
            m_prefixLength = std::stoi(ipCidr.substr(slashPos + 1));
        } else {
            m_ip = ipCidr;
            m_prefixLength = 32; // IP individual
        }
    }
    
    bool Matches(const std::wstring& ip) const {
        if (m_prefixLength == 32) {
            return m_ip == ip;
        }
        
        // Implementar matching CIDR aquí
        // (simplificado para el ejemplo)
        return m_ip.substr(0, m_ip.find_last_of(L'.')) == 
               ip.substr(0, ip.find_last_of(L'.'));
    }
};

// ... (resto de métodos permanecen similares pero usando las interfaces)

} // namespace Drivers
} // namespace Enterprise
} // namespace BWP