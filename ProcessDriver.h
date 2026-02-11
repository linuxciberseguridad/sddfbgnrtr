#include "pch.h"
#include "ProcessDriver.h"
#include <windows.h>
#include <fltuser.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <securitybaseapi.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>

#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace BWP {
namespace Enterprise {
namespace Drivers {

// Constantes
constexpr wchar_t DRIVER_NAME[] = L"BWPProcessMonitor";
constexpr wchar_t DRIVER_DISPLAY_NAME[] = L"BWP Enterprise Process Monitor Driver";
constexpr wchar_t DRIVER_PATH[] = L"%SystemRoot%\\System32\\drivers\\BWPProcMon.sys";
constexpr DWORD DRIVER_CONTROL_START = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_STOP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD DRIVER_CONTROL_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD MESSAGE_BUFFER_SIZE = 4096;

ProcessDriver::ProcessDriver() :
    m_hPort(nullptr),
    m_hCompletion(nullptr),
    m_hDriver(INVALID_HANDLE_VALUE),
    m_isInitialized(false),
    m_isMonitoring(false),
    m_hWorkerThread(nullptr)
{
    InitializeCriticalSection(&m_csLock);
    ZeroMemory(&m_stats, sizeof(m_stats));
    GetSystemTimeAsFileTime(&m_stats.StartTime);
    m_stats.LastEventTime = m_stats.StartTime;
}

ProcessDriver::~ProcessDriver()
{
    Cleanup();
    DeleteCriticalSection(&m_csLock);
}

bool ProcessDriver::Initialize()
{
    EnterCriticalSection(&m_csLock);

    if (m_isInitialized)
    {
        LeaveCriticalSection(&m_csLock);
        return true;
    }

    try
    {
        LogInfo(L"Inicializando ProcessDriver...");

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

        m_isInitialized = true;
        LogInfo(L"ProcessDriver inicializado exitosamente");

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

void ProcessDriver::Cleanup()
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

        LogInfo(L"ProcessDriver limpiado");
    }
    catch (...)
    {
        LogError(L"Excepción durante limpieza");
    }

    LeaveCriticalSection(&m_csLock);
}

bool ProcessDriver::StartMonitoring()
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
        LogInfo(L"Monitoreo de procesos iniciado");

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

bool ProcessDriver::StopMonitoring()
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

        LogInfo(L"Monitoreo de procesos detenido");

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

bool ProcessDriver::IsMonitoring() const
{
    return m_isMonitoring;
}

void ProcessDriver::RegisterProcessCreateCallback(ProcessCreateCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_processCreateCallback = callback;
    m_processCreateContext = context;
    LeaveCriticalSection(&m_csLock);
}

void ProcessDriver::RegisterProcessTerminateCallback(ProcessTerminateCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_processTerminateCallback = callback;
    m_processTerminateContext = context;
    LeaveCriticalSection(&m_csLock);
}

void ProcessDriver::RegisterThreadCreateCallback(ThreadCreateCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_threadCreateCallback = callback;
    m_threadCreateContext = context;
    LeaveCriticalSection(&m_csLock);
}

void ProcessDriver::RegisterThreadTerminateCallback(ThreadTerminateCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_threadTerminateCallback = callback;
    m_threadTerminateContext = context;
    LeaveCriticalSection(&m_csLock);
}

void ProcessDriver::RegisterImageLoadCallback(ImageLoadCallback_t callback, PVOID context)
{
    EnterCriticalSection(&m_csLock);
    m_imageLoadCallback = callback;
    m_imageLoadContext = context;
    LeaveCriticalSection(&m_csLock);
}

std::vector<DWORD> ProcessDriver::GetRunningProcesses() const
{
    std::vector<DWORD> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32))
        {
            do
            {
                processes.push_back(pe32.th32ProcessID);
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    return processes;
}

ProcessInfo ProcessDriver::GetProcessInfo(DWORD processId) const
{
    ProcessInfo info = {};
    info.ProcessId = processId;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (hProcess && hProcess != INVALID_HANDLE_VALUE)
    {
        try
        {
            // Información básica
            info.ParentProcessId = GetParentProcessId(processId);

            // Session ID
            DWORD sessionId;
            if (ProcessIdToSessionId(processId, &sessionId))
            {
                info.SessionId = sessionId;
            }

            // Image path y nombre
            wchar_t imagePath[MAX_PATH] = { 0 };
            if (GetProcessImageFileNameW(hProcess, imagePath, MAX_PATH))
            {
                info.ImagePath = imagePath;

                // Extraer nombre del archivo
                size_t pos = info.ImagePath.find_last_of(L"\\/");
                if (pos != std::wstring::npos)
                {
                    info.ImageName = info.ImagePath.substr(pos + 1);
                }
            }

            // Command line
            info.CommandLine = GetProcessCommandLine(processId);

            // Información de usuario e integridad
            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
            {
                info.UserSid = GetProcessUserSid(processId);
                info.IntegrityLevel = GetProcessIntegrityLevel(processId);
                info.IsElevated = IsProcessElevated(processId);
                CloseHandle(hToken);
            }

            // Tiempos
            FILETIME createTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime))
            {
                info.CreationTime = createTime;
                info.ExitTime = exitTime;
            }

            // Memoria
            PROCESS_MEMORY_COUNTERS_EX pmc;
            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
            {
                info.WorkingSetSize = pmc.WorkingSetSize;
                info.PeakWorkingSetSize = pmc.PeakWorkingSetSize;
                info.VirtualSize = pmc.PrivateUsage;
            }

            // Handles y threads
            info.HandleCount = 0;
            info.ThreadCount = 0;
            GetProcessHandleCount(hProcess, &info.HandleCount);

            // Priority class
            info.PriorityClass = GetPriorityClass(hProcess);

            // Wow64
            BOOL isWow64 = FALSE;
            IsWow64Process(hProcess, &isWow64);
            info.IsWow64 = isWow64 != FALSE;

            // Protected process (simplificado)
            info.IsProtected = false;

            CloseHandle(hProcess);
        }
        catch (...)
        {
            if (hProcess) CloseHandle(hProcess);
        }
    }

    return info;
}

std::vector<ThreadInfo> ProcessDriver::GetProcessThreads(DWORD processId) const
{
    std::vector<ThreadInfo> threads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te32))
        {
            do
            {
                if (te32.th32OwnerProcessID == processId)
                {
                    ThreadInfo info = {};
                    info.ThreadId = te32.th32ThreadID;
                    info.ProcessId = te32.th32OwnerProcessID;
                    info.Priority = te32.tpBasePri;

                    threads.push_back(info);
                }
            } while (Thread32Next(hSnapshot, &te32));
        }

        CloseHandle(hSnapshot);
    }

    return threads;
}

bool ProcessDriver::IsProcessAlive(DWORD processId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess)
    {
        DWORD exitCode;
        BOOL result = GetExitCodeProcess(hProcess, &exitCode);
        CloseHandle(hProcess);

        return result && exitCode == STILL_ACTIVE;
    }

    return false;
}

HANDLE ProcessDriver::OpenProcessWithMaxAccess(DWORD processId)
{
    HANDLE hProcess = nullptr;
    static DWORD accessFlags[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
        PROCESS_QUERY_LIMITED_INFORMATION,
        SYNCHRONIZE
    };

    for (DWORD access : accessFlags)
    {
        hProcess = OpenProcess(access, FALSE, processId);
        if (hProcess)
        {
            break;
        }
    }

    return hProcess;
}

std::wstring ProcessDriver::GetProcessImagePath(DWORD processId)
{
    std::wstring imagePath;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        wchar_t buffer[MAX_PATH] = { 0 };
        DWORD bufferSize = MAX_PATH;

        if (QueryFullProcessImageNameW(hProcess, 0, buffer, &bufferSize))
        {
            imagePath = buffer;
        }

        CloseHandle(hProcess);
    }

    return imagePath;
}

std::wstring ProcessDriver::GetProcessCommandLine(DWORD processId)
{
    std::wstring commandLine;

    // Método usando NtQueryInformationProcess (simplificado)
    // En implementación real usar PEB reading
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
    if (hProcess)
    {
        // Implementación simplificada - en producción leer PEB
        typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength);

        static _NtQueryInformationProcess NtQueryInformationProcess = nullptr;
        if (!NtQueryInformationProcess)
        {
            HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
            if (hNtDll)
            {
                NtQueryInformationProcess = (_NtQueryInformationProcess)
                    GetProcAddress(hNtDll, "NtQueryInformationProcess");
            }
        }

        if (NtQueryInformationProcess)
        {
            PROCESS_BASIC_INFORMATION pbi;
            NTSTATUS status = NtQueryInformationProcess(
                hProcess,
                0, // ProcessBasicInformation
                &pbi,
                sizeof(pbi),
                nullptr
            );

            if (NT_SUCCESS(status) && pbi.PebBaseAddress)
            {
                // Leer PEB y parámetros (código omitido por brevedad)
            }
        }

        CloseHandle(hProcess);
    }

    return commandLine;
}

DWORD ProcessDriver::GetParentProcessId(DWORD processId)
{
    DWORD parentPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32))
        {
            do
            {
                if (pe32.th32ProcessID == processId)
                {
                    parentPid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    return parentPid;
}

bool ProcessDriver::IsProcessElevated(DWORD processId)
{
    bool isElevated = false;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);

            if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size))
            {
                isElevated = elevation.TokenIsElevated != 0;
            }

            CloseHandle(hToken);
        }

        CloseHandle(hProcess);
    }

    return isElevated;
}

std::wstring ProcessDriver::GetProcessIntegrityLevel(DWORD processId)
{
    std::wstring integrityLevel = L"Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            DWORD length = 0;
            GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &length);

            if (length > 0)
            {
                std::vector<BYTE> buffer(length);
                if (GetTokenInformation(hToken, TokenIntegrityLevel, buffer.data(), length, &length))
                {
                    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)buffer.data();
                    DWORD integrity = *GetSidSubAuthority(pTIL->Label.Sid,
                        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                    if (integrity >= SECURITY_MANDATORY_SYSTEM_RID)
                        integrityLevel = L"System";
                    else if (integrity >= SECURITY_MANDATORY_HIGH_RID)
                        integrityLevel = L"High";
                    else if (integrity >= SECURITY_MANDATORY_MEDIUM_RID)
                        integrityLevel = L"Medium";
                    else if (integrity >= SECURITY_MANDATORY_LOW_RID)
                        integrityLevel = L"Low";
                    else
                        integrityLevel = L"Untrusted";
                }
            }

            CloseHandle(hToken);
        }

        CloseHandle(hProcess);
    }

    return integrityLevel;
}

std::wstring ProcessDriver::GetProcessUserSid(DWORD processId)
{
    std::wstring sidString;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            DWORD length = 0;
            GetTokenInformation(hToken, TokenUser, nullptr, 0, &length);

            if (length > 0)
            {
                std::vector<BYTE> buffer(length);
                if (GetTokenInformation(hToken, TokenUser, buffer.data(), length, &length))
                {
                    PTOKEN_USER pUser = (PTOKEN_USER)buffer.data();
                    LPWSTR sid = nullptr;

                    if (ConvertSidToStringSidW(pUser->User.Sid, &sid))
                    {
                        sidString = sid;
                        LocalFree(sid);
                    }
                }
            }

            CloseHandle(hToken);
        }

        CloseHandle(hProcess);
    }

    return sidString;
}

ProcessDriver::Statistics ProcessDriver::GetStatistics() const
{
    EnterCriticalSection(&m_csLock);
    Statistics stats = m_stats;
    LeaveCriticalSection(&m_csLock);
    return stats;
}

// Hilo de trabajo
DWORD WINAPI ProcessDriver::WorkerThreadProc(LPVOID lpParameter)
{
    ProcessDriver* pDriver = reinterpret_cast<ProcessDriver*>(lpParameter);
    return pDriver->WorkerThread();
}

DWORD ProcessDriver::WorkerThread()
{
    LogInfo(L"Hilo de trabajo de ProcessDriver iniciado");

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

    LogInfo(L"Hilo de trabajo de ProcessDriver terminado");
    return 0;
}

bool ProcessDriver::ProcessMessage(const void* message, DWORD messageSize)
{
    if (!message || messageSize < sizeof(FILTER_MESSAGE_HEADER))
        return false;

    auto header = reinterpret_cast<const FILTER_MESSAGE_HEADER*>(message);
    
    switch (header->ReplyLength)
    {
    case sizeof(ProcessCreateMessage):
        HandleProcessCreate(message);
        break;
    case sizeof(ProcessTerminateMessage):
        HandleProcessTerminate(message);
        break;
    case sizeof(ThreadCreateMessage):
        HandleThreadCreate(message);
        break;
    case sizeof(ThreadTerminateMessage):
        HandleThreadTerminate(message);
        break;
    case sizeof(ImageLoadMessage):
        HandleImageLoad(message);
        break;
    default:
        LogDebug(L"Mensaje desconocido del driver: tamaño %lu", header->ReplyLength);
        break;
    }

    return true;
}

void ProcessDriver::HandleProcessCreate(const void* message)
{
    auto msg = reinterpret_cast<const ProcessCreateMessage*>(message);
    
    EnterCriticalSection(&m_csLock);
    if (m_processCreateCallback)
    {
        try
        {
            m_processCreateCallback(
                msg->ProcessId,
                msg->ParentProcessId,
                msg->CreatingThreadId,
                m_processCreateContext
            );
        }
        catch (...) {}
    }
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.ProcessesCreated);
    LogDebug(L"Proceso creado: PID=%lu, Parent=%lu", 
        msg->ProcessId, msg->ParentProcessId);
}

void ProcessDriver::HandleProcessTerminate(const void* message)
{
    auto msg = reinterpret_cast<const ProcessTerminateMessage*>(message);
    
    EnterCriticalSection(&m_csLock);
    if (m_processTerminateCallback)
    {
        try
        {
            m_processTerminateCallback(
                msg->ProcessId,
                m_processTerminateContext
            );
        }
        catch (...) {}
    }
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.ProcessesTerminated);
    LogDebug(L"Proceso terminado: PID=%lu, ExitCode=%lu", 
        msg->ProcessId, msg->ExitCode);
}

void ProcessDriver::HandleThreadCreate(const void* message)
{
    auto msg = reinterpret_cast<const ThreadCreateMessage*>(message);
    
    EnterCriticalSection(&m_csLock);
    if (m_threadCreateCallback)
    {
        try
        {
            m_threadCreateCallback(
                msg->ThreadId,
                msg->ProcessId,
                m_threadCreateContext
            );
        }
        catch (...) {}
    }
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.ThreadsCreated);
    LogDebug(L"Hilo creado: TID=%lu, PID=%lu", 
        msg->ThreadId, msg->ProcessId);
}

void ProcessDriver::HandleThreadTerminate(const void* message)
{
    auto msg = reinterpret_cast<const ThreadTerminateMessage*>(message);
    
    EnterCriticalSection(&m_csLock);
    if (m_threadTerminateCallback)
    {
        try
        {
            m_threadTerminateCallback(
                msg->ThreadId,
                msg->ProcessId,
                m_threadTerminateContext
            );
        }
        catch (...) {}
    }
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.ThreadsTerminated);
    LogDebug(L"Hilo terminado: TID=%lu, PID=%lu", 
        msg->ThreadId, msg->ProcessId);
}

void ProcessDriver::HandleImageLoad(const void* message)
{
    auto msg = reinterpret_cast<const ImageLoadMessage*>(message);
    
    EnterCriticalSection(&m_csLock);
    if (m_imageLoadCallback)
    {
        try
        {
            m_imageLoadCallback(
                msg->ProcessId,
                msg->ImagePath,
                m_imageLoadContext
            );
        }
        catch (...) {}
    }
    LeaveCriticalSection(&m_csLock);

    InterlockedIncrement(&m_stats.ImagesLoaded);
    LogDebug(L"Imagen cargada: PID=%lu, Path=%ls", 
        msg->ProcessId, msg->ImagePath);
}

bool ProcessDriver::ConnectToDriver()
{
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\BWPProcessPort",
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

bool ProcessDriver::DisconnectFromDriver()
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

    return true;
}

bool ProcessDriver::SendControlCode(DWORD controlCode, void* input, DWORD inputSize,
                                   void* output, DWORD outputSize)
{
    if (m_hDriver == INVALID_HANDLE_VALUE)
    {
        // Abrir handle al driver
        m_hDriver = CreateFileW(
            L"\\\\.\\BWPProcessMonitor",
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

bool ProcessDriver::InstallDriver()
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

bool ProcessDriver::UninstallDriver()
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

bool ProcessDriver::LoadDriver()
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

bool ProcessDriver::UnloadDriver()
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

bool ProcessDriver::IsDriverLoaded() const
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

void ProcessDriver::LogError(const wchar_t* format, ...) const
{
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP ProcessDriver ERROR] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
}

void ProcessDriver::LogInfo(const wchar_t* format, ...) const
{
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP ProcessDriver INFO] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
}

void ProcessDriver::LogDebug(const wchar_t* format, ...) const
{
#ifdef _DEBUG
    va_list args;
    va_start(args, format);

    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);

    OutputDebugStringW(L"[BWP ProcessDriver DEBUG] ");
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");

    va_end(args);
#endif
}

} // namespace Drivers
} // namespace Enterprise
} // namespace BWP