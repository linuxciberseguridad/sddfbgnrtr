#pragma once

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntimage.h>

// Constantes de configuración
#define REGISTRY_DRIVER_POOL_TAG 'gBWr'
#define REGISTRY_MAX_PATH 512
#define REGISTRY_CALLBACK_ALTITUDE L"BWP.Enterprise.Registry.2026.1001"
#define REGISTRY_MAX_EVENT_QUEUE 10000
#define REGISTRY_FILTER_HIGHEST 0xF0000000

// Tipos de operaciones de registro monitoreadas
typedef enum _REGISTRY_OPERATION_TYPE
{
    RegOp_Unknown = 0,
    RegOp_CreateKey = 1,
    RegOp_OpenKey = 2,
    RegOp_DeleteKey = 3,
    RegOp_SetValue = 4,
    RegOp_DeleteValue = 5,
    RegOp_QueryKey = 6,
    RegOp_QueryValue = 7,
    RegOp_EnumKey = 8,
    RegOp_EnumValue = 9,
    RegOp_FlushKey = 10,
    RegOp_LoadKey = 11,
    RegOp_UnloadKey = 12,
    RegOp_RenameKey = 13,
    RegOp_KeyHandleClose = 14,
    RegOp_SaveKey = 15,
    RegOp_RestoreKey = 16,
    RegOp_ReplaceKey = 17
} REGISTRY_OPERATION_TYPE;

// Niveles de severidad para alertas
typedef enum _REGISTRY_ALERT_SEVERITY
{
    RegSeverity_Info = 0,
    RegSeverity_Warning = 1,
    RegSeverity_Critical = 2,
    RegSeverity_Blocked = 3
} REGISTRY_ALERT_SEVERITY;

// Categorías de riesgo para operaciones
typedef enum _REGISTRY_RISK_CATEGORY
{
    RegRisk_Legitimate = 0,
    RegRisk_Persistence = 1,      // Run, RunOnce, Services
    RegRisk_DefenseEvasion = 2,   // Disable Defender, Firewall
    RegRisk_PrivilegeEscalation = 3, // Image File Execution Options
    RegRisk_CredentialAccess = 4, // LSASS, SAM
    RegRisk_Execution = 5,        // AppInit_DLLs, Winlogon
    RegRisk_Unknown = 99
} REGISTRY_RISK_CATEGORY;

// Información detallada del proceso
typedef struct _PROCESS_CONTEXT
{
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WCHAR ProcessName[256];
    WCHAR ImagePath[REGISTRY_MAX_PATH];
    ULONG SessionId;
    BOOLEAN IsElevated;
    BOOLEAN IsSystemProcess;
    BOOLEAN IsProtectedProcess;
    WCHAR UserSid[128];
} PROCESS_CONTEXT, *PPROCESS_CONTEXT;

// Información de la clave de registro
typedef struct _REGISTRY_KEY_INFO
{
    WCHAR KeyPath[REGISTRY_MAX_PATH];
    WCHAR KeyName[256];
    WCHAR Hive[64];
    ULONG Disposition; // REG_CREATED_NEW_KEY, REG_OPENED_EXISTING_KEY
    ACCESS_MASK DesiredAccess;
    ULONG Attributes;
    ULONG KeyIndex;
    BOOLEAN IsVirtualized;
    BOOLEAN IsSymbolicLink;
} REGISTRY_KEY_INFO, *PREGISTRY_KEY_INFO;

// Información del valor de registro
typedef struct _REGISTRY_VALUE_INFO
{
    WCHAR ValueName[256];
    ULONG ValueType; // REG_SZ, REG_DWORD, etc.
    ULONG DataSize;
    PVOID Data;
    WCHAR DataString[REGISTRY_MAX_PATH];
    ULONG DataDword;
    ULONGLONG DataQword;
} REGISTRY_VALUE_INFO, *PREGISTRY_VALUE_INFO;

// Evento completo de registro
typedef struct _REGISTRY_EVENT
{
    LIST_ENTRY ListEntry;
    ULONG EventId;
    LARGE_INTEGER Timestamp;
    REGISTRY_OPERATION_TYPE OperationType;
    REGISTRY_ALERT_SEVERITY Severity;
    REGISTRY_RISK_CATEGORY RiskCategory;
    
    PROCESS_CONTEXT ProcessInfo;
    REGISTRY_KEY_INFO KeyInfo;
    REGISTRY_VALUE_INFO ValueInfo;
    
    NTSTATUS ResultStatus;
    ULONG PrePostFlag; // 0 = Pre, 1 = Post
    ULONG_PTR CallbackContext;
    
    BOOLEAN BlockedByPolicy;
    WCHAR BlockReason[512];
} REGISTRY_EVENT, *PREGISTRY_EVENT;

// Estructura de configuración del driver
typedef struct _REGISTRY_DRIVER_CONFIG
{
    BOOLEAN EnableMonitoring;
    BOOLEAN EnableBlocking;
    BOOLEAN EnableTelemetry;
    ULONG EventQueueSize;
    ULONG MaxEventRatePerSecond;
    ULONG MinSeverityToBlock; // RegSeverity_Critical
    WCHAR** ProtectedKeys;
    ULONG ProtectedKeyCount;
    WCHAR** IgnoredKeys;
    ULONG IgnoredKeyCount;
} REGISTRY_DRIVER_CONFIG, *PREGISTRY_DRIVER_CONFIG;

// Callbacks exportados a user-mode
typedef VOID(*PFN_REGISTRY_EVENT_CALLBACK)(PREGISTRY_EVENT Event, PVOID Context);
typedef VOID(*PFN_REGISTRY_BLOCK_CALLBACK)(PREGISTRY_EVENT Event, PVOID Context, PBOOLEAN Block);

// Interfaz pública del driver
extern "C"
{
    // Inicialización y limpieza
    NTSTATUS RegistryDriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
    VOID RegistryDriverUnload(PDRIVER_OBJECT DriverObject);
    
    // Control de monitoreo
    NTSTATUS RegistryStartMonitoring(PREGISTRY_DRIVER_CONFIG Config);
    NTSTATUS RegistryStopMonitoring(VOID);
    NTSTATUS RegistryUpdateConfig(PREGISTRY_DRIVER_CONFIG NewConfig);
    
    // Registro de callbacks
    NTSTATUS RegistryRegisterEventCallback(PFN_REGISTRY_EVENT_CALLBACK Callback, PVOID Context);
    NTSTATUS RegistryRegisterBlockCallback(PFN_REGISTRY_BLOCK_CALLBACK Callback, PVOID Context);
    NTSTATUS RegistryUnregisterCallbacks(VOID);
    
    // Obtención de eventos
    NTSTATUS RegistryGetEvent(PREGISTRY_EVENT Event);
    ULONG RegistryGetEventCount(VOID);
    
    // Estadísticas
    ULONG64 RegistryGetTotalEvents(VOID);
    ULONG64 RegistryGetBlockedEvents(VOID);
    ULONG64 RegistryGetDroppedEvents(VOID);
    
    // Configuración de protección
    NTSTATUS RegistryAddProtectedKey(PCWSTR KeyPath);
    NTSTATUS RegistryRemoveProtectedKey(PCWSTR KeyPath);
    NTSTATUS RegistryAddIgnoredKey(PCWSTR KeyPath);
    NTSTATUS RegistryRemoveIgnoredKey(PCWSTR KeyPath);
}

// Funciones auxiliares internas
NTSTATUS RegistryCreateDevice(PDRIVER_OBJECT DriverObject);
VOID RegistryDeleteDevice(VOID);
NTSTATUS RegistryProcessRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);
BOOLEAN RegistryIsKeyProtected(PCWSTR KeyPath);
BOOLEAN RegistryIsKeyIgnored(PCWSTR KeyPath);
VOID RegistryEnqueueEvent(PREGISTRY_EVENT Event);
NTSTATUS RegistryGetProcessContext(HANDLE ProcessId, PPROCESS_CONTEXT Context);
VOID RegistryFormatKeyPath(PUNICODE_STRING RegistryPath, PWCHAR Output, ULONG OutputSize);
REGISTRY_RISK_CATEGORY RegistryAnalyzeRisk(PREGISTRY_EVENT Event);
REGISTRY_ALERT_SEVERITY RegistryCalculateSeverity(PREGISTRY_EVENT Event);