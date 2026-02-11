#include "RegistryDriver.h"
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

// Variables globales del driver
static PDRIVER_OBJECT g_DriverObject = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static LARGE_INTEGER g_RegistrationHandle = {0};
static KSPIN_LOCK g_EventQueueLock;
static LIST_ENTRY g_EventQueueHead;
static ULONG g_EventQueueCount = 0;
static BOOLEAN g_MonitoringActive = FALSE;
static BOOLEAN g_BlockingEnabled = FALSE;
static REGISTRY_DRIVER_CONFIG g_CurrentConfig;
static PFN_REGISTRY_EVENT_CALLBACK g_EventCallback = NULL;
static PVOID g_EventCallbackContext = NULL;
static PFN_REGISTRY_BLOCK_CALLBACK g_BlockCallback = NULL;
static PVOID g_BlockCallbackContext = NULL;

// Estadísticas
static ULONG64 g_TotalEventsProcessed = 0;
static ULONG64 g_TotalEventsBlocked = 0;
static ULONG64 g_TotalEventsDropped = 0;
static ULONG64 g_TotalErrors = 0;
static KSPIN_LOCK g_StatsLock;

// Listas de claves protegidas/ignoradas
static KSPIN_LOCK g_ProtectedKeysLock;
static LIST_ENTRY g_ProtectedKeysHead;
static KSPIN_LOCK g_IgnoredKeysLock;
static LIST_ENTRY g_IgnoredKeysHead;

typedef struct _PROTECTED_KEY_ENTRY
{
    LIST_ENTRY ListEntry;
    WCHAR KeyPath[REGISTRY_MAX_PATH];
    ULONG KeyPathLength;
} PROTECTED_KEY_ENTRY, *PPROTECTED_KEY_ENTRY;

typedef struct _IGNORED_KEY_ENTRY
{
    LIST_ENTRY ListEntry;
    WCHAR KeyPath[REGISTRY_MAX_PATH];
    ULONG KeyPathLength;
} IGNORED_KEY_ENTRY, *PIGNORED_KEY_ENTRY;

// Pool de eventos para reducir asignaciones dinámicas
typedef struct _EVENT_POOL_ENTRY
{
    LIST_ENTRY ListEntry;
    REGISTRY_EVENT Event;
    BOOLEAN InUse;
} EVENT_POOL_ENTRY, *PEVENT_POOL_ENTRY;

static KSPIN_LOCK g_EventPoolLock;
static LIST_ENTRY g_FreeEventPoolHead;
static LIST_ENTRY g_UsedEventPoolHead;
static ULONG g_EventPoolSize = 256;
static ULONG g_EventPoolCount = 0;

// Mapa de códigos de operación a strings
typedef struct _REG_OP_MAP
{
    REGISTRY_OPERATION_TYPE OpType;
    PCWSTR OpName;
    ULONG PreNotification;
    ULONG PostNotification;
} REG_OP_MAP;

static const REG_OP_MAP g_RegOpMap[] =
{
    { RegOp_CreateKey, L"CreateKey", REG_NOTIFY_CLASS::RegNtPreCreateKey, REG_NOTIFY_CLASS::RegNtPostCreateKey },
    { RegOp_OpenKey, L"OpenKey", REG_NOTIFY_CLASS::RegNtPreOpenKey, REG_NOTIFY_CLASS::RegNtPostOpenKey },
    { RegOp_DeleteKey, L"DeleteKey", REG_NOTIFY_CLASS::RegNtPreDeleteKey, REG_NOTIFY_CLASS::RegNtPostDeleteKey },
    { RegOp_SetValue, L"SetValue", REG_NOTIFY_CLASS::RegNtPreSetValueKey, REG_NOTIFY_CLASS::RegNtPostSetValueKey },
    { RegOp_DeleteValue, L"DeleteValue", REG_NOTIFY_CLASS::RegNtPreDeleteValueKey, REG_NOTIFY_CLASS::RegNtPostDeleteValueKey },
    { RegOp_QueryKey, L"QueryKey", REG_NOTIFY_CLASS::RegNtPreQueryKey, REG_NOTIFY_CLASS::RegNtPostQueryKey },
    { RegOp_QueryValue, L"QueryValue", REG_NOTIFY_CLASS::RegNtPreQueryValueKey, REG_NOTIFY_CLASS::RegNtPostQueryValueKey },
    { RegOp_EnumKey, L"EnumKey", REG_NOTIFY_CLASS::RegNtPreEnumerateKey, REG_NOTIFY_CLASS::RegNtPostEnumerateKey },
    { RegOp_EnumValue, L"EnumValue", REG_NOTIFY_CLASS::RegNtPreEnumerateValueKey, REG_NOTIFY_CLASS::RegNtPostEnumerateValueKey },
    { RegOp_FlushKey, L"FlushKey", REG_NOTIFY_CLASS::RegNtPreFlushKey, REG_NOTIFY_CLASS::RegNtPostFlushKey },
    { RegOp_LoadKey, L"LoadKey", REG_NOTIFY_CLASS::RegNtPreLoadKey, REG_NOTIFY_CLASS::RegNtPostLoadKey },
    { RegOp_UnloadKey, L"UnloadKey", REG_NOTIFY_CLASS::RegNtPreUnLoadKey, REG_NOTIFY_CLASS::RegNtPostUnLoadKey },
    { RegOp_RenameKey, L"RenameKey", REG_NOTIFY_CLASS::RegNtPreRenameKey, REG_NOTIFY_CLASS::RegNtPostRenameKey },
    { RegOp_KeyHandleClose, L"KeyHandleClose", REG_NOTIFY_CLASS::RegNtPreKeyHandleClose, REG_NOTIFY_CLASS::RegNtPostKeyHandleClose },
    { RegOp_SaveKey, L"SaveKey", REG_NOTIFY_CLASS::RegNtPreSaveKey, REG_NOTIFY_CLASS::RegNtPostSaveKey },
    { RegOp_RestoreKey, L"RestoreKey", REG_NOTIFY_CLASS::RegNtPreRestoreKey, REG_NOTIFY_CLASS::RegNtPostRestoreKey },
    { RegOp_ReplaceKey, L"ReplaceKey", REG_NOTIFY_CLASS::RegNtPreReplaceKey, REG_NOTIFY_CLASS::RegNtPostReplaceKey }
};

// Claves de persistencia de malware más comunes
static PCWSTR g_HighRiskPersistenceKeys[] =
{
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    L"\\Registry\\User\\S-.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\User\\S-.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
};

static ULONG g_HighRiskPersistenceKeysCount = sizeof(g_HighRiskPersistenceKeys) / sizeof(g_HighRiskPersistenceKeys[0]);

// Claves de evasión de defensa
static PCWSTR g_DefenseEvasionKeys[] =
{
    L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Microsoft\\Windows Defender",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EventLog",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\SaveZoneInformation",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"
};

static ULONG g_DefenseEvasionKeysCount = sizeof(g_DefenseEvasionKeys) / sizeof(g_DefenseEvasionKeys[0]);

// Configuración por defecto
static const REGISTRY_DRIVER_CONFIG g_DefaultConfig =
{
    TRUE,  // EnableMonitoring
    TRUE,  // EnableBlocking
    TRUE,  // EnableTelemetry
    REGISTRY_MAX_EVENT_QUEUE, // EventQueueSize
    5000,  // MaxEventRatePerSecond
    RegSeverity_Critical, // MinSeverityToBlock
    NULL,  // ProtectedKeys
    0,     // ProtectedKeyCount
    NULL,  // IgnoredKeys
    0      // IgnoredKeyCount
};

// Inicialización del driver
NTSTATUS RegistryDriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Initializing v2.0.2026.1001\n");

    // Guardar DriverObject
    g_DriverObject = DriverObject;
    DriverObject->DriverUnload = RegistryDriverUnload;
    
    // Inicializar estructuras de sincronización
    KeInitializeSpinLock(&g_EventQueueLock);
    KeInitializeSpinLock(&g_StatsLock);
    KeInitializeSpinLock(&g_ProtectedKeysLock);
    KeInitializeSpinLock(&g_IgnoredKeysLock);
    KeInitializeSpinLock(&g_EventPoolLock);
    
    // Inicializar listas
    InitializeListHead(&g_EventQueueHead);
    InitializeListHead(&g_ProtectedKeysHead);
    InitializeListHead(&g_IgnoredKeysHead);
    InitializeListHead(&g_FreeEventPoolHead);
    InitializeListHead(&g_UsedEventPoolHead);
    
    // Crear dispositivo para comunicación con user-mode
    status = RegistryCreateDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[BWP RegistryDriver] Failed to create device: 0x%X\n", status);
        return status;
    }
    
    // Pre-asignar pool de eventos
    for (ULONG i = 0; i < g_EventPoolSize; i++)
    {
        PEVENT_POOL_ENTRY entry = (PEVENT_POOL_ENTRY)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(EVENT_POOL_ENTRY),
            REGISTRY_DRIVER_POOL_TAG);
            
        if (entry)
        {
            RtlZeroMemory(entry, sizeof(EVENT_POOL_ENTRY));
            entry->InUse = FALSE;
            InsertHeadList(&g_FreeEventPoolHead, &entry->ListEntry);
            g_EventPoolCount++;
        }
    }
    
    // Cargar configuración por defecto
    RtlCopyMemory(&g_CurrentConfig, &g_DefaultConfig, sizeof(REGISTRY_DRIVER_CONFIG));
    
    // Agregar claves protegidas por defecto
    for (ULONG i = 0; i < g_HighRiskPersistenceKeysCount; i++)
    {
        RegistryAddProtectedKey(g_HighRiskPersistenceKeys[i]);
    }
    
    for (ULONG i = 0; i < g_DefenseEvasionKeysCount; i++)
    {
        RegistryAddProtectedKey(g_DefenseEvasionKeys[i]);
    }
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Initialization complete\n");
    
    return STATUS_SUCCESS;
}

// Crear dispositivo para comunicación IOCTL
NTSTATUS RegistryCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    PDEVICE_OBJECT deviceObject = NULL;
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\BWPRegistryMonitor");
    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\BWPRegistryMonitor");
    
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject);
        
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // Crear enlace simbólico para acceso desde user-mode
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    deviceObject->Flags |= DO_DIRECT_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    g_DeviceObject = deviceObject;
    
    return STATUS_SUCCESS;
}

// Eliminar dispositivo
VOID RegistryDeleteDevice(VOID)
{
    UNICODE_STRING symLinkName;
    
    if (g_DeviceObject)
    {
        RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\BWPRegistryMonitor");
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

// Registrar callback de registro
NTSTATUS RegistryStartMonitoring(PREGISTRY_DRIVER_CONFIG Config)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING altitude;
    LARGE_INTEGER registrationHandle = {0};
    
    if (g_MonitoringActive)
    {
        return STATUS_ALREADY_COMMITTED;
    }
    
    // Actualizar configuración
    if (Config)
    {
        RtlCopyMemory(&g_CurrentConfig, Config, sizeof(REGISTRY_DRIVER_CONFIG));
    }
    
    // Registrar CmRegisterCallbackEx para monitoreo de registro
    RtlInitUnicodeString(&altitude, REGISTRY_CALLBACK_ALTITUDE);
    
    status = CmRegisterCallbackEx(
        RegistryProcessRegistryCallback,
        &altitude,
        g_DriverObject,
        NULL,
        &registrationHandle,
        NULL);
        
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[BWP RegistryDriver] CmRegisterCallbackEx failed: 0x%X\n", status);
        return status;
    }
    
    g_RegistrationHandle = registrationHandle;
    g_MonitoringActive = TRUE;
    g_BlockingEnabled = g_CurrentConfig.EnableBlocking;
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Registry monitoring started\n");
    
    return STATUS_SUCCESS;
}

// Detener monitoreo
NTSTATUS RegistryStopMonitoring(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!g_MonitoringActive)
    {
        return STATUS_SUCCESS;
    }
    
    if (g_RegistrationHandle.QuadPart != 0)
    {
        status = CmUnRegisterCallback(g_RegistrationHandle);
        if (NT_SUCCESS(status))
        {
            g_RegistrationHandle.QuadPart = 0;
        }
    }
    
    g_MonitoringActive = FALSE;
    g_BlockingEnabled = FALSE;
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Registry monitoring stopped\n");
    
    return status;
}

// Callback principal de registro (kernel mode)
NTSTATUS RegistryProcessRegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    NTSTATUS status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS notificationClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PREG_CREATE_KEY_INFORMATION_V1 createKeyInfo = NULL;
    PREG_OPEN_KEY_INFORMATION_V1 openKeyInfo = NULL;
    PREG_SET_VALUE_KEY_INFORMATION_V1 setValueInfo = NULL;
    PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInfo = NULL;
    PREG_DELETE_KEY_INFORMATION deleteKeyInfo = NULL;
    
    UNREFERENCED_PARAMETER(CallbackContext);
    
    if (!g_MonitoringActive)
    {
        return STATUS_SUCCESS;
    }
    
    // Rate limiting
    static ULONG lastSecond = 0;
    static ULONG eventsThisSecond = 0;
    LARGE_INTEGER currentTime;
    TIME_FIELDS timeFields;
    
    KeQuerySystemTime(&currentTime);
    RtlTimeToTimeFields(&currentTime, &timeFields);
    
    if (timeFields.Second != lastSecond)
    {
        lastSecond = timeFields.Second;
        eventsThisSecond = 0;
    }
    
    eventsThisSecond++;
    
    if (eventsThisSecond > g_CurrentConfig.MaxEventRatePerSecond)
    {
        InterlockedIncrement64(&g_TotalEventsDropped);
        return STATUS_SUCCESS; // Drop event silently
    }
    
    // Obtener evento del pool
    PEVENT_POOL_ENTRY poolEntry = NULL;
    KIRQL irql;
    KeAcquireSpinLock(&g_EventPoolLock, &irql);
    
    if (!IsListEmpty(&g_FreeEventPoolHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_FreeEventPoolHead);
        poolEntry = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
        poolEntry->InUse = TRUE;
        InsertTailList(&g_UsedEventPoolHead, &poolEntry->ListEntry);
    }
    
    KeReleaseSpinLock(&g_EventPoolLock, irql);
    
    if (!poolEntry)
    {
        // Si no hay pool, alocar temporalmente
        poolEntry = (PEVENT_POOL_ENTRY)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(EVENT_POOL_ENTRY),
            REGISTRY_DRIVER_POOL_TAG);
            
        if (!poolEntry)
        {
            InterlockedIncrement64(&g_TotalEventsDropped);
            return STATUS_SUCCESS;
        }
        
        RtlZeroMemory(poolEntry, sizeof(EVENT_POOL_ENTRY));
        poolEntry->InUse = TRUE;
    }
    
    PREGISTRY_EVENT event = &poolEntry->Event;
    RtlZeroMemory(event, sizeof(REGISTRY_EVENT));
    
    // Timestamp
    event->Timestamp = currentTime;
    event->EventId = RtlRandomEx(&g_TotalEventsProcessed) & 0xFFFFFFFF;
    
    // Determinar tipo de operación
    BOOLEAN isPreNotification = TRUE;
    
    for (ULONG i = 0; i < sizeof(g_RegOpMap) / sizeof(g_RegOpMap[0]); i++)
    {
        if (g_RegOpMap[i].PreNotification == notificationClass)
        {
            event->OperationType = g_RegOpMap[i].OpType;
            event->PrePostFlag = 0;
            isPreNotification = TRUE;
            break;
        }
        else if (g_RegOpMap[i].PostNotification == notificationClass)
        {
            event->OperationType = g_RegOpMap[i].OpType;
            event->PrePostFlag = 1;
            isPreNotification = FALSE;
            break;
        }
    }
    
    if (event->OperationType == RegOp_Unknown)
    {
        goto cleanup;
    }
    
    // Obtener información del proceso
    RegistryGetProcessContext(PsGetCurrentProcessId(), &event->ProcessInfo);
    
    // Procesar según el tipo de notificación
    switch (notificationClass)
    {
        case RegNtPreCreateKey:
        case RegNtPostCreateKey:
            createKeyInfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
            if (createKeyInfo)
            {
                RegistryFormatKeyPath(createKeyInfo->CompleteName, 
                    event->KeyInfo.KeyPath, REGISTRY_MAX_PATH);
                
                event->KeyInfo.Disposition = (ULONG)(ULONG_PTR)createKeyInfo->Disposition;
                event->KeyInfo.DesiredAccess = createKeyInfo->DesiredAccess;
                event->KeyInfo.Attributes = createKeyInfo->CreateOptions;
                
                // Verificar si es clave virtualizada
                if (createKeyInfo->CreateOptions & REG_OPTION_VOLATILE)
                {
                    event->KeyInfo.IsVirtualized = TRUE;
                }
            }
            break;
            
        case RegNtPreOpenKey:
        case RegNtPostOpenKey:
            openKeyInfo = (PREG_OPEN_KEY_INFORMATION_V1)Argument2;
            if (openKeyInfo)
            {
                RegistryFormatKeyPath(openKeyInfo->CompleteName, 
                    event->KeyInfo.KeyPath, REGISTRY_MAX_PATH);
                event->KeyInfo.DesiredAccess = openKeyInfo->DesiredAccess;
                event->KeyInfo.Attributes = openKeyInfo->OpenOptions;
            }
            break;
            
        case RegNtPreSetValueKey:
        case RegNtPostSetValueKey:
            setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION_V1)Argument2;
            if (setValueInfo)
            {
                if (setValueInfo->ValueName && setValueInfo->ValueName->Buffer)
                {
                    RtlUnicodeStringToWchar(
                        event->ValueInfo.ValueName,
                        256,
                        setValueInfo->ValueName);
                }
                
                event->ValueInfo.ValueType = setValueInfo->Type;
                event->ValueInfo.DataSize = setValueInfo->DataSize;
                
                if (setValueInfo->Data && setValueInfo->DataSize > 0)
                {
                    event->ValueInfo.Data = ExAllocatePoolWithTag(
                        NonPagedPoolNx,
                        setValueInfo->DataSize,
                        REGISTRY_DRIVER_POOL_TAG);
                        
                    if (event->ValueInfo.Data)
                    {
                        RtlCopyMemory(event->ValueInfo.Data, 
                            setValueInfo->Data, 
                            setValueInfo->DataSize);
                    }
                }
                
                // Interpretar según tipo
                switch (setValueInfo->Type)
                {
                    case REG_SZ:
                    case REG_EXPAND_SZ:
                        if (setValueInfo->Data && setValueInfo->DataSize > 0)
                        {
                            RtlStringCchCopyNW(
                                event->ValueInfo.DataString,
                                REGISTRY_MAX_PATH,
                                (PCWSTR)setValueInfo->Data,
                                setValueInfo->DataSize / sizeof(WCHAR));
                        }
                        break;
                        
                    case REG_DWORD:
                        if (setValueInfo->Data && setValueInfo->DataSize >= sizeof(ULONG))
                        {
                            event->ValueInfo.DataDword = *(PULONG)setValueInfo->Data;
                        }
                        break;
                        
                    case REG_QWORD:
                        if (setValueInfo->Data && setValueInfo->DataSize >= sizeof(ULONGLONG))
                        {
                            event->ValueInfo.DataQword = *(PULONGLONG)setValueInfo->Data;
                        }
                        break;
                }
            }
            break;
            
        case RegNtPreDeleteKey:
        case RegNtPostDeleteKey:
            deleteKeyInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (deleteKeyInfo && deleteKeyInfo->Object)
            {
                // Obtener path de la clave
                UNICODE_STRING keyPath;
                if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(
                    &g_RegistrationHandle,
                    deleteKeyInfo->Object,
                    NULL,
                    &keyPath)))
                {
                    RegistryFormatKeyPath(&keyPath, 
                        event->KeyInfo.KeyPath, 
                        REGISTRY_MAX_PATH);
                }
            }
            break;
            
        case RegNtPreDeleteValueKey:
        case RegNtPostDeleteValueKey:
            deleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (deleteValueInfo && deleteValueInfo->ValueName)
            {
                RtlUnicodeStringToWchar(
                    event->ValueInfo.ValueName,
                    256,
                    deleteValueInfo->ValueName);
            }
            break;
    }
    
    // Extraer nombre del hive y nombre de clave
    if (event->KeyInfo.KeyPath[0] != L'\0')
    {
        // Parsear \Registry\Machine\SOFTWARE\Microsoft
        PWSTR token = wcstok(event->KeyInfo.KeyPath, L"\\");
        if (token)
        {
            if (wcscmp(token, L"Registry") == 0)
            {
                token = wcstok(NULL, L"\\");
                if (token)
                {
                    RtlStringCchCopyW(event->KeyInfo.Hive, 64, token);
                    
                    token = wcstok(NULL, L"");
                    if (token)
                    {
                        RtlStringCchCopyW(event->KeyInfo.KeyName, 256, token);
                    }
                }
            }
        }
    }
    
    // Analizar riesgo
    event->RiskCategory = RegistryAnalyzeRisk(event);
    event->Severity = RegistryCalculateSeverity(event);
    
    // Verificar si está bloqueado por política
    if (isPreNotification && g_BlockingEnabled && 
        event->Severity >= g_CurrentConfig.MinSeverityToBlock)
    {
        BOOLEAN block = FALSE;
        
        if (RegistryIsKeyProtected(event->KeyInfo.KeyPath))
        {
            block = TRUE;
            RtlStringCchCopyW(event->BlockReason, 512, 
                L"Access to protected registry key blocked by BWP Enterprise policy");
        }
        else if (g_BlockCallback)
        {
            g_BlockCallback(event, g_BlockCallbackContext, &block);
        }
        
        event->BlockedByPolicy = block;
        
        if (block)
        {
            InterlockedIncrement64(&g_TotalEventsBlocked);
            
            // Bloquear la operación
            switch (notificationClass)
            {
                case RegNtPreCreateKey:
                case RegNtPreOpenKey:
                case RegNtPreSetValueKey:
                case RegNtPreDeleteKey:
                case RegNtPreDeleteValueKey:
                case RegNtPreRenameKey:
                    status = STATUS_ACCESS_DENIED;
                    event->ResultStatus = STATUS_ACCESS_DENIED;
                    break;
            }
        }
    }
    
    // Encolar evento
    InterlockedIncrement64(&g_TotalEventsProcessed);
    RegistryEnqueueEvent(event);
    
    // Callback a user-mode
    if (g_EventCallback)
    {
        g_EventCallback(event, g_EventCallbackContext);
    }
    
cleanup:
    // Liberar datos alocados
    if (event->ValueInfo.Data)
    {
        ExFreePoolWithTag(event->ValueInfo.Data, REGISTRY_DRIVER_POOL_TAG);
        event->ValueInfo.Data = NULL;
    }
    
    return status;
}

// Encolar evento para lectura desde user-mode
VOID RegistryEnqueueEvent(PREGISTRY_EVENT Event)
{
    KIRQL irql;
    
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    
    if (g_EventQueueCount < g_CurrentConfig.EventQueueSize)
    {
        // Crear copia del evento
        PEVENT_POOL_ENTRY poolEntry = NULL;
        
        // Buscar en pool de usados (ya tenemos el evento en poolEntry)
        PLIST_ENTRY entry = NULL;
        
        for (entry = g_UsedEventPoolHead.Flink; 
             entry != &g_UsedEventPoolHead; 
             entry = entry->Flink)
        {
            PEVENT_POOL_ENTRY current = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
            if (&current->Event == Event)
            {
                poolEntry = current;
                break;
            }
        }
        
        if (poolEntry)
        {
            // Remover de used list y agregar a queue
            RemoveEntryList(&poolEntry->ListEntry);
            InsertTailList(&g_EventQueueHead, &poolEntry->ListEntry);
            g_EventQueueCount++;
        }
    }
    else
    {
        InterlockedIncrement64(&g_TotalEventsDropped);
    }
    
    KeReleaseSpinLock(&g_EventQueueLock, irql);
}

// Obtener evento de la cola
NTSTATUS RegistryGetEvent(PREGISTRY_EVENT Event)
{
    NTSTATUS status = STATUS_NO_MORE_ENTRIES;
    KIRQL irql;
    
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    
    if (!IsListEmpty(&g_EventQueueHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead);
        PEVENT_POOL_ENTRY poolEntry = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
        
        RtlCopyMemory(Event, &poolEntry->Event, sizeof(REGISTRY_EVENT));
        
        // Devolver al pool de libres
        KeAcquireSpinLock(&g_EventPoolLock, &irql);
        poolEntry->InUse = FALSE;
        InsertTailList(&g_FreeEventPoolHead, &poolEntry->ListEntry);
        KeReleaseSpinLock(&g_EventPoolLock, irql);
        
        g_EventQueueCount--;
        status = STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_EventQueueLock, irql);
    
    return status;
}

// Obtener información del proceso
NTSTATUS RegistryGetProcessContext(HANDLE ProcessId, PPROCESS_CONTEXT Context)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS process = NULL;
    PACCESS_TOKEN token = NULL;
    PTOKEN_USER tokenUser = NULL;
    ULONG returnLength = 0;
    HANDLE hProcess = NULL;
    
    RtlZeroMemory(Context, sizeof(PROCESS_CONTEXT));
    Context->ProcessId = ProcessId;
    
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status) && process)
    {
        // Nombre del proceso
        RtlStringCchCopyW(Context->ProcessName, 256, 
            PsGetProcessImageFileName(process));
        
        // Session ID
        Context->SessionId = PsGetProcessSessionId(process);
        
        // Process is protected?
        Context->IsProtectedProcess = (PsIsProtectedProcess(process) != FALSE);
        
        // Token de usuario
        token = PsReferencePrimaryToken(process);
        if (token)
        {
            // Check elevation
            TOKEN_ELEVATION elevation;
            if (SeTokenIsAdmin(token))
            {
                Context->IsElevated = TRUE;
            }
            
            // Get user SID
            status = ZwQueryInformationToken(token, TokenUser, 
                NULL, 0, &returnLength);
                
            if (status == STATUS_BUFFER_TOO_SMALL && returnLength > 0)
            {
                tokenUser = (PTOKEN_USER)ExAllocatePoolWithTag(
                    NonPagedPoolNx, 
                    returnLength,
                    REGISTRY_DRIVER_POOL_TAG);
                    
                if (tokenUser)
                {
                    status = ZwQueryInformationToken(token, TokenUser,
                        tokenUser, returnLength, &returnLength);
                        
                    if (NT_SUCCESS(status) && tokenUser->User.Sid)
                    {
                        WCHAR sidString[128];
                        if (RtlConvertSidToUnicodeString(
                            &RTL_CONSTANT_STRING(sidString, 128),
                            tokenUser->User.Sid,
                            FALSE))
                        {
                            RtlStringCchCopyW(Context->UserSid, 128, sidString);
                        }
                    }
                    
                    ExFreePoolWithTag(tokenUser, REGISTRY_DRIVER_POOL_TAG);
                }
            }
            
            PsDereferencePrimaryToken(token);
        }
        
        // Is system process?
        Context->IsSystemProcess = (ProcessId == (HANDLE)4) || 
            (ProcessId == (HANDLE)0) || 
            (wcsstr(Context->ProcessName, L"System") != NULL);
        
        // Parent process ID
        PEPROCESS parentProcess = PsGetProcessInheritedFromUniqueProcessId(process);
        if (parentProcess)
        {
            Context->ParentProcessId = PsGetProcessId(parentProcess);
        }
        
        // Image path
        status = SeLocateProcessImageName(process, &hProcess);
        if (NT_SUCCESS(status) && hProcess)
        {
            UNICODE_STRING imagePath;
            RtlZeroMemory(&imagePath, sizeof(UNICODE_STRING));
            
            status = ZwQueryInformationProcess(hProcess, 
                ProcessImageFileName,
                NULL, 0, &returnLength);
                
            if (status == STATUS_INFO_LENGTH_MISMATCH && returnLength > 0)
            {
                PUNICODE_STRING pathBuffer = (PUNICODE_STRING)
                    ExAllocatePoolWithTag(PagedPool, returnLength, 
                        REGISTRY_DRIVER_POOL_TAG);
                        
                if (pathBuffer)
                {
                    status = ZwQueryInformationProcess(hProcess,
                        ProcessImageFileName,
                        pathBuffer, returnLength, &returnLength);
                        
                    if (NT_SUCCESS(status))
                    {
                        RtlUnicodeStringToWchar(Context->ImagePath,
                            REGISTRY_MAX_PATH,
                            pathBuffer);
                    }
                    
                    ExFreePoolWithTag(pathBuffer, REGISTRY_DRIVER_POOL_TAG);
                }
            }
            
            ZwClose(hProcess);
        }
        
        ObDereferenceObject(process);
    }
    
    return STATUS_SUCCESS;
}

// Formatear path de registro completo
VOID RegistryFormatKeyPath(PUNICODE_STRING RegistryPath, PWCHAR Output, ULONG OutputSize)
{
    if (!RegistryPath || !RegistryPath->Buffer || OutputSize == 0)
    {
        return;
    }
    
    RtlUnicodeStringToWchar(Output, OutputSize, RegistryPath);
    
    // Normalizar: reemplazar ?? por \Registry
    if (wcsstr(Output, L"\\??\\") == Output)
    {
        WCHAR temp[REGISTRY_MAX_PATH];
        RtlStringCchCopyW(temp, REGISTRY_MAX_PATH, Output + 4);
        RtlStringCchPrintfW(Output, OutputSize, L"\\Registry%s", temp);
    }
    else if (wcsstr(Output, L"\\REGISTRY\\") != Output)
    {
        // Intentar determinar el hive
        if (wcsstr(Output, L"HKLM") == Output || 
            wcsstr(Output, L"HKEY_LOCAL_MACHINE") == Output)
        {
            WCHAR temp[REGISTRY_MAX_PATH];
            PWSTR keyPart = wcschr(Output, L'\\');
            if (keyPart)
            {
                RtlStringCchCopyW(temp, REGISTRY_MAX_PATH, keyPart);
                RtlStringCchPrintfW(Output, OutputSize, 
                    L"\\Registry\\Machine%s", temp);
            }
        }
        else if (wcsstr(Output, L"HKCU") == Output || 
                 wcsstr(Output, L"HKEY_CURRENT_USER") == Output)
        {
            WCHAR temp[REGISTRY_MAX_PATH];
            PWSTR keyPart = wcschr(Output, L'\\');
            if (keyPart)
            {
                RtlStringCchCopyW(temp, REGISTRY_MAX_PATH, keyPart);
                RtlStringCchPrintfW(Output, OutputSize, 
                    L"\\Registry\\User\\CurrentUser%s", temp);
            }
        }
        else if (wcsstr(Output, L"HKU") == Output || 
                 wcsstr(Output, L"HKEY_USERS") == Output)
        {
            WCHAR temp[REGISTRY_MAX_PATH];
            PWSTR keyPart = wcschr(Output, L'\\');
            if (keyPart)
            {
                RtlStringCchCopyW(temp, REGISTRY_MAX_PATH, keyPart);
                RtlStringCchPrintfW(Output, OutputSize, 
                    L"\\Registry\\User%s", temp);
            }
        }
    }
}

// Analizar nivel de riesgo de la operación
REGISTRY_RISK_CATEGORY RegistryAnalyzeRisk(PREGISTRY_EVENT Event)
{
    // Verificar claves de persistencia
    for (ULONG i = 0; i < g_HighRiskPersistenceKeysCount; i++)
    {
        if (wcsstr(Event->KeyInfo.KeyPath, g_HighRiskPersistenceKeys[i]) != NULL)
        {
            // Operaciones de escritura en persistencia = alto riesgo
            if (Event->OperationType == RegOp_SetValue ||
                Event->OperationType == RegOp_CreateKey ||
                Event->OperationType == RegOp_DeleteValue)
            {
                return RegRisk_Persistence;
            }
        }
    }
    
    // Verificar claves de evasión de defensa
    for (ULONG i = 0; i < g_DefenseEvasionKeysCount; i++)
    {
        if (wcsstr(Event->KeyInfo.KeyPath, g_DefenseEvasionKeys[i]) != NULL)
        {
            return RegRisk_DefenseEvasion;
        }
    }
    
    // Verificar Image File Execution Options (depuración/ejecución)
    if (wcsstr(Event->KeyInfo.KeyPath, 
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options") != NULL)
    {
        if (Event->OperationType == RegOp_SetValue ||
            Event->OperationType == RegOp_CreateKey)
        {
            return RegRisk_PrivilegeEscalation;
        }
    }
    
    // Verificar acceso a SAM/LSASS
    if (wcsstr(Event->KeyInfo.KeyPath, 
        L"\\Registry\\Machine\\SAM") != NULL ||
        wcsstr(Event->KeyInfo.KeyPath, 
        L"\\Registry\\Machine\\SECURITY") != NULL)
    {
        if (Event->OperationType == RegOp_OpenKey &&
            (Event->KeyInfo.DesiredAccess & KEY_READ))
        {
            return RegRisk_CredentialAccess;
        }
    }
    
    // Verificar AppInit_DLLs
    if (wcsstr(Event->KeyInfo.KeyPath, 
        L"AppInit_DLLs") != NULL)
    {
        return RegRisk_Execution;
    }
    
    // Verificar Winlogon/Shell
    if (wcsstr(Event->KeyInfo.KeyPath, 
        L"Winlogon") != NULL &&
        wcsstr(Event->KeyInfo.KeyPath, 
        L"Shell") != NULL)
    {
        return RegRisk_Execution;
    }
    
    // Verificar servicios
    if (wcsstr(Event->KeyInfo.KeyPath, 
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services") != NULL)
    {
        if (Event->OperationType == RegOp_CreateKey ||
            Event->OperationType == RegOp_SetValue)
        {
            return RegRisk_Persistence;
        }
    }
    
    return RegRisk_Legitimate;
}

// Calcular severidad basada en riesgo y contexto
REGISTRY_ALERT_SEVERITY RegistryCalculateSeverity(PREGISTRY_EVENT Event)
{
    REGISTRY_ALERT_SEVERITY severity = RegSeverity_Info;
    
    switch (Event->RiskCategory)
    {
        case RegRisk_Persistence:
            if (Event->ProcessInfo.IsSystemProcess)
            {
                severity = RegSeverity_Warning;
            }
            else
            {
                severity = RegSeverity_Critical;
            }
            break;
            
        case RegRisk_DefenseEvasion:
            severity = RegSeverity_Critical;
            break;
            
        case RegRisk_PrivilegeEscalation:
            severity = RegSeverity_Critical;
            break;
            
        case RegRisk_CredentialAccess:
            severity = RegSeverity_Critical;
            break;
            
        case RegRisk_Execution:
            severity = RegSeverity_Warning;
            break;
            
        default:
            // Operaciones de lectura de procesos del sistema = info
            if (Event->OperationType == RegOp_QueryKey ||
                Event->OperationType == RegOp_QueryValue ||
                Event->OperationType == RegOp_EnumKey)
            {
                if (Event->ProcessInfo.IsSystemProcess ||
                    Event->ProcessInfo.IsElevated)
                {
                    severity = RegSeverity_Info;
                }
                else
                {
                    severity = RegSeverity_Warning;
                }
            }
            break;
    }
    
    return severity;
}

// Verificar si una clave está protegida
BOOLEAN RegistryIsKeyProtected(PCWSTR KeyPath)
{
    BOOLEAN isProtected = FALSE;
    KIRQL irql;
    
    if (!KeyPath || g_CurrentConfig.ProtectedKeyCount == 0)
    {
        return FALSE;
    }
    
    KeAcquireSpinLock(&g_ProtectedKeysLock, &irql);
    
    PLIST_ENTRY entry = g_ProtectedKeysHead.Flink;
    while (entry != &g_ProtectedKeysHead)
    {
        PPROTECTED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, PROTECTED_KEY_ENTRY, ListEntry);
        
        if (wcsstr(KeyPath, keyEntry->KeyPath) != NULL)
        {
            isProtected = TRUE;
            break;
        }
        
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
    
    return isProtected;
}

// Agregar clave protegida
NTSTATUS RegistryAddProtectedKey(PCWSTR KeyPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    
    if (!KeyPath)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Verificar si ya existe
    KeAcquireSpinLock(&g_ProtectedKeysLock, &irql);
    
    PLIST_ENTRY entry = g_ProtectedKeysHead.Flink;
    while (entry != &g_ProtectedKeysHead)
    {
        PPROTECTED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, PROTECTED_KEY_ENTRY, ListEntry);
        
        if (_wcsicmp(keyEntry->KeyPath, KeyPath) == 0)
        {
            KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
            return STATUS_OBJECT_NAME_EXISTS;
        }
        
        entry = entry->Flink;
    }
    
    // Crear nueva entrada
    PPROTECTED_KEY_ENTRY newEntry = (PPROTECTED_KEY_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PROTECTED_KEY_ENTRY),
        REGISTRY_DRIVER_POOL_TAG);
        
    if (!newEntry)
    {
        KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(newEntry, sizeof(PROTECTED_KEY_ENTRY));
    RtlStringCchCopyW(newEntry->KeyPath, REGISTRY_MAX_PATH, KeyPath);
    newEntry->KeyPathLength = (ULONG)wcslen(KeyPath);
    
    InsertTailList(&g_ProtectedKeysHead, &newEntry->ListEntry);
    g_CurrentConfig.ProtectedKeyCount++;
    
    KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
    
    return STATUS_SUCCESS;
}

// Eliminar clave protegida
NTSTATUS RegistryRemoveProtectedKey(PCWSTR KeyPath)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    
    KeAcquireSpinLock(&g_ProtectedKeysLock, &irql);
    
    PLIST_ENTRY entry = g_ProtectedKeysHead.Flink;
    while (entry != &g_ProtectedKeysHead)
    {
        PPROTECTED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, PROTECTED_KEY_ENTRY, ListEntry);
        PLIST_ENTRY nextEntry = entry->Flink;
        
        if (_wcsicmp(keyEntry->KeyPath, KeyPath) == 0)
        {
            RemoveEntryList(&keyEntry->ListEntry);
            ExFreePoolWithTag(keyEntry, REGISTRY_DRIVER_POOL_TAG);
            g_CurrentConfig.ProtectedKeyCount--;
            status = STATUS_SUCCESS;
            break;
        }
        
        entry = nextEntry;
    }
    
    KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
    
    return status;
}

// Unload del driver
VOID RegistryDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Unloading...\n");
    
    // Detener monitoreo
    RegistryStopMonitoring();
    
    // Eliminar callbacks
    RegistryUnregisterCallbacks();
    
    // Limpiar listas de claves protegidas
    KIRQL irql;
    
    KeAcquireSpinLock(&g_ProtectedKeysLock, &irql);
    while (!IsListEmpty(&g_ProtectedKeysHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_ProtectedKeysHead);
        PPROTECTED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, PROTECTED_KEY_ENTRY, ListEntry);
        ExFreePoolWithTag(keyEntry, REGISTRY_DRIVER_POOL_TAG);
    }
    KeReleaseSpinLock(&g_ProtectedKeysLock, irql);
    
    // Limpiar cola de eventos
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    while (!IsListEmpty(&g_EventQueueHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead);
        PEVENT_POOL_ENTRY poolEntry = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
        
        KeAcquireSpinLock(&g_EventPoolLock, &irql);
        poolEntry->InUse = FALSE;
        InsertTailList(&g_FreeEventPoolHead, &poolEntry->ListEntry);
        KeReleaseSpinLock(&g_EventPoolLock, irql);
    }
    g_EventQueueCount = 0;
    KeReleaseSpinLock(&g_EventQueueLock, irql);
    
    // Limpiar pool de eventos
    KeAcquireSpinLock(&g_EventPoolLock, &irql);
    while (!IsListEmpty(&g_FreeEventPoolHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_FreeEventPoolHead);
        PEVENT_POOL_ENTRY poolEntry = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
        ExFreePoolWithTag(poolEntry, REGISTRY_DRIVER_POOL_TAG);
        g_EventPoolCount--;
    }
    
    while (!IsListEmpty(&g_UsedEventPoolHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_UsedEventPoolHead);
        PEVENT_POOL_ENTRY poolEntry = CONTAINING_RECORD(entry, EVENT_POOL_ENTRY, ListEntry);
        ExFreePoolWithTag(poolEntry, REGISTRY_DRIVER_POOL_TAG);
        g_EventPoolCount--;
    }
    KeReleaseSpinLock(&g_EventPoolLock, irql);
    
    // Eliminar dispositivo
    RegistryDeleteDevice();
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BWP RegistryDriver] Unloaded. Total events: %llu, Blocked: %llu, Dropped: %llu\n",
        g_TotalEventsProcessed, g_TotalEventsBlocked, g_TotalEventsDropped);
}

// Registrar callback de evento
NTSTATUS RegistryRegisterEventCallback(PFN_REGISTRY_EVENT_CALLBACK Callback, PVOID Context)
{
    g_EventCallback = Callback;
    g_EventCallbackContext = Context;
    return STATUS_SUCCESS;
}

// Registrar callback de bloqueo
NTSTATUS RegistryRegisterBlockCallback(PFN_REGISTRY_BLOCK_CALLBACK Callback, PVOID Context)
{
    g_BlockCallback = Callback;
    g_BlockCallbackContext = Context;
    return STATUS_SUCCESS;
}

// Eliminar callbacks
NTSTATUS RegistryUnregisterCallbacks(VOID)
{
    g_EventCallback = NULL;
    g_EventCallbackContext = NULL;
    g_BlockCallback = NULL;
    g_BlockCallbackContext = NULL;
    return STATUS_SUCCESS;
}

// Obtener número de eventos en cola
ULONG RegistryGetEventCount(VOID)
{
    return g_EventQueueCount;
}

// Obtener total de eventos procesados
ULONG64 RegistryGetTotalEvents(VOID)
{
    return g_TotalEventsProcessed;
}

// Obtener total de eventos bloqueados
ULONG64 RegistryGetBlockedEvents(VOID)
{
    return g_TotalEventsBlocked;
}

// Obtener total de eventos descartados
ULONG64 RegistryGetDroppedEvents(VOID)
{
    return g_TotalEventsDropped;
}

// Actualizar configuración
NTSTATUS RegistryUpdateConfig(PREGISTRY_DRIVER_CONFIG NewConfig)
{
    if (!NewConfig)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlCopyMemory(&g_CurrentConfig, NewConfig, sizeof(REGISTRY_DRIVER_CONFIG));
    g_BlockingEnabled = g_CurrentConfig.EnableBlocking;
    
    return STATUS_SUCCESS;
}

// Agregar clave ignorada
NTSTATUS RegistryAddIgnoredKey(PCWSTR KeyPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    
    if (!KeyPath)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_IgnoredKeysLock, &irql);
    
    PIGNORED_KEY_ENTRY newEntry = (PIGNORED_KEY_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(IGNORED_KEY_ENTRY),
        REGISTRY_DRIVER_POOL_TAG);
        
    if (!newEntry)
    {
        KeReleaseSpinLock(&g_IgnoredKeysLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(newEntry, sizeof(IGNORED_KEY_ENTRY));
    RtlStringCchCopyW(newEntry->KeyPath, REGISTRY_MAX_PATH, KeyPath);
    newEntry->KeyPathLength = (ULONG)wcslen(KeyPath);
    
    InsertTailList(&g_IgnoredKeysHead, &newEntry->ListEntry);
    
    KeReleaseSpinLock(&g_IgnoredKeysLock, irql);
    
    return STATUS_SUCCESS;
}

// Eliminar clave ignorada
NTSTATUS RegistryRemoveIgnoredKey(PCWSTR KeyPath)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    
    KeAcquireSpinLock(&g_IgnoredKeysLock, &irql);
    
    PLIST_ENTRY entry = g_IgnoredKeysHead.Flink;
    while (entry != &g_IgnoredKeysHead)
    {
        PIGNORED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, IGNORED_KEY_ENTRY, ListEntry);
        PLIST_ENTRY nextEntry = entry->Flink;
        
        if (_wcsicmp(keyEntry->KeyPath, KeyPath) == 0)
        {
            RemoveEntryList(&keyEntry->ListEntry);
            ExFreePoolWithTag(keyEntry, REGISTRY_DRIVER_POOL_TAG);
            status = STATUS_SUCCESS;
            break;
        }
        
        entry = nextEntry;
    }
    
    KeReleaseSpinLock(&g_IgnoredKeysLock, irql);
    
    return status;
}

// Verificar si clave está ignorada
BOOLEAN RegistryIsKeyIgnored(PCWSTR KeyPath)
{
    BOOLEAN isIgnored = FALSE;
    KIRQL irql;
    
    if (!KeyPath || IsListEmpty(&g_IgnoredKeysHead))
    {
        return FALSE;
    }
    
    KeAcquireSpinLock(&g_IgnoredKeysLock, &irql);
    
    PLIST_ENTRY entry = g_IgnoredKeysHead.Flink;
    while (entry != &g_IgnoredKeysHead)
    {
        PIGNORED_KEY_ENTRY keyEntry = CONTAINING_RECORD(entry, IGNORED_KEY_ENTRY, ListEntry);
        
        if (wcsstr(KeyPath, keyEntry->KeyPath) != NULL)
        {
            isIgnored = TRUE;
            break;
        }
        
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&g_IgnoredKeysLock, irql);
    
    return isIgnored;
}

// DriverEntry requerido para WDM
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    return RegistryDriverInitialize(DriverObject, RegistryPath);
}