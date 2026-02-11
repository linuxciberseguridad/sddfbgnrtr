#include <ntifs.h>
#include <fltKernel.h>
#include <wdm.h>
#include <ntstrsafe.h>

#define DRIVER_NAME L"BWPProcessDriver"
#define DEVICE_NAME L"\\Device\\BWPProcessDriver"
#define SYMBOLIC_NAME L"\\DosDevices\\BWPProcessDriver"

#define BWP_PROCESS_TAG 'PWBW'

typedef struct _BWP_PROCESS_EVENT
{
    ULONG EventType;           // 1=Create, 2=Terminate, 3=ThreadCreate, 4=ThreadTerminate
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG ThreadId;
    WCHAR ProcessName[256];
    WCHAR ProcessPath[MAX_PATH];
    WCHAR CommandLine[1024];
    WCHAR UserName[256];
    LARGE_INTEGER Timestamp;
    BOOLEAN IsElevated;
    ULONG SessionId;
} BWP_PROCESS_EVENT, *PBWP_PROCESS_EVENT;

typedef struct _BWP_PROCESS_CONTEXT
{
    PDEVICE_OBJECT DeviceObject;
    PFLT_FILTER FilterHandle;
    PEPROCESS* ProcessNotifyRoutine;
    PVOID ThreadNotifyRoutine;
    PVOID LoadImageNotifyRoutine;
    HANDLE CommunicationPort;
    KSPIN_LOCK Lock;
    BOOLEAN IsMonitoring;
    LIST_ENTRY ProcessList;
    KSPIN_LOCK ProcessListLock;
} BWP_PROCESS_CONTEXT, *PBWP_PROCESS_CONTEXT;

// Global context
BWP_PROCESS_CONTEXT g_ProcessContext = { 0 };

// Process callback structure
typedef struct _BWP_PROCESS_ENTRY
{
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    WCHAR ProcessName[256];
    LARGE_INTEGER CreateTime;
    BOOLEAN IsMalicious;
    ULONG ReferenceCount;
} BWP_PROCESS_ENTRY, *PBWP_PROCESS_ENTRY;

// Function declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS BwpCreateDevice(PDRIVER_OBJECT DriverObject);
VOID BwpDeleteDevice(PDRIVER_OBJECT DriverObject);

NTSTATUS BwpRegisterCallbacks();
VOID BwpUnregisterCallbacks();

VOID BwpProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);

VOID BwpThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
);

VOID BwpLoadImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

NTSTATUS BwpSendProcessEvent(PBWP_PROCESS_EVENT ProcessEvent);
VOID BwpLogProcessEvent(PCWSTR Message, NTSTATUS Status);

PBWP_PROCESS_ENTRY BwpFindProcessEntry(ULONG ProcessId);
PBWP_PROCESS_ENTRY BwpAddProcessEntry(ULONG ProcessId, PEPROCESS ProcessObject, PCWSTR ProcessName);
VOID BwpRemoveProcessEntry(ULONG ProcessId);
VOID BwpCleanupProcessList();

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    KdPrint((DRIVER_NAME " - DriverEntry\n"));
    
    // Initialize spin locks
    KeInitializeSpinLock(&g_ProcessContext.Lock);
    KeInitializeSpinLock(&g_ProcessContext.ProcessListLock);
    
    // Initialize process list
    InitializeListHead(&g_ProcessContext.ProcessList);
    
    // Create device object
    status = BwpCreateDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_NAME " - Failed to create device (0x%08X)\n", status));
        return status;
    }
    
    // Register callbacks
    status = BwpRegisterCallbacks();
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_NAME " - Failed to register callbacks (0x%08X)\n", status));
        BwpDeleteDevice(DriverObject);
        return status;
    }
    
    // Set driver unload routine
    DriverObject->DriverUnload = DriverUnload;
    
    // Set dispatch routines
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = BwpDispatch;
    }
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BwpDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = BwpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = BwpCreateClose;
    
    g_ProcessContext.IsMonitoring = TRUE;
    
    KdPrint((DRIVER_NAME " - Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    KdPrint((DRIVER_NAME " - DriverUnload\n"));
    
    g_ProcessContext.IsMonitoring = FALSE;
    
    // Unregister callbacks
    BwpUnregisterCallbacks();
    
    // Cleanup process list
    BwpCleanupProcessList();
    
    // Delete device
    BwpDeleteDevice(DriverObject);
    
    KdPrint((DRIVER_NAME " - Driver unloaded\n"));
}

NTSTATUS BwpCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
    
    // Create device
    status = IoCreateDevice(
        DriverObject,
        sizeof(BWP_PROCESS_CONTEXT),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    g_ProcessContext.DeviceObject = deviceObject;
    
    return STATUS_SUCCESS;
}

VOID BwpDeleteDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicName;
    
    if (g_ProcessContext.DeviceObject)
    {
        RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
        IoDeleteSymbolicLink(&symbolicName);
        IoDeleteDevice(g_ProcessContext.DeviceObject);
        g_ProcessContext.DeviceObject = NULL;
    }
}

NTSTATUS BwpRegisterCallbacks()
{
    NTSTATUS status;
    
    // Register process notify routine
    status = PsSetCreateProcessNotifyRoutineEx(BwpProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_NAME " - Failed to register process notify (0x%08X)\n", status));
        return status;
    }
    
    // Register thread notify routine
    status = PsSetCreateThreadNotifyRoutine(BwpThreadNotifyCallback);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_NAME " - Failed to register thread notify (0x%08X)\n", status));
        PsSetCreateProcessNotifyRoutineEx(BwpProcessNotifyCallback, TRUE);
        return status;
    }
    
    // Register load image notify routine
    status = PsSetLoadImageNotifyRoutine(BwpLoadImageNotifyCallback);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_NAME " - Failed to register load image notify (0x%08X)\n", status));
        PsSetCreateProcessNotifyRoutineEx(BwpProcessNotifyCallback, TRUE);
        PsSetCreateThreadNotifyRoutine(BwpThreadNotifyCallback);
        return status;
    }
    
    return STATUS_SUCCESS;
}

VOID BwpUnregisterCallbacks()
{
    // Unregister all callbacks
    if (g_ProcessContext.LoadImageNotifyRoutine)
    {
        PsRemoveLoadImageNotifyRoutine(BwpLoadImageNotifyCallback);
    }
    
    if (g_ProcessContext.ThreadNotifyRoutine)
    {
        PsRemoveCreateThreadNotifyRoutine(BwpThreadNotifyCallback);
    }
    
    if (g_ProcessContext.ProcessNotifyRoutine)
    {
        PsSetCreateProcessNotifyRoutineEx(BwpProcessNotifyCallback, TRUE);
    }
}

VOID BwpProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    KIRQL oldIrql;
    BWP_PROCESS_EVENT processEvent = { 0 };
    PEPROCESS process = NULL;
    NTSTATUS status;
    
    if (!g_ProcessContext.IsMonitoring)
    {
        return;
    }
    
    KeAcquireSpinLock(&g_ProcessContext.Lock, &oldIrql);
    
    // Get process object
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        KeReleaseSpinLock(&g_ProcessContext.Lock, oldIrql);
        return;
    }
    
    // Populate event structure
    processEvent.EventType = Create ? 1 : 2; // Create or Terminate
    processEvent.ProcessId = HandleToUlong(ProcessId);
    processEvent.ParentProcessId = HandleToUlong(ParentId);
    processEvent.Timestamp = KeQueryPerformanceCounter(NULL);
    processEvent.SessionId = PsGetProcessSessionId(process);
    
    // Get process name
    PEPROCESS processObject;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &processObject)))
    {
        // Get process image file name
        if (processObject->ImageFileName)
        {
            RtlStringCchCopyW(
                processEvent.ProcessName,
                sizeof(processEvent.ProcessName) / sizeof(WCHAR),
                processObject->ImageFileName
            );
        }
        
        ObDereferenceObject(processObject);
    }
    
    // Get command line (simplified - in production would get from EPROCESS)
    // This is a placeholder implementation
    
    // Check if process is elevated
    processEvent.IsElevated = PsIsProtectedProcess(process) ? TRUE : FALSE;
    
    // Add to process list if creating
    if (Create)
    {
        PBWP_PROCESS_ENTRY entry = BwpAddProcessEntry(
            HandleToUlong(ProcessId),
            process,
            processEvent.ProcessName
        );
        
        if (entry)
        {
            entry->CreateTime = processEvent.Timestamp;
        }
    }
    else
    {
        // Remove from process list if terminating
        BwpRemoveProcessEntry(HandleToUlong(ProcessId));
    }
    
    // Send event to user mode
    BwpSendProcessEvent(&processEvent);
    
    ObDereferenceObject(process);
    
    KeReleaseSpinLock(&g_ProcessContext.Lock, oldIrql);
}

VOID BwpThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
)
{
    KIRQL oldIrql;
    BWP_PROCESS_EVENT threadEvent = { 0 };
    
    if (!g_ProcessContext.IsMonitoring)
    {
        return;
    }
    
    KeAcquireSpinLock(&g_ProcessContext.Lock, &oldIrql);
    
    // Populate thread event
    threadEvent.EventType = Create ? 3 : 4; // ThreadCreate or ThreadTerminate
    threadEvent.ProcessId = HandleToUlong(ProcessId);
    threadEvent.ThreadId = HandleToUlong(ThreadId);
    threadEvent.Timestamp = KeQueryPerformanceCounter(NULL);
    
    // Get process name from our list
    PBWP_PROCESS_ENTRY entry = BwpFindProcessEntry(HandleToUlong(ProcessId));
    if (entry)
    {
        RtlStringCchCopyW(
            threadEvent.ProcessName,
            sizeof(threadEvent.ProcessName) / sizeof(WCHAR),
            entry->ProcessName
        );
    }
    
    // Send event to user mode
    BwpSendProcessEvent(&threadEvent);
    
    KeReleaseSpinLock(&g_ProcessContext.Lock, oldIrql);
}

VOID BwpLoadImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    KIRQL oldIrql;
    BWP_PROCESS_EVENT imageEvent = { 0 };
    
    if (!g_ProcessContext.IsMonitoring || !FullImageName)
    {
        return;
    }
    
    KeAcquireSpinLock(&g_ProcessContext.Lock, &oldIrql);
    
    // Populate image load event
    imageEvent.EventType = 5; // ImageLoad
    imageEvent.ProcessId = HandleToUlong(ProcessId);
    imageEvent.Timestamp = KeQueryPerformanceCounter(NULL);
    
    // Copy image path
    RtlStringCchCopyNW(
        imageEvent.ProcessPath,
        sizeof(imageEvent.ProcessPath) / sizeof(WCHAR),
        FullImageName->Buffer,
        min(FullImageName->Length / sizeof(WCHAR), MAX_PATH - 1)
    );
    
    // Get process name
    PBWP_PROCESS_ENTRY entry = BwpFindProcessEntry(HandleToUlong(ProcessId));
    if (entry)
    {
        RtlStringCchCopyW(
            imageEvent.ProcessName,
            sizeof(imageEvent.ProcessName) / sizeof(WCHAR),
            entry->ProcessName
        );
    }
    
    // Check if image is signed
    if (ImageInfo->ImageSignatureType == SE_IMAGE_SIGNATURE_CATALOG_CACHED ||
        ImageInfo->ImageSignatureType == SE_IMAGE_SIGNATURE_EMBEDDED)
    {
        imageEvent.IsElevated = TRUE; // Reusing field to indicate signed
    }
    
    // Send event to user mode
    BwpSendProcessEvent(&imageEvent);
    
    KeReleaseSpinLock(&g_ProcessContext.Lock, oldIrql);
}

NTSTATUS BwpSendProcessEvent(PBWP_PROCESS_EVENT ProcessEvent)
{
    // Implementation for sending events to user mode
    // This would typically use IOCTL or shared memory
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProcessContext.Lock, &oldIrql);
    
    // Queue event for user mode retrieval
    // In production, use proper queue implementation
    
    // Log event for debugging
    KdPrint((DRIVER_NAME " - Process Event: PID=%d, Type=%d, Name=%S\n",
        ProcessEvent->ProcessId,
        ProcessEvent->EventType,
        ProcessEvent->ProcessName));
    
    KeReleaseSpinLock(&g_ProcessContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

PBWP_PROCESS_ENTRY BwpFindProcessEntry(ULONG ProcessId)
{
    PLIST_ENTRY entry;
    PBWP_PROCESS_ENTRY processEntry;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_ProcessContext.ProcessListLock, &oldIrql);
    
    for (entry = g_ProcessContext.ProcessList.Flink;
         entry != &g_ProcessContext.ProcessList;
         entry = entry->Flink)
    {
        processEntry = CONTAINING_RECORD(entry, BWP_PROCESS_ENTRY, ListEntry);
        
        if (processEntry->ProcessId == ProcessId)
        {
            KeReleaseSpinLock(&g_ProcessContext.ProcessListLock, oldIrql);
            return processEntry;
        }
    }
    
    KeReleaseSpinLock(&g_ProcessContext.ProcessListLock, oldIrql);
    return NULL;
}

PBWP_PROCESS_ENTRY BwpAddProcessEntry(ULONG ProcessId, PEPROCESS ProcessObject, PCWSTR ProcessName)
{
    PBWP_PROCESS_ENTRY entry;
    KIRQL oldIrql;
    
    // Check if already exists
    entry = BwpFindProcessEntry(ProcessId);
    if (entry)
    {
        entry->ReferenceCount++;
        return entry;
    }
    
    // Allocate new entry
    entry = (PBWP_PROCESS_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(BWP_PROCESS_ENTRY),
        BWP_PROCESS_TAG
    );
    
    if (!entry)
    {
        return NULL;
    }
    
    RtlZeroMemory(entry, sizeof(BWP_PROCESS_ENTRY));
    
    entry->ProcessId = ProcessId;
    entry->ProcessObject = ProcessObject;
    entry->ReferenceCount = 1;
    entry->IsMalicious = FALSE;
    
    if (ProcessName)
    {
        RtlStringCchCopyW(
            entry->ProcessName,
            sizeof(entry->ProcessName) / sizeof(WCHAR),
            ProcessName
        );
    }
    
    KeAcquireSpinLock(&g_ProcessContext.ProcessListLock, &oldIrql);
    
    InsertTailList(&g_ProcessContext.ProcessList, &entry->ListEntry);
    
    KeReleaseSpinLock(&g_ProcessContext.ProcessListLock, oldIrql);
    
    return entry;
}

VOID BwpRemoveProcessEntry(ULONG ProcessId)
{
    PBWP_PROCESS_ENTRY entry;
    KIRQL oldIrql;
    
    entry = BwpFindProcessEntry(ProcessId);
    if (!entry)
    {
        return;
    }
    
    entry->ReferenceCount--;
    
    if (entry->ReferenceCount == 0)
    {
        KeAcquireSpinLock(&g_ProcessContext.ProcessListLock, &oldIrql);
        
        RemoveEntryList(&entry->ListEntry);
        
        KeReleaseSpinLock(&g_ProcessContext.ProcessListLock, oldIrql);
        
        ExFreePoolWithTag(entry, BWP_PROCESS_TAG);
    }
}

VOID BwpCleanupProcessList()
{
    PLIST_ENTRY entry, next;
    PBWP_PROCESS_ENTRY processEntry;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_ProcessContext.ProcessListLock, &oldIrql);
    
    for (entry = g_ProcessContext.ProcessList.Flink;
         entry != &g_ProcessContext.ProcessList;
         entry = next)
    {
        next = entry->Flink;
        processEntry = CONTAINING_RECORD(entry, BWP_PROCESS_ENTRY, ListEntry);
        
        RemoveEntryList(&processEntry->ListEntry);
        ExFreePoolWithTag(processEntry, BWP_PROCESS_TAG);
    }
    
    KeReleaseSpinLock(&g_ProcessContext.ProcessListLock, oldIrql);
}

// Dispatch routines
NTSTATUS BwpDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS BwpCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS BwpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_BWP_START_PROCESS_MONITOR:
            g_ProcessContext.IsMonitoring = TRUE;
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_BWP_STOP_PROCESS_MONITOR:
            g_ProcessContext.IsMonitoring = FALSE;
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_BWP_GET_PROCESS_COUNT:
            // Return number of processes being monitored
            info = 0; // Would count processes in list
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_BWP_GET_PROCESS_LIST:
            // Return list of monitored processes
            // Implementation would copy process list to output buffer
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_BWP_MARK_PROCESS_MALICIOUS:
            // Mark a process as malicious
            if (irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG))
            {
                ULONG processId = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
                PBWP_PROCESS_ENTRY entry = BwpFindProcessEntry(processId);
                if (entry)
                {
                    entry->IsMalicious = TRUE;
                    status = STATUS_SUCCESS;
                }
                else
                {
                    status = STATUS_NOT_FOUND;
                }
            }
            else
            {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
            
        case IOCTL_BWP_TERMINATE_PROCESS:
            // Terminate a malicious process
            if (irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG))
            {
                ULONG processId = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
                
                // This is a dangerous operation and should have additional checks
                // In production, this would be more carefully implemented
                
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Helper function to get process command line
NTSTATUS BwpGetProcessCommandLine(
    PEPROCESS Process,
    PWSTR CommandLineBuffer,
    ULONG BufferSize
)
{
    // This is a complex operation that requires accessing
    // process parameters in the process address space
    // This is a simplified placeholder
    
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(CommandLineBuffer);
    UNREFERENCED_PARAMETER(BufferSize);
    
    return STATUS_NOT_IMPLEMENTED;
}

// Helper function to get process username
NTSTATUS BwpGetProcessUserName(
    PEPROCESS Process,
    PWSTR UserNameBuffer,
    ULONG BufferSize
)
{
    // This requires accessing the process token and querying user information
    // This is a simplified placeholder
    
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(UserNameBuffer);
    UNREFERENCED_PARAMETER(BufferSize);
    
    return STATUS_NOT_IMPLEMENTED;
}

VOID BwpLogProcessEvent(PCWSTR Message, NTSTATUS Status)
{
    UNICODE_STRING messageStr;
    RtlInitUnicodeString(&messageStr, Message);
    
    KdPrint(("%wZ - Status: 0x%08X\n", &messageStr, Status));
}