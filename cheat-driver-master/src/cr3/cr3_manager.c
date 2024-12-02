#include "cr3_manager.h"
#include "../utils/memory_utils.h"
#include <intrin.h>

static PCR3_MANAGER g_Cr3Manager = NULL;

// Helper function to read CR3 directly
static __forceinline CR3_TYPE ReadCr3(void) {
    return __readcr3();
}

// Helper to get process base address using advanced techniques
static NTSTATUS GetProcessBaseAddress(PEPROCESS Process, PVOID* BaseAddress) {
    if (!Process || !BaseAddress) return STATUS_INVALID_PARAMETER;
    
    // Use multiple methods to ensure reliability
    PVOID pBaseAddress = NULL;
    
    // Method 1: PEB access
    PPEB pPeb = PsGetProcessPeb(Process);
    if (pPeb) {
        __try {
            pBaseAddress = pPeb->ImageBaseAddress;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Handle exception
        }
    }
    
    // Method 2: Process VAD tree traversal
    if (!pBaseAddress) {
        // Implement VAD tree traversal here
        // This provides a backup method if PEB access fails
    }
    
    *BaseAddress = pBaseAddress;
    return pBaseAddress ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// Snapshot management functions
static VOID TakeProcessSnapshot(PCR3_MANAGER Manager, HANDLE ProcessId, CR3_TYPE Cr3, PVOID BaseAddress) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&Manager->SnapshotLock, &oldIrql);
    
    // Add new snapshot
    ULONG index = Manager->SnapshotCount % MAX_CR3_SNAPSHOTS;
    Manager->Snapshots[index].Cr3Value = Cr3;
    Manager->Snapshots[index].BaseAddress = BaseAddress;
    KeQuerySystemTime(&Manager->Snapshots[index].Timestamp);
    
    if (Manager->SnapshotCount < MAX_CR3_SNAPSHOTS) {
        Manager->SnapshotCount++;
    }
    
    KeReleaseSpinLock(&Manager->SnapshotLock, oldIrql);
}

// Advanced CR3 verification
static BOOLEAN VerifyCr3Integrity(PCR3_MANAGER Manager, CR3_TYPE Cr3, HANDLE ProcessId) {
    BOOLEAN isValid = TRUE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&Manager->SnapshotLock, &oldIrql);
    
    // Compare against historical snapshots
    for (ULONG i = 0; i < Manager->SnapshotCount; i++) {
        if (Manager->Snapshots[i].Cr3Value != Cr3) {
            // Analyze pattern of changes
            if (IsSuspiciousCr3Change(Manager->Snapshots[i].Cr3Value, Cr3)) {
                isValid = FALSE;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&Manager->SnapshotLock, oldIrql);
    return isValid;
}

// CR3 cache refresh routine
static VOID NTAPI Cr3CacheRefreshDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    PCR3_MANAGER manager = (PCR3_MANAGER)Context;
    if (!manager || !manager->Cache.IsActive) return;
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&manager->Cache.CacheLock, &oldIrql);
    
    // Refresh cache entries
    for (ULONG i = 0; i < CR3_CACHE_SIZE; i++) {
        PCR3_ENTRY entry = &manager->Cache.Entries[i];
        if (entry->ProcessId != NULL) {
            PEPROCESS process;
            if (NT_SUCCESS(PsLookupProcessByProcessId(entry->ProcessId, &process))) {
                // Update CR3 and check for shuffling
                CR3_TYPE newCr3 = ReadCr3();
                if (newCr3 != entry->CurrentCr3) {
                    entry->ShuffleCount++;
                    entry->IsShuffled = TRUE;
                    entry->CurrentCr3 = newCr3;
                }
                ObDereferenceObject(process);
            }
        }
    }
    
    KeReleaseSpinLock(&manager->Cache.CacheLock, oldIrql);
}

NTSTATUS InitializeCr3Manager(PCR3_MANAGER Manager, PPOLYMORPHIC_CONTEXT PolyContext) {
    if (!Manager || !PolyContext) return STATUS_INVALID_PARAMETER;
    
    RtlZeroMemory(Manager, sizeof(CR3_MANAGER));
    Manager->PolyContext = PolyContext;
    
    // Initialize locks
    KeInitializeSpinLock(&Manager->Cache.CacheLock);
    KeInitializeSpinLock(&Manager->SnapshotLock);
    
    // Setup refresh timer
    KeInitializeTimer(&Manager->Cache.RefreshTimer);
    KeInitializeDpc(&Manager->Cache.RefreshDpc, Cr3CacheRefreshDpc, Manager);
    
    // Start periodic refresh
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -((LONGLONG)CR3_REFRESH_INTERVAL * 10000);
    KeSetTimerEx(&Manager->Cache.RefreshTimer, dueTime, CR3_REFRESH_INTERVAL, &Manager->Cache.RefreshDpc);
    
    Manager->Cache.IsActive = TRUE;
    g_Cr3Manager = Manager;
    
    return STATUS_SUCCESS;
}

NTSTATUS GetProcessCr3AndBase(PCR3_MANAGER Manager, HANDLE ProcessId, PCR3_TYPE Cr3, PVOID* BaseAddress) {
    if (!Manager || !ProcessId || !Cr3 || !BaseAddress) return STATUS_INVALID_PARAMETER;
    
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process;
    
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;
    
    // Check cache first
    KIRQL oldIrql;
    KeAcquireSpinLock(&Manager->Cache.CacheLock, &oldIrql);
    
    PCR3_ENTRY cacheEntry = NULL;
    for (ULONG i = 0; i < CR3_CACHE_SIZE; i++) {
        if (Manager->Cache.Entries[i].ProcessId == ProcessId) {
            cacheEntry = &Manager->Cache.Entries[i];
            break;
        }
    }
    
    if (cacheEntry) {
        *Cr3 = cacheEntry->CurrentCr3;
        *BaseAddress = cacheEntry->BaseAddress;
        
        // Verify integrity
        if (!VerifyCr3Integrity(Manager, *Cr3, ProcessId)) {
            status = STATUS_UNSUCCESSFUL;
        }
    } else {
        // Cache miss - create new entry
        for (ULONG i = 0; i < CR3_CACHE_SIZE; i++) {
            if (Manager->Cache.Entries[i].ProcessId == NULL) {
                cacheEntry = &Manager->Cache.Entries[i];
                cacheEntry->ProcessId = ProcessId;
                cacheEntry->CurrentCr3 = ReadCr3();
                cacheEntry->OriginalCr3 = cacheEntry->CurrentCr3;
                status = GetProcessBaseAddress(process, &cacheEntry->BaseAddress);
                
                if (NT_SUCCESS(status)) {
                    *Cr3 = cacheEntry->CurrentCr3;
                    *BaseAddress = cacheEntry->BaseAddress;
                    TakeProcessSnapshot(Manager, ProcessId, *Cr3, *BaseAddress);
                }
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&Manager->Cache.CacheLock, oldIrql);
    ObDereferenceObject(process);
    
    return status;
}

NTSTATUS HandleCr3Shuffle(PCR3_MANAGER Manager, HANDLE ProcessId) {
    if (!Manager || !ProcessId) return STATUS_INVALID_PARAMETER;
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&Manager->Cache.CacheLock, &oldIrql);
    
    PCR3_ENTRY entry = NULL;
    for (ULONG i = 0; i < CR3_CACHE_SIZE; i++) {
        if (Manager->Cache.Entries[i].ProcessId == ProcessId) {
            entry = &Manager->Cache.Entries[i];
            break;
        }
    }
    
    if (entry && entry->IsShuffled) {
        // Implement advanced shuffle handling
        CR3_TYPE newCr3 = ReadCr3();
        
        // Verify the new CR3 is valid
        if (VerifyCr3Integrity(Manager, newCr3, ProcessId)) {
            entry->CurrentCr3 = newCr3;
            entry->ShuffleCount++;
            TakeProcessSnapshot(Manager, ProcessId, newCr3, entry->BaseAddress);
        }
        
        entry->IsShuffled = FALSE;
    }
    
    KeReleaseSpinLock(&Manager->Cache.CacheLock, oldIrql);
    return STATUS_SUCCESS;
}

VOID CleanupCr3Manager(PCR3_MANAGER Manager) {
    if (!Manager) return;
    
    // Stop refresh timer
    Manager->Cache.IsActive = FALSE;
    KeCancelTimer(&Manager->Cache.RefreshTimer);
    
    // Secure cleanup
    SecureZeroMemory(&Manager->Cache, sizeof(CR3_CACHE));
    SecureZeroMemory(&Manager->Snapshots, sizeof(CR3_SNAPSHOT) * MAX_CR3_SNAPSHOTS);
    
    g_Cr3Manager = NULL;
} 