#include "polymorphic_engine.h"
#include <bcrypt.h>

// Hardware-based entropy collection
static VOID CollectHardwareEntropy(PENTROPY_POOL Pool) {
    LARGE_INTEGER tsc, perfCounter;
    ULONG cpuInfo[4];

    KeQueryPerformanceCounter(&perfCounter);
    tsc.QuadPart = __rdtsc();
    __cpuid(cpuInfo, 0);

    ExInterlockedXor64((PLONG64)&Pool->Pool[Pool->Index % POLY_ENTROPY_POOL_SIZE],
                       tsc.QuadPart ^ perfCounter.QuadPart,
                       &Pool->Lock);
    Pool->Index = (Pool->Index + 8) % POLY_ENTROPY_POOL_SIZE;
}

static VOID NTAPI ShuffleTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PPOLYMORPHIC_CONTEXT polyContext = (PPOLYMORPHIC_CONTEXT)Context;
    if (polyContext != NULL) {
        ObfuscateMemoryRegions(polyContext);
        MutateDeviceCharacteristics(polyContext);
        UpdateEntropyPool(polyContext);
    }
}

NTSTATUS ObfuscateMemoryRegions(PPOLYMORPHIC_CONTEXT Context) {
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    // Acquire lock at elevated IRQL
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    ExAcquireFastMutex(&Context->ContextLock);

    // Iterate through memory regions and apply XOR-based obfuscation
    for (entry = Context->DecoyRegions.Flink;
         entry != &Context->DecoyRegions;
         entry = entry->Flink) {
        PMEMORY_REGION region = CONTAINING_RECORD(entry, MEMORY_REGION, Link);
        
        // Apply polymorphic transformation
        for (SIZE_T i = 0; i < region->Size; i++) {
            PUCHAR byte = (PUCHAR)region->BaseAddress + i;
            *byte ^= Context->EntropyPool.Pool[i % POLY_ENTROPY_POOL_SIZE];
        }
    }

    Context->MutationCounter++;
    ExReleaseFastMutex(&Context->ContextLock);
    KeLowerIrql(oldIrql);

    return status;
}

NTSTATUS MutateDeviceCharacteristics(PPOLYMORPHIC_CONTEXT Context) {
    UCHAR randomValue[32];
    NTSTATUS status;

    status = BCryptGenRandom(NULL, randomValue, sizeof(randomValue), 
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Generate new device name with timing-based entropy
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);
    
    WCHAR newName[MAX_DEVICE_NAME_LENGTH];
    status = RtlStringCchPrintfW(
        newName,
        MAX_DEVICE_NAME_LENGTH,
        L"\\Device\\Poly_%08X%08X_%08X",
        timestamp.LowPart,
        randomValue[0] ^ randomValue[1],
        Context->MutationCounter
    );

    if (NT_SUCCESS(status)) {
        ExAcquireFastMutex(&Context->ContextLock);
        RtlInitUnicodeString(&Context->DeviceName, newName);
        ExReleaseFastMutex(&Context->ContextLock);
    }

    return status;
}

VOID UpdateEntropyPool(PPOLYMORPHIC_CONTEXT Context) {
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    // Update entropy pool only if sufficient time has passed
    if ((currentTime.QuadPart - Context->EntropyPool.LastUpdate.QuadPart) > 
        10000000) { // 1 second in 100ns intervals
        CollectHardwareEntropy(&Context->EntropyPool);
        Context->EntropyPool.LastUpdate = currentTime;
    }
}

NTSTATUS InitializePolymorphicEngine(PPOLYMORPHIC_CONTEXT Context, STEALTH_LEVEL Level) {
    NTSTATUS status;

    RtlZeroMemory(Context, sizeof(POLYMORPHIC_CONTEXT));
    Context->StealthLevel = Level;
    
    KeInitializeSpinLock(&Context->EntropyPool.Lock);
    ExInitializeFastMutex(&Context->ContextLock);
    InitializeListHead(&Context->DecoyRegions);

    // Initialize periodic timer for memory shuffling
    KeInitializeTimer(&Context->ShuffleTimer);
    KeInitializeDpc(&Context->ShuffleDpc, ShuffleTimerDpc, Context);

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -((LONGLONG)MEMORY_SHUFFLE_INTERVAL * 10000);
    KeSetTimerEx(&Context->ShuffleTimer, dueTime, MEMORY_SHUFFLE_INTERVAL, &Context->ShuffleDpc);

    // Initialize entropy pool
    UpdateEntropyPool(Context);
    
    // Create initial memory layout
    status = CreatePolymorphicDecoys(Context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Generate initial memory signature
    return GenerateMemorySignature(Context);
}

static NTSTATUS GenerateRandomBytes(PVOID Buffer, ULONG Size) {
    return BCryptGenRandom(NULL, Buffer, Size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

NTSTATUS GenerateRandomDeviceName(PUNICODE_STRING DeviceName) {
    WCHAR nameBuffer[MAX_DEVICE_NAME_LENGTH];
    UCHAR randomBytes[16];
    NTSTATUS status;

    status = GenerateRandomBytes(randomBytes, sizeof(randomBytes));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create a random device name using the random bytes
    status = RtlStringCchPrintfW(
        nameBuffer,
        MAX_DEVICE_NAME_LENGTH,
        L"\\Device\\Poly_%02X%02X%02X%02X",
        randomBytes[0], randomBytes[1], randomBytes[2], randomBytes[3]
    );

    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(DeviceName, nameBuffer);
    }

    return status;
}

NTSTATUS AllocateRandomBaseAddress(PVOID* BaseAddress, SIZE_T Size) {
    PHYSICAL_ADDRESS lowAddress, highAddress;
    ULONG_PTR randomOffset;
    
    lowAddress.QuadPart = 0;
    highAddress.QuadPart = -1;

    // Generate random offset
    GenerateRandomBytes(&randomOffset, sizeof(randomOffset));
    randomOffset &= 0xFFFFF000; // Align to page boundary

    *BaseAddress = MmAllocateContiguousMemorySpecifyCache(
        Size,
        lowAddress,
        highAddress,
        lowAddress,
        MmCached
    );

    if (*BaseAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

NTSTATUS CreateDecoyRegions(PPOLYMORPHIC_CONTEXT Context) {
    ULONG numRegions;
    GenerateRandomBytes(&numRegions, sizeof(numRegions));
    numRegions = (numRegions % 5) + 2; // 2-6 decoy regions

    for (ULONG i = 0; i < numRegions; i++) {
        SIZE_T regionSize;
        PVOID regionBase;
        
        GenerateRandomBytes(&regionSize, sizeof(regionSize));
        regionSize = (regionSize % (MAX_MEMORY_REGION_SIZE - MIN_MEMORY_REGION_SIZE)) + MIN_MEMORY_REGION_SIZE;

        if (NT_SUCCESS(AllocateRandomBaseAddress(&regionBase, regionSize))) {
            // Fill with random data
            PUCHAR buffer = (PUCHAR)regionBase;
            GenerateRandomBytes(buffer, (ULONG)regionSize);
        }
    }

    return STATUS_SUCCESS;
}