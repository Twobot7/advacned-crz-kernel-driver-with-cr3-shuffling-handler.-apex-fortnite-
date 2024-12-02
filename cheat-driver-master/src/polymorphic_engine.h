#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>

#define POLY_ENTROPY_POOL_SIZE 256
#define MAX_DEVICE_NAME_LENGTH 128
#define MIN_MEMORY_REGION_SIZE 0x2000
#define MAX_MEMORY_REGION_SIZE 0x100000
#define MAX_DECOY_REGIONS 16
#define MEMORY_SHUFFLE_INTERVAL 60000 // 60 seconds

typedef enum _STEALTH_LEVEL {
    StealthLow,
    StealthMedium,
    StealthHigh,
    StealthUltra
} STEALTH_LEVEL;

typedef struct _ENTROPY_POOL {
    UCHAR Pool[POLY_ENTROPY_POOL_SIZE];
    ULONG Index;
    KSPIN_LOCK Lock;
    LARGE_INTEGER LastUpdate;
} ENTROPY_POOL, *PENTROPY_POOL;

typedef struct _MEMORY_SIGNATURE {
    UCHAR Pattern[32];
    SIZE_T Size;
    BOOLEAN IsActive;
} MEMORY_SIGNATURE, *PMEMORY_SIGNATURE;

typedef struct _POLYMORPHIC_CONTEXT {
    UNICODE_STRING UniqueId;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicName;
    PVOID RandomBaseAddress;
    SIZE_T RegionSize;
    LIST_ENTRY DecoyRegions;
    FAST_MUTEX ContextLock;
    ENTROPY_POOL EntropyPool;
    STEALTH_LEVEL StealthLevel;
    MEMORY_SIGNATURE Signature;
    KTIMER ShuffleTimer;
    KDPC ShuffleDpc;
    BOOLEAN IsObfuscated;
    ULONG MutationCounter;
} POLYMORPHIC_CONTEXT, *PPOLYMORPHIC_CONTEXT;

// Advanced initialization and cleanup
NTSTATUS InitializePolymorphicEngine(PPOLYMORPHIC_CONTEXT Context, STEALTH_LEVEL Level);
VOID CleanupPolymorphicEngine(PPOLYMORPHIC_CONTEXT Context);

// Enhanced stealth features
NTSTATUS ObfuscateMemoryRegions(PPOLYMORPHIC_CONTEXT Context);
NTSTATUS MutateDeviceCharacteristics(PPOLYMORPHIC_CONTEXT Context);
NTSTATUS GenerateMemorySignature(PPOLYMORPHIC_CONTEXT Context);
VOID UpdateEntropyPool(PPOLYMORPHIC_CONTEXT Context);

// Advanced memory management
NTSTATUS AllocateStealthMemory(PVOID* BaseAddress, SIZE_T Size, BOOLEAN UseObfuscation);
NTSTATUS CreatePolymorphicDecoys(PPOLYMORPHIC_CONTEXT Context);
VOID ShuffleMemoryPeriodically(PPOLYMORPHIC_CONTEXT Context); 