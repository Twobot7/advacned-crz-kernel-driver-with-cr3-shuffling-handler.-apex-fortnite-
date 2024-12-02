#pragma once
#include <ntifs.h>

typedef struct _MEMORY_REGION {
    LIST_ENTRY Link;
    PVOID BaseAddress;
    SIZE_T Size;
    BOOLEAN IsDecoy;
} MEMORY_REGION, *PMEMORY_REGION;

NTSTATUS InitializeMemoryManager(void);
NTSTATUS AllocateRandomizedMemory(SIZE_T Size, PVOID* BaseAddress);
VOID ShuffleMemoryRegions(void);
VOID CleanupMemoryManager(void); 