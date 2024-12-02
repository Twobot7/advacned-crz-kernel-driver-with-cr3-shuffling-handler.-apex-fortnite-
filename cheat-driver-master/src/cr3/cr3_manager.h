#pragma once
#include <ntifs.h>
#include "../polymorphic_engine.h"

#define CR3_CACHE_SIZE 128
#define CR3_REFRESH_INTERVAL 1000 // 1 second
#define MAX_CR3_SNAPSHOTS 16

typedef struct _CR3_ENTRY {
    HANDLE ProcessId;
    CR3_TYPE CurrentCr3;
    CR3_TYPE OriginalCr3;
    PVOID BaseAddress;
    LARGE_INTEGER LastUpdate;
    BOOLEAN IsShuffled;
    ULONG ShuffleCount;
} CR3_ENTRY, *PCR3_ENTRY;

typedef struct _CR3_CACHE {
    CR3_ENTRY Entries[CR3_CACHE_SIZE];
    KSPIN_LOCK CacheLock;
    KDPC RefreshDpc;
    KTIMER RefreshTimer;
    BOOLEAN IsActive;
} CR3_CACHE, *PCR3_CACHE;

typedef struct _CR3_SNAPSHOT {
    CR3_TYPE Cr3Value;
    PVOID BaseAddress;
    LARGE_INTEGER Timestamp;
} CR3_SNAPSHOT, *PCR3_SNAPSHOT;

typedef struct _CR3_MANAGER {
    CR3_CACHE Cache;
    CR3_SNAPSHOT Snapshots[MAX_CR3_SNAPSHOTS];
    ULONG SnapshotCount;
    KSPIN_LOCK SnapshotLock;
    PPOLYMORPHIC_CONTEXT PolyContext;
} CR3_MANAGER, *PCR3_MANAGER;

NTSTATUS InitializeCr3Manager(PCR3_MANAGER Manager, PPOLYMORPHIC_CONTEXT PolyContext);
VOID CleanupCr3Manager(PCR3_MANAGER Manager);
NTSTATUS GetProcessCr3AndBase(PCR3_MANAGER Manager, HANDLE ProcessId, PCR3_TYPE Cr3, PVOID* BaseAddress);
NTSTATUS HandleCr3Shuffle(PCR3_MANAGER Manager, HANDLE ProcessId);
BOOLEAN DetectCr3Tampering(PCR3_MANAGER Manager, HANDLE ProcessId); 