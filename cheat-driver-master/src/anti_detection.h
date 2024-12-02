#pragma once
#include <ntifs.h>
#include "polymorphic_engine.h"

#define MAX_DECOY_DRIVERS 8
#define HEARTBEAT_INTERVAL 5000 // 5 seconds
#define INTEGRITY_CHECK_ROUNDS 32

typedef struct _DETECTION_CONTEXT {
    BOOLEAN IsMonitoringActive;
    KTIMER HeartbeatTimer;
    KDPC HeartbeatDpc;
    LIST_ENTRY DecoyDrivers;
    KSPIN_LOCK StateLock;
    ULONG IntegrityKey[4];
    PVOID SelfMapAddress;
} DETECTION_CONTEXT, *PDETECTION_CONTEXT;

NTSTATUS InitializeAntiDetection(PPOLYMORPHIC_CONTEXT PolyContext);
VOID CleanupAntiDetection(void); 