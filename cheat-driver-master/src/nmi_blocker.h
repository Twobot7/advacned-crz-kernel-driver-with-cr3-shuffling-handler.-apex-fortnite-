#pragma once
#include "polymorphic_engine.h"
#include <ntifs.h>

typedef struct _NMI_CALLBACK_CONTEXT {
    PVOID OriginalHandler;
    BOOLEAN IsBlocked;
    KSPIN_LOCK StateLock;
    MEMORY_SIGNATURE HandlerSignature;
    LIST_ENTRY PolymorphicHandlers;
} NMI_CALLBACK_CONTEXT, *PNMI_CALLBACK_CONTEXT;

NTSTATUS InitializeNmiBlocker(PPOLYMORPHIC_CONTEXT PolyContext);
NTSTATUS EnableNmiBlocking(void);
NTSTATUS DisableNmiBlocking(void);
VOID CleanupNmiBlocker(void); 