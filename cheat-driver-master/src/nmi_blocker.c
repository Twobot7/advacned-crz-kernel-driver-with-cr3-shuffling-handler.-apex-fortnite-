#include "nmi_blocker.h"
#include <intrin.h>

#define NMI_CALLBACK_SIGNATURE_SIZE 32
#define MAX_HANDLER_DECOYS 8

static NMI_CALLBACK_CONTEXT g_NmiContext;
static PPOLYMORPHIC_CONTEXT g_PolyContext;

// Function to create polymorphic NMI handler
static VOID GeneratePolymorphicHandler(PVOID* HandlerAddress, SIZE_T* HandlerSize) {
    UCHAR handlerTemplate[] = {
        0x50,                   // push rax
        0x53,                   // push rbx
        0x51,                   // push rcx
        0x52,                   // push rdx
        0x48, 0x31, 0xC0,      // xor rax, rax
        0x48, 0xC7, 0xC0, 0x01, // mov rax, 1
        0x5A,                   // pop rdx
        0x59,                   // pop rcx
        0x5B,                   // pop rbx
        0x58,                   // pop rax
        0xCF                    // iretq
    };

    SIZE_T codeSize = sizeof(handlerTemplate);
    PVOID codeBuffer = ExAllocatePool(NonPagedPool, codeSize);
    
    if (codeBuffer) {
        // Apply polymorphic transformation
        for (SIZE_T i = 0; i < codeSize; i++) {
            ((PUCHAR)codeBuffer)[i] = handlerTemplate[i] ^ 
                g_PolyContext->EntropyPool.Pool[i % POLY_ENTROPY_POOL_SIZE];
        }

        *HandlerAddress = codeBuffer;
        *HandlerSize = codeSize;
    }
}

static VOID NTAPI PolymorphicNmiHandler(void) {
    if (g_NmiContext.IsBlocked) {
        return;
    }

    if (g_NmiContext.OriginalHandler) {
        ((void(*)())g_NmiContext.OriginalHandler)();
    }
}

NTSTATUS InitializeNmiBlocker(PPOLYMORPHIC_CONTEXT PolyContext) {
    g_PolyContext = PolyContext;
    KeInitializeSpinLock(&g_NmiContext.StateLock);
    InitializeListHead(&g_NmiContext.PolymorphicHandlers);

    // Create initial set of polymorphic handlers
    for (ULONG i = 0; i < MAX_HANDLER_DECOYS; i++) {
        PVOID handlerAddr;
        SIZE_T handlerSize;
        GeneratePolymorphicHandler(&handlerAddr, &handlerSize);
        
        if (handlerAddr) {
            PMEMORY_REGION region = ExAllocatePool(NonPagedPool, sizeof(MEMORY_REGION));
            if (region) {
                region->BaseAddress = handlerAddr;
                region->Size = handlerSize;
                region->IsDecoy = TRUE;
                InsertTailList(&g_NmiContext.PolymorphicHandlers, &region->Link);
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnableNmiBlocking(void) {
    KIRQL oldIrql;
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);
    KeAcquireSpinLockAtDpcLevel(&g_NmiContext.StateLock);

    g_NmiContext.IsBlocked = TRUE;
    
    // Rotate handlers
    if (!IsListEmpty(&g_NmiContext.PolymorphicHandlers)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_NmiContext.PolymorphicHandlers);
        PMEMORY_REGION region = CONTAINING_RECORD(entry, MEMORY_REGION, Link);
        
        // Install new handler
        g_NmiContext.OriginalHandler = HalSetSystemInformation(
            HalNmiHandler,
            sizeof(PVOID),
            &region->BaseAddress
        );

        InsertTailList(&g_NmiContext.PolymorphicHandlers, entry);
    }

    KeReleaseSpinLockFromDpcLevel(&g_NmiContext.StateLock);
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS DisableNmiBlocking(void) {
    KIRQL oldIrql;
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);
    KeAcquireSpinLockAtDpcLevel(&g_NmiContext.StateLock);

    g_NmiContext.IsBlocked = FALSE;
    
    if (g_NmiContext.OriginalHandler) {
        HalSetSystemInformation(
            HalNmiHandler,
            sizeof(PVOID),
            &g_NmiContext.OriginalHandler
        );
    }

    KeReleaseSpinLockFromDpcLevel(&g_NmiContext.StateLock);
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}

VOID CleanupNmiBlocker(void) {
    // Restore original handler
    DisableNmiBlocking();

    // Free polymorphic handlers
    while (!IsListEmpty(&g_NmiContext.PolymorphicHandlers)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_NmiContext.PolymorphicHandlers);
        PMEMORY_REGION region = CONTAINING_RECORD(entry, MEMORY_REGION, Link);
        
        if (region->BaseAddress) {
            ExFreePool(region->BaseAddress);
        }
        ExFreePool(region);
    }
} 