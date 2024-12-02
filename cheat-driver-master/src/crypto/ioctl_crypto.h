#pragma once
#include <ntifs.h>

#define CRYPTO_KEY_SIZE 32
#define CRYPTO_IV_SIZE 16
#define CRYPTO_BLOCK_SIZE 16
#define CRYPTO_ROUNDS 14

typedef struct _CRYPTO_CONTEXT {
    UCHAR Key[CRYPTO_KEY_SIZE];
    UCHAR IV[CRYPTO_IV_SIZE];
    ULONG SessionId;
    LARGE_INTEGER LastUpdate;
    KSPIN_LOCK Lock;
} CRYPTO_CONTEXT, *PCRYPTO_CONTEXT;

NTSTATUS InitializeCrypto(PCRYPTO_CONTEXT Context);
NTSTATUS EncryptIOCTLBuffer(PCRYPTO_CONTEXT Context, PVOID Buffer, SIZE_T Size);
NTSTATUS DecryptIOCTLBuffer(PCRYPTO_CONTEXT Context, PVOID Buffer, SIZE_T Size);
VOID RotateKeys(PCRYPTO_CONTEXT Context); 