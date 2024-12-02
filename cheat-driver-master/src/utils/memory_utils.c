#include <ntifs.h>

// Securely wipes memory by overwriting it with zeros
VOID SecureZeroMemory(PVOID Buffer, SIZE_T Size) {
    if (Buffer && Size > 0) {
        volatile UCHAR* ptr = (volatile UCHAR*)Buffer;
        while (Size--) {
            *ptr++ = 0;
        }
    }
} 