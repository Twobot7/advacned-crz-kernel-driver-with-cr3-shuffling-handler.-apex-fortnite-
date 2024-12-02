#include <ntifs.h>
#include <ntstrsafe.h>
#include "driver_codes.h"
#include "driver_config.h"
#include "polymorphic_engine.h"
#include "signature_spoofer.h"
#include "iat_spoofer.h"
#include "crypto/ioctl_crypto.h"
#include "utils/memory_utils.h"
#include "anti_detection.h"
#include "cr3/cr3_manager.h"

// Copies virtual memory from one process to another.
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN PVOID FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

// Forward declaration for suppressing code analysis warnings.
DRIVER_INITIALIZE DriverEntry;

// Dispatch function.
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DriverDispatch;

// Performs a memory copy request.
NTSTATUS DriverCopy(IN PDRIVER_COPY_MEMORY copy) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;

	status = PsLookupProcessByProcessId((HANDLE)copy->ProcessId, &process);

	if (NT_SUCCESS(status)) {
		PEPROCESS sourceProcess, targetProcess;
		PVOID sourcePtr, targetPtr;

		if (copy->Write == FALSE) {
			sourceProcess = process;
			targetProcess = PsGetCurrentProcess();
			sourcePtr = (PVOID)copy->Target;
			targetPtr = (PVOID)copy->Source;
		} else {
			sourceProcess = PsGetCurrentProcess();
			targetProcess = process;
			sourcePtr = (PVOID)copy->Source;
			targetPtr = (PVOID)copy->Target;
		}

		SIZE_T bytes;
		status = MmCopyVirtualMemory(sourceProcess, sourcePtr, targetProcess, targetPtr, copy->Size, KernelMode, &bytes);

		ObDereferenceObject(process);
	}

	return status;
}

// Handles a IRP request.
NTSTATUS DriverDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	PVOID ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

	// Initialize response
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		// Decrypt incoming IOCTL
		status = DecryptIOCTLBuffer(&g_CryptoContext, ioBuffer, inputLength);
		if (!NT_SUCCESS(status)) {
			goto complete_request;
		}

		ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
		
		// Verify IOCTL integrity
		if (!VerifyIOCTLIntegrity(ioControlCode, ioBuffer, inputLength)) {
			status = STATUS_INVALID_PARAMETER;
			goto complete_request;
		}

		if (ioControlCode == IOCTL_DRIVER_COPY_MEMORY) {
			if (ioBuffer && inputLength >= sizeof(DRIVER_COPY_MEMORY)) {
				// Process the request
				status = DriverCopy((PDRIVER_COPY_MEMORY)ioBuffer);
				Irp->IoStatus.Information = sizeof(DRIVER_COPY_MEMORY);
				
				// Encrypt response
				if (NT_SUCCESS(status)) {
					status = EncryptIOCTLBuffer(&g_CryptoContext, ioBuffer, 
						Irp->IoStatus.Information);
				}
			} else {
				status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} else {
			status = STATUS_INVALID_PARAMETER;
		}
		
		// Rotate crypto keys periodically
		RotateKeys(&g_CryptoContext);
	}

complete_request:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// Unloads the driver.
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
	// Cleanup CR3 manager first
	CleanupCr3Manager(&g_Cr3Manager);

	// Cleanup anti-detection first
	CleanupAntiDetection();

	// Securely wipe and free polymorphic context
	SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
	CleanupPolymorphicEngine(&g_PolyContext);

	// Securely wipe and free crypto context
	SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));

	// Delete symbolic link and device
	IoDeleteSymbolicLink(&g_PolyContext.SymbolicName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

// Add global context
static POLYMORPHIC_CONTEXT g_PolyContext;

// Add global crypto context
static CRYPTO_CONTEXT g_CryptoContext;

// Add global CR3 manager
static CR3_MANAGER g_Cr3Manager;

// Entry point for the driver.
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject = NULL;

	UNREFERENCED_PARAMETER(RegistryPath);

	// Initialize polymorphic engine
	status = InitializePolymorphicEngine(&g_PolyContext);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Initialize anti-detection after polymorphic engine
	status = InitializeAntiDetection(&g_PolyContext);
	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Initialize crypto context
	status = InitializeCrypto(&g_CryptoContext);
	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Initialize CR3 manager after polymorphic engine
	status = InitializeCr3Manager(&g_Cr3Manager, &g_PolyContext);
	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Spoof signature
	status = SpoofSignature(&g_PolyContext);
	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Spoof IAT
	status = SpoofIAT(&g_PolyContext);
	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Use generated device name
	status = IoCreateDevice(
		DriverObject,
		0,
		&g_PolyContext.DeviceName,
		DRIVER_DEVICE_TYPE,
		0,
		FALSE,
		&deviceObject
	);

	if (!NT_SUCCESS(status)) {
		SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Set up dispatch routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	DriverObject->DriverUnload = DriverUnload;

	// Create symbolic link with randomized name
	status = IoCreateSymbolicLink(&g_PolyContext.SymbolicName, &g_PolyContext.DeviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		SecureZeroMemory(&g_CryptoContext, sizeof(CRYPTO_CONTEXT));
		SecureZeroMemory(&g_PolyContext, sizeof(POLYMORPHIC_CONTEXT));
		CleanupPolymorphicEngine(&g_PolyContext);
		return status;
	}

	// Create decoy regions
	status = CreateDecoyRegions(&g_PolyContext);
	if (!NT_SUCCESS(status)) {
		// Continue even if decoy creation fails
		DbgPrint("Warning: Failed to create decoy regions\n");
	}

	return STATUS_SUCCESS;
}
