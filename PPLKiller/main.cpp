#include <wdm.h>
#include "procinfo.h"
#include <stdio.h>
#include <stdarg.h>

// Exclude some false positive matches that have started 'happening' to occur in the KPROCESS/Pcb header
#ifdef _M_AMD64
#define PS_SEARCH_START				0x600
#else
#define PS_SEARCH_START				0x200
#endif

// The meaning of these values is currently unknown. They give identical results in PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
#define POSSIBLE_SIGNATURE_LEVEL(x)  ((x >= 6) && (x <= 64) && ((x % 6 == 0) || (x % 4 == 0)))

extern "C"
{
	DRIVER_INITIALIZE
	DriverEntry;

	DRIVER_UNLOAD
	DriverUnload;

	_Dispatch_type_(IRP_MJ_CREATE)
	_Dispatch_type_(IRP_MJ_CLOSE)
	DRIVER_DISPATCH
	DriverCreateClose;

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
	FindSignatureLevelOffsets(
		_Out_ PULONG SignatureLevelOffset,
		_Out_ PULONG SectionSignatureLevelOffset
		);

	NTSTATUS
	UnprotectProcesses(
		_In_ ULONG PsProtectionOffset,
		_In_ ULONG SignatureLevelOffset,
		_In_ ULONG SectionSignatureLevelOffset,
		_Out_ PULONG NumProcessesUnprotected,
		_Out_ PULONG NumSignatureRequirementsRemoved
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Log)
#pragma alloc_text(PAGE, FindPsProtectionOffset)
#pragma alloc_text(PAGE, FindSignatureLevelOffsets)
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
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Message, VaList);
	va_end(VaList);
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
	
	// Query all running processes
	ULONG NumProtectedProcesses = 0, BestMatchCount = 0, Offset = 0;
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
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
		goto finished;

	// Enumerate the process list
	Entry = SystemProcessInfo;
	while (Entry->NextEntryOffset != 0)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes,
									nullptr,
									OBJ_KERNEL_HANDLE,
									nullptr,
									nullptr);
		CLIENT_ID ClientId = { Entry->UniqueProcessId, nullptr };
		HANDLE ProcessHandle;
		Status = ZwOpenProcess(&ProcessHandle,
								PROCESS_QUERY_LIMITED_INFORMATION,
								&ObjectAttributes,
								&ClientId);
		if (NT_SUCCESS(Status))
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
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
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
		
		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}

	// Go over the possible offsets to find the one that is correct for all processes
	for (ULONG i = PS_SEARCH_START; i < PAGE_SIZE; ++i)
	{
		if (CandidateOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumProtectedProcesses)
			{
				Log("Found multiple offsets for PS_PROTECTION that match all processes! You should uninstall some rootkits.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			Offset = i;
			BestMatchCount = CandidateOffsets[i];
		}
	}

	if (BestMatchCount == 0 && NumProtectedProcesses > 0)
	{
		Log("Did not find any possible offsets for the PS_PROTECTION field.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumProtectedProcesses)
	{
		Log("Best found PS_PROTECTION offset match +0x%02X is only valid for %u of %u protected processes.\n",
			Offset, BestMatchCount, NumProtectedProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (NumProtectedProcesses > 0)
		Log("Found PS_PROTECTION offset +0x%02X.\n", Offset);
	else
		Log("Did not find any protected processes.\n");
	*PsProtectionOffset = Offset;

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
	ExFreePoolWithTag(CandidateOffsets, 'LPPK');
	return Status;
}

// This is only called on Windows >= 10.0.15063.0. The 'MS signature required' mitigation
// policy predates that, but the kernel mode check in MiValidateSectionCreate does not
NTSTATUS
FindSignatureLevelOffsets(
	_Out_ PULONG SignatureLevelOffset,
	_Out_ PULONG SectionSignatureLevelOffset
	)
{
	PAGED_CODE();

	*SignatureLevelOffset = 0;
	*SectionSignatureLevelOffset = 0;

	// Since the EPROCESS struct is opaque and we don't know its size, allocate for 4K possible offsets
	PULONG CandidateSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							PAGE_SIZE * sizeof(ULONG),
							'LPPK'));
	if (CandidateSignatureLevelOffsets == nullptr)
		return STATUS_NO_MEMORY;
	PULONG CandidateSectionSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							PAGE_SIZE * sizeof(ULONG),
							'LPPK'));
	if (CandidateSectionSignatureLevelOffsets == nullptr)
	{
		ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'LPPK');
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(CandidateSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);
	RtlZeroMemory(CandidateSectionSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);
	
	// Query all running processes
	ULONG NumSignatureRequiredProcesses = 0, BestMatchCount = 0;
	ULONG SignatureOffset = 0, SectionSignatureOffset = 0;
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
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
		goto finished;

	// Enumerate the process list
	Entry = SystemProcessInfo;
	while (Entry->NextEntryOffset != 0)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes,
									nullptr,
									OBJ_KERNEL_HANDLE,
									nullptr,
									nullptr);
		CLIENT_ID ClientId = { Entry->UniqueProcessId, nullptr };
		HANDLE ProcessHandle;
		Status = ZwOpenProcess(&ProcessHandle,
								PROCESS_QUERY_LIMITED_INFORMATION,
								&ObjectAttributes,
								&ClientId);
		if (NT_SUCCESS(Status))
		{
			// Query the process's signature policy status
			PROCESS_MITIGATION_POLICY_INFORMATION PolicyInfo;
			PolicyInfo.Policy = ProcessSignaturePolicy;
			Status = ZwQueryInformationProcess(ProcessHandle,
												ProcessMitigationPolicy,
												&PolicyInfo,
												sizeof(PolicyInfo),
												nullptr);

			// If it has a signature policy requirement, get the EPROCESS
			if (NT_SUCCESS(Status) && PolicyInfo.u.SignaturePolicy.u.Flags != 0)
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
					// Find plausible offsets in the EPROCESS (30/28, 56/8, 24/24 or 6/6). NB: while the offset found
					// here will be correct, POSSIBLE_SIGNATURE_LEVEL(x) does not imply x.SignaturePolicy.Flags != 0!
					ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process) - sizeof(UCHAR);
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
					{
						UCHAR CandidateSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i);
						ULONG CandidateSectionSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i + sizeof(UCHAR));

						if (POSSIBLE_SIGNATURE_LEVEL(CandidateSignatureLevel) &&
							POSSIBLE_SIGNATURE_LEVEL(CandidateSectionSignatureLevel))
						{
							CandidateSignatureLevelOffsets[i]++;
							i += sizeof(UCHAR);
							CandidateSectionSignatureLevelOffsets[i]++;
						}
					}
					NumSignatureRequiredProcesses++;
					ObfDereferenceObject(Process);
				}
			}
			ZwClose(ProcessHandle);
		}
		
		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}

	// Go over the possible offsets to find the combination that is correct for all processes
	for (ULONG i = PS_SEARCH_START; i < PAGE_SIZE; ++i)
	{
		if (CandidateSignatureLevelOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumSignatureRequiredProcesses)
			{
				Log("Found multiple offsets for SignatureLevel that match all processes! This is probably a bug - please report.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			SignatureOffset = i;
			SectionSignatureOffset = i + sizeof(UCHAR);
			BestMatchCount = CandidateSignatureLevelOffsets[i];
		}
	}

	if (BestMatchCount == 0 && NumSignatureRequiredProcesses > 0)
	{
		Log("Did not find any possible offsets for the SignatureLevel field.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumSignatureRequiredProcesses)
	{
		Log("Best found SignatureLevel offset match +0x%02X is only valid for %u of %u processes.\n",
			SignatureOffset, BestMatchCount, NumSignatureRequiredProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (NumSignatureRequiredProcesses > 0)
		Log("Found SignatureLevel offset +0x%02X and SectionSignatureLevel offset +0x%02X.\n",
			SignatureOffset, SectionSignatureOffset);
	else
		Log("Did not find any non-system processes with signature requirements.\n");
	*SignatureLevelOffset = SignatureOffset;
	*SectionSignatureLevelOffset = SectionSignatureOffset;

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
	ExFreePoolWithTag(CandidateSectionSignatureLevelOffsets, 'LPPK');
	ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'LPPK');
	return Status;
}

NTSTATUS
UnprotectProcesses(
	_In_ ULONG PsProtectionOffset,
	_In_ ULONG SignatureLevelOffset,
	_In_ ULONG SectionSignatureLevelOffset,
	_Out_ PULONG NumProcessesUnprotected,
	_Out_ PULONG NumSignatureRequirementsRemoved
	)
{
	PAGED_CODE();

	*NumProcessesUnprotected = 0;
	*NumSignatureRequirementsRemoved = 0;

	// Query all running processes
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
	if ((Status = ZwQuerySystemInformation(SystemProcessInformation,
											SystemProcessInfo,
											0,
											&Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
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
		goto finished;

	// Enumerate the process list
	Entry = SystemProcessInfo;
	while (Entry->NextEntryOffset != 0)
	{
		PEPROCESS Process;
		Status = PsLookupProcessByProcessId(Entry->UniqueProcessId,
											&Process);
		if (NT_SUCCESS(Status))
		{
			ULONG Pid = HandleToULong(Entry->UniqueProcessId);
			PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
				reinterpret_cast<PUCHAR>(Process) + PsProtectionOffset);

			// Skip non-light protected processes (i.e. System).
			// You could also discriminate by signer, e.g. to leave LSASS or antimalware protection enabled
			if (PsProtection->Level != 0 &&
				PsProtection->s.Type == PsProtectedTypeProtectedLight)
			{
				Log("PID %u (%wZ) at 0x%p is a PPL: { type: %u, audit: %u, signer: %u }.\n", Pid, &Entry->ImageName,
					Process, PsProtection->s.Type, PsProtection->s.Audit, PsProtection->s.Signer);
				
				// Goodnight sweet prince
				PsProtection->Level = 0;
				(*NumProcessesUnprotected)++;
				Log("Protection removed.\n");
			}

			// The meaning of these values is currently unknown. There are other non-zero
			// possibilities that do not have a matching signature mitigation policy (8/0, 6/6)
			PUCHAR SignatureLevel = reinterpret_cast<PUCHAR>(Process) + SignatureLevelOffset;
			PUCHAR SectionSignatureLevel = reinterpret_cast<PUCHAR>(Process) + SectionSignatureLevelOffset;
			if (Pid != 0 && Pid != 4 &&												// Not a system process?
				SignatureLevelOffset != 0 && SectionSignatureLevelOffset != 0 &&	// >= Windows 10 RS2, and offsets known?
				(*SignatureLevel == 24 || *SignatureLevel == 30 || *SignatureLevel == 56) &&
				(*SectionSignatureLevel == 8 || *SectionSignatureLevel == 24 || *SectionSignatureLevel == 28))
			{
				Log("PID %u (%wZ) at 0x%p has code signing requirements: { image: %u, section: %u }\n", Pid,
					&Entry->ImageName, Process, *SignatureLevel, *SectionSignatureLevel);

				// Hasta la vista baby
				*SignatureLevel = 0;
				*SectionSignatureLevel = 0;
				(*NumSignatureRequirementsRemoved)++;
				Log("Requirements removed.\n");
			}

			ObfDereferenceObject(Process);
		}

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
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

	// Only Windows 10.0.15063.0 and later are afflicted with kernel-enforced MS code signing requirements.
	ULONG SignatureLevelOffset = 0, SectionSignatureLevelOffset = 0;
	if (VersionInfo.dwBuildNumber >= 15063)
	{
		// Find the offsets of the [Section]SignatureLevel fields
		Status = FindSignatureLevelOffsets(&SignatureLevelOffset, &SectionSignatureLevelOffset);
		if (!NT_SUCCESS(Status))
		{
			Log("Failed to find the SignatureLevel and SectionSignatureLevel offsets for Windows %u.%u.%u.\n",
				VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
			return Status;
		}
	}

	// Remove protection from all running processes. Currently (as of 10.0.15063.0) there is a 1-to-1
	// correspondence between PPL and signature required processes, but this function will remove either
	ULONG NumUnprotected, NumSignatureRequirementsRemoved;
	Status = UnprotectProcesses(PsProtectionOffset,
								SignatureLevelOffset,
								SectionSignatureLevelOffset,
								&NumUnprotected,
								&NumSignatureRequirementsRemoved);
	if (!NT_SUCCESS(Status))
	{
		Log("Error %08X\n", Status);
		return Status;
	}
	Log("Success. Removed PPL protection from %u processes.\n", NumUnprotected);
	if (VersionInfo.dwBuildNumber >= 15063)
		Log("Removed code signing requirements from %u processes.\n", NumSignatureRequirementsRemoved);

	// Set driver callback functions
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->DriverUnload = DriverUnload;

	Log("Driver loaded successfully. You can unload it again now since it doesn't do anything.\n");

	return STATUS_SUCCESS;
}
