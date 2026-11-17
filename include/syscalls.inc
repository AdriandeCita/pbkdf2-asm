; syscalls.inc - Linux x86-64 system call numbers and constants for the CLI.
;
; Numbers from arch/x86/entry/syscalls/syscall_64.tbl in the kernel source.
; Calling convention: number in rax; arguments in rdi, rsi, rdx, r10, r8, r9;
; result in rax (a value in -4095..-1 is -errno). The syscall instruction
; clobbers rcx and r11.
;
; Cryptographic modules must not include this file.

%ifndef SYSCALLS_INC
%define SYSCALLS_INC

SYS_READ    equ 0
SYS_WRITE   equ 1
SYS_EXIT    equ 60

STDIN_FD    equ 0
STDOUT_FD   equ 1
STDERR_FD   equ 2

; errno values (include/uapi/asm-generic/errno-base.h), returned negated.
EINTR       equ 4               ; interrupted by a signal: retry
EIO         equ 5               ; used for a write that makes no progress

%endif
