; cli.asm - standalone pbkdf2 executable (spec section 5.2).
;
; Linked only into build/pbkdf2, statically and without libc. Talks to the
; kernel through raw system calls (include/syscalls.inc).
;
; Milestone 1: _start only exits with EXIT_SUCCESS. Argument parsing,
; stdin, and the call into pbkdf2_hmac_sha256 are Milestone 5.

default rel

%include "syscalls.inc"

; Process exit statuses (spec section 5.2).
EXIT_SUCCESS    equ 0
EXIT_FAILURE    equ 1           ; library or I/O error
EXIT_USAGE      equ 2           ; bad arguments or input over a size limit

section .text

; ---------------------------------------------------------------------------
; _start
;
; Purpose:   Process entry point, called by the kernel, not by code.
; Args:      [rsp] = argc, [rsp+8..] = argv pointers, NULL, envp pointers,
;            NULL (System V process startup layout). Unused for now.
; Returns:   Does not return; exits the process with EXIT_SUCCESS.
; Modifies:  rax, rdi (and rcx, r11 via syscall)
; Preserves: nothing; there is no caller
; Stack:     rsp is 16-byte aligned on entry; not used yet
; Inputs:    not modified
; Overlap:   not applicable (no buffers)
; ---------------------------------------------------------------------------
global _start:function
_start:
    mov     edi, EXIT_SUCCESS
    mov     eax, SYS_EXIT
    syscall

section .note.GNU-stack noalloc noexec nowrite progbits
