; pbkdf2.asm - PBKDF2-HMAC-SHA-256 (RFC 8018 section 5.2), built on hmac.asm.
;
; Milestone 1: only pbkdf2_abi_version, to verify that the shared library
; can be built and called from Python. pbkdf2_hmac_sha256 is Milestone 4.

default rel

%include "pbkdf2.inc"

section .text

; ---------------------------------------------------------------------------
; pbkdf2_abi_version
;
; Purpose:   Report the version of the exported interface, so callers can
;            check they were built against a compatible library.
; Args:      none
; Returns:   eax = PBKDF2_ABI_VERSION (uint32). Cannot fail.
; Modifies:  rax
; Preserves: all callee-saved registers (none are used)
; Stack:     none used; no alignment assumption
; Inputs:    none
; Overlap:   not applicable (no buffers)
; ---------------------------------------------------------------------------
global pbkdf2_abi_version:function
pbkdf2_abi_version:
    mov     eax, PBKDF2_ABI_VERSION
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
