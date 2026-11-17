; pbkdf2.asm - PBKDF2-HMAC-SHA-256 (RFC 8018 section 5.2), built on hmac.asm.
;
;     DK = T_1 || T_2 || ... truncated to output_len bytes
;     T_i = U_1 ^ U_2 ^ ... ^ U_c
;     U_1 = HMAC(P, S || INT_32_BE(i)),  U_j = HMAC(P, U_{j-1})
;
; Every HMAC uses the same key P, so the HMAC context is initialized once
; (absorbing the ipad and opad blocks) and a byte copy of it starts each
; HMAC. That saves two of the four compressions per iteration.
;
; This is the only function that validates its inputs; see the error codes
; in include/pbkdf2.inc.

default rel

%include "pbkdf2.inc"
%include "hmac.inc"

extern hmac_sha256_init
extern hmac_sha256_update
extern hmac_sha256_final

COUNTER_SIZE    equ 4               ; INT_32_BE(i)

; Stack frame of pbkdf2_hmac_sha256, offsets from rsp after the prologue.
FRAME_TEMPLATE  equ 0                               ; HMAC ctx after init(P)
FRAME_WORK      equ FRAME_TEMPLATE + HMAC_CTX_SIZE  ; copy used per HMAC
FRAME_U         equ FRAME_WORK + HMAC_CTX_SIZE      ; U_j
FRAME_T         equ FRAME_U + SHA256_DIGEST_SIZE    ; T_i accumulator
FRAME_COUNTER   equ FRAME_T + SHA256_DIGEST_SIZE    ; INT_32_BE(i)
FRAME_SIZE      equ FRAME_COUNTER + 8               ; counter slot + padding
SAVED_REGS      equ 6

; Entry rsp is 8 mod 16; after the pushes and FRAME_SIZE it must be 0.
; Skipped in the Makefile's `nasm -M` dependency pass, where __?PASS?__ is
; 0 and equ values are not available to %if (NASM 2.16.01).
%if __?PASS?__ != 0
    %if (8 + SAVED_REGS * 8 + FRAME_SIZE) % 16 != 0
        %error "pbkdf2 frame breaks 16-byte call alignment"
    %endif
%endif

; Start a new HMAC under P: FRAME_WORK = FRAME_TEMPLATE. Clobbers rcx,
; rsi, rdi.
%macro copy_template 0
    lea     rsi, [rsp + FRAME_TEMPLATE]
    lea     rdi, [rsp + FRAME_WORK]
    mov     ecx, HMAC_CTX_SIZE / 8
    rep     movsq
%endmacro

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

; ---------------------------------------------------------------------------
; pbkdf2_hmac_sha256
;
; Purpose:   Derive params->output_len bytes from password and salt with
;            PBKDF2-HMAC-SHA-256 and params->iterations iterations.
; Args:      rdi = const struct pbkdf2_params *params (PBKDF2_PARAMS_SIZE
;                  bytes; layout in include/pbkdf2.inc)
;            rsi = uint8_t *output (params->output_len bytes)
; Returns:   eax = PBKDF2_OK (0), or PBKDF2_ERR_NULL, PBKDF2_ERR_ITERATIONS,
;            PBKDF2_ERR_OUTPUT_LEN, checked in that order. On error,
;            output is not written. password or salt may be NULL only if
;            its length is 0. output_len may be 1..PBKDF2_MAX_OUTPUT_LEN.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, rbp, r12-r15 (saved on the stack on the success path;
;            the validation path uses none of them)
; Stack:     48 bytes of saved registers + FRAME_SIZE (488) bytes holding
;            two HMAC contexts, U, T and the counter, all zeroed before
;            returning; rsp is 16-byte aligned at every call
; Inputs:    params, password and salt are not modified
; Overlap:   output must not overlap params, password or salt (salt is
;            reread for every 32-byte output block)
; ---------------------------------------------------------------------------
global pbkdf2_hmac_sha256:function
pbkdf2_hmac_sha256:
    ; Validation: no frame yet, so errors return directly.
    test    rdi, rdi
    jz      .err_null
    test    rsi, rsi
    jz      .err_null
    cmp     qword [rdi + PBKDF2_PARAMS_PASSWORD], 0
    jne     .password_ok
    cmp     qword [rdi + PBKDF2_PARAMS_PASSWORD_LEN], 0
    jne     .err_null
.password_ok:
    cmp     qword [rdi + PBKDF2_PARAMS_SALT], 0
    jne     .salt_ok
    cmp     qword [rdi + PBKDF2_PARAMS_SALT_LEN], 0
    jne     .err_null
.salt_ok:
    cmp     dword [rdi + PBKDF2_PARAMS_ITERATIONS], 0
    je      .err_iterations
    mov     rax, [rdi + PBKDF2_PARAMS_OUTPUT_LEN]
    test    rax, rax
    jz      .err_output_len
    mov     rcx, PBKDF2_MAX_OUTPUT_LEN
    cmp     rax, rcx
    ja      .err_output_len

    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, FRAME_SIZE
    mov     r15, rdi                ; params (salt and iterations reread)
    mov     r12, rsi                ; next output byte
    mov     r13, rax                ; output bytes left
    mov     ebp, [r15 + PBKDF2_PARAMS_ITERATIONS]

    lea     rdi, [rsp + FRAME_TEMPLATE]
    mov     rsi, [r15 + PBKDF2_PARAMS_PASSWORD]
    mov     rdx, [r15 + PBKDF2_PARAMS_PASSWORD_LEN]
    call    hmac_sha256_init wrt ..plt

    mov     r14d, 1                 ; block index i; cannot wrap, since
                                    ; output_len <= PBKDF2_MAX_OUTPUT_LEN
.block:
    ; U_1 = HMAC(P, S || INT_32_BE(i))
    copy_template
    lea     rdi, [rsp + FRAME_WORK]
    mov     rsi, [r15 + PBKDF2_PARAMS_SALT]
    mov     rdx, [r15 + PBKDF2_PARAMS_SALT_LEN]
    call    hmac_sha256_update wrt ..plt
    mov     eax, r14d
    bswap   eax
    mov     [rsp + FRAME_COUNTER], eax
    lea     rdi, [rsp + FRAME_WORK]
    lea     rsi, [rsp + FRAME_COUNTER]
    mov     edx, COUNTER_SIZE
    call    hmac_sha256_update wrt ..plt
    lea     rdi, [rsp + FRAME_WORK]
    lea     rsi, [rsp + FRAME_U]
    call    hmac_sha256_final wrt ..plt

    ; T_i = U_1
    mov     rax, [rsp + FRAME_U + 0]
    mov     [rsp + FRAME_T + 0], rax
    mov     rax, [rsp + FRAME_U + 8]
    mov     [rsp + FRAME_T + 8], rax
    mov     rax, [rsp + FRAME_U + 16]
    mov     [rsp + FRAME_T + 16], rax
    mov     rax, [rsp + FRAME_U + 24]
    mov     [rsp + FRAME_T + 24], rax

    mov     ebx, ebp                ; iterations left, counting U_1
    dec     ebx
    jz      .emit_block
.iterate:
    ; U_j = HMAC(P, U_{j-1}), in place; T_i ^= U_j
    copy_template
    lea     rdi, [rsp + FRAME_WORK]
    lea     rsi, [rsp + FRAME_U]
    mov     edx, SHA256_DIGEST_SIZE
    call    hmac_sha256_update wrt ..plt
    lea     rdi, [rsp + FRAME_WORK]
    lea     rsi, [rsp + FRAME_U]
    call    hmac_sha256_final wrt ..plt
    mov     rax, [rsp + FRAME_U + 0]
    xor     [rsp + FRAME_T + 0], rax
    mov     rax, [rsp + FRAME_U + 8]
    xor     [rsp + FRAME_T + 8], rax
    mov     rax, [rsp + FRAME_U + 16]
    xor     [rsp + FRAME_T + 16], rax
    mov     rax, [rsp + FRAME_U + 24]
    xor     [rsp + FRAME_T + 24], rax
    dec     ebx
    jnz     .iterate

.emit_block:
    ; Append min(32, bytes left) bytes of T_i to the output.
    mov     ecx, SHA256_DIGEST_SIZE
    cmp     r13, rcx
    cmovb   rcx, r13
    lea     rsi, [rsp + FRAME_T]
    mov     rdi, r12
    add     r12, rcx
    sub     r13, rcx
    rep     movsb
    inc     r14d
    test    r13, r13
    jnz     .block

    ; The frame holds the key-derived template context and derived-key
    ; material: wipe all of it.
    mov     rdi, rsp
    mov     ecx, FRAME_SIZE
    xor     eax, eax
    rep     stosb

    add     rsp, FRAME_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    mov     eax, PBKDF2_OK
    ret

.err_null:
    mov     eax, PBKDF2_ERR_NULL
    ret
.err_iterations:
    mov     eax, PBKDF2_ERR_ITERATIONS
    ret
.err_output_len:
    mov     eax, PBKDF2_ERR_OUTPUT_LEN
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
