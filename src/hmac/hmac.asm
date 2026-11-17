; hmac.asm - HMAC-SHA-256 (RFC 2104), built on sha256.asm.
;
;     HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))
;
; where K0 is the key zero-padded to one block, or H(K) zero-padded if the
; key is longer than a block. Streaming interface over a caller-allocated
; context (include/hmac.inc):
;
;     hmac_sha256_init(ctx, key, key_len)
;     hmac_sha256_update(ctx, data, len)    any number of times
;     hmac_sha256_final(ctx, mac)           wipes ctx
;
; Like the SHA-256 functions, these do not validate pointers and cannot
; fail. Calls into sha256.asm go through `wrt ..plt`, which ld -shared
; requires for exported symbols of another object (a direct call in the
; static executable).

default rel

%include "hmac.inc"

extern sha256_init
extern sha256_update
extern sha256_final

QWORDS_PER_BLOCK    equ SHA256_BLOCK_SIZE / 8
; A pad byte repeated in all 8 bytes of a qword, so the key block can be
; XORed eight bytes at a time.
BYTE_TO_QWORD       equ 0x0101010101010101
IPAD_QWORD          equ HMAC_IPAD_BYTE * BYTE_TO_QWORD
; Turns K0 ^ ipad into K0 ^ opad in place.
IPAD_TO_OPAD_QWORD  equ (HMAC_IPAD_BYTE ^ HMAC_OPAD_BYTE) * BYTE_TO_QWORD

section .text

; ---------------------------------------------------------------------------
; hmac_sha256_init
;
; Purpose:   Start an HMAC under key: derive K0, then absorb K0 ^ ipad into
;            the inner hash and K0 ^ opad into the outer hash.
; Args:      rdi = struct hmac_sha256_ctx *ctx (HMAC_CTX_SIZE bytes)
;            rsi = const uint8_t *key (may be NULL when key_len is 0)
;            rdx = size_t key_len (any length; over 64 bytes is hashed)
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, r12, r13 (saved on the stack); rbp, r14, r15 unused
; Stack:     24 bytes of saved registers + 64-byte key block, zeroed before
;            returning; rsp is 16-byte aligned at every call
; Inputs:    key is not modified
; Overlap:   key must not overlap ctx
; ---------------------------------------------------------------------------
global hmac_sha256_init:function
hmac_sha256_init:
    push    rbx
    push    r12
    push    r13
    sub     rsp, SHA256_BLOCK_SIZE  ; [rsp] = K0, then K0 ^ ipad, K0 ^ opad
    mov     rbx, rdi                ; ctx
    mov     r12, rsi                ; key
    mov     r13, rdx                ; key_len

    mov     rdi, rsp
    mov     ecx, SHA256_BLOCK_SIZE
    xor     eax, eax
    rep     stosb

    cmp     r13, SHA256_BLOCK_SIZE
    ja      .hash_key
    mov     rdi, rsp                ; short key: K0 = key || zeros
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb
    jmp     .absorb_pads

.hash_key:                          ; long key: K0 = H(key) || zeros
    lea     rdi, [rbx + HMAC_CTX_INNER] ; inner ctx is free scratch for now
    call    sha256_init wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_INNER]
    mov     rsi, r12
    mov     rdx, r13
    call    sha256_update wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_INNER]
    mov     rsi, rsp
    call    sha256_final wrt ..plt

.absorb_pads:
    mov     rax, IPAD_QWORD
    xor     ecx, ecx
.xor_ipad:
    xor     [rsp + rcx*8], rax
    inc     ecx
    cmp     ecx, QWORDS_PER_BLOCK
    jb      .xor_ipad

    lea     rdi, [rbx + HMAC_CTX_INNER]
    call    sha256_init wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_INNER]
    mov     rsi, rsp
    mov     edx, SHA256_BLOCK_SIZE
    call    sha256_update wrt ..plt

    mov     rax, IPAD_TO_OPAD_QWORD
    xor     ecx, ecx
.xor_opad:
    xor     [rsp + rcx*8], rax
    inc     ecx
    cmp     ecx, QWORDS_PER_BLOCK
    jb      .xor_opad

    lea     rdi, [rbx + HMAC_CTX_OUTER]
    call    sha256_init wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_OUTER]
    mov     rsi, rsp
    mov     edx, SHA256_BLOCK_SIZE
    call    sha256_update wrt ..plt

    ; The block is key material: do not leave it on the stack.
    mov     rdi, rsp
    mov     ecx, SHA256_BLOCK_SIZE
    xor     eax, eax
    rep     stosb

    add     rsp, SHA256_BLOCK_SIZE
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; hmac_sha256_update
;
; Purpose:   Absorb len message bytes into the inner hash.
; Args:      rdi = struct hmac_sha256_ctx *ctx (initialized)
;            rsi = const uint8_t *data (may be NULL when len is 0)
;            rdx = size_t len
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags (via sha256_update)
; Preserves: rbx, rbp, r12-r15 (sha256_update preserves them)
; Stack:     tail call: uses sha256_update's stack, entered with the
;            caller's alignment
; Inputs:    data is not modified
; Overlap:   data must not overlap ctx
; ---------------------------------------------------------------------------
global hmac_sha256_update:function
hmac_sha256_update:
    add     rdi, HMAC_CTX_INNER
    jmp     sha256_update wrt ..plt

; ---------------------------------------------------------------------------
; hmac_sha256_final
;
; Purpose:   Finish the inner hash, feed its digest to the outer hash, and
;            write the MAC. Both halves of ctx end up zeroed (sha256_final
;            wipes each); call hmac_sha256_init before reusing it.
; Args:      rdi = struct hmac_sha256_ctx *ctx (initialized)
;            rsi = uint8_t mac[32] (output)
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, r12 (saved on the stack); rbp, r13-r15 unused
; Stack:     16 bytes of saved registers + 32-byte inner digest (zeroed
;            before returning) + 8 bytes padding; rsp is 16-byte aligned
;            at every call
; Inputs:    ctx is consumed and zeroed
; Overlap:   mac must not overlap ctx. mac may be the buffer most recently
;            passed to hmac_sha256_update (that data is already absorbed).
; ---------------------------------------------------------------------------
global hmac_sha256_final:function
hmac_sha256_final:
    push    rbx
    push    r12
    sub     rsp, SHA256_DIGEST_SIZE + 8 ; inner digest + alignment padding
    mov     rbx, rdi                ; ctx
    mov     r12, rsi                ; mac

    lea     rdi, [rbx + HMAC_CTX_INNER]
    mov     rsi, rsp
    call    sha256_final wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_OUTER]
    mov     rsi, rsp
    mov     edx, SHA256_DIGEST_SIZE
    call    sha256_update wrt ..plt
    lea     rdi, [rbx + HMAC_CTX_OUTER]
    mov     rsi, r12
    call    sha256_final wrt ..plt

    xor     eax, eax                ; wipe the inner digest
    mov     [rsp + 0], rax
    mov     [rsp + 8], rax
    mov     [rsp + 16], rax
    mov     [rsp + 24], rax

    add     rsp, SHA256_DIGEST_SIZE + 8
    pop     r12
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
