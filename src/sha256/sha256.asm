; sha256.asm - SHA-256 (FIPS 180-4).
;
; Streaming interface over a caller-allocated context (include/sha256.inc):
;
;     sha256_init(ctx)
;     sha256_update(ctx, data, len)     any number of times
;     sha256_final(ctx, digest)         wipes ctx
;
; plus the raw block function sha256_compress(state, block).
;
; These are building blocks: they do not validate pointers and cannot
; fail. Input checking happens once, in pbkdf2_hmac_sha256.
;
; Section numbers in comments refer to FIPS 180-4.

default rel

%include "sha256.inc"

SCHEDULE_WORDS  equ 64              ; W[0..63], one per round (6.2.2)
MESSAGE_WORDS   equ 16              ; W[0..15] come straight from the block
SCHEDULE_SIZE   equ SCHEDULE_WORDS * 4
PAD_BYTE        equ 0x80            ; the '1' bit that starts padding (5.1.1)
LENGTH_OFFSET   equ SHA256_BLOCK_SIZE - SHA256_LENGTH_SIZE

section .rodata

align 16
; Round constants K0..K63 (4.2.2).
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

; Initial hash value H(0) (5.3.3).
sha256_h0:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

section .text

; ---------------------------------------------------------------------------
; sha256_compress
;
; Purpose:   Process one 64-byte block: expand the message schedule and run
;            the 64 rounds, adding the result into the hash state (6.2.2).
; Args:      rdi = uint32_t state[8] (native byte order, updated in place)
;            rsi = const uint8_t block[64]
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, rbp, r12-r15 (saved on the stack)
; Stack:     48 bytes of saved registers + 256-byte schedule W[0..63],
;            which is zeroed before returning. Leaf function: makes no
;            calls, so it assumes no alignment.
; Inputs:    block is not modified
; Overlap:   state and block must not overlap
; ---------------------------------------------------------------------------
global sha256_compress:function
sha256_compress:
sha256_compress_local:              ; file-local alias: a direct call to the
                                    ; global name would need the PLT in the .so
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SCHEDULE_SIZE      ; [rsp + 4*i] = W[i]

    ; W[0..15]: the block as big-endian 32-bit words.
    xor     ecx, ecx
.load_words:
    mov     eax, [rsi + rcx*4]
    bswap   eax
    mov     [rsp + rcx*4], eax
    inc     ecx
    cmp     ecx, MESSAGE_WORDS
    jb      .load_words

    ; W[16..63] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16]   (6.2.2 step 1)
.expand_words:
    mov     eax, [rsp + rcx*4 - 15*4]   ; s0(x) = ror7 ^ ror18 ^ shr3 (4.1.2)
    mov     edx, eax
    ror     edx, 7
    mov     ebx, eax
    ror     ebx, 18
    xor     edx, ebx
    shr     eax, 3
    xor     eax, edx
    mov     edx, [rsp + rcx*4 - 2*4]    ; s1(x) = ror17 ^ ror19 ^ shr10
    mov     ebx, edx
    ror     ebx, 17
    mov     ebp, edx
    ror     ebp, 19
    xor     ebx, ebp
    shr     edx, 10
    xor     edx, ebx
    add     eax, edx
    add     eax, [rsp + rcx*4 - 7*4]
    add     eax, [rsp + rcx*4 - 16*4]
    mov     [rsp + rcx*4], eax
    inc     ecx
    cmp     ecx, SCHEDULE_WORDS
    jb      .expand_words

    ; Working variables a..h (6.2.2 step 2).
    mov     r8d, [rdi + 0*4]        ; a
    mov     r9d, [rdi + 1*4]        ; b
    mov     r10d, [rdi + 2*4]       ; c
    mov     r11d, [rdi + 3*4]       ; d
    mov     r12d, [rdi + 4*4]       ; e
    mov     r13d, [rdi + 5*4]       ; f
    mov     r14d, [rdi + 6*4]       ; g
    mov     r15d, [rdi + 7*4]       ; h
    lea     rbp, [sha256_k]

    ; 64 rounds (6.2.2 step 3). Temporaries: eax = T1, ebx = T2, edx/esi.
    xor     ecx, ecx
.round:
    mov     eax, r12d               ; S1(e) = ror6 ^ ror11 ^ ror25 (4.1.2)
    ror     eax, 6
    mov     ebx, r12d
    ror     ebx, 11
    xor     eax, ebx
    mov     ebx, r12d
    ror     ebx, 25
    xor     eax, ebx
    mov     ebx, r13d               ; Ch(e,f,g) = g ^ (e & (f ^ g))
    xor     ebx, r14d
    and     ebx, r12d
    xor     ebx, r14d
    add     eax, ebx
    add     eax, r15d
    add     eax, [rbp + rcx*4]
    add     eax, [rsp + rcx*4]      ; T1 = h + S1(e) + Ch + K[i] + W[i]

    mov     ebx, r8d                ; S0(a) = ror2 ^ ror13 ^ ror22
    ror     ebx, 2
    mov     edx, r8d
    ror     edx, 13
    xor     ebx, edx
    mov     edx, r8d
    ror     edx, 22
    xor     ebx, edx
    mov     edx, r8d                ; Maj(a,b,c) = (a & b) | (c & (a | b))
    or      edx, r9d
    and     edx, r10d
    mov     esi, r8d
    and     esi, r9d
    or      edx, esi
    add     ebx, edx                ; T2 = S0(a) + Maj

    mov     r15d, r14d              ; h = g
    mov     r14d, r13d              ; g = f
    mov     r13d, r12d              ; f = e
    lea     r12d, [r11 + rax]       ; e = d + T1
    mov     r11d, r10d              ; d = c
    mov     r10d, r9d               ; c = b
    mov     r9d, r8d                ; b = a
    lea     r8d, [rax + rbx]        ; a = T1 + T2

    inc     ecx
    cmp     ecx, SCHEDULE_WORDS
    jb      .round

    ; H(i) = H(i-1) + working variables (6.2.2 step 4).
    add     [rdi + 0*4], r8d
    add     [rdi + 1*4], r9d
    add     [rdi + 2*4], r10d
    add     [rdi + 3*4], r11d
    add     [rdi + 4*4], r12d
    add     [rdi + 5*4], r13d
    add     [rdi + 6*4], r14d
    add     [rdi + 7*4], r15d

    ; The schedule is derived from the message (in HMAC, from the key):
    ; do not leave it on the stack. DF is clear per the ABI.
    mov     rdi, rsp
    mov     ecx, SCHEDULE_SIZE / 8
    xor     eax, eax
    rep     stosq

    add     rsp, SCHEDULE_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; sha256_init
;
; Purpose:   Start a new hash: state = H(0), length = 0.
; Args:      rdi = struct sha256_ctx *ctx (SHA256_CTX_SIZE bytes)
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx
; Preserves: all callee-saved registers (none are used)
; Stack:     none used; no alignment assumption
; Inputs:    not applicable (ctx is output only; its buffer is not cleared)
; Overlap:   not applicable (single buffer)
; ---------------------------------------------------------------------------
global sha256_init:function
sha256_init:
    lea     rcx, [sha256_h0]
    mov     rax, [rcx + 0]
    mov     [rdi + SHA256_CTX_STATE + 0], rax
    mov     rax, [rcx + 8]
    mov     [rdi + SHA256_CTX_STATE + 8], rax
    mov     rax, [rcx + 16]
    mov     [rdi + SHA256_CTX_STATE + 16], rax
    mov     rax, [rcx + 24]
    mov     [rdi + SHA256_CTX_STATE + 24], rax
    mov     qword [rdi + SHA256_CTX_LENGTH], 0
    ret

; ---------------------------------------------------------------------------
; sha256_update
;
; Purpose:   Absorb len bytes: top up the context's partial block, compress
;            every full block, and buffer the remainder.
; Args:      rdi = struct sha256_ctx *ctx (initialized)
;            rsi = const uint8_t *data (may be NULL when len is 0)
;            rdx = size_t len (total over all updates must stay below
;                  2^61 bytes, so the bit length fits in 64 bits)
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, r12, r13 (saved on the stack); rbp, r14, r15 unused
; Stack:     24 bytes of saved registers; rsp is 16-byte aligned at the
;            call to sha256_compress (callee stack included)
; Inputs:    data is not modified
; Overlap:   data must not overlap ctx
; ---------------------------------------------------------------------------
global sha256_update:function
sha256_update:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi                ; ctx
    mov     r12, rsi                ; next input byte
    mov     r13, rdx                ; input bytes left

    mov     rax, [rbx + SHA256_CTX_LENGTH]
    mov     ecx, eax
    and     ecx, SHA256_BLOCK_SIZE - 1  ; bytes already in the buffer
    add     rax, r13
    mov     [rbx + SHA256_CTX_LENGTH], rax
    test    ecx, ecx
    jz      .full_blocks

    ; Top up the partial block. rax = room left in it.
    lea     rdi, [rbx + SHA256_CTX_BUFFER + rcx]
    mov     eax, SHA256_BLOCK_SIZE
    sub     eax, ecx
    cmp     r13, rax
    jb      .stash                  ; still not full: buffer all of the input
    mov     ecx, eax
    mov     rsi, r12
    rep     movsb
    add     r12, rax
    sub     r13, rax
    mov     rdi, rbx
    lea     rsi, [rbx + SHA256_CTX_BUFFER]
    call    sha256_compress_local

    ; Compress full blocks straight from the input, without copying.
.full_blocks:
    cmp     r13, SHA256_BLOCK_SIZE
    jb      .tail
    mov     rdi, rbx
    mov     rsi, r12
    call    sha256_compress_local
    add     r12, SHA256_BLOCK_SIZE
    sub     r13, SHA256_BLOCK_SIZE
    jmp     .full_blocks

.tail:
    lea     rdi, [rbx + SHA256_CTX_BUFFER]  ; buffer is empty here
.stash:                             ; copy r13 bytes from r12 to rdi
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb

    pop     r13
    pop     r12
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; sha256_final
;
; Purpose:   Pad the message (5.1.1), compress the last block(s), write the
;            digest, then zero the whole context. Call sha256_init before
;            reusing ctx.
; Args:      rdi = struct sha256_ctx *ctx (initialized)
;            rsi = uint8_t digest[32] (output, big-endian per 6.2.2)
; Returns:   nothing. Cannot fail.
; Modifies:  rax, rcx, rdx, rsi, rdi, r8-r11, flags
; Preserves: rbx, r12 (saved on the stack); rbp, r13-r15 unused
; Stack:     16 bytes of saved registers + 8 bytes padding; rsp is 16-byte
;            aligned at the calls to sha256_compress
; Inputs:    ctx is consumed and zeroed
; Overlap:   digest must not overlap ctx
; ---------------------------------------------------------------------------
global sha256_final:function
sha256_final:
    push    rbx
    push    r12
    sub     rsp, 8                  ; keep rsp 16-byte aligned for calls
    mov     rbx, rdi                ; ctx
    mov     r12, rsi                ; digest

    ; Append the 0x80 byte after the buffered bytes.
    mov     rcx, [rbx + SHA256_CTX_LENGTH]
    and     ecx, SHA256_BLOCK_SIZE - 1
    mov     byte [rbx + SHA256_CTX_BUFFER + rcx], PAD_BYTE
    inc     ecx
    cmp     ecx, LENGTH_OFFSET
    jbe     .pad_to_length

    ; No room for the length: zero-fill and compress this block, then put
    ; the length in a fresh block of zeros.
    lea     rdi, [rbx + SHA256_CTX_BUFFER + rcx]
    neg     ecx
    add     ecx, SHA256_BLOCK_SIZE
    xor     eax, eax
    rep     stosb
    mov     rdi, rbx
    lea     rsi, [rbx + SHA256_CTX_BUFFER]
    call    sha256_compress_local
    xor     ecx, ecx

.pad_to_length:                     ; zero bytes ecx..55, then the length
    lea     rdi, [rbx + SHA256_CTX_BUFFER + rcx]
    neg     ecx
    add     ecx, LENGTH_OFFSET
    xor     eax, eax
    rep     stosb
    mov     rax, [rbx + SHA256_CTX_LENGTH]
    shl     rax, 3                  ; bytes -> bits
    bswap   rax                     ; big-endian
    mov     [rbx + SHA256_CTX_BUFFER + LENGTH_OFFSET], rax
    mov     rdi, rbx
    lea     rsi, [rbx + SHA256_CTX_BUFFER]
    call    sha256_compress_local

    ; Digest = state words, big-endian.
    xor     ecx, ecx
.store_words:
    mov     eax, [rbx + SHA256_CTX_STATE + rcx*4]
    bswap   eax
    mov     [r12 + rcx*4], eax
    inc     ecx
    cmp     ecx, SHA256_STATE_WORDS
    jb      .store_words

    ; Wipe the context: in HMAC it holds key-derived state.
    mov     rdi, rbx
    mov     ecx, SHA256_CTX_SIZE
    xor     eax, eax
    rep     stosb

    add     rsp, 8
    pop     r12
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
