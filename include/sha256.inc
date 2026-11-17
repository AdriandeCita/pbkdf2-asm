; sha256.inc - SHA-256 sizes and the sha256_ctx layout (FIPS 180-4).
;
; Shared by sha256.asm and its callers (hmac.asm). The context is
; transparent: tests/test_sha256.py mirrors it as a ctypes.Structure and
; checks its offsets against the values below, so keep the two in sync.
;
; No extern declarations here: NASM rejects an extern for a symbol the
; including file then defines, so each consumer declares the functions it
; calls itself.
;
; struct sha256_ctx {                 offset  size
;     uint32_t state[8];              0       32   H0..H7, native byte order
;     uint64_t length;                32      8    total bytes fed in
;     uint8_t  buffer[64];            40      64   bytes of a not yet
; };                                  104          compressed block
;
; The number of buffered bytes is length mod 64, so there is no separate
; counter. Caller-allocated, 8-byte aligned.

%ifndef SHA256_INC
%define SHA256_INC

SHA256_BLOCK_SIZE       equ 64      ; bytes per compression block
SHA256_DIGEST_SIZE      equ 32      ; bytes in a digest
SHA256_STATE_WORDS      equ 8       ; 32-bit words in the hash state
SHA256_LENGTH_SIZE      equ 8       ; bytes of bit length closing the padding

SHA256_CTX_STATE        equ 0
SHA256_CTX_LENGTH       equ 32
SHA256_CTX_BUFFER       equ 40
SHA256_CTX_SIZE         equ 104

%endif
