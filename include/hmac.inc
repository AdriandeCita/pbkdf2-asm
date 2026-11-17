; hmac.inc - HMAC-SHA-256 constants and the hmac_sha256_ctx layout.
;
; Shared by hmac.asm and its callers (pbkdf2.asm). Mirrored by HmacCtx in
; tests/bindings.py, which checks its offsets against the values below.
;
; struct hmac_sha256_ctx {            offset  size
;     struct sha256_ctx inner;        0       104  H((K0 ^ ipad) || message)
;     struct sha256_ctx outer;        104     104  H((K0 ^ opad) || inner)
; };                                  208
;
; After hmac_sha256_init both halves have absorbed exactly one block (the
; padded key) and nothing else. Such a context can be copied byte for byte
; and reused for many messages under the same key; PBKDF2 relies on this.
; Caller-allocated, 8-byte aligned.

%ifndef HMAC_INC
%define HMAC_INC

%include "sha256.inc"

HMAC_IPAD_BYTE      equ 0x36        ; RFC 2104 section 2
HMAC_OPAD_BYTE      equ 0x5c

HMAC_CTX_INNER      equ 0
HMAC_CTX_OUTER      equ SHA256_CTX_SIZE
HMAC_CTX_SIZE       equ 2 * SHA256_CTX_SIZE

%endif
