; pbkdf2.inc - public interface definitions shared by the assembly modules.
;
; Mirrored by Pbkdf2Params and the PBKDF2_ERR_* checks in tests/bindings.py
; and tests/test_pbkdf2.py, which compare them against the values below.
;
; struct pbkdf2_params {              offset  size
;     const uint8_t *password;        0       8
;     size_t         password_len;    8       8
;     const uint8_t *salt;            16      8
;     size_t         salt_len;        24      8
;     uint32_t       iterations;      32      4    (+4 padding, ignored)
;     size_t         output_len;      40      8
; };                                  48
;
; int pbkdf2_hmac_sha256(const struct pbkdf2_params *params, uint8_t *output)

%ifndef PBKDF2_INC
%define PBKDF2_INC

%include "sha256.inc"

; Version of the exported interface. Bump when an exported function's
; signature, the params structure layout, or the error codes change.
PBKDF2_ABI_VERSION      equ 1

PBKDF2_PARAMS_PASSWORD      equ 0
PBKDF2_PARAMS_PASSWORD_LEN  equ 8
PBKDF2_PARAMS_SALT          equ 16
PBKDF2_PARAMS_SALT_LEN      equ 24
PBKDF2_PARAMS_ITERATIONS    equ 32
PBKDF2_PARAMS_OUTPUT_LEN    equ 40
PBKDF2_PARAMS_SIZE          equ 48

; Return codes of pbkdf2_hmac_sha256. When several inputs are invalid, the
; first applicable code in this order is returned. On any error nothing is
; written to output.
PBKDF2_OK               equ 0
PBKDF2_ERR_NULL         equ 1       ; params or output is NULL, or password
                                    ; or salt is NULL with a nonzero length
PBKDF2_ERR_ITERATIONS   equ 2       ; iterations is 0
PBKDF2_ERR_OUTPUT_LEN   equ 3       ; output_len is 0 or over the maximum

; RFC 8018 section 5.2: at most 2^32 - 1 blocks of hLen bytes.
PBKDF2_MAX_BLOCKS       equ 0xffffffff
PBKDF2_MAX_OUTPUT_LEN   equ PBKDF2_MAX_BLOCKS * SHA256_DIGEST_SIZE

%endif
