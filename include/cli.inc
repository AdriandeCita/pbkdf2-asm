; cli.inc - limits and exit statuses of the pbkdf2 executable (spec 5.2).
;
; Used by src/cli/cli.asm only; tests/test_cli.py reads the values through
; tests/bindings.py:inc_constants.

%ifndef CLI_INC
%define CLI_INC

; Process exit statuses.
EXIT_SUCCESS            equ 0
EXIT_FAILURE            equ 1       ; library or I/O error
EXIT_USAGE              equ 2       ; bad arguments or input over a size limit

; Size limits of the fixed .bss buffers. Larger input exits with EXIT_USAGE.
CLI_MAX_PASSWORD_LEN    equ 4096    ; bytes read from stdin
CLI_MAX_SALT_LEN        equ 1024    ; decoded bytes (twice as many hex digits)
CLI_MAX_OUTPUT_LEN      equ 1024    ; derived-key bytes (-l)

%endif
