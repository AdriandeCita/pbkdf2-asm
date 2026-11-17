; cli.asm - standalone pbkdf2 executable (spec section 5.2).
;
;     pbkdf2 -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX  < password
;
; Linked only into build/pbkdf2, statically and without libc. Talks to the
; kernel through raw system calls (include/syscalls.inc) and does no
; cryptography itself: it parses arguments, reads the password from stdin,
; calls pbkdf2_hmac_sha256, and writes the key as lowercase hex.
;
; Order of work: all arguments are checked before stdin is read, so a usage
; error never consumes the password. Every exit goes through exit_wipe,
; which zeroes the password and derived-key buffers.
;
; Internal helpers follow the System V ABI and use only caller-saved
; registers, so _start keeps its state in rbx, rbp and r12-r15.

default rel

%include "syscalls.inc"
%include "cli.inc"
%include "pbkdf2.inc"

extern pbkdf2_hmac_sha256

UINT32_MAX      equ 0xffffffff
DECIMAL_BASE    equ 10
NIBBLE_BITS     equ 4
NIBBLE_MASK     equ 0x0f
ASCII_CASE_BIT  equ 0x20            ; 'A' | 0x20 = 'a'
NEWLINE         equ 10

; hex_decode status codes (edx).
HEX_OK          equ 0
HEX_ODD         equ 1
HEX_INVALID     equ 2
HEX_TOO_LONG    equ 3

PASSWORD_BUF_SIZE   equ CLI_MAX_PASSWORD_LEN + 1    ; +1 detects overlong input
HEX_BUF_SIZE        equ CLI_MAX_OUTPUT_LEN * 2 + 1  ; +1 for the newline

section .rodata

hex_digits:     db "0123456789abcdef"

msg_prefix:     db "pbkdf2: ", 0
msg_newline:    db NEWLINE, 0
msg_usage:      db "; usage: pbkdf2 -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX "
                db "< password", NEWLINE, 0

; Usage errors (EXIT_USAGE).
msg_unknown:        db "unknown argument", 0
msg_no_value:       db "option needs a value", 0
msg_repeated:       db "option given more than once", 0
msg_missing:        db "-i, -l and -s are all required", 0
msg_bad_iterations: db "-i must be a decimal number from 0 to 4294967295", 0
msg_bad_length:     db "-l must be a decimal number", 0
msg_long_length:    db "-l is over the output length limit", 0
msg_odd_hex:        db "-s has an odd number of hex digits", 0
msg_bad_hex:        db "-s contains a non-hex character", 0
msg_long_salt:      db "-s is over the salt length limit", 0
msg_long_password:  db "password is over the length limit", 0

; Library and I/O errors (EXIT_FAILURE).
msg_zero_iterations: db "iterations must be at least 1", 0
msg_zero_length:    db "output length must be at least 1", 0
msg_derive_failed:  db "key derivation failed", 0
msg_read_failed:    db "cannot read the password from stdin", 0
msg_write_failed:   db "cannot write to stdout", 0

section .bss

; Explicit fill: plain `alignb 8` makes NASM 2.16.01 -Wall warn about its
; own macro ("unknown warning name: push").
alignb 8, resb 1
params:         resb PBKDF2_PARAMS_SIZE
password_buf:   resb PASSWORD_BUF_SIZE
salt_buf:       resb CLI_MAX_SALT_LEN
key_buf:        resb CLI_MAX_OUTPUT_LEN
hex_buf:        resb HEX_BUF_SIZE

section .text

; ---------------------------------------------------------------------------
; _start
;
; Purpose:   Process entry point, called by the kernel, not by code. Runs
;            the whole program (spec 5.2) and exits.
; Args:      [rsp] = argc, [rsp+8..] = argv pointers, NULL, envp pointers,
;            NULL (System V process startup layout).
; Returns:   Does not return. Exit status EXIT_SUCCESS, EXIT_FAILURE
;            (library or I/O error) or EXIT_USAGE (include/cli.inc).
; Modifies:  everything
; Preserves: nothing; there is no caller
; Stack:     rsp is 16-byte aligned on entry and nothing is pushed, so it
;            is aligned at every call
; Inputs:    argv strings are not modified
; Overlap:   not applicable
; ---------------------------------------------------------------------------
global _start:function
_start:
    mov     r12, [rsp]              ; argc
    lea     r13, [rsp + 8]          ; argv
    xor     r14d, r14d              ; -i value (string), 0 = not given
    xor     r15d, r15d              ; -l value
    xor     ebx, ebx                ; -s value
    mov     ebp, 1                  ; argv index; argv[0] is the program

    ; Each argument must be exactly "-i", "-l" or "-s", followed by its
    ; value as a separate argument.
.next_arg:
    cmp     rbp, r12
    jae     .args_done
    mov     rsi, [r13 + rbp*8]
    cmp     byte [rsi], '-'
    jne     .unknown
    movzx   eax, byte [rsi + 1]
    test    eax, eax
    jz      .unknown                ; "-" alone
    cmp     byte [rsi + 2], 0
    jne     .unknown                ; longer than two characters
    inc     rbp
    cmp     rbp, r12
    jae     .no_value
    mov     rdx, [r13 + rbp*8]      ; the option's value
    inc     rbp
    cmp     eax, 'i'
    je      .opt_i
    cmp     eax, 'l'
    je      .opt_l
    cmp     eax, 's'
    je      .opt_s
    jmp     .unknown
.opt_i:
    test    r14, r14
    jnz     .repeated
    mov     r14, rdx
    jmp     .next_arg
.opt_l:
    test    r15, r15
    jnz     .repeated
    mov     r15, rdx
    jmp     .next_arg
.opt_s:
    test    rbx, rbx
    jnz     .repeated
    mov     rbx, rdx
    jmp     .next_arg

.args_done:
    test    r14, r14
    jz      .missing
    test    r15, r15
    jz      .missing
    test    rbx, rbx
    jz      .missing

    ; -i: iterations, a uint32. 0 is passed on; the library rejects it.
    mov     rdi, r14
    call    parse_decimal
    test    edx, edx
    jnz     .bad_iterations
    mov     ecx, UINT32_MAX
    cmp     rax, rcx
    ja      .bad_iterations
    mov     [params + PBKDF2_PARAMS_ITERATIONS], eax

    ; -l: output length. 0 is passed on; the library rejects it.
    mov     rdi, r15
    call    parse_decimal
    test    edx, edx
    jnz     .bad_length
    cmp     rax, CLI_MAX_OUTPUT_LEN
    ja      .long_length
    mov     [params + PBKDF2_PARAMS_OUTPUT_LEN], rax
    mov     r15, rax                ; from here on: output length

    ; -s: salt as hex.
    mov     rdi, rbx
    lea     rsi, [salt_buf]
    mov     edx, CLI_MAX_SALT_LEN
    call    hex_decode
    cmp     edx, HEX_ODD
    je      .odd_hex
    cmp     edx, HEX_INVALID
    je      .bad_hex
    cmp     edx, HEX_TOO_LONG
    je      .long_salt
    lea     rcx, [salt_buf]
    mov     [params + PBKDF2_PARAMS_SALT], rcx
    mov     [params + PBKDF2_PARAMS_SALT_LEN], rax

    ; Password: all of stdin, as is.
    lea     rdi, [password_buf]
    mov     esi, PASSWORD_BUF_SIZE
    call    read_all
    test    rax, rax
    js      .read_failed
    cmp     rax, CLI_MAX_PASSWORD_LEN
    ja      .long_password
    lea     rcx, [password_buf]
    mov     [params + PBKDF2_PARAMS_PASSWORD], rcx
    mov     [params + PBKDF2_PARAMS_PASSWORD_LEN], rax

    lea     rdi, [params]
    lea     rsi, [key_buf]
    call    pbkdf2_hmac_sha256      ; static link: a direct call
    cmp     eax, PBKDF2_OK
    jne     .derive_failed

    ; Key -> lowercase hex + newline. r15 >= 1 here: 0 failed above.
    lea     rsi, [key_buf]
    lea     rdi, [hex_buf]
    lea     r8, [hex_digits]
    mov     rcx, r15
.hex_byte:
    movzx   eax, byte [rsi]
    mov     edx, eax
    shr     eax, NIBBLE_BITS
    and     edx, NIBBLE_MASK
    movzx   eax, byte [r8 + rax]
    movzx   edx, byte [r8 + rdx]
    mov     [rdi], al
    mov     [rdi + 1], dl
    inc     rsi
    add     rdi, 2
    dec     rcx
    jnz     .hex_byte
    mov     byte [rdi], NEWLINE

    mov     edi, STDOUT_FD
    lea     rsi, [hex_buf]
    lea     rdx, [r15*2 + 1]
    call    write_all
    test    rax, rax
    js      .write_failed
    mov     edi, EXIT_SUCCESS
    call    exit_wipe

    ; Error exits: rdi = message, then a call that does not return.
.unknown:
    lea     rdi, [msg_unknown]
    call    die_usage
.no_value:
    lea     rdi, [msg_no_value]
    call    die_usage
.repeated:
    lea     rdi, [msg_repeated]
    call    die_usage
.missing:
    lea     rdi, [msg_missing]
    call    die_usage
.bad_iterations:
    lea     rdi, [msg_bad_iterations]
    call    die_usage
.bad_length:
    lea     rdi, [msg_bad_length]
    call    die_usage
.long_length:
    lea     rdi, [msg_long_length]
    call    die_usage
.odd_hex:
    lea     rdi, [msg_odd_hex]
    call    die_usage
.bad_hex:
    lea     rdi, [msg_bad_hex]
    call    die_usage
.long_salt:
    lea     rdi, [msg_long_salt]
    call    die_usage
.long_password:
    lea     rdi, [msg_long_password]
    call    die_usage
.read_failed:
    lea     rdi, [msg_read_failed]
    call    die
.write_failed:
    lea     rdi, [msg_write_failed]
    call    die
.derive_failed:
    lea     rdi, [msg_zero_iterations]
    cmp     eax, PBKDF2_ERR_ITERATIONS
    je      .die_derive
    lea     rdi, [msg_zero_length]
    cmp     eax, PBKDF2_ERR_OUTPUT_LEN
    je      .die_derive
    lea     rdi, [msg_derive_failed]
.die_derive:
    call    die

; ---------------------------------------------------------------------------
; Internal helpers. Not exported; System V ABI; caller-saved registers only.
; ---------------------------------------------------------------------------

; parse_decimal: rdi = NUL-terminated string of ASCII digits.
; Returns rax = value, edx = 0; or edx = 1 if the string is empty, has a
; non-digit (signs included), or does not fit in 64 bits.
parse_decimal:
    xor     eax, eax
    mov     r8d, DECIMAL_BASE
    cmp     byte [rdi], 0
    je      .bad
.digit:
    movzx   ecx, byte [rdi]
    test    ecx, ecx
    jz      .ok
    sub     ecx, '0'
    cmp     ecx, 9
    ja      .bad                    ; unsigned: also catches chars below '0'
    mul     r8                      ; rdx:rax = rax * 10
    jc      .bad                    ; CF: high half nonzero, overflow
    add     rax, rcx
    jc      .bad
    inc     rdi
    jmp     .digit
.ok:
    xor     edx, edx
    ret
.bad:
    mov     edx, 1
    ret

; hex_value: converts the ASCII hex digit in %1 (a 32-bit register) to its
; value in place; jumps to %2 if it is not a hex digit.
%macro hex_value 2
    cmp     %1, '0'
    jb      %2
    cmp     %1, '9'
    jbe     %%decimal
    or      %1, ASCII_CASE_BIT      ; fold 'A'-'F' to 'a'-'f'
    cmp     %1, 'a'
    jb      %2
    cmp     %1, 'f'
    ja      %2
    sub     %1, 'a' - 10
    jmp     %%done
%%decimal:
    sub     %1, '0'
%%done:
%endmacro

; hex_decode: rdi = NUL-terminated hex string, rsi = output buffer,
; rdx = output capacity in bytes.
; Returns rax = bytes written and edx = HEX_OK, or edx = HEX_ODD,
; HEX_TOO_LONG or HEX_INVALID (checked in that order; on error the output
; may be partly written).
hex_decode:
    xor     ecx, ecx                ; string length
.length:
    cmp     byte [rdi + rcx], 0
    je      .measured
    inc     rcx
    jmp     .length
.measured:
    test    ecx, 1
    jnz     .odd
    shr     rcx, 1                  ; output bytes
    cmp     rcx, rdx
    ja      .too_long
    mov     rax, rcx
    xor     r8d, r8d                ; output index
.pair:
    cmp     r8, rax
    je      .ok
    movzx   r9d, byte [rdi + r8*2]
    hex_value r9d, .invalid
    movzx   r10d, byte [rdi + r8*2 + 1]
    hex_value r10d, .invalid
    shl     r9d, NIBBLE_BITS
    or      r9d, r10d
    mov     [rsi + r8], r9b
    inc     r8
    jmp     .pair
.ok:
    mov     edx, HEX_OK
    ret
.odd:
    mov     edx, HEX_ODD
    ret
.too_long:
    mov     edx, HEX_TOO_LONG
    ret
.invalid:
    mov     edx, HEX_INVALID
    ret

; read_all: rdi = buffer, rsi = capacity. Reads stdin until end of file
; or until the buffer is full, retrying on EINTR and continuing after
; short reads. Returns rax = bytes read, or -errno.
read_all:
    mov     r8, rdi                 ; buffer
    mov     r9, rsi                 ; capacity
    xor     r10d, r10d              ; bytes read so far
.again:
    cmp     r10, r9
    jae     .done                   ; full; the caller checks for overflow
    mov     eax, SYS_READ
    mov     edi, STDIN_FD
    lea     rsi, [r8 + r10]
    mov     rdx, r9
    sub     rdx, r10
    syscall                         ; clobbers rcx, r11; keeps r8-r10
    cmp     rax, -EINTR
    je      .again
    test    rax, rax
    js      .error
    jz      .done                   ; end of file
    add     r10, rax
    jmp     .again
.done:
    mov     rax, r10
.error:
    ret

; write_all: edi = fd, rsi = buffer, rdx = length. Writes everything,
; retrying on EINTR and continuing after short writes. Returns rax = 0,
; or -errno (-EIO if the kernel accepts nothing without an error).
write_all:
    mov     r8d, edi                ; fd
    mov     r9, rsi                 ; next byte
    mov     r10, rdx                ; bytes left
.again:
    test    r10, r10
    jz      .ok
    mov     eax, SYS_WRITE
    mov     edi, r8d
    mov     rsi, r9
    mov     rdx, r10
    syscall
    cmp     rax, -EINTR
    je      .again
    test    rax, rax
    js      .error
    jz      .no_progress
    add     r9, rax
    sub     r10, rax
    jmp     .again
.ok:
    xor     eax, eax
    ret
.no_progress:
    mov     rax, -EIO
.error:
    ret

; write_str: edi = fd, rsi = NUL-terminated string. Returns as write_all.
write_str:
    xor     edx, edx
.length:
    cmp     byte [rsi + rdx], 0
    je      write_all               ; tail call with rdx = length
    inc     rdx
    jmp     .length

; die_usage / die: rdi = NUL-terminated reason. Write one line to stderr
; ("pbkdf2: <reason>", plus the usage summary for die_usage) and exit with
; EXIT_USAGE / EXIT_FAILURE. Do not return. A failing stderr is ignored:
; there is nowhere left to report it.
die_usage:
    push    rdi                     ; keep the reason across the call
    mov     edi, STDERR_FD
    lea     rsi, [msg_prefix]
    call    write_str
    pop     rsi
    mov     edi, STDERR_FD
    call    write_str
    mov     edi, STDERR_FD
    lea     rsi, [msg_usage]
    call    write_str
    mov     edi, EXIT_USAGE
    call    exit_wipe

die:
    push    rdi
    mov     edi, STDERR_FD
    lea     rsi, [msg_prefix]
    call    write_str
    pop     rsi
    mov     edi, STDERR_FD
    call    write_str
    mov     edi, STDERR_FD
    lea     rsi, [msg_newline]
    call    write_str
    mov     edi, EXIT_FAILURE
    call    exit_wipe

; exit_wipe: edi = exit status. Zero the password, derived-key and hex
; buffers (spec 5.2), then exit. Does not return.
exit_wipe:
    mov     edx, edi                ; status (rep stosb uses rdi)
    xor     eax, eax
    lea     rdi, [password_buf]
    mov     ecx, PASSWORD_BUF_SIZE
    rep     stosb
    lea     rdi, [key_buf]
    mov     ecx, CLI_MAX_OUTPUT_LEN
    rep     stosb
    lea     rdi, [hex_buf]
    mov     ecx, HEX_BUF_SIZE
    rep     stosb
    mov     edi, edx
    mov     eax, SYS_EXIT
    syscall

section .note.GNU-stack noalloc noexec nowrite progbits
