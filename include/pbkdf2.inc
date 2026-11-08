; pbkdf2.inc - public interface definitions shared by the assembly modules.
;
; The pbkdf2_params structure layout and error codes are added here in
; Milestone 4, together with the matching ctypes definitions in tests/.

%ifndef PBKDF2_INC
%define PBKDF2_INC

; Version of the exported interface. Bump when an exported function's
; signature, the params structure layout, or the error codes change.
PBKDF2_ABI_VERSION equ 1

%endif
