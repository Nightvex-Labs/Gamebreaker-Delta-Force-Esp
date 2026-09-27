; Direct syscall stub — bypasses ntdll wrapper for one hot API.
;
; The syscall number is loaded from a global variable g_ssn_NtQSI that is
; resolved at runtime by walking ntdll's export table (SysWhispers-style).
; This defeats any user-mode hook installed on ntdll!NtQuerySystemInformation
; by AV/EDR without needing to hunt for the original bytes.

PUBLIC DhDirectNtQuerySystemInformation
EXTERN g_ssn_NtQSI:DWORD

.CODE
DhDirectNtQuerySystemInformation PROC
    mov r10, rcx                    ; syscall calling convention: arg1 in R10
    mov eax, DWORD PTR [g_ssn_NtQSI]
    syscall
    ret
DhDirectNtQuerySystemInformation ENDP

END
