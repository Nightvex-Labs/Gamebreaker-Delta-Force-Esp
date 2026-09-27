; DeltaHack — spray wrapper for VTBL_DECRYPT_120.
; Now matches REAL dispatch convention from 0x14323B130:
;   rcx = ACE instance ptr (*0x15CEDA120)
;   r8  = Handler.Index (u32)
;   r9  = Handler.Index (u32) — same value
;   xmm0 = xmm1 = input FEncVector (16B)
;
; Wrapper signature (C-side):
;   void CallVtblDecryptSpray(
;       void* fn_ptr,        ; rcx  → will move to rax
;       void* fv_in_ptr,     ; rdx  → xmm0/xmm1
;       uint64_t rcx_val,    ; r8   → real rcx (instance ptr)
;       uint64_t r8_val,     ; r9   → real r8 (Handler.Index)
;       void* fv_out_ptr);   ; stack @ [rsp+28h]

_TEXT SEGMENT

PUBLIC CallVtblDecryptSpray

CallVtblDecryptSpray PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 30h                    ; align + shadow for callee

    mov     rax, rcx                    ; rax = fn_ptr
    mov     rsi, r8                     ; rsi = rcx_val (instance ptr)
    mov     rdi, r9                     ; rdi = r8_val (Handler.Index)

    ; fv_out from 5th arg on stack.
    ; Layout after 3 pushes (24) + sub 30h (48) = 72 (48h) bytes below ret addr.
    ; Original stack on entry:  [rsp+0]=ret, [rsp+8..27]=shadow (rcx..r9), [rsp+28]=arg5
    ; Now:                       [rsp+48]=ret, [rsp+70]=arg5 (fv_out)
    mov     rbx, [rsp + 50h + 20h]      ; rbx = fv_out_ptr

    movdqu  xmm0, xmmword ptr [rdx]     ; xmm0 = fv_in (16B)
    movdqu  xmm1, xmmword ptr [rdx]     ; xmm1 = fv_in (main input)

    mov     rcx, rsi                    ; rcx = instance ptr (real)
    xor     rdx, rdx                    ; rdx = 0 (real dispatch had rdx=Handler ptr sometimes; try 0 first)
    mov     r8, rdi                     ; r8 = Handler.Index
    mov     r9, rdi                     ; r9 = Handler.Index (mirror)

    call    rax

    movdqu  xmmword ptr [rbx], xmm0     ; store 16B result

    add     rsp, 30h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
CallVtblDecryptSpray ENDP

_TEXT ENDS
END
