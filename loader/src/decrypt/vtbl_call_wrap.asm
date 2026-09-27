; DeltaHack — MASM wrapper for VTBL_DECRYPT_120 shellcode.
;
; MSVC x64 ABI passes __m128 by REFERENCE (spilled to stack, pointer in reg),
; not by value in xmm — but the shellcode expects xmm1 = FVector directly.
; This trampoline sets up registers exactly as the game code does before
; calling the fn via subsystem_vtable[6].

_TEXT SEGMENT

PUBLIC CallVtblDecryptRaw

; extern "C" void CallVtblDecryptRaw(void* fn_ptr, void* fv_ptr, unsigned idx);
;   rcx = fn_ptr   (shellcode entry, = VTBL_DECRYPT_120 body)
;   rdx = fv_ptr   (16 bytes: [X_bits, Y_bits, Z_bits, handler_word])
;   r8  = idx      (u32 handler.Index)
;
; The shellcode expects on entry:
;   rcx = unused
;   rdx = unused
;   r8  = idx
;   r9  = idx
;   xmm1 = fv (16 bytes, low64 = X|Y bits)
; and returns xmm0 = { decrypted X|Y | orig Z|handler }.
; We store xmm0 back into fv_ptr before returning.

CallVtblDecryptRaw PROC
    push    rbx
    push    rsi
    sub     rsp, 30h                ; shadow (32) + align to 16 after 2 pushes

    mov     rax, rcx                ; rax = fn_ptr
    mov     rbx, rdx                ; rbx = fv_ptr (preserve across call)
    movdqu  xmm1, xmmword ptr [rdx] ; xmm1 = fv
    movdqu  xmm0, xmmword ptr [rdx] ; xmm0 = fv (some callees read it too)
    mov     r9, r8                  ; r9  = idx
    xor     rcx, rcx
    xor     rdx, rdx

    call    rax

    movdqu  xmmword ptr [rbx], xmm0 ; store result

    add     rsp, 30h
    pop     rsi
    pop     rbx
    ret
CallVtblDecryptRaw ENDP

_TEXT ENDS
END
