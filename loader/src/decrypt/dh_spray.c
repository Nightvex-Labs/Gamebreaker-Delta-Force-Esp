// DeltaHack — r8-key spray against VTBL_DECRYPT_120.
#include "../../inc/dh_spray.h"
#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

// From vtbl_spray_wrap.asm — 5-arg version passing rcx (instance) too.
extern void CallVtblDecryptSpray(void* fn_ptr, void* fv_in_ptr,
                                 unsigned __int64 rcx_val,
                                 unsigned __int64 r8_key,
                                 void* fv_out_ptr);

// From dh_vtbl_decrypt.c — the shellcode page
extern void* g_vtbl_page_get(void);   // helper below (added there or here)

// Local reference to installed shellcode — populated by VtblDecryptInitStatic
// or VtblDecryptInitLive before spray is called.
extern void* GetVtblShellcode(void);   // defined below via weak forward

// Delta Feistel constants — for candidate derivations.
#define MAGIC_A     0x2E2AC781u
#define TEA_DELTA   0x61C88647u
#define KEY_STEP    0xE8EA9F63u

// ---- Candidate r8 generators ----------------------------------------------

static u64 spray_candidates(u16 idx, u32 handler_full, u64* out, int max_n)
{
    u64 I = (u64)idx;
    u32 iu = (u32)idx;
    int n = 0;

    // === TOP CANDIDATES (2026-09-20 morning — rcx now = instance ptr) ===
    // Real dispatch: r8d = r9d = Handler.Index (from 0x14323B130 disasm).
    // So the FIRST candidate MUST be Handler.Index itself.
    if (n<max_n) out[n++] = I;                          // ★★★ Handler.Index (as real dispatch does)
    if (n<max_n) out[n++] = (u64)handler_full;          // full Handler u32 (Index|flags|enc)
    if (n<max_n) out[n++] = (u64)(u32)handler_full;     // sign-extended full handler

    // 0x14323A9C0 sets key = 0x2537 when cache_flag == 0 for Index<0x2000
    if (n<max_n) out[n++] = 0x2537ULL;                  // hardcoded fallback key
    if (n<max_n) out[n++] = 0x2537ULL | (I << 16);      // 0x2537 with Idx echoed
    if (n<max_n) out[n++] = 0x2537ULL ^ I;              // XOR with Idx
    if (n<max_n) out[n++] = 0x2537ULL << 32 | I;        // 0x2537 in high dword
    if (n<max_n) out[n++] = 0x2537ULL << 48;            // shifted way up
    if (n<max_n) out[n++] = (u64)(0x2537ULL * iu);      // scaled by Idx

    // Zero
    if (n<max_n) out[n++] = 0;
    if (n<max_n) out[n++] = I;                          // just Index
    if (n<max_n) out[n++] = handler_full;               // full 4B Handler
    if (n<max_n) out[n++] = (u64)handler_full & 0xFFFFu;// low u16 of handler
    if (n<max_n) out[n++] = ~I & 0xFFFFu;               // NOT(Idx) truncated
    if (n<max_n) out[n++] = I | (I << 16);              // Idx replicated x2
    if (n<max_n) out[n++] = I | (I << 16) | (I << 32) | (I << 48); // x4
    if (n<max_n) out[n++] = I << 32;
    if (n<max_n) out[n++] = I << 48;

    // Multiplications by Feistel constants
    if (n<max_n) out[n++] = (u64)(iu * MAGIC_A);
    if (n<max_n) out[n++] = (u64)(iu * TEA_DELTA);
    if (n<max_n) out[n++] = (u64)(iu * KEY_STEP);
    if (n<max_n) out[n++] = (u64)iu * MAGIC_A;
    if (n<max_n) out[n++] = (u64)iu * TEA_DELTA;
    if (n<max_n) out[n++] = (u64)iu * KEY_STEP;

    // XORs with constants
    if (n<max_n) out[n++] = I ^ MAGIC_A;
    if (n<max_n) out[n++] = I ^ TEA_DELTA;
    if (n<max_n) out[n++] = I ^ KEY_STEP;
    if (n<max_n) out[n++] = I ^ ((u64)MAGIC_A << 32);
    if (n<max_n) out[n++] = ((u64)MAGIC_A << 32) | I;
    if (n<max_n) out[n++] = ((u64)TEA_DELTA << 32) | I;

    // Bit rotations of Idx
    if (n<max_n) out[n++] = (I << 8)  | (I >> (64-8));
    if (n<max_n) out[n++] = (I << 12) | (I >> (64-12));
    if (n<max_n) out[n++] = (I << 13) | (I >> (64-13));
    if (n<max_n) out[n++] = (I << 16) | (I >> (64-16));
    if (n<max_n) out[n++] = (I << 20) | (I >> (64-20));
    if (n<max_n) out[n++] = (I << 32) | (I >> (64-32));

    // Constants alone (in case r8 doesn't depend on Idx at all)
    if (n<max_n) out[n++] = MAGIC_A;
    if (n<max_n) out[n++] = TEA_DELTA;
    if (n<max_n) out[n++] = KEY_STEP;
    if (n<max_n) out[n++] = ~(u64)0;
    if (n<max_n) out[n++] = 0xFFFFFFFFULL;
    if (n<max_n) out[n++] = 0xDEADBEEFULL;

    // Handler-derived with shifts
    if (n<max_n) out[n++] = ((u64)handler_full << 32) | handler_full;
    if (n<max_n) out[n++] = ((u64)iu << 32) | iu;

    return n;
}

// ---- Public: run spray ----------------------------------------------------

int SprayVtblKey(const DH_SPRAY_INPUT* in,
                 DH_SPRAY_RESULT* results, int max_results)
{
    if (!in || !results || max_results <= 0) return 0;

    void* shellcode = GetVtblShellcode();
    if (!shellcode) {
        DH_ERROR("SprayVtblKey: shellcode not installed");
        return 0;
    }

    u64 keys[64];
    int nkey = (int)spray_candidates(in->enc.EncHandler.Index,
                                     *(u32*)&in->enc.EncHandler,
                                     keys, 64);

    int n = 0;
    for (int i = 0; i < nkey && n < max_results; i++) {
        u64 r8 = keys[i];

        // Input FEncVector (16 bytes)
        __declspec(align(16)) u8 fv_in[16];
        __declspec(align(16)) u8 fv_out[16];
        memcpy(fv_in, &in->enc, 16);
        memset(fv_out, 0, 16);

        __try {
            CallVtblDecryptSpray(shellcode, fv_in, in->rcx_val, r8, fv_out);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        DH_SPRAY_RESULT* r = &results[n++];
        r->r8 = r8;
        memcpy(&r->out_x, fv_out + 0, 4);
        memcpy(&r->out_y, fv_out + 4, 4);
        memcpy(&r->out_z, fv_out + 8, 4);
        r->dx = r->out_x - in->gt_x;
        r->dy = r->out_y - in->gt_y;
        r->dz = r->out_z - in->gt_z;
        r->dist2d = sqrtf(r->dx*r->dx + r->dy*r->dy);
        r->sane = (r->out_x == r->out_x) && (r->out_y == r->out_y) &&
                  (fabsf(r->out_x) < 500000.f) && (fabsf(r->out_y) < 500000.f);
        r->matches = r->sane && (fabsf(r->dx) < 1.0f) && (fabsf(r->dy) < 1.0f);
        r->label = NULL;
    }
    return n;
}
