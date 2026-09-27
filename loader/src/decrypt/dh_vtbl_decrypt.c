// DeltaHack — VTBL_DECRYPT_120 shellcode-executor.
//
// The universal FEncVector decrypt function that Delta invokes via
// subsystem_vtable[6] (FENCVEC_IMPL variant 0x14323B130 bDynamic=0 path).
//
// Located at VA 0x143246120 in Delta.exe (build 1.102.37117.80). Pure Feistel
// cipher over the packed low64 of the FVector (X_bits | Y_bits). No memory
// reads, no calls, no rip-relative refs, no TLS refs — pure math.
//
// We copy 571 bytes to a local PAGE_EXECUTE_READWRITE buffer and invoke as
// __m128 fastcall(void*, __m128 fv, u32 idx, u32 idx2). MS x64 ABI puts fv in
// xmm1 (slot 1 float), idx in r8 (slot 2 int), idx2 in r9 (slot 3 int) —
// exactly what the function expects.
//
// Constants inside: MAGIC_A = 0x2E2AC781, TEA-DELTA = 0x61C88647,
// key-step = 0xE8EA9F63, 20 Feistel rounds (2 loop iters × 10 rounds).

#include "../../inc/dh_ace_decrypt.h"
#include "../../inc/dh_rpm.h"
#include <emmintrin.h>
#include <math.h>

// Baked-in shellcode from live-dumped Delta text at RVA 0x03245120 (571 bytes).
#include "vtbl_shellcode_array.inc"

// -----------------------------------------------------------------------------
// Module state
// -----------------------------------------------------------------------------

// MASM wrapper — sets xmm1 = fv, r8/r9 = idx, calls shellcode.
extern void CallVtblDecryptRaw(void* fn_ptr, void* fv_ptr, unsigned idx);

static void* g_vtbl_page = NULL;
static void* g_vtbl_fn   = NULL;

// Public accessor for spray/probing modules.
void* GetVtblShellcode(void) { return g_vtbl_fn; }

// -----------------------------------------------------------------------------
// Init variants: from-baked-bytes and RPM-live
// -----------------------------------------------------------------------------

static BOOL install_shellcode(const void* bytes, u32 size)
{
    if (g_vtbl_page) {
        VirtualFree(g_vtbl_page, 0, MEM_RELEASE);
        g_vtbl_page = NULL;
        g_vtbl_fn   = NULL;
    }
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, bytes, size);

    // Prologue sanity: 48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18
    static const u8 kProlog[] = { 0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x74,0x24,0x10, 0x48,0x89,0x7C,0x24,0x18 };
    if (memcmp(mem, kProlog, sizeof(kProlog)) != 0) {
        DH_WARN("VtblDecrypt: prologue mismatch, refusing to install");
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
    g_vtbl_page = mem;
    g_vtbl_fn   = mem;
    DH_INFO("VtblDecrypt shellcode installed: %u bytes @ %p", size, mem);
    return TRUE;
}

// Init from baked shellcode (static data). No RPM required.
BOOL VtblDecryptInitStatic(void)
{
    return install_shellcode(kVtblDecryptShellcode, (u32)sizeof(kVtblDecryptShellcode));
}

// Init by RPM-reading live Delta at (baseDelta + 0x03245120). Preferred at
// runtime — survives micro-updates that shift function VA slightly, provided
// the RVA and body stay identical.
BOOL VtblDecryptInitLive(HANDLE hDev, u64 procCR3, u64 baseDelta)
{
    u64 va = baseDelta + 0x03245120;
    u8 buf[571];
    if (!RpmReadVirtual(hDev, procCR3, va, buf, sizeof(buf))) {
        DH_WARN("VtblDecrypt: RPM read failed @ 0x%llX", (unsigned long long)va);
        return FALSE;
    }
    return install_shellcode(buf, (u32)sizeof(buf));
}

// -----------------------------------------------------------------------------
// Call
// -----------------------------------------------------------------------------

// Decrypt one FEncVector. Returns TRUE on success; result placed in *out.
// The function only alters (X, Y); Z passes through. handler_word from input
// is ignored except that idx = handler.Index is fed to the cipher as the key
// derivation seed.
BOOL VtblDecryptCall(const DH_ENC_VECTOR* enc, DH_FVECTOR* out)
{
    if (!g_vtbl_fn || !enc || !out) return FALSE;

    // Fast-path: unencrypted marker Index == 0xFFFF or bEncrypted == 0.
    if (enc->EncHandler.Index == 0xFFFF || !enc->EncHandler.bEncrypted) {
        out->X = enc->X;
        out->Y = enc->Y;
        out->Z = enc->Z;
        return TRUE;
    }

    // Working copy: raw 16 bytes of FEncVector. Wrapper overwrites it in place.
    __declspec(align(16)) unsigned char io[16];
    memcpy(io, enc, 16);
    u32 idx = enc->EncHandler.Index;

    __try {
        CallVtblDecryptRaw(g_vtbl_fn, io, idx);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DH_WARN("VtblDecrypt: shellcode faulted (Index=0x%04X)", idx);
        return FALSE;
    }

    memcpy(&out->X, io + 0, 4);
    memcpy(&out->Y, io + 4, 4);
    memcpy(&out->Z, io + 8, 4);
    return TRUE;
}

void VtblDecryptFree(void)
{
    if (g_vtbl_page) {
        VirtualFree(g_vtbl_page, 0, MEM_RELEASE);
        g_vtbl_page = NULL;
        g_vtbl_fn   = NULL;
    }
}

// -----------------------------------------------------------------------------
// State-cache decrypt (for bDynamic=1 actors — long path in FENCVEC_IMPL)
// -----------------------------------------------------------------------------
//
// The long path in FENCVEC_IMPL/L1_DECRYPT reads a pre-decrypted 16-byte
// entry from a per-thread-slot state buffer:
//
//     xmm6 = state_data[20 * (Index & 0xFFF)]
//
// state_data pointers live inside LOOKUP_TABLE (@ 0x15E111AC0), one per slot:
//     LOOKUP + 0xC8  = slot 0 state_data
//     LOOKUP + 0x108 = slot 1 state_data
//     LOOKUP + 0x148 = slot 2 state_data
//     LOOKUP + 0x188 = slot 3 state_data
//
// The game populates these caches when rendering visible actors, so for any
// actor currently drawn we can read plaintext by walking all 4 slots.

#define DELTA_LOOKUP_TABLE_VA   0x15E111AC0ULL

BOOL StateCacheDecrypt(HANDLE hDev, u64 procCR3, const DH_ENC_VECTOR* enc, DH_FVECTOR* out)
{
    if (!enc || !out) return FALSE;

    // Fast-path unencrypted marker.
    if (enc->EncHandler.Index == 0xFFFF || !enc->EncHandler.bEncrypted) {
        out->X = enc->X; out->Y = enc->Y; out->Z = enc->Z;
        return TRUE;
    }

    u32 idx_low12 = (u32)enc->EncHandler.Index & 0xFFF;
    u64 offset = (u64)idx_low12 * 20;

    // Slot offsets inside LOOKUP_TABLE where state_data pointer lives.
    static const u32 slot_off[4] = { 0xC8, 0x108, 0x148, 0x188 };

    for (int slot = 0; slot < 4; slot++) {
        u64 state_ptr = 0;
        if (!RpmRead64(hDev, procCR3, DELTA_LOOKUP_TABLE_VA + slot_off[slot], &state_ptr))
            continue;
        if (!state_ptr || state_ptr < 0x100000) continue;

        u8 fv[16] = {0};
        if (!RpmReadVirtual(hDev, procCR3, state_ptr + offset, fv, sizeof(fv)))
            continue;

        float x, y, z;
        memcpy(&x, fv + 0, 4);
        memcpy(&y, fv + 4, 4);
        memcpy(&z, fv + 8, 4);

        // Cached entry may still be encrypted if freshly evicted. Header byte
        // at +12 (bit 8 of handler.byte2 = bEncrypted flag in the CACHED
        // header) tells us. If cached header.bEncrypted == 0, X/Y is plaintext.
        // (The `flag` byte from the disasm at [rdx + 0x10] i.e. state_data +
        // 20*N + 16 is what determines dispatch-skip in L1_DECRYPT.)
        u8 cache_flag = fv[13];  // byte 1 of cached FEncHandler = bEncrypted

        // Also do a plausibility check: Delta map coords typically fit in
        // ±100km. NaN check via self-compare.
        if (x != x || y != y || z != z) continue;
        if (fabsf(x) > 500000.0f || fabsf(y) > 500000.0f || fabsf(z) > 500000.0f) continue;

        // Prefer entries where cache says plaintext, but accept anything
        // plausible.
        (void)cache_flag;  // reserved for stricter policy
        out->X = x; out->Y = y; out->Z = z;
        return TRUE;
    }
    return FALSE;
}

// -----------------------------------------------------------------------------
// Combined decrypt — tries state cache first, falls back to VTBL shellcode
// based on the flags byte.
// -----------------------------------------------------------------------------

BOOL AceFullDecrypt(HANDLE hDev, u64 procCR3, const DH_ENC_VECTOR* enc, DH_FVECTOR* out)
{
    if (!enc || !out) return FALSE;

    // Plaintext marker
    if (enc->EncHandler.Index == 0xFFFF || !enc->EncHandler.bEncrypted) {
        out->X = enc->X; out->Y = enc->Y; out->Z = enc->Z;
        return TRUE;
    }

    // Try state-cache first (works for bDynamic=1 actors, which is the common
    // encrypted case for enemies).
    if (StateCacheDecrypt(hDev, procCR3, enc, out))
        return TRUE;

    // Fall back to VTBL shellcode (works for bDynamic=0 static-key actors).
    if (VtblDecryptCall(enc, out))
        return TRUE;

    return FALSE;
}
