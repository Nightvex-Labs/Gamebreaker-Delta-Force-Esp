// DeltaHack — external key derivation via RPM.
// Reads Delta's LOOKUP_TABLE + key_obj linked-list chain and derives the
// Feistel-20 key locally. See dh_derive_key.h for algorithm.
#include "../../inc/dh_derive_key.h"
#include <intrin.h>   // _rotr64

// Internal single-shot attempt. Returns TRUE if all reads consistent.
static BOOL derive_once(HANDLE hDev, u64 procCR3, u16 handler_index, u64* out_key)
{
    const u32 slot_hi = (u32)handler_index >> 13;
    const u32 low12   = (u32)handler_index & 0xFFF;
    const u32 bit12   = ((u32)handler_index >> 12) & 1;
    const u64 slot_base = DH_LOOKUP_TABLE_VA + (u64)slot_hi * 0x300;

    // === Cache A gate (only for Idx < 0x2000) =============================
    if (handler_index < 0x2000) {
        u64 state_A_ptr = 0;
        if (!RpmReadVirtual(hDev, procCR3, slot_base + (u64)bit12 * 40 + 0x228, &state_A_ptr, 8)) return FALSE;
        if (state_A_ptr < 0x10000 || state_A_ptr > 0x0000FFFFFFFFFFFFULL) return FALSE;

        u8 flag = 0;
        if (!RpmReadVirtual(hDev, procCR3, state_A_ptr + (u64)low12 * 16 + 0xC, &flag, 1)) return FALSE;

        if (flag == 0) {
            *out_key = 0x2537ULL;
            return TRUE;
        }
    }

    // === key_obj linked-list walk =========================================
    u64 key_obj_ptr = 0;
    if (!RpmReadVirtual(hDev, procCR3, slot_base + 0x278, &key_obj_ptr, 8)) return FALSE;
    if (key_obj_ptr < 0x10000 || key_obj_ptr > 0x0000FFFFFFFFFFFFULL) return FALSE;

    // Read key_obj header in ONE burst: [+0x10..+0x20] = list_head(8), count(4), misc(4)
    struct { u64 list_head; u32 count; u32 misc; } kh = {0};
    if (!RpmReadVirtual(hDev, procCR3, key_obj_ptr + 0x10, &kh, 16)) return FALSE;

    if (kh.count > 64) return FALSE;   // sanity: expect small chain
    if (kh.count > 0 && (kh.list_head < 0x10000 || kh.list_head > 0x0000FFFFFFFFFFFFULL)) return FALSE;

    u64 rbp = 0;
    if (kh.count > 0) {
        if (!RpmReadVirtual(hDev, procCR3, kh.list_head, &rbp, 8)) return FALSE;
    }

    u64 cur = kh.list_head;
    for (u32 i = 1; i < kh.count; i++) {
        // Read next-ptr first
        u64 next = 0;
        if (!RpmReadVirtual(hDev, procCR3, cur + 8, &next, 8)) return FALSE;
        if (next < 0x10000 || next > 0x0000FFFFFFFFFFFFULL) return FALSE;
        cur = next;
        // Batch: read (a, b) = 8 bytes in ONE RPM instead of two
        u32 ab[2] = {0, 0};
        if (!RpmReadVirtual(hDev, procCR3, cur, ab, 8)) return FALSE;

        rbp ^= (u64)ab[1];                   // b
        u8 cl = (u8)((ab[0] + i) & 0x3F);    // a
        rbp = _rotr64(rbp, cl);
        rbp -= (u64)ab[0];
    }

    *out_key = rbp;
    return TRUE;
}

// Per-Handler.Index key cache (12 ms TTL — covers one Delta frame @ 60fps).
// Delta rotates the key each rendered frame, so caching for less than one
// frame duration ensures we always use the "current" key while sparing
// duplicate linked-list walks for the same enemy within the same frame.
typedef struct { u64 key; u64 ts_ms; u8 valid; } DKEntry;
static DKEntry g_dkcache[0x2000] = {0};
#define DK_TTL_MS 12ULL

BOOL DeriveKey(HANDLE hDev, u64 procCR3, u16 handler_index, u64* out_key)
{
    if (!out_key) return FALSE;

    u64 now = GetTickCount64();
    if (handler_index < 0x2000) {
        DKEntry* e = &g_dkcache[handler_index];
        if (e->valid && (now - e->ts_ms) < DK_TTL_MS) {
            *out_key = e->key;
            return TRUE;
        }
    }

    u64 k = 0;
    if (!derive_once(hDev, procCR3, handler_index, &k)) return FALSE;

    if (handler_index < 0x2000) {
        DKEntry* e = &g_dkcache[handler_index];
        e->key = k;
        e->ts_ms = now;
        e->valid = 1;
    }
    *out_key = k;
    return TRUE;
}
