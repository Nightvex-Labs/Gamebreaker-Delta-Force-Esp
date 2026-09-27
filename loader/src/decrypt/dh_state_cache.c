// DeltaHack — State-cache reader impl.
#include "../../inc/dh_state_cache.h"
#include "../../inc/dh_rpm.h"
#include <math.h>
#include <string.h>

BOOL StateCacheV2(HANDLE hDev, u64 procCR3,
                  u16 handlerIndex,
                  DH_FVECTOR* out)
{
    if (!out) return FALSE;
    if (handlerIndex == 0xFFFF) return FALSE;   // caller should fast-path

    u32 slot_hi = (u32)(handlerIndex >> 13) & 0x7;   // 0..7
    u32 bit12   = (u32)(handlerIndex >> 12) & 0x1;   // 0 or 1
    u32 low12   = (u32)handlerIndex & 0xFFF;         // 0..4095

    // slot_offset = 0x300 * slot_hi + 40 * bit12 + 0x238
    u64 slot_off = (u64)slot_hi * 0x300ULL + (u64)bit12 * 40ULL + 0x238ULL;
    u64 slot_va  = DELTA_LOOKUP_TABLE_VA + slot_off;

    u64 state_ptr = 0;
    if (!RpmRead64(hDev, procCR3, slot_va, &state_ptr))
        return FALSE;
    if (!state_ptr || state_ptr < 0x100000) return FALSE;

    // entry = state_ptr + 24 * low12
    u64 entry_va = state_ptr + (u64)low12 * 24ULL;

    // Read the whole 24B entry in one IOCTL.
    u8 entry[24] = {0};
    if (!RpmReadVirtual(hDev, procCR3, entry_va, entry, sizeof(entry)))
        return FALSE;

    // Flag byte
    u8 flag = entry[0x14];
    if (flag == 0) return FALSE;

    // Extract X/Y/Z
    float x, y, z;
    memcpy(&x, entry + 0x00, 4);
    memcpy(&y, entry + 0x04, 4);
    memcpy(&z, entry + 0x08, 4);

    // Sanity — NaN + map-scale reasonable
    if (x != x || y != y || z != z) return FALSE;
    if (fabsf(x) > 300000.f || fabsf(y) > 300000.f || fabsf(z) > 30000.f)
        return FALSE;

    out->X = x; out->Y = y; out->Z = z;
    return TRUE;
}

BOOL StateCacheDecryptV2(HANDLE hDev, u64 procCR3,
                        const DH_ENC_VECTOR* enc,
                        DH_FVECTOR* out)
{
    if (!enc || !out) return FALSE;
    if (enc->EncHandler.Index == 0xFFFF || !enc->EncHandler.bEncrypted) {
        out->X = enc->X; out->Y = enc->Y; out->Z = enc->Z;
        return TRUE;
    }
    return StateCacheV2(hDev, procCR3, enc->EncHandler.Index, out);
}
