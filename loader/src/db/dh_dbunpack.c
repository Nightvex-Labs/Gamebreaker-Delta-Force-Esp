// DBPACK decoder for kdu-shipped '.bin' vulnerable-driver payloads.
// Format: MSDelta PA30 patch bytes, XOR'd byte-by-byte with rolling 32-bit key
// 0xF62E6CE0 (kdu Shared/consts.h PROVIDER_RES_KEY). To recover the original
// .sys: undo XOR, feed to msdelta ApplyDeltaB against an empty source.

#include "../../inc/dh_dbunpack.h"
#include <intrin.h>

#define PROVIDER_RES_KEY   0xF62E6CE0u
#define DELTA_FILE_TYPE_RAW 0x00000001i64

typedef struct _DELTA_INPUT_LOCAL {
    LPCVOID lpcStart;   // read-only view (Editable = FALSE path only)
    SIZE_T  uSize;
    BOOL    Editable;
} DELTA_INPUT_LOCAL, *LPDELTA_INPUT_LOCAL;

typedef struct _DELTA_OUTPUT_LOCAL {
    LPVOID lpStart;
    SIZE_T uSize;
} DELTA_OUTPUT_LOCAL, *LPDELTA_OUTPUT_LOCAL;

typedef BOOL (WINAPI *pfnApplyDeltaB)(LONGLONG, DELTA_INPUT_LOCAL, DELTA_INPUT_LOCAL, LPDELTA_OUTPUT_LOCAL);
typedef BOOL (WINAPI *pfnDeltaFree )(LPVOID);

static void dh_db_xor_roll(void* buf, DWORD size, DWORD key) {
    if (!buf || !size) return;
    ULONG k = key;
    unsigned char* p = (unsigned char*)buf;
    do {
        *p ^= (unsigned char)k;
        k = _rotl(k, 1);
        ++p;
    } while (--size);
}

BOOL DbUnpack(const void* InBuf, DWORD InSize, void** OutBuf, DWORD* OutSize) {
    if (!InBuf || !InSize || !OutBuf || !OutSize) return FALSE;
    *OutBuf = NULL; *OutSize = 0;

    HANDLE hp = GetProcessHeap();

    void* scratch = HeapAlloc(hp, 0, InSize);
    if (!scratch) return FALSE;
    memcpy(scratch, InBuf, InSize);
    dh_db_xor_roll(scratch, InSize, PROVIDER_RES_KEY);

    HMODULE hMs = LoadLibraryW(L"msdelta.dll");
    if (!hMs) { HeapFree(hp, 0, scratch); return FALSE; }

    pfnApplyDeltaB pApply = (pfnApplyDeltaB)GetProcAddress(hMs, "ApplyDeltaB");
    pfnDeltaFree   pFree  = (pfnDeltaFree)  GetProcAddress(hMs, "DeltaFree");
    if (!pApply || !pFree) {
        HeapFree(hp, 0, scratch);
        FreeLibrary(hMs);
        return FALSE;
    }

    DELTA_INPUT_LOCAL  src = {0};
    DELTA_INPUT_LOCAL  dlt;
    dlt.lpcStart = scratch;
    dlt.uSize    = InSize;
    dlt.Editable = FALSE;
    DELTA_OUTPUT_LOCAL out = {0};

    BOOL ok = pApply(DELTA_FILE_TYPE_RAW, src, dlt, &out);
    HeapFree(hp, 0, scratch);
    if (!ok) { FreeLibrary(hMs); return FALSE; }

    void* final = HeapAlloc(hp, 0, out.uSize);
    if (final) {
        memcpy(final, out.lpStart, out.uSize);
        *OutBuf  = final;
        *OutSize = (DWORD)out.uSize;
    }
    pFree(out.lpStart);
    FreeLibrary(hMs);
    return final != NULL;
}
