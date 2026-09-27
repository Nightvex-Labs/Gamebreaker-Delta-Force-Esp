#define _CRT_SECURE_NO_WARNINGS
#include "../inc/dh_item_catalog.h"
#include "../inc/dh_rpm.h"
#include <stdlib.h>
#include <string.h>

#define CAT_SLOTS 32768u
#define CAT_MASK  (CAT_SLOTS - 1u)

#ifndef DELTA_RVA_GOBJECTS
#define DELTA_RVA_GOBJECTS  0x1E689F18ULL
#endif

static u32 HashPacked(u64 p) {
    u64 h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 8; i++) {
        h ^= (u64)((p >> (i * 8)) & 0xFFULL);
        h *= 0x100000001b3ULL;
    }
    return (u32)(h ^ (h >> 32));
}

static void CatalogInsert(DhItemCatalog* c, u64 packed, u64 row) {
    u32 idx = HashPacked(packed) & CAT_MASK;
    for (u32 i = 0; i < CAT_SLOTS; i++) {
        u32 slot = (idx + i) & CAT_MASK;
        if (c->slots[slot].row == 0) {
            c->slots[slot].packed = packed;
            c->slots[slot].row = row;
            c->count++;
            return;
        }
        if (c->slots[slot].packed == packed) return;
    }
}

u64 DhItemCatalogLookup(const DhItemCatalog* c, u64 packed) {
    if (!c || !c->slots) return 0;
    u32 idx = HashPacked(packed) & CAT_MASK;
    for (u32 i = 0; i < CAT_SLOTS; i++) {
        u32 slot = (idx + i) & CAT_MASK;
        if (c->slots[slot].row == 0) return 0;
        if (c->slots[slot].packed == packed) return c->slots[slot].row;
    }
    return 0;
}

void DhItemCatalogFree(DhItemCatalog* c) {
    if (!c) return;
    if (c->slots) free(c->slots);
    memset(c, 0, sizeof(*c));
}

// Walk GObjects per-index, find UObject whose Name=="GameItem". Verify the
// chosen candidate by probing its RowMap shape (11-digit decimal first key).
// This is more robust than pre-filtering by class name — Delta ships packages
// / archetypes that also carry the name "GameItem" and pre-filter can hide
// the real one behind them. We accept the first candidate whose +0x30/+0x38
// probe shape matches a UDataTable RowMap.
static u64 FindGameItemDT(HANDLE hDev, u64 procCR3,
                          u64 gObjVA, u64 gNamesVA) {
    u32 numElements = 0;
    if (!RpmReadVirtual(hDev, procCR3, gObjVA + 0x04, &numElements, 4)) return 0;
    if (numElements == 0 || numElements > 0x400000u) return 0;

    static const u32 candOffs[] = { 0x30, 0x38, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70 };

    u32 scanned = 0, name_hits = 0, cls_datatable_hits = 0;
    for (u32 i = 0; i < numElements; i++) {
        u64 obj = 0;
        if (!RpmGetUObjectByIndex(hDev, procCR3, gObjVA, (i32)i, &obj) || !obj)
            continue;
        scanned++;
        char nm[32] = {0};
        if (!RpmGetObjectName(hDev, procCR3, gNamesVA, obj, nm, sizeof(nm))) continue;
        if (strcmp(nm, "GameItem") != 0) continue;
        name_hits++;

        char cls[32] = {0};
        int cls_ok = RpmGetObjectClassName(hDev, procCR3, gNamesVA, obj, cls, sizeof(cls));
        if (cls_ok && strcmp(cls, "DataTable") == 0) cls_datatable_hits++;

        // Verify UDataTable shape: probe candidate RowMap offsets. Real DT has
        // a heap ptr followed by a small positive integer (Num), whose first
        // key resolves to a decimal 10-11 char string.
        for (int c = 0; c < 8; c++) {
            u64 dataPtr = 0;
            if (!RpmReadVirtual(hDev, procCR3, obj + candOffs[c], &dataPtr, 8))
                continue;
            if (dataPtr < 0x100000000ULL || dataPtr >= 0x0001000000000000ULL) continue;
            u8 sanity = 0;
            if (!RpmReadVirtual(hDev, procCR3, dataPtr, &sanity, 1)) continue;
            i32 num = 0;
            RpmReadVirtual(hDev, procCR3, obj + candOffs[c] + 8, &num, 4);
            if (num <= 0 || num > 100000) continue;
            u32 kIdx = 0;
            RpmReadVirtual(hDev, procCR3, dataPtr, &kIdx, 4);
            if (kIdx == 0 || kIdx == 0xFFFFFFFFu) continue;
            char kn[24] = {0};
            if (!RpmResolveFName(hDev, procCR3, gNamesVA, kIdx, kn, sizeof(kn))) continue;
            int all_d = kn[0] != 0;
            for (int j = 0; kn[j]; j++) {
                if (kn[j] < '0' || kn[j] > '9') { all_d = 0; break; }
            }
            if (!all_d) continue;
            if (strlen(kn) < 8 || strlen(kn) > 11) continue;
            DH_INFO("dh_item_catalog: candidate obj=0x%llx cls=\"%s\" name=\"GameItem\" "
                    "num=%d firstKey=\"%s\"",
                    (unsigned long long)obj, cls, num, kn);
            return obj;
        }
    }
    DH_INFO("dh_item_catalog: scanned=%u name_hits=%u dt_cls_hits=%u no RowMap match",
            scanned, name_hits, cls_datatable_hits);
    return 0;
}

// Probe UDataTable for RowMap data ptr + num. UE4.24 canonical is +0x30,
// but Delta reorders — try candidates and pick the one whose first slot
// resolves to a decimal-string FName (item catalog code shape).
static BOOL ProbeRowMap(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                        u64 dt_obj, u64* dataOut, i32* numOut) {
    static const u32 cand[] = { 0x30, 0x38, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70 };
    for (int i = 0; i < 8; i++) {
        u64 dataPtr = 0;
        RpmReadVirtual(hDev, procCR3, dt_obj + cand[i], &dataPtr, 8);
        if (dataPtr < 0x100000000ULL) continue;
        if (dataPtr >= 0x0001000000000000ULL) continue;
        u8 sanity = 0;
        if (!RpmReadVirtual(hDev, procCR3, dataPtr, &sanity, 1)) continue;
        i32 num = 0;
        RpmReadVirtual(hDev, procCR3, dt_obj + cand[i] + 8, &num, 4);
        if (num <= 0 || num > 100000) continue;
        u32 kIdx = 0;
        RpmReadVirtual(hDev, procCR3, dataPtr, &kIdx, 4);
        if (kIdx == 0 || kIdx == 0xFFFFFFFFu) continue;
        char kn[24] = {0};
        if (!RpmResolveFName(hDev, procCR3, gNamesVA, kIdx, kn, sizeof(kn))) continue;
        int all_d = kn[0] != 0;
        for (int j = 0; kn[j]; j++) {
            if (kn[j] < '0' || kn[j] > '9') { all_d = 0; break; }
        }
        if (!all_d) continue;
        if (strlen(kn) < 8 || strlen(kn) > 11) continue;
        *dataOut = dataPtr;
        *numOut  = num;
        return TRUE;
    }
    return FALSE;
}

BOOL DhItemCatalogInit(DhItemCatalog* c, HANDLE hDev, u64 procCR3, u64 baseVA) {
    if (!c) return FALSE;
    memset(c, 0, sizeof(*c));

    u64 gObj   = baseVA + DELTA_RVA_GOBJECTS;
    u64 gNames = baseVA + DF_RVA_FNAMEPOOL;

    DH_INFO("dh_item_catalog: locating GameItem UDataTable...");
    u64 dt = FindGameItemDT(hDev, procCR3, gObj, gNames);
    if (!dt) {
        DH_INFO("dh_item_catalog: GameItem UDataTable not found in GObjects");
        return FALSE;
    }
    c->dt_obj = dt;

    if (!ProbeRowMap(hDev, procCR3, gNames, dt, &c->rowmap_data, &c->rowmap_num)) {
        DH_INFO("dh_item_catalog: RowMap probe failed for GameItem@0x%llx",
                (unsigned long long)dt);
        return FALSE;
    }
    DH_INFO("dh_item_catalog: GameItem obj=0x%llx data=0x%llx num=%d",
            (unsigned long long)dt, (unsigned long long)c->rowmap_data,
            c->rowmap_num);

    // Bulk-read RowMap in 64KB chunks.
    u32 total = (u32)c->rowmap_num * 24u;
    u8* buf = (u8*)malloc(total);
    if (!buf) return FALSE;
    const u32 CHUNK = 65536u;
    for (u32 off = 0; off < total; off += CHUNK) {
        u32 want = (total - off) > CHUNK ? CHUNK : (total - off);
        if (!RpmReadVirtual(hDev, procCR3, c->rowmap_data + off,
                            buf + off, want)) {
            DH_INFO("dh_item_catalog: bulk read failed @ off=0x%x", off);
            free(buf);
            return FALSE;
        }
    }

    c->slots = (DhItemEntry*)calloc(CAT_SLOTS, sizeof(DhItemEntry));
    if (!c->slots) { free(buf); return FALSE; }
    c->mask = CAT_MASK;

    for (i32 i = 0; i < c->rowmap_num; i++) {
        const u8* kv = buf + (u32)i * 24u;
        u32 kIdx    = *(const u32*)(kv + 0);
        u64 rowPtr  = *(const u64*)(kv + 8);
        if (kIdx == 0 || kIdx == 0xFFFFFFFFu || !rowPtr) continue;
        char kn[24] = {0};
        if (!RpmResolveFName(hDev, procCR3, gNames, kIdx, kn, sizeof(kn))) continue;
        u64 packed = 0;
        int ok = kn[0] != 0;
        for (int j = 0; kn[j]; j++) {
            if (kn[j] < '0' || kn[j] > '9') { ok = 0; break; }
            packed = packed * 10 + (u64)(kn[j] - '0');
        }
        if (!ok || packed == 0) continue;
        CatalogInsert(c, packed, rowPtr);
    }
    free(buf);
    DH_INFO("dh_item_catalog: built %u entries from %d rows",
            c->count, c->rowmap_num);
    return c->count > 0 ? TRUE : FALSE;
}
