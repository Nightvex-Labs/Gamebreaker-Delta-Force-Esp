#pragma once
#include "dh_common.h"
#include <windows.h>

// GameItem DataTable catalog: FItemID -> row_ptr hashmap.
// Built once at daemon boot via GObjects walk + bulk RowMap read + FName resolve.
// Lookup is O(1) on hot path.

typedef struct {
    u64 packed;   // Cat * 1e9 + Seq (11-digit item catalog code)
    u64 row;      // FDFMCommonItemRow*
} DhItemEntry;

typedef struct {
    DhItemEntry* slots;   // open-addressing, power-of-two size
    u32 mask;
    u32 count;

    u64 dt_obj;           // GameItem UDataTable UObject
    u64 rowmap_data;      // TSparseArray Data ptr
    i32 rowmap_num;
} DhItemCatalog;

// One-time init. Returns TRUE on success + populated hashmap.
// baseVA is Delta image base (for adding RVAs to GObjects / FNamePool).
BOOL DhItemCatalogInit(DhItemCatalog* cat,
                       HANDLE hDev, u64 procCR3, u64 baseVA);

// O(1) lookup. Returns row ptr or 0 if not present.
u64  DhItemCatalogLookup(const DhItemCatalog* cat, u64 packed);

void DhItemCatalogFree(DhItemCatalog* cat);
