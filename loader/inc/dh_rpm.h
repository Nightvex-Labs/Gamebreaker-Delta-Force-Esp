#pragma once
#include "dh_common.h"

// Discovered EPROCESS.Peb offset for the running OS build.
// Auto-initialized on first RpmFindProcess() call. See dh_rpm.c.
extern u32 g_eproc_peb_off;
extern u64 g_rpm_psisp;

// CR3 discovery via low-stub scan (first 1MB physical).
BOOL RpmFindSystemCR3(HANDLE hDev, u64* cr3Out);

// Page walk: translate virtual → physical using a given CR3.
BOOL RpmVirtToPhys(HANDLE hDev, u64 cr3, u64 va, u64* paOut);

// Read virtual memory of a process given its CR3.
BOOL RpmReadVirtual(HANDLE hDev, u64 cr3, u64 va, void* buf, u32 size);
BOOL RpmWriteVirtual(HANDLE hDev, u64 cr3, u64 va, const void* buf, u32 size);

// Helper: 8-byte kernel virtual write.
static inline BOOL RpmWrite64(HANDLE hDev, u64 cr3, u64 va, u64 val) {
    return RpmWriteVirtual(hDev, cr3, va, &val, 8);
}

// Bump VA→PA cache generation. Call at start of each main tick to invalidate
// all cached translations. Safe cache = translations valid only within one
// generation, so no cross-tick staleness or race with cam thread.
void RpmBumpGeneration(void);

// Walk EPROCESS list to find a process by image name. Returns its CR3.
// procName must be the 15-char ImageFileName (e.g. "DeltaForceClie").
// Unlink our own EPROCESS from ActiveProcessLinks — hides us from every
// tool that walks NtQuerySystemInformation(SystemProcessInformation): Task
// Manager, tasklist.exe, Process Hacker, ProcessExplorer. Requires that
// RpmFindProcess has been called at least once so g_rpm_psisp is cached.
BOOL RpmHideOwnProcess(HANDLE hDev, u64 sysCR3);

// Walk EPROCESS list, unlink every entry whose ImageFileName starts with
// nameA (case-insensitive). Returns count of newly-hidden processes.
// Used by daemon to sweep for overlay + any other same-named instances.
int  RpmHideAllByImageName(HANDLE hDev, u64 sysCR3, const char* nameA);

BOOL RpmFindProcess(HANDLE hDev, u64 sysCR3,
                    const char* procName, u64* procCR3, u64* eprocessOut);

// Convenience: read u64 from virtual address.
static inline BOOL RpmRead64(HANDLE hDev, u64 cr3, u64 va, u64* out) {
    return RpmReadVirtual(hDev, cr3, va, out, 8);
}

// Fast path: main image base of a process via PEB.ImageBaseAddress.
BOOL RpmGetMainImageBase(HANDLE hDev, u64 procCR3, u64 pebVA,
                         u64* baseOut, u64* sizeOut);

// Walk PEB.Ldr.InLoadOrderModuleList, find module by BaseDllName (case-insensitive).
// dllName is WCHAR (e.g. L"DeltaForceClient-Win64-Shipping.exe").
BOOL RpmFindModule(HANDLE hDev, u64 procCR3, u64 pebVA,
                   const wchar_t* dllName, u64* baseOut, u64* sizeOut);

// Callback for module enumeration. Return FALSE to stop.
typedef BOOL (*RpmModuleCb)(const wchar_t* name, u64 base, u64 size, void* ctx);
BOOL RpmEnumModules(HANDLE hDev, u64 procCR3, u64 pebVA,
                    RpmModuleCb cb, void* ctx);

// ---- Delta UE4 primitives ----

// Delta UObject REORDERED layout (from Dumper-7 CoreUObject_classes.hpp:19)
#define UOBJ_VTABLE     0x00
#define UOBJ_CLASS      0x08
#define UOBJ_OUTER      0x10
#define UOBJ_FLAGS      0x18
#define UOBJ_NAME       0x1C   // FName {int32 ComparisonIndex; uint32 Number}
#define UOBJ_INDEX      0x24
#define UOBJ_SIZE       0x28

// FUObjectArray layout (from live probe + Basic.hpp)
// GObjects at Delta+0x1E68AF58:
#define GOBJ_LAST_NON_GC       0x04
#define GOBJ_CHUNKS_PTR        0x10   // FUObjectItem**
#define GOBJ_PREALLOC          0x18
#define GOBJ_ITEM_SIZE         0x18   // 24 bytes per FUObjectItem
#define GOBJ_ELEMENTS_PER_CHUNK 0x10000

// FName XOR key for Delta — determined empirically by decoding known strings
// like "None" (index 0) and "GetWeaponBase". The IDA snippet using 0x0E is for
// a different name buffer (SGCharacter internal), NOT FNamePool.
#define DELTA_FNAME_XOR_KEY    0xFF

// Get UObject pointer at global index. gObjectsVA = base + 0x1E68AF58.
BOOL RpmGetUObjectByIndex(HANDLE hDev, u64 procCR3, u64 gObjectsVA,
                          i32 index, u64* outObj);

// Get FNamePool base address. Just adds RVA to image base for convenience.
static inline u64 RpmGNamesVA(u64 imageBase) { return imageBase + 0x1E662B80; }

// Resolve FName ComparisonIndex → string. XOR-decrypts with 0x0E per byte.
// Standard UE4.24 FNamePool layout: {header, Blocks[8192]}.
BOOL RpmResolveFName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                     u32 comparisonIndex, char* out, u32 outSize);

// Read UObject.Name as string. name must fit 128 bytes.
BOOL RpmGetObjectName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                      u64 obj, char* out, u32 outSize);

// Read UObject.Class then that class's Name.
BOOL RpmGetObjectClassName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                           u64 obj, char* out, u32 outSize);

// FEncVector decode. If bEncrypted flag is 0, X/Y/Z are raw. If non-zero,
// they've been XORed with per-instance key (algo TBD — for now returns
// raw bytes and reports bEncrypted state).
BOOL RpmReadEncVector(HANDLE hDev, u64 procCR3, u64 vecVA,
                      float* xOut, float* yOut, float* zOut,
                      u8* bEncryptedOut);

// UStruct / UClass offsets (Delta REORDERED — verified in GOLDEN_OFFSETS).
#define USTRUCT_SUPER      0x48   // UStruct::SuperStruct  (chain root == UObject)
#define UCLASS_CDO         0x140  // UClass::ClassDefaultObject

// ObjectFlags bit — matches vanilla UE4 RF_ClassDefaultObject.
#define RF_CLASS_DEFAULT_OBJECT   0x00000010u

// Walk GObjects, resolve each object's Name via FNamePool, string-match
// against targetName. Returns the first matching UObject* (typically a
// UClass) or 0. Cheap (one full GObjects sweep), meant for lazy-init cache.
u64 RpmFindUClassByName(HANDLE hDev, u64 procCR3, u64 gObjectsVA,
                       u64 gNamesVA, const char* targetName);

// TRUE iff classPtr's SuperStruct chain (walked up to 8 hops) contains
// ancestorClass. Zero args = FALSE. Reads at most 8 u64s.
BOOL RpmIsClassDescendantOf(HANDLE hDev, u64 procCR3,
                            u64 classPtr, u64 ancestorClass);
