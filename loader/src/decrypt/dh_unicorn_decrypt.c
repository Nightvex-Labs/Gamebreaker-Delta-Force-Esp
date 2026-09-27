// DeltaHack — Unicorn-based FEncVector decrypt.
//
// Wraps Unicorn Engine 2.1.4 to execute Delta's own decrypt routine on 16-byte
// FEncVector payloads. Missing pages get lazy-mapped by RPM'ing from live
// Delta via our kdu shellcode BYOVD driver.
//
// Reference: https://raw.githubusercontent.com/DErDYAST1R/DeltaForce/main/decryption.h
// (Dec 2025 leak — Wegame CN build. This module adapts to current Steam
// Global build 1.102.37117.80 by dynamically resolving the fn address.)
//
// Signature (verified via Fischsalat's IDA decompile on UC forum thread
// #653290, and via KismetMathLibrary::DecVector UFunction params):
//   void __fastcall decrypt(FVector* io, u64 length, u64* offset_or_flag);
//   - io: pointer to 16 bytes of encrypted position data (FEncVector layout)
//   - length: 0x10 for FEncVector (leak said 0x10; Fischsalat's disasm said
//             0xC — we pass 0x10 which is the game-side value in current path)
//   - offset_or_flag: pointer to u64 whose low 16 bits are EncHandler.Index
//
// Fn address resolution:
//   1. Walk GObjects, find UFunction "DecVector" in KismetMathLibrary
//   2. Read UFunction+0xE0 → ExecFunction ptr
//   3. That's Delta's current-build decrypt fn address

#include "../../inc/dh_unicorn_decrypt.h"
#include "../../inc/dh_rpm.h"
#include "../../inc/dh_vmprotect.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

// Unicorn headers
#include <unicorn/unicorn.h>

// -----------------------------------------------------------------------------
// Emulator layout constants (from leak, verbatim)
// -----------------------------------------------------------------------------
#define UC_STACK_BASE   0x10000000ULL
#define UC_STACK_SIZE   0x100000ULL
#define UC_DATA_BASE    0x20000000ULL
#define UC_DATA_SIZE    0x100000ULL
#define UC_CODE_WINDOW  0x100000ULL   // 1 MB pre-map around fnAddr
#define UC_INSN_LIMIT   100000
#define UC_DATA_ADDR    (UC_DATA_BASE + 0x1000ULL)
#define UC_OFFSET_ADDR  (UC_DATA_BASE + 0x2000ULL)

// -----------------------------------------------------------------------------
// Module state — one instance per process
// -----------------------------------------------------------------------------
typedef struct {
    uc_engine* uc;
    HANDLE     hDev;
    u64        procCR3;
    u64        baseDelta;
    u64        decrypt_fn_va;
    uc_hook    hook_unmapped;
    // Stats
    u64 n_calls;
    u64 n_fast_path;
    u64 n_success;
    u64 n_emu_fail;
    u64 n_lazy_pages;
} DH_UC;

static DH_UC g_uc = {0};

// -----------------------------------------------------------------------------
// Lazy page-map callback — RPM missing page from live Delta into UC
// -----------------------------------------------------------------------------
static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value,
                             void* user_data)
{
    (void)type; (void)size; (void)value; (void)user_data;
    u64 aligned = address & ~0xFFFULL;

    // Try to map. UC_ERR_MAP means already mapped by an earlier fault — that
    // is fine, we just write into it.
    uc_err e = uc_mem_map(uc, aligned, 0x1000, UC_PROT_ALL);
    if (e != UC_ERR_OK && e != UC_ERR_MAP) {
        // Can't map — page collides with something we already mapped bigger
        // than 4K, or Unicorn is out of address space. Log and let the
        // emulator fault out.
        return false;
    }

    // RPM the page from Delta. If RPM fails, leave the page zero-filled —
    // the emulator will likely SIGSEGV inside the decrypt at some read but
    // we return false-fault upstream anyway.
    u8 page[0x1000];
    memset(page, 0, sizeof(page));
    if (RpmReadVirtual(g_uc.hDev, g_uc.procCR3, aligned, page, sizeof(page))) {
        uc_mem_write(uc, aligned, page, sizeof(page));
        g_uc.n_lazy_pages++;
    } else {
        uc_mem_write(uc, aligned, page, sizeof(page));  // zero fill
    }

    // Return true: we handled the fault, retry the failing instruction.
    return true;
}

// -----------------------------------------------------------------------------
// GObjects walk — find UFunction "DecVector" and read its ExecFunction
// -----------------------------------------------------------------------------
//
// UE4.24 layout (from Delta's dumper7 output SDK/CoreUObject_classes.hpp:289):
//   UFunction : UStruct : UField : UObject
//   +0x000 UObject
//   +0x028 UField
//   +0x030 UStruct
//   +0x0B8 Pad_B8[0x08]
//   +0x0C0 FunctionFlags       (u32)
//   +0x0C4 Pad_C4[0x1C]
//   +0x0E0 ExecFunction         (void*)  ← the native decrypt entry
//
// UObject:
//   +0x00 vtable
//   +0x08 ObjectFlags (u32)
//   +0x0C InternalIndex (i32)
//   +0x10 UClass* Class
//   +0x18 FName Name  (u32 CompIdx, u32 Number)
//   +0x20 UObject* Outer
//
// FUObjectArray layout (UE4.24, matches existing main.c code):
//   +0x00 ObjFirstGCIndex (i32)
//   +0x04 ObjLastNonGCIndex (i32)
//   +0x08 MaxObjectsNotConsideredByGC (i32)
//   +0x0C OpenForDisregardForGC (i32)
//   +0x10 FUObjectItem** Chunks  ← chunked storage
//   +0x18 NumChunks (i32)
//   +0x1C MaxChunks (i32)
//   +0x20 NumElements (i32)
//   +0x24 MaxElements (i32)
//   Each chunk: FUObjectItem[64 * 1024]. FUObjectItem = {UObject*, i32 Flags,
//   i32 ClusterIndex, i32 SerialNumber} = 24 bytes.
//
// We walk chunks, check each UObject's FName against "DecVector", verify Class
// name is "Function", read +0xE0.

#define UOBJ_INDEX_OFFSET      0x0C
#define UOBJ_CLASS_OFFSET      0x10
#define UOBJ_NAME_OFFSET       0x18
#define UFUNC_EXEC_OFFSET      0xE0
#define OBJITEM_STRIDE         0x18  // FUObjectItem = 24B
#define OBJITEMS_PER_CHUNK     (64 * 1024)

static BOOL resolve_dec_vector(HANDLE hDev, u64 procCR3,
                               u64 gObjectsVA, u64 gNamesVA,
                               u64* outFnVA)
{
    u8 gaHdr[0x30];
    if (!RpmReadVirtual(hDev, procCR3, gObjectsVA, gaHdr, sizeof(gaHdr))) {
        DH_WARN("UcDecrypt: RPM GObjects header failed @ 0x%llX",
                (unsigned long long)gObjectsVA);
        return FALSE;
    }
    u64 chunksPtr    = *(u64*)(gaHdr + 0x10);
    i32 numChunks    = *(i32*)(gaHdr + 0x18);
    i32 numElements  = *(i32*)(gaHdr + 0x20);
    if (!chunksPtr || numChunks <= 0 || numElements <= 0) {
        DH_WARN("UcDecrypt: GObjects header sanity failed (chunks=%d elems=%d)",
                numChunks, numElements);
        return FALSE;
    }

    DH_INFO("UcDecrypt: GObjects head chunks=%d elems=%d chunksPtr=0x%llX",
            numChunks, numElements, (unsigned long long)chunksPtr);

    // Iterate chunks
    int scanned = 0;
    int matched = 0;
    for (i32 ci = 0; ci < numChunks; ci++) {
        u64 chunkVA = 0;
        if (!RpmRead64(hDev, procCR3, chunksPtr + (u64)ci * 8, &chunkVA))
            continue;
        if (!chunkVA) continue;

        int chunkLimit = OBJITEMS_PER_CHUNK;
        int consumed = ci * OBJITEMS_PER_CHUNK;
        if (numElements - consumed < chunkLimit)
            chunkLimit = numElements - consumed;
        if (chunkLimit <= 0) break;

        // Bulk-read a big slab of chunk items to reduce IOCTL count.
        // Each item is 24 bytes → 64KB items = 1.5MB per chunk. Too much
        // for one IOCTL — do it in fixed 48KB slices (2048 items × 24B).
        #define SLICE_ITEMS 2048
        static u8 slice[SLICE_ITEMS * OBJITEM_STRIDE];

        for (int base = 0; base < chunkLimit; base += SLICE_ITEMS) {
            int n = chunkLimit - base;
            if (n > SLICE_ITEMS) n = SLICE_ITEMS;
            if (!RpmReadVirtual(hDev, procCR3,
                                chunkVA + (u64)base * OBJITEM_STRIDE,
                                slice, (u32)(n * OBJITEM_STRIDE)))
                continue;

            for (int k = 0; k < n; k++) {
                scanned++;
                u64 uobj = *(u64*)(slice + k * OBJITEM_STRIDE);
                if (!uobj) continue;

                // Read the FName at UObject+0x18 (u32 CompIdx, u32 Number).
                u32 name[2];
                if (!RpmReadVirtual(hDev, procCR3, uobj + UOBJ_NAME_OFFSET,
                                    name, sizeof(name)))
                    continue;
                u32 nameIdx = name[0];

                // Resolve name via FNamePool. Uses existing helper from
                // dh_rpm which decodes UE5-style FName block header with
                // Delta's XOR mask.
                char buf[128];
                if (!RpmResolveFName(hDev, procCR3, gNamesVA, nameIdx,
                                     buf, sizeof(buf)))
                    continue;

                if (strcmp(buf, "DecVector") != 0) continue;

                matched++;

                // Verify Class is UFunction by reading class name.
                u64 classPtr = 0;
                if (!RpmRead64(hDev, procCR3, uobj + UOBJ_CLASS_OFFSET,
                               &classPtr) || !classPtr)
                    continue;

                u32 clsName[2];
                if (!RpmReadVirtual(hDev, procCR3,
                                    classPtr + UOBJ_NAME_OFFSET,
                                    clsName, sizeof(clsName)))
                    continue;

                char clsBuf[64];
                if (!RpmResolveFName(hDev, procCR3, gNamesVA, clsName[0],
                                     clsBuf, sizeof(clsBuf)))
                    continue;

                if (strcmp(clsBuf, "Function") != 0) {
                    DH_INFO("UcDecrypt: DecVector match but Class=%s (skip)",
                            clsBuf);
                    continue;
                }

                // Read ExecFunction at UFunction+0xE0.
                u64 execFn = 0;
                if (!RpmRead64(hDev, procCR3, uobj + UFUNC_EXEC_OFFSET,
                               &execFn) || !execFn) {
                    DH_WARN("UcDecrypt: ExecFunction read failed @ 0x%llX",
                            (unsigned long long)(uobj + UFUNC_EXEC_OFFSET));
                    continue;
                }

                DH_INFO("UcDecrypt: DecVector UFunction @0x%llX ExecFunction=0x%llX",
                        (unsigned long long)uobj,
                        (unsigned long long)execFn);
                *outFnVA = execFn;
                return TRUE;
            }
        }
    }

    DH_WARN("UcDecrypt: DecVector not found after scanning %d objects "
            "(matched name=%d)", scanned, matched);
    return FALSE;
}

// -----------------------------------------------------------------------------
// Init / free
// -----------------------------------------------------------------------------

static BOOL init_unicorn_regions(void)
{
    uc_err e = uc_open(UC_ARCH_X86, UC_MODE_64, &g_uc.uc);
    if (e != UC_ERR_OK) {
        DH_WARN("UcDecrypt: uc_open failed: %s", uc_strerror(e));
        return FALSE;
    }

    e = uc_mem_map(g_uc.uc, UC_STACK_BASE, UC_STACK_SIZE,
                   UC_PROT_READ | UC_PROT_WRITE);
    if (e != UC_ERR_OK) {
        DH_WARN("UcDecrypt: stack map failed: %s", uc_strerror(e));
        return FALSE;
    }

    e = uc_mem_map(g_uc.uc, UC_DATA_BASE, UC_DATA_SIZE,
                   UC_PROT_READ | UC_PROT_WRITE);
    if (e != UC_ERR_OK) {
        DH_WARN("UcDecrypt: data map failed: %s", uc_strerror(e));
        return FALSE;
    }

    e = uc_hook_add(g_uc.uc, &g_uc.hook_unmapped,
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED,
                    (void*)hook_mem_invalid, NULL, 1, 0);
    if (e != UC_ERR_OK) {
        DH_WARN("UcDecrypt: hook install failed: %s", uc_strerror(e));
        return FALSE;
    }
    return TRUE;
}

static BOOL premap_code_window(u64 fnVA)
{
    // Pre-map 1MB centered on fnAddr aligned to page. RPM everything now
    // so the first emu call has hot code without hook thrash.
    u64 code_base = fnVA & ~0xFFFULL;
    u64 code_size = UC_CODE_WINDOW;

    uc_err e = uc_mem_map(g_uc.uc, code_base, code_size, UC_PROT_ALL);
    if (e != UC_ERR_OK && e != UC_ERR_MAP) {
        DH_WARN("UcDecrypt: code map failed: %s", uc_strerror(e));
        return FALSE;
    }

    // Read the full window in one big RPM if possible; RPM helper handles
    // page-cross internally.
    u8* buf = (u8*)VirtualAlloc(NULL, (SIZE_T)code_size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return FALSE;

    if (!RpmReadVirtual(g_uc.hDev, g_uc.procCR3, code_base, buf,
                        (u32)code_size)) {
        DH_WARN("UcDecrypt: RPM code window failed @ 0x%llX",
                (unsigned long long)code_base);
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    e = uc_mem_write(g_uc.uc, code_base, buf, code_size);
    VirtualFree(buf, 0, MEM_RELEASE);
    if (e != UC_ERR_OK) {
        DH_WARN("UcDecrypt: uc_mem_write code failed: %s", uc_strerror(e));
        return FALSE;
    }

    DH_INFO("UcDecrypt: pre-mapped 0x%llX bytes @ 0x%llX",
            (unsigned long long)code_size, (unsigned long long)code_base);
    return TRUE;
}

BOOL UcDecryptInit(HANDLE hDev, u64 procCR3, u64 baseDelta,
                   u64 gObjectsVA, u64 gNamesVA,
                   u64 decryptFnVaHint)
{
    VMProtectBeginUltra("UcDecryptInit");
    if (g_uc.uc) UcDecryptFree();
    memset(&g_uc, 0, sizeof(g_uc));
    g_uc.hDev      = hDev;
    g_uc.procCR3   = procCR3;
    g_uc.baseDelta = baseDelta;

    if (!init_unicorn_regions()) { VMProtectEnd(); return FALSE; }

    u64 fnVA = decryptFnVaHint;
    if (!fnVA) {
        if (!resolve_dec_vector(hDev, procCR3, gObjectsVA, gNamesVA, &fnVA)) {
            // Fallback to FENCVEC_IMPL — the INNER decrypt fn that takes
            // (FVector*, 0xC, FEncHandler*) directly (matches Fischsalat's
            // decompile call FuncPtr(&TmpVec, 0xC, &Handler)).
            //
            // FENCVEC_WRAPPER @0x1432464E0 is the outer that vtable-calls to
            // get the encrypted vec first — CANNOT be emulated standalone
            // because it requires This=UObject with valid vtable.
            //
            // FENCVEC_IMPL @0x14323B030 is the target; it operates purely on
            // the 12-byte payload + 4-byte handler.
            fnVA = baseDelta + 0x0323B030ULL;
            DH_INFO("UcDecrypt: SDK walk failed, using FENCVEC_IMPL @0x%llX",
                    (unsigned long long)fnVA);
        }
    }
    g_uc.decrypt_fn_va = fnVA;

    if (!premap_code_window(fnVA)) { VMProtectEnd(); return FALSE; }

    DH_INFO("UcDecrypt: initialized, decrypt_fn @0x%llX",
            (unsigned long long)fnVA);
    VMProtectEnd();
    return TRUE;
}

u64 UcDecryptGetFnVa(void)
{
    return g_uc.decrypt_fn_va;
}

// -----------------------------------------------------------------------------
// Decrypt call
// -----------------------------------------------------------------------------

static BOOL emulate_one(const u8 in16[16], u16 flag, u8 out16[16])
{
    if (!g_uc.uc || !g_uc.decrypt_fn_va) return FALSE;

    // FENCVEC_IMPL @ 0x14323B030 real signature (from disasm):
    //   XMM0 = input FVector packed as __m128 (16 bytes by value)
    //   RCX  = &output buffer (result gets written here later by callee via
    //          movaps [rcx], xmm0 — but Unicorn returns state in xmm0 too)
    //   RDX  = &FEncHandler (fn reads Index at [rdx+0], flags later)
    //   Return: XMM0 = decrypted FVector packed
    //
    // We prepare:
    //   DATA_ADDR+0x00..+0x0F = handler struct (fn dereferences RDX)
    //   RCX = DATA_ADDR + 0x40  (scratch for callee's writeback)
    //   RDX = DATA_ADDR + 0x00  (points to FEncVector head — Handler starts
    //         at offset 0xC into the FEncVector, but the fn ONLY reads
    //         [rdx+0] as u16 Index, so we lay out Handler at DATA_ADDR
    //         directly).
    //   XMM0 = full 16 bytes of in16 loaded from DATA_ADDR+0x10
    uc_err e;
    // Zero the region
    uint8_t region[0x80];
    memset(region, 0, sizeof(region));
    // Handler @ +0x00 (4 bytes)
    memcpy(region + 0x00, in16 + 12, 4);
    // XMM0 source @ +0x10 (16 bytes = full FEncVector including handler)
    memcpy(region + 0x10, in16, 16);
    e = uc_mem_write(g_uc.uc, UC_DATA_ADDR, region, sizeof(region));
    if (e != UC_ERR_OK) return FALSE;

    // Load XMM0 register with the 16-byte FEncVector value.
    // uc_reg_write with UC_X86_REG_XMM0 expects a pointer to a __m128 value.
    e = uc_reg_write(g_uc.uc, UC_X86_REG_XMM0, in16);
    if (e != UC_ERR_OK) { DH_WARN("UcDecrypt: xmm0 write failed: %s", uc_strerror(e)); return FALSE; }
    (void)flag;

    // Zero out the stack region above RSP so calls don't consume junk.
    static u8 zero_stack[0x8000];  // 32KB high-water zero band
    memset(zero_stack, 0, sizeof(zero_stack));
    u64 rsp = UC_STACK_BASE + UC_STACK_SIZE - 0x1000;
    uc_mem_write(g_uc.uc, rsp - 0x2000, zero_stack, 0x2000);

    // Regs (per FENCVEC_IMPL disasm at 0x14323B030):
    //   RCX = &output buffer (fn passes it downstream)
    //   RDX = &Handler struct — fn reads Index at [rdx]
    //   XMM0 = input FEncVector (loaded above)
    u64 rcxAddr = UC_DATA_ADDR + 0x40;
    u64 rdxAddr = UC_DATA_ADDR + 0x00;
    uc_reg_write(g_uc.uc, UC_X86_REG_RCX, &rcxAddr);
    uc_reg_write(g_uc.uc, UC_X86_REG_RDX, &rdxAddr);
    uc_reg_write(g_uc.uc, UC_X86_REG_RSP, &rsp);
    uc_reg_write(g_uc.uc, UC_X86_REG_RBP, &rsp);

    e = uc_emu_start(g_uc.uc, g_uc.decrypt_fn_va, 0, 0, UC_INSN_LIMIT);
    if (e != UC_ERR_OK) {
        u64 rip = 0;
        uc_reg_read(g_uc.uc, UC_X86_REG_RIP, &rip);
        DH_WARN("UcDecrypt: emu failed: %s at RIP=0x%llX flag=0x%04X",
                uc_strerror(e), (unsigned long long)rip, flag);
        g_uc.n_emu_fail++;
        return FALSE;
    }

    // Read back the decrypted 16 bytes from XMM0 (return register).
    if (uc_reg_read(g_uc.uc, UC_X86_REG_XMM0, out16) != UC_ERR_OK)
        return FALSE;
    return TRUE;
}

BOOL UcDecryptVector(const DH_ENC_VECTOR* enc, DH_FVECTOR* out)
{
    if (!enc || !out) return FALSE;
    g_uc.n_calls++;

    // Fast-path plaintext sentinel.
    if (enc->EncHandler.Index == 0xFFFF || !enc->EncHandler.bEncrypted) {
        out->X = enc->X; out->Y = enc->Y; out->Z = enc->Z;
        g_uc.n_fast_path++;
        return TRUE;
    }

    u8 in16[16];
    memcpy(in16, enc, 16);

    u8 out16[16];
    if (!emulate_one(in16, enc->EncHandler.Index, out16))
        return FALSE;

    memcpy(&out->X, out16 + 0, 4);
    memcpy(&out->Y, out16 + 4, 4);
    memcpy(&out->Z, out16 + 8, 4);
    g_uc.n_success++;
    return TRUE;
}

BOOL UcDecryptVectorAtVA(HANDLE hDev, u64 procCR3, u64 vecVA, DH_FVECTOR* out)
{
    if (!out) return FALSE;
    DH_ENC_VECTOR enc;
    if (!RpmReadVirtual(hDev, procCR3, vecVA, &enc, sizeof(enc)))
        return FALSE;
    return UcDecryptVector(&enc, out);
}

void UcDecryptFree(void)
{
    if (g_uc.uc) {
        uc_close(g_uc.uc);
        g_uc.uc = NULL;
    }
    memset(&g_uc, 0, sizeof(g_uc));
}

void UcDecryptStats(void)
{
    printf("UcDecrypt: calls=%llu fast=%llu ok=%llu fail=%llu lazy_pages=%llu fn=0x%llX\n",
        (unsigned long long)g_uc.n_calls,
        (unsigned long long)g_uc.n_fast_path,
        (unsigned long long)g_uc.n_success,
        (unsigned long long)g_uc.n_emu_fail,
        (unsigned long long)g_uc.n_lazy_pages,
        (unsigned long long)g_uc.decrypt_fn_va);
}
