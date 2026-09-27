// DeltaHack — ACE FEncVector decrypt module.
//
// Universal FEncVector decrypt via .rdata xref locator + local RWX buf-copy.
// Architecture (from 2026-07 UC-leak of Tencent Delta external cheat):
//   RPM-read decrypt_fn body from Delta .text → VirtualAlloc(RWX) local copy →
//   patch rip-relative references → call as function pointer in our process.
//
// Universal decrypt signature (from IDA of APlayerCameraManager::GetCameraLocation):
//   void decrypt_fn(FVector* io_buffer, uint32_t size=0xC, FEncHandler* handler);
//
// Detection rule: if EncHandler.Index == 0xFFFF → plaintext, skip.
//                 else → call decrypt_fn on {X,Y,Z} copy.
#pragma once
#include "dh_common.h"

// Plaintext FVector (12 bytes)
typedef struct {
    float X;
    float Y;
    float Z;
} DH_FVECTOR;

// FEncHandler (4 bytes) — matches CoreUObject_structs.hpp:552-562
typedef struct {
    u16 Index;         // +0x00  0xFFFF = plaintext, else nonce slot (low 12 bits used)
    i8  bEncrypted;    // +0x02  1 = crypted, 0 = plaintext (sanity)
    u8  flags;         // +0x03  bit0=bDynamic, bit1=bShareKey, bit2=bBitwiseCopyable
} DH_ENC_HANDLER;

// FEncVector (16 bytes) — matches CoreUObject_structs.hpp:566-573
typedef struct {
    float           X;             // +0x00
    float           Y;             // +0x04
    float           Z;             // +0x08
    DH_ENC_HANDLER  EncHandler;    // +0x0C
} DH_ENC_VECTOR;

// State of the decrypt module — one instance per session.
typedef struct {
    HANDLE  hDev;              // Kernel driver handle for RPM
    u64     procCR3;           // Target process CR3
    u64     base;              // Delta image base
    u64     size;              // Delta image size

    u64     decrypt_fn_va;     // VA of universal FEncVector decrypt in Delta
    u32     decrypt_fn_size;   // Bytes of function body we copied
    void*   local_fn;          // Our RWX buffer holding the copy
    u32     local_fn_capacity; // Allocated capacity

    // Function pointer for the local call (typed).
    void (__fastcall *call)(DH_FVECTOR* io, u32 size, DH_ENC_HANDLER* handler);

    // Stats
    u64     n_decrypt_calls;
    u64     n_plaintext_hits;
    u64     n_decrypt_faults;
} DH_ACE_DECRYPT;

// Initialize:
//   1. RPM-scan .rdata (or full image) for UTF-16 "double decryption in..."
//   2. Backward-scan .text for lea r??, [rip+X] whose X hits that .rdata offset
//   3. Forward-scan 30-100 bytes past xref for E8 rel32 → decrypt_fn VA
//   4. RPM-read decrypt_fn body (heuristic size), copy into local RWX
//   5. Optionally patch rip-relative refs (see .c for strategy notes)
//
// Returns TRUE on success. On failure inspect dh_log for the exact stage.
BOOL AceDecryptInit(DH_ACE_DECRYPT* dec,
                    HANDLE hDev, u64 procCR3, u64 base, u64 size);

// Decrypt a single FEncVector. Fast-path when Index == 0xFFFF.
// Non-plaintext path calls the local RWX'd decrypt_fn under SEH — a broken
// copy that touches unmapped memory returns FALSE rather than crashing.
BOOL AceDecryptVector(DH_ACE_DECRYPT* dec,
                      const DH_ENC_VECTOR* enc,
                      DH_FVECTOR* outPlain);

// Bulk decrypt N FEncVectors at once (single SEH scope).
BOOL AceDecryptVectors(DH_ACE_DECRYPT* dec,
                       const DH_ENC_VECTOR* encArr, u32 count,
                       DH_FVECTOR* outArr);

// Free resources.
void AceDecryptFree(DH_ACE_DECRYPT* dec);

// Diagnostic: report stats.
void AceDecryptStats(const DH_ACE_DECRYPT* dec);

// Diagnostic: dump the located decrypt_fn body (hex) up to first 128 bytes.
void AceDecryptDumpBody(const DH_ACE_DECRYPT* dec);

// -----------------------------------------------------------------------------
// Scheme-B XORPS decrypt (Unicorn-verified, pure C reimpl)
// -----------------------------------------------------------------------------
// Init: locate 8x16B key table by AOB `48 89 4D F0 0F 57 09`, walk back to
//       `lea rcx, [rip+X]`, RPM-read 128B key blob into module state.
// Once initialized, call AceDecryptXorps(&enc, &out) — pure C XOR.
BOOL AceDecryptXorpsInit(HANDLE hDev, u64 procCR3, u64 base, u64 size);
BOOL AceDecryptXorps(const DH_ENC_VECTOR* enc, DH_FVECTOR* out);

// -----------------------------------------------------------------------------
// VTBL_DECRYPT_120 shellcode-executor (build 1.102.37117.80).
// -----------------------------------------------------------------------------
// Located at VA 0x143246120 in Delta.exe. Pure Feistel over packed (X_bits |
// Y_bits) u64. Z passes through. No memory refs / no calls / no rip-relatives
// — safe to memcpy to local RWX and call as function pointer.
//
// Init: install baked shellcode bytes (static, offline-safe) or RPM-live copy.
// Call: takes an FEncVector, returns decrypted FVector.

BOOL VtblDecryptInitStatic(void);
BOOL VtblDecryptInitLive(HANDLE hDev, u64 procCR3, u64 baseDelta);
BOOL VtblDecryptCall(const DH_ENC_VECTOR* enc, DH_FVECTOR* out);
void VtblDecryptFree(void);

// State-cache decrypt — reads game's pre-decrypted per-thread-slot buffer at
// (LOOKUP_TABLE @ 0x15E111AC0 + slot descriptor + 8) → 16 bytes at offset
// 20*(Index & 0xFFF). Applicable to bDynamic=1 actors (long path in
// FENCVEC_IMPL). Tries all 4 slots.
BOOL StateCacheDecrypt(HANDLE hDev, u64 procCR3, const DH_ENC_VECTOR* enc, DH_FVECTOR* out);

// Full decrypt with automatic path selection: state-cache first, then VTBL
// shellcode. Zero-injection external. Must be preceded by VtblDecryptInit*().
BOOL AceFullDecrypt(HANDLE hDev, u64 procCR3, const DH_ENC_VECTOR* enc, DH_FVECTOR* out);

// -----------------------------------------------------------------------------
// Overlay entry — spawns a full-screen layered GDI window that shows radar +
// world-to-screen ESP boxes over the target game. Blocks until the window
// closes. Uses the caller's driver handle for RPM.
// -----------------------------------------------------------------------------
int OverlayRun(HANDLE hDev, u64 procCR3, u64 base);
int OverlayRunImGui(void);
int DaemonEspRun(HANDLE hDev, u64 procCR3, u64 base);
DWORD WINAPI DaemonEspRun_ThreadEntry(LPVOID param);
// Create Global\DeltaHackEsp shmem so the overlay can attach before Delta
// has been detected. Idempotent — DaemonEspRun's own create_shmem() call
// then becomes a no-op.
int DaemonEspEnsureShmem(void);

// -----------------------------------------------------------------------------
// C280 Feistel decrypt (pure C port of Delta 0x14323C280).
// Feed the 12-byte ciphertext from state_data cache + handler.Index.
// Returns FALSE on 0x2000 refusal (needs game-side vtbl key we can't emulate).
// -----------------------------------------------------------------------------
BOOL C280DecryptExternal(u16 handler_index,
                         u32 x_bits_in, u32 y_bits_in, u32 z_bits_in,
                         u32 *x_out, u32 *y_out, u32 *z_out);
BOOL C280DecryptExternalEx(u16 handler_index, u32 rbx_key,
                           u32 x_bits_in, u32 y_bits_in, u32 z_bits_in,
                           u32 *x_out, u32 *y_out, u32 *z_out);
