// DeltaHack — Unicorn-based FEncVector position decrypt.
//
// External path (DErDYAST1R/DeltaForce 2025-12 leak, adapted to build
// 1.102.37117.80). Emulates Delta's own decrypt fn in Unicorn Engine, lazily
// mapping any page the emulator touches by RPM'ing from live Delta.
//
// Call signature (from leak):
//   void __fastcall decrypt_fn(FVector* data, u64 length, u64* offset_ptr);
//   RCX=&data (16B FEncVector-in-place), RDX=length(0x10), R8=&offset,
//   *offset = encryptionFlag (u16 EncHandler.Index for FEncVector case).
//
// Fn address is resolved dynamically per-launch by walking GObjects for
// UFunction "KismetMathLibrary.DecVector" and reading its ExecFunction ptr
// at UFunction+0xE0 — build-independent, survives ACE rotating the .data
// fn-ptr slot.
#pragma once
#include "dh_common.h"
#include "dh_ace_decrypt.h"

// One-shot init. Opens Unicorn, allocates STACK/DATA regions, installs the
// lazy-map hook, and either accepts a caller-provided fn VA or resolves it
// from live Delta via GObjects walk.
//
// If decryptFnVaHint != 0, that VA is used directly (skip the resolve).
// Otherwise, GObjects at gObjectsVA + FNamePool at gNamesVA are walked.
BOOL UcDecryptInit(HANDLE hDev, u64 procCR3, u64 baseDelta,
                   u64 gObjectsVA, u64 gNamesVA,
                   u64 decryptFnVaHint);

// Return the resolved fn VA (0 if not initialized or resolve failed).
u64 UcDecryptGetFnVa(void);

// Decrypt one FEncVector. Returns TRUE on success; result in *out.
// Fast-path: Index==0xFFFF or bEncrypted==0 → passthrough copy.
BOOL UcDecryptVector(const DH_ENC_VECTOR* enc, DH_FVECTOR* out);

// Decrypt raw 16 bytes at a target VA (RPM 16 bytes → emulate → return
// plaintext). Handles the flag check internally by reading Handler.Index
// from bytes[+0x0C..+0x0D]. Used by daemon for pawn+Mesh+ComponentToWorld
// path where the encrypted vector lives inside the target process, not in
// a pre-fetched local struct.
BOOL UcDecryptVectorAtVA(HANDLE hDev, u64 procCR3, u64 vecVA, DH_FVECTOR* out);

// Free all Unicorn state.
void UcDecryptFree(void);

// Stats.
void UcDecryptStats(void);
