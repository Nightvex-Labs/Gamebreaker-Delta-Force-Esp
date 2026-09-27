// DeltaHack — external key derivation.
//
// Replicates the inline key-derivation code from Delta's 0x14323B2F0
// decrypt variant. Reads Delta's LOOKUP_TABLE + key_obj chain via RPM
// and computes the Feistel-20 key locally. No TLS, no injection.
//
// Algorithm (verified from Delta.exe disasm 2026-09-20):
//
//   if (Handler.Index < 0x2000):
//       state_A = *(LOOKUP + slot_hi*0x300 + bit12*40 + 0x228)
//       flag   = *(state_A + low12*16 + 0xC)
//       if (flag == 0):
//           return 0x2537                     // hardcoded fallback
//
//   key_obj = *(LOOKUP + slot_hi*0x300 + 0x278)
//   list_head = *(key_obj + 0x10)
//   count     = *(key_obj + 0x18) as u32
//
//   rbp = *(u64*)list_head
//   for (i = 1; i < count; i++):
//       list_head = *(list_head + 8)          // next node
//       r9d = *(u32*)list_head
//       r8d = *(u32*)(list_head + 4)
//       rbp ^= r8d
//       cl  = (r9d + i) & 0x3F
//       rbp = ROR64(rbp, cl)
//       rbp -= r9d
//
//   return rbp
#pragma once
#include "dh_common.h"
#include "dh_rpm.h"

#define DH_LOOKUP_TABLE_VA   0x15E111AC0ULL   // static in Delta.exe

// Derive the Feistel key for a specific Handler.Index.
// Returns TRUE on success (out_key populated), FALSE on RPM/consistency failure.
BOOL DeriveKey(HANDLE hDev, u64 procCR3, u16 handler_index, u64* out_key);
