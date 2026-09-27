// DeltaHack — Delta ACE state cache reader.
//
// Derived directly from FENCVEC_IMPL disasm @ 0x14323B030 (build 1.102.37117.80):
//   0x14323B04D  lea r14, [rip+0x1aed6a6c]              ; LOOKUP @ 0x15E111AC0
//   0x14323B05B  shr rax, 0xd                            ; slot_hi = Index>>13
//   0x14323B064  lea rsi, [rax + rax*2]                  ; rsi = 3*slot_hi
//   0x14323B068  shl rsi, 8                              ; rsi = 0x300*slot_hi
//   0x14323B09F  shr rax, 0xc                            ; rax = Index>>12
//   0x14323B0A3  and eax, 1                              ; rax = bit12(Index)
//   0x14323B0AA  lea rax, [rax + rax*4]                  ; rax = 5*bit12
//   0x14323B0AE  lea rax, [rsi + rax*8]                  ; rax = rsi + 40*bit12
//   0x14323B0B2  mov rax, qword ptr [rax + r14 + 0x238]  ; state_ptr = *(LOOKUP + rax + 0x238)
//   0x14323B0A6  lea rcx, [rdi + rdi*2]                  ; rcx = 3*(Index & 0xFFF)
//   0x14323B0BA  cmp byte ptr [rax + rcx*8 + 0x14], 0    ; check flag at state+24*(Idx&0xFFF)+0x14
//   0x14323B0C5  mov rax, qword ptr [rcx]                ; load 16B of decrypted vector
//
// entry layout (24 bytes stride, verified):
//   +0x00..+0x0F  FVector plaintext (X,Y,Z + 4B pad or Handler-echo)
//   +0x10..+0x13  4-byte int (frame_id? key_hash?)
//   +0x14         u8 flag (1 = fresh plaintext cached, 0 = stale/invalid)
//   +0x15..+0x17  padding
#pragma once
#include "dh_common.h"
#include "dh_ace_decrypt.h"

#define DELTA_LOOKUP_TABLE_VA   0x15E111AC0ULL

// Read plaintext FVector from the state cache for a given FEncHandler.Index.
// Returns TRUE if entry was found with flag=1 and vector values look sane.
BOOL StateCacheV2(HANDLE hDev, u64 procCR3,
                  u16 handlerIndex,
                  DH_FVECTOR* out);

// Wrapper — takes a full FEncVector, dispatches to state cache path.
// Handles fast-path (Index==0xFFFF or bEncrypted==0) by returning raw XYZ.
BOOL StateCacheDecryptV2(HANDLE hDev, u64 procCR3,
                        const DH_ENC_VECTOR* enc,
                        DH_FVECTOR* out);
