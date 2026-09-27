# Delta Force — FEncVector Decrypt Algorithm

**Target build**: Delta Force `1.102.37117.80` (Steam Global 2026-08-29)
**Engine**: UE4.24.2 + Tencent ACE + SGuard64
**Verified**: 2026-09-20 live raid on 2PC (Win11 25H2, Hyper-V ON)

---

## 1. Overview

Delta encrypts `AGPCharacter::LastFrameWorldPosition` and other `FEncVector`
fields to prevent external ESP/aimbot from reading player positions. The
cipher is a **20-round Feistel network** operating on the packed low 64 bits
of the FEncVector, with a **per-frame rotating key** derived from a
linked-list mixer over a dynamic key object.

Full pipeline (per actor per frame):

```
Delta stores encrypted (X, Y, Z) at pawn + 0x1D10          (16 B FEncVector)
         ↓
Handler.Index at pawn+0x1D10+0xC selects a key derivation chain
         ↓
LOOKUP_TABLE[slot_hi].key_obj → linked-list walk → 64-bit KEY
         ↓
Feistel-20 decrypt with (xmm1 = fv, r8 = KEY) → plaintext (X, Y, Z)
```

---

## 2. Struct layouts

### 2.1 FEncVector (16 bytes)

```c
struct FEncVector {
    float X;              // +0x0  encrypted (part of low 64 bits packed)
    float Y;              // +0x4  encrypted
    float Z;              // +0x8  passthrough (Feistel doesn't touch high 64)
    struct FEncHandler {  // +0xC  (4 bytes total)
        uint16_t Index;   // +0xC  actor's cipher slot in LOOKUP_TABLE
        int8_t   bEncrypted;  // +0xE  1 if data at +0..+7 is encrypted
        uint8_t  flags;   // +0xF  bit0 = bDynamic
    } EncHandler;
};
```

Notes:
- Encrypted memory layout: bytes 0..3 hold `X_bits`, bytes 4..7 hold `Y_bits`
  as 32-bit float representations. When loaded into `xmm1`, low 64 bits =
  `(Y_bits << 32) | X_bits` (little-endian).
- Z (bytes 8..11) is NOT touched by the Feistel and passes through unchanged.
  For fully-encrypted world positions, some builds also encrypt Z separately
  — verify by comparing decrypted Z to ground truth.
- `Index == 0xFFFF` is the **local-player sentinel** — for our own actor,
  the vector is plaintext.

### 2.2 AGPCharacter (relevant offsets, UE4.24 Delta build)

```c
struct AGPCharacter {
    ...
    // +0x1C24  float LastCrouchInDifferentLocationTime
    // +0x1C28  float LastProneInDifferentLocationTime
    // +0x1C2C  FVector LastCrouchLocation      // plaintext, ONLY updates on crouch
    // +0x1C38  FVector LastProneLocation       // plaintext, ONLY updates on prone
    // +0x1D04  FVector WorldVelocity
    // +0x1D10  FEncVector LastFrameWorldPosition   ← ★ ENCRYPTED per-frame world pos
};
```

**Use `pawn + 0x1D10` as the encrypted input**. Other offsets:
- `+0x1C2C` LastCrouchLocation is plaintext but STALE (last crouch position)
- `+0x1D10` LastFrameWorldPosition is encrypted but LIVE (every render frame)

### 2.3 LOOKUP_TABLE @ VA 0x15E111AC0

Delta's ACE state cache. Layout per 0x300-byte slot (indexed by `slot_hi = Handler.Index >> 13`):

```
slot_base = 0x15E111AC0 + slot_hi * 0x300

  +0x000..+0x1EF   unused / padding for our path
  +0x1F0          mode_flag byte  — 0 for our path (dynamic decrypt)
  +0x228          Cache A pointer (per bit12 == 0)
  +0x250          Cache A pointer (per bit12 == 1, offset = 0x228 + 40)
  +0x238          Cache B pointer (plaintext cache, per bit12 == 0)
  +0x278          key_obj pointer — DYNAMIC, reallocated per Delta frame
  +0x300          next slot
```

### 2.4 Cache A entry (16 bytes, stride 16, indexed by `low12`)

```c
struct CacheA_Entry {
    uint8_t  padding[0xC];    // +0..0xB
    uint8_t  flag;            // +0xC  — 0 → fallback to hardcoded key 0x2537
                              //           non-zero → walk key_obj linked-list
    uint8_t  misc[3];         // +0xD..0xF
};
```

### 2.5 key_obj (dynamic C++ object at LOOKUP+0x278)

```c
struct key_obj {
    uint8_t  header[0x10];    // vtable + private state (not used externally)
    void*    list_head;       // +0x10  head of linked-list mixer nodes
    uint32_t count;           // +0x18  number of nodes (usually 2..12)
    uint8_t  tls_byte;        // +0x1C  TLS slot index (internal, ignore externally)
};

struct KeyNode {              // 16 bytes each
    uint32_t a;               // +0x0  round rotation count seed
    uint32_t b;               // +0x4  XOR value  
    void*    next;            // +0x8  next node (NULL at tail)
};
```

**Critical**: `key_obj` pointer at `LOOKUP+0x278` is reallocated by ACE every
Delta frame. External readers must re-read it each derivation cycle (or
cache for ≤ one Delta frame = ~12 ms @ 60 fps).

---

## 3. Key derivation algorithm

Ported line-for-line from Delta's `sub_14323B2F0` (`0x14323B440..0x14323B462`).
Verified by 4 independent reads: sub_14323B2F0, sub_14323A9C0, sub_14323EA70,
sub_14323B130.

```c
uint64_t DeriveKey(uint16_t handler_index) {
    uint32_t slot_hi = handler_index >> 13;
    uint32_t low12   = handler_index & 0xFFF;
    uint32_t bit12   = (handler_index >> 12) & 1;
    uint64_t slot_base = 0x15E111AC0ULL + (uint64_t)slot_hi * 0x300;

    // === Cache A gate (only for Idx < 0x2000) ===
    if (handler_index < 0x2000) {
        void* state_A = *(void**)(slot_base + bit12 * 40 + 0x228);
        uint8_t flag = *(uint8_t*)((uint8_t*)state_A + low12 * 16 + 0xC);
        if (flag == 0) return 0x2537ULL;    // hardcoded fallback (rare)
    }

    // === key_obj linked-list walk ===
    void* key_obj = *(void**)(slot_base + 0x278);
    void* head    = *(void**)((uint8_t*)key_obj + 0x10);
    uint32_t count = *(uint32_t*)((uint8_t*)key_obj + 0x18);
    // tls_byte at +0x1C is NOT used externally (only for internal atomic lock)

    uint64_t rbp = *(uint64_t*)head;        // seed = first 8 bytes at head
    void* cur = head;

    for (uint32_t i = 1; i < count; i++) {
        cur = *(void**)((uint8_t*)cur + 8);        // walk to next node
        uint32_t a = *(uint32_t*)cur;               // node[+0x0]
        uint32_t b = *(uint32_t*)((uint8_t*)cur + 4); // node[+0x4]

        rbp ^= (uint64_t)b;                         // XOR with b
        uint8_t cl = (a + i) & 0x3F;                // rot count = (a + i) mod 64
        rbp = _rotr64(rbp, cl);                     // rotate right
        rbp -= (uint64_t)a;                         // subtract a
    }

    return rbp;
}
```

Edge cases:
- `count == 0` → rbp stays as `*head`, returned as key
- `count == 1` → loop skipped, key = `*head`
- `head == NULL` or `key_obj == NULL` → derivation impossible, skip actor

---

## 4. Feistel-20 cipher (VTBL_DECRYPT_120)

**Location in Delta.exe**: `0x143246120` (571 bytes, `.text` section).

Called by Delta as a virtual method: `[*0x15CEDA120].vtable[6]` where
`0x15CEDA120` holds an ACE-managed instance pointer, and `vtable[6]` at
`0x155F9E308` = the Feistel-20 leaf.

### 4.1 Calling convention

```
Input:
  xmm1     = FEncVector packed 16 B (only low 64 = Y<<32|X matter)
  r8       = 64-bit derived KEY
  (xmm0 also loaded for some paths, mirror xmm1 to be safe)

Output:
  xmm0 low 64 = decrypted (Y<<32 | X), high 64 = orig xmm1 high (Z passthrough)

Clobbers: standard MSVC x64 volatile regs.
```

### 4.2 Cipher structure (pseudocode)

```
Load:  r11 = xmm1 lo64        ; r11 = (Y_bits << 32) | X_bits
       rax = r11 >> 32        ; rax(dword) = Y_bits
       ebx = 0x2E2AC781       ; MAGIC (constant across all rounds)
       rdi = r8               ; rdi = 64-bit key
       esi = 2                ; outer loop counter

Outer loop (2 iters × 10 inner rounds = 20 rounds total):
  For each of 10 rounds:
    round_const_i = ebx - offset_i        ; various offsets:
                                          ;   -0x647, -0x3c6ef9b9, -0x9b9,
                                          ;   +0x61c88647, +0x255992d5, ...

    ecx = round_const_i
    rdx = rdi                             ; key
    ecx >>= 6
    cl  &= 0x3F
    rdx = ROL(rdx, cl)                    ; rotate key

    r8_mix = X_bits
    r8_mix >>= 5
    r8_mix ^= (X_bits << 4)                ; Feistel F: (X>>5) ^ (X<<4)
    r8_mix += X_bits                       ; + X

    ecx = (uint32_t)(rdx + round_const_i)  ; rotated_key + constant
    r8_mix ^= ecx

    Y_bits -= r8_mix                       ; Y half ← Y - mix (SUBTRACT direction)

    ; Now next round: same shape but with roles swapped (X<->Y)
    ...

Epilogue:
  ecx = Y_bits (final)
  rcx <<= 32
  eax = X_bits (final)
  rcx |= rax                              ; rcx = (Y << 32) | X
  xmm1 = punpckhqdq(xmm1, xmm1)           ; preserve Z bits
  xmm0 = movq(rcx)
  xmm0 = punpcklqdq(xmm0, xmm1)           ; { decrypted X|Y in low, orig Z in high }
  ret
```

### 4.3 Constants

```
MAGIC_A        = 0x2E2AC781
TEA_DELTA      = 0x61C88647
KEY_STEP       = 0xE8EA9F63        (used in some sibling functions)
Round offsets  = {-0x647, -0x3c6ef9b9, -0x9b9, +0x61c88647, +0x255992d5,
                  -0x372, -0x62b, -0xd2b, -0x664, -0x171566e4, +0xe8ea9f63}
```

Feistel is **its own inverse only if key schedule is reversed**. This
particular function is compiled as the DECRYPT direction (subtracts).
Running it twice ≠ identity.

### 4.4 Practical use — copy as shellcode

Bake the 571 bytes from `Delta.exe + 0x03245120` into your process as
`PAGE_EXECUTE_READWRITE`. No rip-relative refs, no calls, no TLS = fully
relocatable. Call via a small MASM wrapper that sets up xmm1 and r8:

```asm
CallVtblDecrypt PROC
    ; rcx = fn_ptr, rdx = &FEncVector, r8 = key, r9 = &out
    push rbx
    push rsi
    sub  rsp, 30h
    mov  rax, rcx                    ; rax = fn ptr
    mov  rbx, r9                     ; rbx = out ptr
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [rdx]
    mov  r9, r8                      ; r9 = key mirror
    xor  rcx, rcx
    xor  rdx, rdx
    call rax
    movdqu xmmword ptr [rbx], xmm0   ; store 16 B result
    add  rsp, 30h
    pop  rsi
    pop  rbx
    ret
CallVtblDecrypt ENDP
```

---

## 5. Full external decrypt pipeline

```c
bool DecryptWorldPosition(uint64_t pawn_va, Vec3* out_pos) {
    // 1. Read encrypted FEncVector from pawn
    FEncVector enc;
    if (!RPM(pawn_va + 0x1D10, &enc, sizeof(enc))) return false;

    // 2. Handle local-player sentinel
    if (enc.EncHandler.Index == 0xFFFF) {
        out_pos->x = enc.X; out_pos->y = enc.Y; out_pos->z = enc.Z;
        return true;    // already plaintext for our own actor
    }

    // 3. Derive the current cipher key
    uint64_t key = DeriveKey(enc.EncHandler.Index);
    if (key == 0) return false;

    // 4. Call baked Feistel-20 shellcode
    alignas(16) uint8_t fv_in[16], fv_out[16];
    memcpy(fv_in, &enc, 16);
    CallVtblDecrypt(g_shellcode_page, fv_in, key, fv_out);

    // 5. Extract plaintext
    memcpy(&out_pos->x, fv_out + 0, 4);
    memcpy(&out_pos->y, fv_out + 4, 4);
    memcpy(&out_pos->z, fv_out + 8, 4);

    // 6. Sanity: NaN/inf/out-of-range → decrypt failed (stale key_obj)
    if (!isfinite(out_pos->x) || !isfinite(out_pos->y) || !isfinite(out_pos->z)) return false;
    if (fabsf(out_pos->x) > 200000.f || fabsf(out_pos->y) > 200000.f ||
        fabsf(out_pos->z) > 20000.f) return false;

    return true;
}
```

Success rate observed on live raid: ~85-95% per attempt. Failures are
almost always caused by ACE reallocating `key_obj` between our RPMs
(non-atomic reads across the chain). Solve either with:
- **Retry**: re-derive up to 3× on sanity fail
- **Cache**: keep last-good position per Handler.Index for ~500 ms

---

## 6. Internal decrypt (for dumper injection)

If your code runs INSIDE Delta.exe (injected DLL, dumper module, etc.),
skip our external algorithm entirely — just call Delta's own decrypt:

```c
// Delta's public FEncVector decrypt entry:
using FencvecWrapper = void(__fastcall*)(__m128 fv, FEncHandler* handler);
auto decrypt_fn = (FencvecWrapper)(delta_base + 0x03245XXX);  // FENCVEC_WRAPPER

// Call in-place — Delta handles all key derivation, cache walks, TLS locks:
__m128 fv = _mm_loadu_ps((float*)&enc_vector);
decrypt_fn(fv, &enc_vector.EncHandler);
// fv now contains decrypted values in low 64 bits
```

Advantages of internal path:
- Zero cipher code duplication
- Uses Delta's own thread-safe key rental (TLS xchg)
- Immune to `key_obj` reallocation races
- Full 100% success rate

**FENCVEC_WRAPPER VA**: `0x1432464E0` (Delta build 1.102.37117.80).
RVA: `0x032454E0`. Signature scan for stability across micro-patches:

```
40 57 48 83 EC 30 33 C0 0F 29 74 24 20 48 8B FA 48 89 54 24 48
```

---

## 7. Integration checklist for Dumper

If porting to a dumper that INJECTS into Delta:

1. **Wait for ACE init** — key_obj chain populates ~2-4 s after Delta startup.
   Use `WaitForSingleObject` on some ACE-created event, or poll
   `*(LOOKUP+0x278) != 0` until non-zero.
2. **Resolve FENCVEC_WRAPPER by signature** — do NOT hardcode the VA, it
   shifts per micro-patch.
3. **Call decrypt for every `FEncVector` field** you encounter during
   the SDK walk — the dump will then contain PLAINTEXT world positions.
4. **Handle nested encryption** — some `FEncTransform` (48 B) contains
   FEncVector components too; decrypt each recursively.
5. **Camera/Local sentinel**: if `Handler.Index == 0xFFFF`, DO NOT
   decrypt — already plaintext.

---

## 8. Known cipher siblings in Delta

Delta's encryption module (0x143235000..0x143260000) has 11 Feistel-variant
functions. Only VTBL_DECRYPT_120 is used for FEncVector runtime. Other
siblings decrypt different data types:

| VA          | Purpose                                       |
|-------------|-----------------------------------------------|
| 0x14323A9C0 | Uncached-key path with 0x2537 fallback        |
| 0x14323B030 | FENCVEC_IMPL — Cache B plaintext fast path    |
| 0x14323B130 | Dispatch wrapper with virtual call            |
| 0x14323B2F0 | Self-contained decrypt + inline key derive    |
| 0x14323B690 | bit12=1 variant                                |
| 0x14323C0C0 | Batch dispatcher                              |
| 0x14323C790 | Thread-safe entry                              |
| 0x14323EA70 | Multi-block Feistel + XTEA remix (larger types)|
| 0x143246120 | ★ VTBL_DECRYPT_120 — leaf, xmm1+r8 → xmm0     |
| 0x143246A10 | 10-round Feistel — FVector2D variant?         |
| 0x143250200 | Slot 4 vtable — DECRYPT var-size              |
| 0x143250710 | Slot 3 vtable — ENCRYPT var-size (mirror of 4)|

---

## 9. Verification data

**Live raid test 2026-09-20**:
- Enemy `Handler.Index=0x000F`, ground truth `(-27136.2, -21253.9, 910.2)`
- Derived key: `0xF626F4C00FC2CCCB`
- Decrypted output: `(-27132.7, -21242.8, 936.2)`
- Δd2d = **11.7 units** — within player movement noise (last-seen was
  a crouch snapshot 3 s stale)

**Continuous tracking test**:
```
04:44:22  out(-20654, -7168,  362)
04:44:24  out(-21475, -6822,  362)   ΔX/Δt = 2.7 m/s
04:44:28  out(-21660, -7079, -168)   Z drop (player jumped down)
04:44:33  out(-20627, -7479, -168)
04:44:37  out(-20331, -8187, -168)   Δt=15 s traj = smooth walk
```

Values move as a real player — ~5 m/s max, smooth trajectory, Z respects
building floors. Cipher formula is correct.

---

## 10. Sources / cross-references

- `C:/DeltaHack/delta_bin/vtbl_decrypt_120.bin` — 571-byte Feistel body
- `C:/DeltaHack/re/night2/CRITICAL_FINDING_B2F0.md` — original discovery
- `C:/DeltaHack/re/night2/fn_14323A9C0.md` — 0x2537 branch confirmation
- `C:/DeltaHack/re/night2/fn_14323EA70.md` — XTEA-remix sibling
- `C:/DeltaHack/loader/src/decrypt/dh_derive_key.c` — reference C impl
- `C:/DeltaHack/loader/src/decrypt/vtbl_spray_wrap.asm` — MASM wrapper
- `C:/DeltaHack/sdk/GOLDEN_OFFSETS.md` — full offset dump
