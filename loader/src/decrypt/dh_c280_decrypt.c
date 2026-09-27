/*
 * dh_c280_decrypt.c
 * Delta Force field decrypt — pure-C external port of 0x14323C280 Feistel.
 *
 * Reversed from Delta build 1.102.37117.80 (CI 2026-08-29 Ma4Release Global).
 * Source disasm:
 *   C:\DeltaHack\delta_bin\decrypt_dis\L1_INNER_A.asm   (0x14323C280..0x14323C788)
 *   C:\DeltaHack\delta_bin\decrypt_dis\cf80_full.asm    (caller wrapper 0x14323CF80)
 *   C:\DeltaHack\delta_bin\decrypt_dis\afd0_full.asm    (outer 0x14323AFD0)
 *
 * External-mode contract:
 *   - Caller has RPM'd the 20-byte state-cache entry at state_data + 20*idx
 *     (state_data = *(state_entry+0x08)).
 *   - Caller passes the first 12 bytes of that cache entry (an FVector-shaped
 *     ciphertext) as three u32 args x_bits_in, y_bits_in, z_bits_in.
 *   - handler_index == FEncHandler.Index (low 12 bits are idx; the whole
 *     word is compared against 0x2000 to pick the rbx branch).
 *   - Returns plaintext u32 triple. Z passes through unchanged because the
 *     wrapper's block-2 branch (length >= 0x18) never fires on a 12-byte
 *     FVector-sized payload; Feistel block 1 covers (X,Y) only.
 *
 * rbx selection — the fixed C280DecryptExternal entrypoint hard-picks
 * KEY_FAST (0x2537). That matches the b_encrypted==0 branch for
 * handler_index<0x2000 with cache[+0x10]==0. If the caller has RPM'd
 * state_entry[+0x3C] and found it non-zero (per-slot b_encrypted set),
 * call C280DecryptExternalEx with rbx_key=1 instead. If handler_index
 * >= 0x2000 the game routes through a vtbl-provided key that we cannot
 * emulate without in-process code — the function returns FALSE and the
 * caller must skip that slot or route through a different decrypt path.
 */

#include <stdint.h>
#include <string.h>

typedef int      BOOL;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

/* ---- Feistel constants (extracted from L1_INNER_A.asm) ---- */
#define MAGIC_A   0x2E2AC781u   /* 0x14323C2A0 mov ebp, 0x2E2AC781            */
#define TEA_DELTA 0x61C88647u   /* rounds 2 & 3 additive                       */
#define KEY_STEP  0xE8EA9F63u   /* 0x14323C4E0 add ebp, 0xE8EA9F63 (per outer) */
#define KEY_FAST  0x2537u       /* b_encrypted==0 fast-path rbx                */

/* rol_lo32(v, cl) — semantics of asm sequence
 *     rol rdx, cl
 *     lea eax, [rdx + <imm>]
 * The 64-bit rotate is performed first, then the low 32 bits are consumed
 * by lea. cl is masked to 6 bits by hardware; we mirror that. */
static inline u32 rol_lo32(u64 v, u32 cl)
{
    cl &= 63u;
    if (cl == 0u) return (u32)v;
    return (u32)((v << cl) | (v >> (64u - cl)));
}

/* mix(v) = ((v >> 5) ^ (v << 4)) + v — TEA-style avalanche.
 * asm: mov eax,edx ; shr eax,5 ; shl edx,4 ; xor eax,edx ; add eax,<orig> */
static inline u32 mix32(u32 v)
{
    return ((v >> 5) ^ (v << 4)) + v;
}

/* Feistel block: 2 outer iters × 10 rounds on the pair (X,Y).
 * Reversed from 0x14323C2C0..0x14323C4E0. */
static void feistel_block10x2(u32 *pX, u32 *pY, u64 rbx)
{
    u32 X = *pX, Y = *pY;
    u32 ebp = MAGIC_A;                              /* 0x14323C2A0 */

    for (int outer = 0; outer < 2; ++outer)
    {
        /* 0x14323C2C0: lea eax,[rbp - 0x647]      */
        u32 K1 = ebp - 0x647u;
        /* 0x14323C2D0: lea eax,[rbp - 0x3C6EF9B9] */
        u32 K2 = ebp - 0x3C6EF9B9u;
        u32 K3;                                     /* captured at r6 */

        /* Round 1 — 0x14323C2E0
         *   shr eax, 6 ; and cl, 0x3F ; rol rdx, cl
         *   add K1  ; sub Y, (mix(X) ^ ...) */
        Y -= mix32(X) ^ (rol_lo32(rbx, (K1 >> 6) & 63u) + K1);

        /* Round 2 — 0x14323C310
         *   mov ecx, ebp ; and cl, 0x3F ; rol rdx, cl
         *   add TEA_DELTA + K1 ; sub X, (mix(Y) ^ ...) */
        X -= mix32(Y) ^ (rol_lo32(rbx, ebp & 63u) + TEA_DELTA + K1);

        /* Round 3 — 0x14323C340
         *   mov eax, ebp ; shr eax, 6 ; and cl, 0x3F ; rol rdx, cl
         *   add TEA_DELTA + K1 ; sub Y, ... */
        Y -= mix32(X) ^ (rol_lo32(rbx, (ebp >> 6) & 63u) + TEA_DELTA + K1);

        /* Round 4 — 0x14323C378
         *   lea ecx,[rbp+7] ; and cl,0x3F ; rol rdx, cl
         *   add K2 ; sub X, ... */
        X -= mix32(Y) ^ (rol_lo32(rbx, (ebp + 7u) & 63u) + K2);

        /* Round 5 — 0x14323C3A8
         *   lea eax,[rbp-0x9B9] ; shr eax, 6 ; and cl,0x3F ; rol rdx, cl
         *   add K2 ; sub Y, ... */
        Y -= mix32(X) ^ (rol_lo32(rbx, ((ebp - 0x9B9u) >> 6) & 63u) + K2);

        /* Round 6 — 0x14323C3E0
         *   lea eax,[rbp - 0x78DDED2B]   ; captures K3
         *   lea ecx,[rbp + 0xE] ; and cl,0x3F ; rol rdx, cl
         *   add 0x255992D5 + K1 ; sub X, ... */
        K3 = ebp - 0x78DDED2Bu;
        X -= mix32(Y) ^ (rol_lo32(rbx, (ebp + 0xEu) & 63u) + 0x255992D5u + K1);

        /* Round 7 — 0x14323C418
         *   lea eax,[rbp - 0x372] ; shr eax, 6 ; and cl,0x3F ; rol rdx, cl
         *   add 0x255992D5 + K1 ; sub Y, ... */
        Y -= mix32(X) ^ (rol_lo32(rbx, ((ebp - 0x372u) >> 6) & 63u) + 0x255992D5u + K1);

        /* Round 8 — 0x14323C450
         *   lea ecx,[rbp - 0x62B] ; and cl,0x3F ; rol rdx, cl
         *   add K3 ; sub X, ... */
        X -= mix32(Y) ^ (rol_lo32(rbx, (ebp - 0x62Bu) & 63u) + K3);

        /* Round 9 — 0x14323C480
         *   lea eax,[rbp - 0xD2B] ; shr eax, 6 ; and cl,0x3F ; rol rdx, cl
         *   add K3 ; sub Y, ... */
        Y -= mix32(X) ^ (rol_lo32(rbx, ((ebp - 0xD2Bu) >> 6) & 63u) + K3);

        /* Round 10 — 0x14323C4B0
         *   lea eax,[rbp - 0x171566E4]  ; additive captured BEFORE step
         *   lea ecx,[rbp - 0x664] ; and cl,0x3F ; rol rdx, cl
         *   sub X, (mix(Y) ^ (rol + (ebp - 0x171566E4))) */
        X -= mix32(Y) ^ (rol_lo32(rbx, (ebp - 0x664u) & 63u) + (ebp - 0x171566E4u));

        /* 0x14323C4E0: add ebp, 0xE8EA9F63 */
        ebp += KEY_STEP;
    }

    *pX = X;
    *pY = Y;
}

/*
 * C280DecryptExternal — fast-path FVector decrypt for ESP position update.
 *
 * Ports the outer + inner Feistel of 0x14323C280 for a 12-byte payload.
 * rbx is hard-picked to KEY_FAST (0x2537), which is correct when the
 * per-slot b_encrypted flag at state_entry[+0x3C] is 0 AND the state
 * cache byte at cache[+0x10] is 0 (the ordinary player-actor route).
 *
 * If handler_index >= 0x2000 the algorithm requires a vtbl-driven key
 * fetch we cannot emulate externally — return FALSE.
 */
BOOL C280DecryptExternal(u16 handler_index,
                         u32 x_bits_in, u32 y_bits_in, u32 z_bits_in,
                         u32 *x_out, u32 *y_out, u32 *z_out)
{
    if (!x_out || !y_out || !z_out)
        return FALSE;

    /* 0x14323C288..0x14323C29C: cmp bx, 0x2000 ; jae vtbl_branch */
    if (handler_index >= 0x2000u)
        return FALSE;

    u32 X = x_bits_in;
    u32 Y = y_bits_in;

    /* 0x14323C2A0..0x14323C4E8: 2 x 10 Feistel rounds on (X,Y) */
    feistel_block10x2(&X, &Y, (u64)KEY_FAST);

    *x_out = X;
    *y_out = Y;
    /* Block 2 (0x14323C500..0x14323C780) fires only when length >= 0x18.
     * For a 12-byte FVector payload it stays dormant, so Z passes through. */
    *z_out = z_bits_in;
    return TRUE;
}

/*
 * C280DecryptExternalEx — variant when caller has RPM'd state_entry[+0x3C]
 * and confirmed it is non-zero (per-slot b_encrypted set). In that case
 * the game hard-picks rbx=1 regardless of handler_index. Kept as a separate
 * entrypoint because the fixed C280DecryptExternal signature has no room
 * to pass the b_encrypted flag through.
 */
BOOL C280DecryptExternalEx(u16 handler_index, u32 rbx_key,
                           u32 x_bits_in, u32 y_bits_in, u32 z_bits_in,
                           u32 *x_out, u32 *y_out, u32 *z_out)
{
    (void)handler_index;
    if (!x_out || !y_out || !z_out)
        return FALSE;

    u32 X = x_bits_in;
    u32 Y = y_bits_in;
    feistel_block10x2(&X, &Y, (u64)rbx_key);

    *x_out = X;
    *y_out = Y;
    *z_out = z_bits_in;
    return TRUE;
}
