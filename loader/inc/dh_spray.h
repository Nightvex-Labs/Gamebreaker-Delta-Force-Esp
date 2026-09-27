// DeltaHack — VTBL_DECRYPT_120 r8-key spray harness.
//
// Purpose: since no direct caller of 0x143246120 exists in Delta.text and
// the fn is only stored in vtable @0x155F9E308, we can't statically observe
// the r8 (key) convention. Brute force: try N candidate r8 values against
// a known-plaintext-GT actor, log any r8 that produces coords matching GT.
#pragma once
#include "dh_common.h"
#include "dh_ace_decrypt.h"

// Configure the ground-truth actor (in-relevance enemy) that we spray
// against. All candidates are tested against these known plaintext coords.
typedef struct {
    DH_ENC_VECTOR enc;      // encrypted FEncVector (as read from root+0x168)
    float gt_x, gt_y, gt_z; // ground-truth from FRepMovement pawn+0x1C2C
    u16 handler_index;      // enc.EncHandler.Index (for candidate derivations)
    u64 rcx_val;            // ACE instance ptr (*0x15CEDA120 live) — real dispatch passes this
} DH_SPRAY_INPUT;

// Result of one candidate r8 evaluation.
typedef struct {
    u64   r8;
    float out_x, out_y, out_z;
    float dx, dy, dz;
    float dist2d;
    int   sane;             // 1 if output is finite + magnitude reasonable
    int   matches;          // 1 if within ±0.5 units of GT (X and Y)
    const char* label;      // human-readable candidate description
} DH_SPRAY_RESULT;

// Run the spray. Fills results[] up to max_results. Returns count of ones
// actually written. Prints DH_INFO lines for any candidate whose output
// is within map-scale of GT.
int SprayVtblKey(const DH_SPRAY_INPUT* in,
                 DH_SPRAY_RESULT* results, int max_results);
