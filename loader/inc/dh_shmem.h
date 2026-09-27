// DeltaHack — shared memory layout for daemon↔overlay IPC.
//
// Named mapping in Global\ namespace so daemon (Session 0, SYSTEM) publishes
// and overlay (Session 1, user) reads. Daemon-side polls RPM at 100Hz and
// stamps the entire struct in one memcpy under a spin-lock write mark.
#pragma once
#include "dh_common.h"

// Anonymized shmem name — no "DeltaHack" string in binary. Fixed GUID
// blends with typical Windows service objects in winobj / handle scans.
#define DH_SHMEM_NAME  L"Global\\{7A9F3B21-4E2D-4B12-A5F7-8D6E4C9F1B3A}"
#define DH_SHMEM_MAGIC 0xDECAF0DE
#define DH_MAX_PLAYERS 64
#define DH_MAX_LOOT    512

typedef struct {
    wchar_t name[32];
    int   team;
    float x, y, z;
    float vx, vy, vz;              // velocity (units/sec) — for client-side prediction
    u64   pos_ts_ms;               // GetTickCount64() at last position update
    float cap_hh;                  // UCapsuleComponent.CapsuleHalfHeight — shrinks on crouch/prone
    float cap_r;                   // UCapsuleComponent.CapsuleRadius
    float yaw;                     // Pawn root relative-rotation Yaw (deg); 0 = north
    float hp;                      // AttributeSetHealth.Health.CurrentValue
    float hp_max;                  // AttributeSetHealth.MaxHealth.CurrentValue
    u8    dbg_crouch;              // raw pawn+0x480 byte (bit0 == bIsCrouched)
    i32   dbg_proned;              // raw pawn+0x7A0 int32
    u8    dbg_pose;                // pawn+0x1B48 = ECharacterLogicPoseType (0..3)
    float dbg_cap_root;            // Root+0x180 -> +0x5D0 CapsuleHalfHeight
    float dbg_mesh_rel_z;          // Mesh+0x11C RelativeLocation.Z
    i32   live_status;             // AGPPlayerState.CurrentCharacterLiveStatus @0x94C
                                    // 0=None 1=Alive 2=Death 3=ImpendingDeath(knock)
    // Equipment (helmet + armor vest). Pulled from
    // pawn+0x3960 -> UCharacterEquipComponent -> EquipedArmorInfoArray
    // Filtered by EEquipmentType (Helmet=1, BreastPlate=5).
    u8    helmet_tier;             // FArmorInfo.ArmorLevel (int32 truncated); 0 = none
    float helmet_durability;       // FArmorInfo.Durability (current, no max)
    u8    armor_tier;
    float armor_durability;
    // Weapon + ammo. Walked via pawn+0x2650 (LastSocketCachedWeapon3P,
    // FEncryptedObjectProperty) → AWeaponBase.
    //   AWeaponBase+0x818  = WeaponID uint64 (plaintext)
    //   AWeaponBase+0x1118 = CachedAttributeSetWeaponAmmo (encrypted ptr)
    //   AttrSet+0x58       = ClipAmmoCount float (plaintext)
    u64   weapon_id;               // uint64 catalog id; 0 = none / unresolved
    float weapon_ammo;             // ClipAmmoCount (current mag)
    char  weapon_name[24];         // resolved short name (e.g. "AK-74", "M4A1")
    int   valid;
    int   local;
    int   is_bot;
    int   is_dead;
    u64   pawn;                    // stable key for cam thread's pos lookup
} DH_SHMEM_PLAYER;

// Single loot spot (container / pickup / floor pile). Daemon iterates
// Level.Actors, filters by class-name pattern, writes plaintext world pos +
// rarity guess. Overlay renders dot + label per entry.
typedef struct {
    float x, y, z;              // world position (UE units)
    u8    rarity;               // 0=grey / 1=green / 2=blue / 3=purple / 4=gold / 5=red
    u8    is_corpse;            // 0=container, 1=dead pawn drop
    u32   value;                // optional price hint (0 if unknown)
    char  name[24];             // short class-name fragment
    int   valid;
} DH_SHMEM_LOOT;

typedef struct {
    volatile u32 magic;
    volatile u32 sequence;          // odd = writer in progress, even = stable
    volatile u32 count;
    i32   myTeam;
    float myX, myY, myZ;
    // ---- cam seqlock guards fields between cam_seq_begin and cam_seq_end ----
    // Written at ~250Hz by dedicated cam thread. Overlay reads under cam_seq
    // to see fresh yaw/pitch/fov without waiting for the slow entity walker.
    volatile u32 cam_seq;
    float myYaw, myPitch, myRoll;
    float fov;
    u32   frame_id;                 // increments each poll
    DH_SHMEM_PLAYER players[DH_MAX_PLAYERS];
    // Loot — published under its own tiny seqlock so overlay can iterate
    // safely while daemon is mid-write. Small counts (<256) so lock-free
    // memcpy is fine after even/odd guard.
    volatile u32    loot_seq;
    volatile u32    loot_count;
    DH_SHMEM_LOOT   loot[DH_MAX_LOOT];
    // Position seqlock — pos-thread @120Hz writes ONLY players[i].x/y/z/
    // vx/vy/vz/pos_ts_ms under this seqlock. Overlay reads pos under
    // pos_seq (not main `sequence`), so pos updates are independent of
    // heavy main-tick fields (HP, armor, name).
    volatile u32    pos_seq;
    // Perf diagnostic: measured refresh rates published by daemon.
    // Overlay reads and shows in HUD.
    float           main_hz;    // main tick effective Hz (rolling avg)
    float           cam_hz;     // cam thread effective Hz (rolling avg)
} DH_SHMEM;

// PCM/ctrl pointers cached by main thread so the fast cam thread doesn't
// have to walk GWorld→GameState→PlayerArray each tick.
typedef struct {
    volatile u64 ctrl;      // APlayerController
    volatile u64 pcm;       // APlayerCameraManager
    volatile u64 pawn;      // local pawn (for POV.Location fallback)
    volatile u64 root;      // local root component (for RelativeLocation local sentinel)
    volatile u64 last_refresh_ms;
} DH_CAM_CACHE;
