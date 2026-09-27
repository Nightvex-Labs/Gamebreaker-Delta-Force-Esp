// DeltaHack shared-memory ABI between payload.dll (producer, inside Delta)
// and dh_overlay.exe (consumer, separate process).
//
// Backing: named file-mapping "Local\DeltaHackESP" + size = sizeof(DHShared).
// Both sides use MEM_MAP_READ/WRITE — payload writes, overlay reads.
#pragma once
#include <stdint.h>

#define DH_SHM_NAME       L"Local\\DeltaHackESP"
#define DH_SHM_MAGIC      0xDE17ACE5u
#define DH_SHM_VERSION    1u
#define DH_MAX_PLAYERS    64

#pragma pack(push, 1)
typedef struct DHPlayer {
    int32_t  team;
    int32_t  camp;
    uint64_t pawn;         // raw pawn ptr — useful for identity across frames
    float    x, y, z;      // world position (RootComponent C2W translation)
    char     name[32];     // UTF-8, null-terminated
} DHPlayer;

typedef struct DHShared {
    uint32_t magic;
    uint32_t version;
    uint64_t frame_counter; // increments each write — overlay uses to detect updates
    uint64_t last_write_us; // producer timestamp (QPC-based microseconds)

    // Local camera view — used for World→Screen projection in overlay.
    float    cam_x, cam_y, cam_z;      // camera location (world)
    float    cam_pitch, cam_yaw, cam_roll; // camera rotation (degrees)
    float    fov;                       // vertical FOV in degrees
    int32_t  screen_w, screen_h;        // client-area resolution (informational)

    // Local player identity — overlay hides "self" from the ESP.
    uint64_t self_pawn;

    int32_t  count;
    int32_t  _pad;
    DHPlayer players[DH_MAX_PLAYERS];
} DHShared;
#pragma pack(pop)

// Sanity checks — compile-time.
typedef char dh_shared_sizecheck[sizeof(DHShared) < 65536 ? 1 : -1];
