// DeltaHack — ESP daemon. Runs as SYSTEM in Session 0, owns kdu driver
// handle, polls player positions from Delta at 100Hz, publishes to
// Global\DeltaHackEsp shared memory that the overlay in user Session 1 reads.

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sddl.h>
#include "../../inc/dh_common.h"
#include "../../inc/dh_rpm.h"
#include "../../inc/dh_ace_decrypt.h"
#include "../../inc/dh_unicorn_decrypt.h"
#include "../../inc/dh_state_cache.h"
#include "../../inc/dh_spray.h"
#include "../../inc/dh_shmem.h"
#include "../../inc/dh_derive_key.h"
#include "../../inc/dh_item_catalog.h"

static DhItemCatalog g_item_catalog = {0};
static int           g_item_catalog_ready = 0;

// From vtbl_spray_wrap.asm + dh_vtbl_decrypt.c
extern void CallVtblDecryptSpray(void* fn_ptr, void* fv_in_ptr,
                                 unsigned __int64 rcx_val,
                                 unsigned __int64 r8_key,
                                 void* fv_out_ptr);
extern void* GetVtblShellcode(void);

static int g_vtbl_ready = 0;
static int g_xorps_ready = 0;
static int g_uc_ready = 0;

#ifndef DF_RVA_GNAMES
#define DF_RVA_GNAMES              0x1E661B40ULL
#endif

#ifndef DF_RVA_GWORLD
#define DF_RVA_GWORLD                0x1DA98608ULL
#endif
// Offsets rederived from fresh Dumper-7 (SDK 2026-09-20) — old values wrong.
#ifndef DF_WORLD_GAMESTATE
#define DF_WORLD_GAMESTATE           0x140ULL   /* FEncryptedObjectProperty_ */
#endif
#ifndef DF_GAMESTATE_PLAYERARRAY
#define DF_GAMESTATE_PLAYERARRAY     0x388ULL   /* TArray<APlayerState*> */
#endif
#ifndef DF_PLAYERSTATE_PAWNPRIVATE
#define DF_PLAYERSTATE_PAWNPRIVATE   0x3F8ULL   /* APawn* */
#endif
#ifndef DF_GPPS_TEAMID
#define DF_GPPS_TEAMID               0x660ULL   /* AGPPlayerState::TeamID */
#endif
#ifndef DF_GPPS_BDEAD
#define DF_GPPS_BDEAD                0x4B4ULL   /* AGPPlayerState::bDead */
#endif
#ifndef DF_PLAYERSTATE_NAMEPRIV
#define DF_PLAYERSTATE_NAMEPRIV      0x478ULL   /* FString PlayerNamePrivate */
#endif
#ifndef DF_ACTOR_ROOTCOMPONENT
#define DF_ACTOR_ROOTCOMPONENT       0x180ULL   /* FEncryptedObjectProperty_ */
#endif
// Ptr decrypt for FEncryptedObjectProperty_ on Global Steam: 48-bit mask
// (verified 3r4y/dfsdk + DErDYAST1R Dec 2025). Kernel VAs would need sign
// extension into upper 16 bits, but userland heap ptrs fit in 48 bits.
#define DF_ENC_PTR_MASK              0x0000FFFFFFFFFFFFULL

static DH_SHMEM* g_shmem = NULL;
static HANDLE    g_mapping = NULL;

// Shared with fast cam thread. Main thread updates g_cam_cache once a second;
// cam thread reads it every ~4ms and does PCM/ctrl RPMs without walking
// GObjects/GameState/PlayerArray each tick.
static volatile DH_CAM_CACHE g_cam_cache = {0};
static HANDLE   g_cam_thread = NULL;
static volatile LONG g_cam_stop = 0;

// Fast-track: parallel array of (pawn, root, slot) that the cam thread reads
// each iteration @120Hz to refresh positions. Populated by main tick at end
// of publish. Positions become age-synced with camera → boxes glued to model.
#define DH_FAST_TRACK_MAX 128
typedef struct {
    u64 pawn;
    u64 root;
    u32 slot;
    u8  active;
    u8  is_dead;
    u8  _pad[2];
} DH_FAST_ENTRY;
static volatile LONG g_fast_lock = 0;
static DH_FAST_ENTRY g_fast_track[DH_FAST_TRACK_MAX] = {0};
static int g_fast_track_n = 0;
// Per-slot previous-position for velocity computation in cam thread.
static struct { float x, y, z; u64 ts_ms; u8 valid; } g_fast_prev[DH_FAST_TRACK_MAX] = {0};

// Global handles the cam thread needs (set once in DaemonEspRun before
// spawning the cam thread). Cam thread reads only — never writes them.
static HANDLE g_hDev = NULL;
static u64    g_procCR3 = 0;
static u64    g_base = 0;

// Fast pawn-position refresh — called from cam thread. Iterates the parallel
// fast-track array (populated by main tick), reads each pawn's root+FEncVec,
// decrypts if needed, and writes fresh x/y/z/vx/vy/vz/pos_ts_ms into the
// shmem player slot. Camera and positions get the SAME timestamp → box
// glued to model, no client-side extrapolation needed.
static void fast_pos_refresh(void)
{
    if (!g_shmem) return;
    // Snapshot the fast track under lock. LONG spin — sub-microsecond.
    DH_FAST_ENTRY snap[DH_FAST_TRACK_MAX];
    int snap_n = 0;
    while (InterlockedCompareExchange(&g_fast_lock, 1, 0) != 0) { /* spin */ }
    snap_n = g_fast_track_n;
    if (snap_n > DH_FAST_TRACK_MAX) snap_n = DH_FAST_TRACK_MAX;
    memcpy(snap, (void*)g_fast_track, sizeof(DH_FAST_ENTRY) * snap_n);
    InterlockedExchange(&g_fast_lock, 0);

    u64 now_ms = GetTickCount64();
    for (int i = 0; i < snap_n; i++) {
        if (!snap[i].active || snap[i].is_dead) continue;
        // PAWN-KEY lookup — find current shmem slot by pawn ptr (stable
        // across main-tick reorderings; slot index alone races).
        int slot = -1;
        for (u32 j = 0; j < g_shmem->count && j < DH_MAX_PLAYERS; j++) {
            if (g_shmem->players[j].pawn == snap[i].pawn) { slot = (int)j; break; }
        }
        if (slot < 0) continue;
        u64 root = snap[i].root;
        if (root == 0 && snap[i].pawn) {
            u64 rootRaw = 0;
            if (!RpmRead64(g_hDev, g_procCR3, snap[i].pawn + 0x180, &rootRaw)) continue;
            root = rootRaw & DF_ENC_PTR_MASK;
        }
        if (root < 0x100000 || root >= 0x1000000000000ULL) continue;
        DH_ENC_VECTOR pv = {0};
        if (!RpmReadVirtual(g_hDev, g_procCR3, root + 0x148, &pv, 16)) continue;
        float x, y, z;
        if (pv.EncHandler.Index == 0xFFFF) {
            x = pv.X; y = pv.Y; z = pv.Z;
        } else if (g_vtbl_ready) {
            u64 key = 0;
            if (!DeriveKey(g_hDev, g_procCR3, pv.EncHandler.Index, &key)) continue;
            __declspec(align(16)) u8 fi[16];
            __declspec(align(16)) u8 fo[16];
            memcpy(fi, &pv, 16); memset(fo, 0, 16);
            CallVtblDecryptSpray(GetVtblShellcode(), fi, 0, key, fo);
            memcpy(&x, fo+0, 4); memcpy(&y, fo+4, 4); memcpy(&z, fo+8, 4);
        } else continue;
        if (!(x == x && y == y && z == z)) continue;
        if (fabsf(x) > 200000.f || fabsf(y) > 200000.f) continue;

        // Velocity from previous fast-track sample.
        float vx = 0, vy = 0, vz = 0;
        if (g_fast_prev[i].valid) {
            u64 dt_ms = now_ms - g_fast_prev[i].ts_ms;
            if (dt_ms > 0 && dt_ms < 500) {
                float dt = (float)dt_ms / 1000.f;
                vx = (x - g_fast_prev[i].x) / dt;
                vy = (y - g_fast_prev[i].y) / dt;
                vz = (z - g_fast_prev[i].z) / dt;
                if (fabsf(vx) > 2000.f || fabsf(vy) > 2000.f) {
                    vx = vy = vz = 0;
                }
            }
        }
        g_fast_prev[i].x = x; g_fast_prev[i].y = y; g_fast_prev[i].z = z;
        g_fast_prev[i].ts_ms = now_ms; g_fast_prev[i].valid = 1;

        // Write to shmem slot found by pawn key. Individual float writes are
        // 4-byte atomic on x64 — no seqlock needed for pos-only fields.
        DH_SHMEM_PLAYER* p = &g_shmem->players[slot];
        p->x = x; p->y = y; p->z = z;
        p->vx = vx; p->vy = vy; p->vz = vz;
        p->pos_ts_ms = now_ms;
    }
}

// Fast cam-only refresh — ONE 32B RPM covers POV.Location+Rotation+FOV.
// Publishes yaw/pitch/roll/fov under cam_seq mini-seqlock so overlay sees
// ~8ms-fresh camera on every render (120Hz cap).
static void cam_refresh_once(void)
{
    u64 pcm  = g_cam_cache.pcm;
    u64 ctrl = g_cam_cache.ctrl;
    if (!pcm && !ctrl) return;

    float pitch = 0, yaw = 0, roll = 0, fov = 0;
    float locX = 0, locY = 0, locZ = 0;
    u16   loc_idx = 0;
    int   got_rot = 0, got_fov = 0, got_loc = 0;

    if (pcm) {
        // Single 32B read covers: FEncVector Location(16) + FRotator(12) + FOV(4).
        // 4× fewer IOCTL round-trips vs the naive per-field version.
        u8 pov_buf[0x20];
        if (RpmReadVirtual(g_hDev, g_procCR3, pcm + 0x31DB0, pov_buf, sizeof(pov_buf))) {
            DH_ENC_VECTOR pov;
            memcpy(&pov, pov_buf, sizeof(pov));
            loc_idx = pov.EncHandler.Index;
            if (loc_idx == 0xFFFF) {
                locX = pov.X; locY = pov.Y; locZ = pov.Z;
                got_loc = 1;
            }
            float rot[3];
            memcpy(rot, pov_buf + 0x10, 12);
            if (rot[0] == rot[0] && rot[1] == rot[1] && rot[2] == rot[2]) {
                pitch = rot[0]; yaw = rot[1]; roll = rot[2];
                got_rot = 1;
            }
            float f;
            memcpy(&f, pov_buf + 0x1C, 4);
            if (f == f && f > 30.f && f < 170.f) {
                fov = f; got_fov = 1;
            }
        }
    }

    // Fallback rotation from APlayerController.ControlRotation
    if (!got_rot && ctrl) {
        float pi_r = 0, yaw_r = 0, roll_r = 0;
        if (RpmReadVirtual(g_hDev, g_procCR3, ctrl + 0x380, &pi_r,  4) &&
            RpmReadVirtual(g_hDev, g_procCR3, ctrl + 0x384, &yaw_r, 4) &&
            RpmReadVirtual(g_hDev, g_procCR3, ctrl + 0x388, &roll_r,4)) {
            if (pi_r == pi_r && yaw_r == yaw_r) {
                pitch = pi_r; yaw = yaw_r; roll = roll_r;
                got_rot = 1;
            }
        }
    }

    if (!g_shmem) return;

    // Mini-seqlock: bump odd, write, bump even. Overlay retries on odd.
    g_shmem->cam_seq = g_shmem->cam_seq + 1;    // odd
    MemoryBarrier();
    if (got_rot) {
        g_shmem->myYaw   = yaw;
        g_shmem->myPitch = pitch;
        g_shmem->myRoll  = roll;
    }
    if (got_fov) g_shmem->fov = fov;
    if (got_loc) {
        // Only update cam pos when we get a live plaintext POV (Index=0xFFFF).
        // Otherwise leave last-known-good so overlay doesn't jump to (0,0,0).
        g_shmem->myX = locX;
        g_shmem->myY = locY;
        g_shmem->myZ = locZ;
    }
    MemoryBarrier();
    g_shmem->cam_seq = g_shmem->cam_seq + 1;    // even
}

static DWORD WINAPI CamThreadBody(LPVOID unused)
{
    (void)unused;
    // 120Hz cam refresh = 8.33ms period — matches user-requested daemon cap.
    // ONE batched RPM per tick, so aggregate load is only ~120 RPMs/sec.
    LARGE_INTEGER freq = {0}, last = {0};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last);
    const double target = 1.0 / 120.0;

    // Cam rate meter — publishes to shmem->cam_hz every 60 cycles.
    LARGE_INTEGER chzFreq = {0}, chzMark = {0};
    QueryPerformanceFrequency(&chzFreq);
    QueryPerformanceCounter(&chzMark);
    u32 cam_cyc = 0;
    while (!InterlockedCompareExchange(&g_cam_stop, 0, 0)) {
        cam_refresh_once();
        if (++cam_cyc >= 60 && g_shmem) {
            LARGE_INTEGER now_c;
            QueryPerformanceCounter(&now_c);
            double s = (double)(now_c.QuadPart - chzMark.QuadPart) / (double)chzFreq.QuadPart;
            if (s > 0.001) g_shmem->cam_hz = (float)(60.0 / s);
            chzMark = now_c; cam_cyc = 0;
        }
        // fast_pos_refresh();   // OFF — starves main tick (kdu IOCTL contention)
        while (1) {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            double elapsed = (double)(now.QuadPart - last.QuadPart) / (double)freq.QuadPart;
            if (elapsed >= target) { last = now; break; }
            if (target - elapsed > 0.001) Sleep(1);
        }
    }
    return 0;
}

// Per-pawn velocity tracker for client-side prediction.
// Keyed by pawn ptr; LRU on miss. Overlay uses vx/vy/vz + pos_ts_ms to
// extrapolate position to current render time, killing the "jelly" effect
// from daemon→overlay pipeline latency.
static struct { u64 pawn; float x, y, z; u64 ts_ms; } g_vel_track[256] = {0};

static u64 compute_velocity(u64 pawn, float px, float py, float pz,
                             float* out_vx, float* out_vy, float* out_vz)
{
    u64 now_ms = GetTickCount64();
    int slot = -1, oldest_slot = 0;
    u64 oldest_ts = ~0ULL;
    for (int v = 0; v < 256; v++) {
        if (g_vel_track[v].pawn == pawn) { slot = v; break; }
        if (g_vel_track[v].ts_ms < oldest_ts) {
            oldest_ts = g_vel_track[v].ts_ms;
            oldest_slot = v;
        }
    }
    if (slot < 0) {
        slot = oldest_slot;
        g_vel_track[slot].pawn = pawn;
        *out_vx = *out_vy = *out_vz = 0;
    } else {
        u64 dt_ms = now_ms - g_vel_track[slot].ts_ms;
        if (dt_ms > 0 && dt_ms < 500) {
            float dt = (float)dt_ms / 1000.f;
            *out_vx = (px - g_vel_track[slot].x) / dt;
            *out_vy = (py - g_vel_track[slot].y) / dt;
            *out_vz = (pz - g_vel_track[slot].z) / dt;
            // Clamp — reject teleport jumps
            if (fabsf(*out_vx) > 2000.f || fabsf(*out_vy) > 2000.f) {
                *out_vx = *out_vy = *out_vz = 0;
            }
        } else {
            *out_vx = *out_vy = *out_vz = 0;
        }
    }
    g_vel_track[slot].x = px;
    g_vel_track[slot].y = py;
    g_vel_track[slot].z = pz;
    g_vel_track[slot].ts_ms = now_ms;
    return now_ms;
}

static BOOL create_shmem(void)
{
    // Idempotent: caller may invoke early (main.c) to unblock the overlay
    // before Delta is even running, then again from DaemonEspRun.
    if (g_mapping && g_shmem) return TRUE;

    // SD "D:(A;;GA;;;WD)" = Everyone (WD) → full access. Session 1 user reads.
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    PSECURITY_DESCRIPTOR psd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;WD)(A;;GA;;;SY)", SDDL_REVISION_1, &psd, NULL)) {
        DH_ERROR("SD build failed err=%lu", GetLastError());
        return FALSE;
    }
    sa.lpSecurityDescriptor = psd;

    g_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
        PAGE_READWRITE, 0, sizeof(DH_SHMEM), DH_SHMEM_NAME);
    LocalFree(psd);
    if (!g_mapping) {
        DH_ERROR("CreateFileMapping err=%lu", GetLastError());
        return FALSE;
    }
    g_shmem = (DH_SHMEM*)MapViewOfFile(g_mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_shmem) {
        DH_ERROR("MapViewOfFile err=%lu", GetLastError());
        CloseHandle(g_mapping); g_mapping = NULL;
        return FALSE;
    }
    memset(g_shmem, 0, sizeof(*g_shmem));
    g_shmem->magic = DH_SHMEM_MAGIC;
    DH_INFO("shmem %ls ready @ %p (%u bytes)", DH_SHMEM_NAME, g_shmem, (u32)sizeof(DH_SHMEM));
    return TRUE;
}

// Public wrapper — call from main.c before entering the FindProcess retry
// loop so the overlay can attach immediately, even while Delta isn't up yet.
int DaemonEspEnsureShmem(void)
{
    return create_shmem() ? DH_OK : DH_ERR_GENERIC;
}

// One-shot hex dumper — reads `bytes` starting at `base+start`, logs each
// 16-byte row prefixed with tag so a python script can grep it back out.
static void auto_dump_region(HANDLE hDev, u64 procCR3, u64 baseAddr,
                             u32 start, u32 bytes, const char* tag)
{
    if (bytes > 0x1000) bytes = 0x1000;
    static u8 buf[0x1000];
    if (!RpmReadVirtual(hDev, procCR3, baseAddr + start, buf, bytes)) {
        DH_INFO("dump %s @ %llx+%X: READ FAIL", tag,
                (unsigned long long)baseAddr, start);
        return;
    }
    DH_INFO("dump %s @ %llx+%X len=%u ==", tag,
            (unsigned long long)baseAddr, start, bytes);
    u32 rows = bytes / 16;
    for (u32 r = 0; r < rows; r++) {
        DH_INFO("  DMP:%s+0x%04X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                tag, start + r*16,
                buf[r*16+0], buf[r*16+1], buf[r*16+2], buf[r*16+3],
                buf[r*16+4], buf[r*16+5], buf[r*16+6], buf[r*16+7],
                buf[r*16+8], buf[r*16+9], buf[r*16+10], buf[r*16+11],
                buf[r*16+12], buf[r*16+13], buf[r*16+14], buf[r*16+15]);
    }
}

// SKELETON REMOVED 2026-09-26 — bones read cost ~3.8 KB RPM per pawn per tick
// (largest hot-path read). User cut the feature to reclaim FPS. Stub kept as
// no-op for source layout; delete on next major cleanup.
#if 0
static void read_skeleton_for_slot(HANDLE hDev, u64 procCR3,
                                   u64 pawn, u64 root,
                                   float px, float py, float pz,
                                   DH_SHMEM_PLAYER* p)
{
    if (!p) return;
    memset(p->bones_world, 0, sizeof(p->bones_world));
    p->bones_num = 0;
    if (!pawn || pawn < 0x100000) return;

    float rotPitch = 0, rotYaw = 0, rotRoll = 0;
    if (root >= 0x100000) {
        RpmReadVirtual(hDev, procCR3, root + 0x178, &rotPitch, 4);
        RpmReadVirtual(hDev, procCR3, root + 0x17C, &rotYaw,   4);
        RpmReadVirtual(hDev, procCR3, root + 0x180, &rotRoll,  4);
    }
    #define YAW_CACHE_SLOTS 256
    static struct { u64 pawn; float yaw; u64 ts_ms; } s_yaw_cache[YAW_CACHE_SLOTS] = {0};
    u64 now_yc = GetTickCount64();
    int free_yc = -1, hit_yc = -1;
    for (int i = 0; i < YAW_CACHE_SLOTS; i++) {
        if (s_yaw_cache[i].pawn == pawn) { hit_yc = i; break; }
        if (free_yc < 0 && (s_yaw_cache[i].pawn == 0 ||
                            (now_yc - s_yaw_cache[i].ts_ms) > 30000))
            free_yc = i;
    }
    int yaw_ok = (rotYaw == rotYaw) && (rotPitch == rotPitch) &&
                  fabsf(rotYaw) <= 360.0f;
    if (!yaw_ok && hit_yc >= 0) {
        rotYaw = s_yaw_cache[hit_yc].yaw;
        yaw_ok = 1;
    }
    if (yaw_ok) {
        int slot = hit_yc >= 0 ? hit_yc : free_yc;
        if (slot >= 0) {
            s_yaw_cache[slot].pawn  = pawn;
            s_yaw_cache[slot].yaw   = rotYaw;
            s_yaw_cache[slot].ts_ms = now_yc;
        }
    }
    #undef YAW_CACHE_SLOTS

    u64 meshBn = 0;
    RpmRead64(hDev, procCR3, pawn + 0x3D0, &meshBn);
    if (meshBn < 0x100000) return;

    #define BONE_OFF_CACHE 64
    static struct { u64 mesh; u32 off; } s_off_cache[BONE_OFF_CACHE] = {0};
    static const u32 CAND_OFFS[] = {
        0xEB8, 0xEC8, 0xED8, 0xEE8,
        0x760, 0x770, 0x8A0, 0x8B0, 0x9C0
    };
    static u8 csBuf[80*48];
    float bestSpread = 0.0f;
    float bestBuf[80*3] = {0};
    int   bestOk = 0;

    u32 lockedOff = 0;
    int cache_slot = -1;
    for (int i = 0; i < BONE_OFF_CACHE; i++) {
        if (s_off_cache[i].mesh == meshBn) {
            lockedOff = s_off_cache[i].off;
            cache_slot = i;
            break;
        }
    }

    u32 loopOffs[16]; int loopN = 0;
    if (lockedOff) loopOffs[loopN++] = lockedOff;
    else for (int ci = 0; ci < (int)(sizeof(CAND_OFFS)/sizeof(CAND_OFFS[0])); ci++)
        loopOffs[loopN++] = CAND_OFFS[ci];

    u32 winnerOff = lockedOff;
    for (int li = 0; li < loopN; li++) {
        u32 off = loopOffs[li];
        u64 cd = 0;
        RpmRead64(hDev, procCR3, meshBn + off, &cd);
        if (cd < 0x100000) continue;
        if (!RpmReadVirtual(hDev, procCR3, cd, csBuf, sizeof(csBuf))) continue;
        float minZ = 1e9f, maxZ = -1e9f;
        float tmp[80*3] = {0};
        int ok = 0;
        for (int bi = 0; bi < 80; bi++) {
            float lx, ly, lz;
            memcpy(&lx, &csBuf[bi*48 + 0x10], 4);
            memcpy(&ly, &csBuf[bi*48 + 0x14], 4);
            memcpy(&lz, &csBuf[bi*48 + 0x18], 4);
            if (!(lx == lx && ly == ly && lz == lz)) break;
            if (fabsf(lx) > 500.0f || fabsf(ly) > 500.0f || fabsf(lz) > 500.0f) break;
            tmp[bi*3+0] = lx; tmp[bi*3+1] = ly; tmp[bi*3+2] = lz;
            if (lz < minZ) minZ = lz;
            if (lz > maxZ) maxZ = lz;
            ok++;
        }
        if (ok < 32) continue;
        float spread = maxZ - minZ;
        if (spread > bestSpread) {
            bestSpread = spread;
            bestOk = ok;
            memcpy(bestBuf, tmp, sizeof(tmp));
            winnerOff = off;
        }
    }
    if (bestSpread > 30.0f && !lockedOff && winnerOff) {
        if (cache_slot < 0) {
            for (int i = 0; i < BONE_OFF_CACHE; i++) {
                if (s_off_cache[i].mesh == 0) {
                    s_off_cache[i].mesh = meshBn;
                    s_off_cache[i].off  = winnerOff;
                    break;
                }
            }
        }
    }
    #undef BONE_OFF_CACHE
    if (bestSpread <= 30.0f || bestOk <= 0) return;

    // ---- Anchor position ----
    // Actor.Location and CachedComponentSpaceTransforms are populated at
    // DIFFERENT frame boundaries in UE. When the character moves or crouches
    // one lags the other by up to 1 frame -> the skeleton visually swims
    // behind or in front of the body.
    // Canonical fix: read the mesh's own ComponentToWorld.Translation. That
    // value is updated in the same USceneComponent::UpdateComponentToWorld
    // pass that populates the bone transforms -> guaranteed in-sync.
    //
    // Delta-side USceneComponent layout puts ComponentToWorld inside the
    // Pad_1A2[0xAE] region (0x1A2..0x250). Standard UE4.24 offset for the
    // Translation FVector inside that FTransform is +0x1D0. We probe that
    // slot on the mesh's own USceneComponent chunk and, if the values look
    // reasonable, use them as anchor. Otherwise we fall back to the actor's
    // encrypted position (px, py, pz).
    float anchor_x = px, anchor_y = py, anchor_z = pz;
    float c2w[3] = {0};
    if (RpmReadVirtual(hDev, procCR3, meshBn + 0x1D0, c2w, sizeof(c2w))) {
        int c2w_ok = (c2w[0] == c2w[0]) && (c2w[1] == c2w[1]) && (c2w[2] == c2w[2]);
        float mx = c2w[0], my = c2w[1], mz = c2w[2];
        float dx = mx - px, dy = my - py, dz = mz - pz;
        // Sanity: mesh should be within 300 units of the actor (same pawn)
        // and translation magnitude must be non-trivial.
        if (c2w_ok && fabsf(dx) < 300.0f && fabsf(dy) < 300.0f && fabsf(dz) < 300.0f &&
            (fabsf(mx) + fabsf(my)) > 1.0f) {
            anchor_x = mx;
            anchor_y = my;
            anchor_z = mz;
        }
    }

    float ry = (rotYaw - 90.0f) * 3.14159265f / 180.0f;
    float cy = cosf(ry), sy_r = sinf(ry);
    float minZ_ms = 1e9f, maxZ_ms = -1e9f;
    for (int bi = 0; bi < bestOk && bi < 80; bi++) {
        float lz = bestBuf[bi*3+2];
        if (lz < minZ_ms) minZ_ms = lz;
        if (lz > maxZ_ms) maxZ_ms = lz;
    }
    // ---- Z anchor ----
    // Mesh feet sit on ground plane = actor.Z - StandingHalfHeight, NOT
    // actor.Z - CurrentHalfHeight. When the character crouches actor.Z
    // stays put and CapsuleHalfHeight shrinks (88 -> 40 in UE default);
    // the mesh RelativeLocation stays at its standing value so the feet
    // don't actually rise. Using p->cap_hh (post-crouch = 40) drops the
    // skeleton 48 units into the floor while crouching. Lock to the
    // canonical standing half-height (88) regardless of stance.
    const float STAND_HH = 88.0f;
    float zAnchor = anchor_z - STAND_HH - minZ_ms;
    for (int bi = 0; bi < bestOk && bi < 80; bi++) {
        float lx = bestBuf[bi*3+0];
        float ly = bestBuf[bi*3+1];
        float lz = bestBuf[bi*3+2];
        float wx =  cy * lx - sy_r * ly;
        float wy =  sy_r * lx + cy * ly;
        p->bones_world[bi][0] = anchor_x + wx;
        p->bones_world[bi][1] = anchor_y + wy;
        p->bones_world[bi][2] = zAnchor + lz;
    }
    p->bones_num = bestOk;
    (void)maxZ_ms;
}
#endif

// Read helmet + body-armor (BreastPlate) tier + current durability from the
// pawn's CharacterEquipComponent and stamp them into the shmem slot.
//
// Multiple candidate offsets on the pawn hold FEncryptedObjectProperty
// -> CharacterEquipComponent depending on which subclass Delta actually
// spawned (ADFMPlayerCharacter, ADFMCharacter, AGPCharacter, ...).
// We probe them in order; the first that leads to a plausible
// EquipedArmorInfoArray wins and gets locked per pawn.
//
// Comp -> array:
//   comp + 0x1E8   TArray<FArmorInfo> EquipedArmorInfoArray
//                  ({u64 Data, i32 Num, i32 Max})
// FArmorInfo stride 0x88:
//   +0x00 uint8   EquipmentType (Helmet=1, BreastPlate=5)
//   +0x18 float   ArmorHP  (current combat HP)
//   +0x1C float   MaxArmorHP
//   +0x20 float   Durability (long-term wear)
//   +0x80 int32   ArmorLevel
//
// EquipedArmorInfoArray is Net/RepNotify -> replicated to every client
// that can see the pawn, so remote enemy reads work by design.
// Reads helmet + body-armor tier + current HP from the pawn's
// UCharacterEquipComponent. Verified chain (2026-09-21):
//   pawn + 0x3960 or 0x24E0  FEncryptedObjectProperty
//                            & DF_ENC_PTR_MASK -> UCharacterEquipComponent*
//   comp + 0x1E8             TArray<FArmorInfo> EquipedArmorInfoArray
// FArmorInfo stride 0x88 (SDK layout, hex-dump verified):
//   +0x00 uint8   EquipmentType (Helmet=1, BreastPlate=5)
//   +0x18 float   ArmorHP       (current combat HP -- shown as "durability")
//   +0x80 int32   ArmorLevel    (tier 1..N)
// NOTE: On Delta's live server the array is populated ONLY on the owning
// client (COND_OwnerOnly-style filter). Remote pawns publish a shell of
// this component whose array is empty (arrData=0, arrNum=0), so armour
// ESP currently works only for the local pawn (which the overlay hides
// via is_local anyway). Remote enemy armour requires either a reverse of
// UCharacterEquipComponent::Get3PArmorLevel_BS to find the replicated
// field, or an in-process hook on ClientNotifyEquipmentLvInfoFor3P.
// See docs/ARMOR_STATUS.txt for the full investigation.
static void read_armor_via_equipcomp(HANDLE hDev, u64 procCR3, u64 pawn,
                                      DH_SHMEM_PLAYER* p)
{
    // Cache the offset that first produced a valid FArmorInfo entry so we
    // do not re-probe every tick.
    #define AR_CACHE_SLOTS 128
    static struct { u64 pawn; u32 off; u8 valid; } s_cache[AR_CACHE_SLOTS] = {0};
    int hit_slot = -1, free_slot = -1;
    for (int i = 0; i < AR_CACHE_SLOTS; i++) {
        if (s_cache[i].pawn == pawn) { hit_slot = i; break; }
        if (free_slot < 0 && s_cache[i].pawn == 0) free_slot = i;
    }
    #undef AR_CACHE_SLOTS

    // Two encrypted candidate offsets — ADFMPlayerCharacter primary and
    // ADFMCharacter cache. Both mask to the same target on players; one
    // may work for sibling subclasses.
    static const u32 CAND[] = { 0x3960, 0x24E0 };
    u32 candStart = 0;
    int candCount = (int)(sizeof(CAND) / sizeof(CAND[0]));
    if (hit_slot >= 0 && s_cache[hit_slot].valid) {
        candStart = s_cache[hit_slot].off;
        candCount = 1;
    }

    for (int ci = 0; ci < candCount; ci++) {
        u32 poff = candCount == 1 ? candStart : CAND[ci];
        u64 raw = 0;
        if (!RpmRead64(hDev, procCR3, pawn + poff, &raw)) continue;
        u64 comp = raw & DF_ENC_PTR_MASK;
        if (comp < 0x100000) continue;

        // Path A (local pawn only) — FArmorInfo array at +0x1E8. Carries
        // both tier and current ArmorHP. Server-side COND_OwnerOnly
        // filter zeros this out for observers, so fall through to
        // Path B when we can't fill both slots here.
        u64 arrData = 0;
        i32 arrNum  = 0;
        int filled  = 0;
        if (RpmRead64(hDev, procCR3, comp + 0x1E8, &arrData) &&
            RpmReadVirtual(hDev, procCR3, comp + 0x1F0, &arrNum, 4) &&
            arrNum > 0 && arrNum <= 16 &&
            arrData >= 0x100000)
        {
            u8 buf[0x88];
            u8 tmp_h_tier = 0, tmp_a_tier = 0;
            float tmp_h_hp = 0, tmp_a_hp = 0;
            for (int i = 0; i < arrNum; i++) {
                if (!RpmReadVirtual(hDev, procCR3,
                                    arrData + (u64)i * 0x88ULL,
                                    buf, sizeof(buf))) continue;
                u8 kind  = buf[0x00];
                float hp = 0;   memcpy(&hp,  &buf[0x18], 4);
                i32 lvl  = 0;   memcpy(&lvl, &buf[0x80], 4);
                if (!(hp == hp)) hp = 0.0f;
                if (hp < 0.0f || hp > 100000.0f) hp = 0.0f;
                if (lvl < 0 || lvl > 15) lvl = 0;
                if (kind == 1 && lvl > 0) {
                    tmp_h_tier = (u8)lvl; tmp_h_hp = hp; filled++;
                } else if (kind == 5 && lvl > 0) {
                    tmp_a_tier = (u8)lvl; tmp_a_hp = hp; filled++;
                }
            }
            if (filled > 0) {
                p->helmet_tier       = tmp_h_tier;
                p->helmet_durability = tmp_h_hp;
                p->armor_tier        = tmp_a_tier;
                p->armor_durability  = tmp_a_hp;
                if (hit_slot < 0 && free_slot >= 0) {
                    s_cache[free_slot].pawn  = pawn;
                    s_cache[free_slot].off   = poff;
                    s_cache[free_slot].valid = 1;
                }
                return;
            }
        }

        // Path B (works for observers) —
        //   UCharacterEquipComponent::EquipmentInfoArray  // 0x01D8(0x10), Net+RepNotify
        //   TArray<FEquipmentInfo> with EEquipmentType-indexed 13 slots.
        //   Server replicates this to all clients.
        //
        // FEquipmentInfo layout (stride 0x30):
        //   +0x00 uint64 ItemID      unique per-item model (helmet variant)
        //   +0x08 uint64 Gid         per-instance guid
        //   +0x10 float  Health      RepSkip on observers -> 0
        //   +0x14 float  MaxHealth   RepSkip on observers -> 0
        //   +0x18 float  Durability
        //   +0x1C float  MaxDurability
        //
        // Slot 1 = Helmet, Slot 5 = BreastPlate. Tier is NOT in FEquipmentInfo,
        // but MaxDurability is a reliable proxy per Delta's tier ladder:
        //   Helmets  T1: dur<=10, T2: <=18, T3: <=28, T4: <=38, T5: <=50, T6+
        //   Plates   T1: <=18,    T2: <=28, T3: <=50, T4: <=75, T5: <=100, T6+
        u64 eArr = 0;
        i32 eNum = 0;
        if (RpmRead64(hDev, procCR3, comp + 0x01D8, &eArr) &&
            RpmReadVirtual(hDev, procCR3, comp + 0x01E0, &eNum, 4) &&
            eArr >= 0x100000 && eNum > 0 && eNum <= 16)
        {
            u8 tier_h = 0, tier_a = 0;
            float dur_h = 0, dur_a = 0;
            u64  iid_h = 0, iid_a = 0;
            for (int i = 0; i < eNum && i < 13; i++) {
                if (i != 1 && i != 5) continue;   // helmet / breastplate only
                u8 ei[0x20];
                if (!RpmReadVirtual(hDev, procCR3,
                                    eArr + (u64)i * 0x30ULL,
                                    ei, sizeof(ei))) continue;
                u64 itemid = 0;
                float dur = 0, mdur = 0;
                memcpy(&itemid, &ei[0x00], 8);
                memcpy(&dur,    &ei[0x18], 4);
                memcpy(&mdur,   &ei[0x1C], 4);
                if (itemid == 0 || !(mdur == mdur) || mdur <= 0.0f) continue;
                u8 tier = 0;
                if (i == 1) {  // Helmet
                    if      (mdur > 50.0f) tier = 6;
                    else if (mdur > 38.0f) tier = 5;
                    else if (mdur > 28.0f) tier = 4;
                    else if (mdur > 18.0f) tier = 3;
                    else if (mdur > 10.0f) tier = 2;
                    else                   tier = 1;
                    tier_h = tier; dur_h = dur; iid_h = itemid;
                } else {       // BreastPlate (slot 5)
                    if      (mdur > 100.0f) tier = 6;
                    else if (mdur > 75.0f)  tier = 5;
                    else if (mdur > 50.0f)  tier = 4;
                    else if (mdur > 28.0f)  tier = 3;
                    else if (mdur > 18.0f)  tier = 2;
                    else                    tier = 1;
                    tier_a = tier; dur_a = dur; iid_a = itemid;
                }
            }
            if (tier_h || tier_a) {
                p->helmet_tier       = tier_h;
                p->helmet_durability = dur_h;    // reuse durability slot for current dur
                p->armor_tier        = tier_a;
                p->armor_durability  = dur_a;
                #define EQTIER_LOG_SLOTS 128
                static u64 s_eqtier_logged[EQTIER_LOG_SLOTS] = {0};
                int already = 0, empty = -1;
                for (int j = 0; j < EQTIER_LOG_SLOTS; j++) {
                    if (s_eqtier_logged[j] == pawn) { already = 1; break; }
                    if (empty < 0 && s_eqtier_logged[j] == 0) empty = j;
                }
                if (!already && empty >= 0) {
                    s_eqtier_logged[empty] = pawn;
                    DH_INFO("EQTIER pawn=%llx H=T%u dur=%.1f iid=%llx | A=T%u dur=%.1f iid=%llx",
                            (unsigned long long)pawn,
                            (unsigned)tier_h, dur_h, (unsigned long long)iid_h,
                            (unsigned)tier_a, dur_a, (unsigned long long)iid_a);
                }
                #undef EQTIER_LOG_SLOTS
                if (hit_slot < 0 && free_slot >= 0) {
                    s_cache[free_slot].pawn  = pawn;
                    s_cache[free_slot].off   = poff;
                    s_cache[free_slot].valid = 1;
                }
                return;
            }
        }
    }
}

// Weapon readout — walks candidate offsets on pawn for AWeaponBase*.
// SDK-verified PC layout (2026-09-22 diff):
//   AWeaponBase + 0x0838 = WeaponID uint64 (plaintext)
//   AWeaponBase + 0x1238 = CachedAttributeSetWeaponAmmo (encrypted ptr)
//     AttrSet     + 0x0058 = ClipAmmoCount float
//
// pawn+0x0798 (WMC on AGPCharacter per SDK) is null on observers —
// Delta reordered pawn layout. Empirical scan showed pawn+0x2658
// yielded valid weapon on local pawn. Try a small set of candidates;
// filter by "wid fits in uint32 and non-zero" — real Delta WeaponIDs
// are small integers (~1..1B).
static void read_weapon_for_slot(HANDLE hDev, u64 procCR3, u64 pawn,
                                 DH_SHMEM_PLAYER* p)
{
    p->weapon_id      = 0;
    p->weapon_ammo    = 0.0f;
    p->weapon_name[0] = 0;
    if (!pawn || pawn < 0x100000) return;

    static const u32 W_CAND[] = { 0x2650, 0x2658, 0x2660, 0x2668, 0x2670, 0x2680, 0x2688 };
    const int W_N = (int)(sizeof(W_CAND)/sizeof(W_CAND[0]));

    for (int ci = 0; ci < W_N; ci++) {
        u64 wRaw = 0;
        if (!RpmRead64(hDev, procCR3, pawn + W_CAND[ci], &wRaw)) continue;
        u64 weapon = wRaw & DF_ENC_PTR_MASK;
        if (weapon < 0x100000 || weapon >= 0x1000000000000ULL) continue;

        u64 wid = 0;
        if (!RpmRead64(hDev, procCR3, weapon + 0x0838, &wid)) continue;
        // Sanity: Delta WeaponIDs fit in uint32 and are non-zero.
        if (wid == 0 || wid > 0x00000000FFFFFFFFULL) continue;

        // Ammo — best effort. AttrSet is encrypted ptr; on observers may be null.
        float ammo = 0.0f;
        u64 attrRaw = 0;
        if (RpmRead64(hDev, procCR3, weapon + 0x1238, &attrRaw)) {
            u64 attr = attrRaw & DF_ENC_PTR_MASK;
            if (attr >= 0x100000 && attr < 0x1000000000000ULL) {
                float a = 0.0f;
                if (RpmReadVirtual(hDev, procCR3, attr + 0x0058, &a, 4) &&
                    a == a && a >= 0.0f && a <= 10000.0f) ammo = a;
            }
        }

        p->weapon_id   = wid;
        p->weapon_ammo = ammo;

        #define WHIT_SLOTS 128
        static u64 s_whit_logged[WHIT_SLOTS] = {0};
        int already = 0, empty = -1;
        for (int j = 0; j < WHIT_SLOTS; j++) {
            if (s_whit_logged[j] == pawn) { already = 1; break; }
            if (empty < 0 && s_whit_logged[j] == 0) empty = j;
        }
        if (!already && empty >= 0) {
            s_whit_logged[empty] = pawn;
            DH_INFO("WHIT pawn=%llx off=%04X w=%llx wid=%llu ammo=%.1f",
                    (unsigned long long)pawn, W_CAND[ci],
                    (unsigned long long)weapon,
                    (unsigned long long)wid, ammo);
        }
        #undef WHIT_SLOTS
        return;
    }
}

static void read_equipment_for_slot(HANDLE hDev, u64 procCR3, u64 pawn,
                                    DH_SHMEM_PLAYER* p)
{
    if (!p) return;
    p->helmet_tier = 0; p->helmet_durability = 0.0f;
    p->armor_tier  = 0; p->armor_durability  = 0.0f;
    if (!pawn || pawn < 0x100000) return;
    read_armor_via_equipcomp(hDev, procCR3, pawn, p);
    read_weapon_for_slot(hDev, procCR3, pawn, p);
}


static void poll_and_publish(HANDLE hDev, u64 procCR3, u64 base)
{
    DH_SHMEM local;
    memset(&local, 0, sizeof(local));
    local.magic = DH_SHMEM_MAGIC;
    local.fov = 90.f;
    local.myTeam = -1;

    // Per-slot pawn+root tracking for cam-thread fast-track. Populated as
    // we build local.players[]. Passed to g_fast_track at publish time.
    static u64 local_pawn_track[DH_MAX_PLAYERS] = {0};
    static u64 local_root_track[DH_MAX_PLAYERS] = {0};
    memset(local_pawn_track, 0, sizeof(local_pawn_track));
    memset(local_root_track, 0, sizeof(local_root_track));

    u64 uworld = 0;
    RpmRead64(hDev, procCR3, base + DF_RVA_GWORLD, &uworld);
    if (!uworld) goto commit;

    u64 gsRaw = 0;
    RpmRead64(hDev, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
    u64 gameState = gsRaw & DF_ENC_PTR_MASK;
    if (!gameState || gameState < 0x100000) goto commit;

    // --- Local-pawn discovery via GameInstance chain ----------------------
    // Old logic marked local from FEncryptedObjectProperty.Index==0xFFFF
    // sentinel, but Delta uses that sentinel for EVERY entity whose
    // RelativeLocation is server-authorised as plaintext — teammates near
    // you included. Result: 2/3 teammates flagged is_local=1 and dropped
    // by overlay's `if (!e.valid || e.local) continue;`.
    //
    // Chain (offsets from Dumper-7 2026-09-20 SDK):
    //   UWorld       + 0x190  = OwningGameInstance (encrypted)
    //   UGameInstance+ 0x38   = LocalPlayers TArray<ULocalPlayer*>
    //   ULocalPlayer + 0x30   = PlayerController (from UPlayer, plaintext)
    //   APlayerCtrl  + 0x3F0  = AcknowledgedPawn (FEncryptedObjectProperty)
    // Cache 500ms — chain is stable within a session, walking it every
    // tick would burn 4 RPMs a lot faster than needed.
    static u64 s_local_pawn = 0;
    static u64 s_local_pawn_ms = 0;
    u64 now_lp = GetTickCount64();
    if (s_local_pawn == 0 || (now_lp - s_local_pawn_ms) > 500) {
        u64 giRaw = 0;
        RpmRead64(hDev, procCR3, uworld + DF_WORLD_OWNINGGAMEINST, &giRaw);
        u64 gi = giRaw & DF_ENC_PTR_MASK;
        if (gi >= 0x100000) {
            u64 lpArr = 0; i32 lpNum = 0;
            RpmRead64(hDev, procCR3, gi + 0x38, &lpArr);
            RpmReadVirtual(hDev, procCR3, gi + 0x40, &lpNum, 4);
            if (lpArr && lpNum > 0) {
                u64 lp = 0;
                RpmRead64(hDev, procCR3, lpArr, &lp);
                if (lp >= 0x100000) {
                    u64 pc = 0;
                    RpmRead64(hDev, procCR3, lp + 0x30, &pc);
                    if (pc >= 0x100000) {
                        u64 pawnRaw = 0;
                        RpmRead64(hDev, procCR3, pc + 0x3F0, &pawnRaw);
                        u64 lpawn = pawnRaw & DF_ENC_PTR_MASK;
                        if (lpawn >= 0x100000) {
                            s_local_pawn = lpawn;
                            s_local_pawn_ms = now_lp;
                        }
                    }
                }
            }
        }
    }

    // SKELETON REMOVED 2026-09-26 — one-shot bone dump kept under #if 0 below
    // for reference; static s_bones_dumped no longer required.
#if 0
    if (!s_bones_dumped && s_local_pawn != 0) {
        // Delta UObject REORDERED (see sdk\GOLDEN_OFFSETS.md):
        //   +0x00 VTable   +0x08 Class   +0x10 Outer
        //   +0x18 Flags    +0x1C Name(FName 0x8)   +0x24 Index
        u64 classPtrRaw = 0;
        RpmRead64(hDev, procCR3, s_local_pawn + 0x08, &classPtrRaw);
        u64 classPtr = classPtrRaw & DF_ENC_PTR_MASK;
        char cnBuf[96] = {0};
        if (classPtr >= 0x100000) {
            u32 cn_idx = 0;
            RpmReadVirtual(hDev, procCR3, classPtr + 0x1C, &cn_idx, 4);
            u64 gNamesVA0 = base + DF_RVA_GNAMES;
            RpmResolveFName(hDev, procCR3, gNamesVA0, cn_idx, cnBuf, sizeof(cnBuf));
        }
        // Hex dump [0x3C0..0x3F8) so we see what actually lives near
        // ACharacter.Mesh/CharacterMovement/CapsuleComponent slots.
        u8 pawnDump[0x40] = {0};
        RpmReadVirtual(hDev, procCR3, s_local_pawn + 0x3C0, pawnDump, sizeof(pawnDump));
        DH_INFO("== pawn=%llx class='%s' rawClassPtr=%llx ==",
                (unsigned long long)s_local_pawn, cnBuf,
                (unsigned long long)classPtrRaw);
        for (int r = 0; r < 4; r++) {
            DH_INFO("  pawn+0x%03X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    0x3C0 + r*16,
                    pawnDump[r*16+0], pawnDump[r*16+1], pawnDump[r*16+2], pawnDump[r*16+3],
                    pawnDump[r*16+4], pawnDump[r*16+5], pawnDump[r*16+6], pawnDump[r*16+7],
                    pawnDump[r*16+8], pawnDump[r*16+9], pawnDump[r*16+10], pawnDump[r*16+11],
                    pawnDump[r*16+12], pawnDump[r*16+13], pawnDump[r*16+14], pawnDump[r*16+15]);
        }
        // Try both pawn+0x3D0 (ACharacter.Mesh) and ACharacterBase.AllMesh
        // TArray @ 0xAB8[0] which Delta may prefer for TPP body.
        u64 meshRaw = 0;
        RpmRead64(hDev, procCR3, s_local_pawn + 0x3D0, &meshRaw);
        u64 meshD = meshRaw & DF_ENC_PTR_MASK;
        u64 allMeshData = 0; i32 allMeshNum = 0;
        RpmRead64(hDev, procCR3, s_local_pawn + 0xAB8, &allMeshData);
        RpmReadVirtual(hDev, procCR3, s_local_pawn + 0xAC0, &allMeshNum, 4);
        DH_INFO("== raw pawn+0x3D0=%llx  AllMesh(0xAB8) data=%llx num=%d ==",
                (unsigned long long)meshRaw,
                (unsigned long long)allMeshData, (int)allMeshNum);
        // Prefer AllMesh[0] when available — Delta usually puts the main
        // skeletal body there while pawn+0x3D0 can be a first-person clone.
        if (allMeshData >= 0x100000 && allMeshNum > 0) {
            u64 mainMesh = 0;
            RpmRead64(hDev, procCR3, allMeshData, &mainMesh);
            DH_INFO("== AllMesh[0] = %llx ==", (unsigned long long)mainMesh);
            if (mainMesh >= 0x100000) meshD = mainMesh;
        }
        s_bones_dumped = 1;  // one-shot regardless of chain success
        if (meshD >= 0x100000) {
            // Hex dump mesh+0x700..0x740 to locate SkeletalMesh field
            u8 mDump[0x60] = {0};
            RpmReadVirtual(hDev, procCR3, meshD + 0x700, mDump, sizeof(mDump));
            for (int r = 0; r < (int)(sizeof(mDump)/16); r++) {
                DH_INFO("  mesh+0x%03X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                        0x700 + r*16,
                        mDump[r*16+0], mDump[r*16+1], mDump[r*16+2], mDump[r*16+3],
                        mDump[r*16+4], mDump[r*16+5], mDump[r*16+6], mDump[r*16+7],
                        mDump[r*16+8], mDump[r*16+9], mDump[r*16+10], mDump[r*16+11],
                        mDump[r*16+12], mDump[r*16+13], mDump[r*16+14], mDump[r*16+15]);
            }
            u64 skmesh = 0;
            RpmRead64(hDev, procCR3, meshD + 0x728, &skmesh);
            DH_INFO("== raw mesh+0x728 skmesh=%llx ==", (unsigned long long)skmesh);
            if (skmesh >= 0x100000) {
                // Dump USkeletalMesh 0x180..0x2C0 to find RefSkeleton
                // (non-UPROPERTY, offset unknown). Look for a TArray
                // pattern: valid data ptr + Num == expected bone count.
                u8 smDump[0x140] = {0};
                RpmReadVirtual(hDev, procCR3, skmesh + 0x180, smDump, sizeof(smDump));
                for (int r = 0; r < 0x140/16; r++) {
                    DH_INFO("  skmesh+0x%03X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                            0x180 + r*16,
                            smDump[r*16+0], smDump[r*16+1], smDump[r*16+2], smDump[r*16+3],
                            smDump[r*16+4], smDump[r*16+5], smDump[r*16+6], smDump[r*16+7],
                            smDump[r*16+8], smDump[r*16+9], smDump[r*16+10], smDump[r*16+11],
                            smDump[r*16+12], smDump[r*16+13], smDump[r*16+14], smDump[r*16+15]);
                }
                // FReferenceSkeleton embedded in USkeletalMesh; layout
                // deduced from hex dump: RawRefBoneInfo TArray at +0x1A8
                //   Data @ +0x1A8, Num @ +0x1B0, Max @ +0x1B4
                //   FinalRefBoneInfo (with virtual bones) @ +0x1C8
                u64 refBoneData = 0;
                i32 refBoneNum  = 0;
                RpmRead64(hDev, procCR3, skmesh + 0x1A8, &refBoneData);
                RpmReadVirtual(hDev, procCR3, skmesh + 0x1B0, &refBoneNum, 4);
                DH_INFO("== SKELETON BONE DUMP: mesh=%llx skmesh=%llx refBoneData=%llx num=%d ==",
                        (unsigned long long)meshD, (unsigned long long)skmesh,
                        (unsigned long long)refBoneData, (int)refBoneNum);
                if (refBoneNum > 200) refBoneNum = 200;
                u64 gNamesVA = base + DF_RVA_GNAMES;
                // Try both entry-strides 0x10 and 0x14 by printing first
                // 4 entries at each. Whichever yields valid FNames wins.
                for (int stride_test = 0; stride_test < 2; stride_test++) {
                    u32 stride = stride_test == 0 ? 0x10 : 0x14;
                    DH_INFO("  -- probing stride 0x%X --", stride);
                    for (int bi = 0; bi < 4 && bi < refBoneNum; bi++) {
                        u32 fname_idx = 0, fname_num = 0;
                        i32 parentIdx = 0;
                        RpmReadVirtual(hDev, procCR3, refBoneData + (u64)bi*stride,     &fname_idx, 4);
                        RpmReadVirtual(hDev, procCR3, refBoneData + (u64)bi*stride + 4, &fname_num, 4);
                        RpmReadVirtual(hDev, procCR3, refBoneData + (u64)bi*stride + 8, &parentIdx, 4);
                        char nameBuf[64] = {0};
                        RpmResolveFName(hDev, procCR3, gNamesVA, fname_idx, nameBuf, sizeof(nameBuf));
                        DH_INFO("    [%d] fname_idx=%u num=%u parent=%d name='%s'",
                                bi, fname_idx, fname_num, (int)parentIdx, nameBuf);
                    }
                }
                // Full dump — stride 0x10 (standard shipping build)
                for (int bi = 0; bi < refBoneNum; bi++) {
                    u32 fname_idx = 0, fname_num = 0;
                    i32 parentIdx = 0;
                    RpmReadVirtual(hDev, procCR3, refBoneData + bi*0x10,     &fname_idx, 4);
                    RpmReadVirtual(hDev, procCR3, refBoneData + bi*0x10 + 4, &fname_num, 4);
                    RpmReadVirtual(hDev, procCR3, refBoneData + bi*0x10 + 8, &parentIdx, 4);
                    char nameBuf[64] = {0};
                    RpmResolveFName(hDev, procCR3, gNamesVA, fname_idx, nameBuf, sizeof(nameBuf));
                    DH_INFO("  [%3d] parent=%3d idx=%u num=%u name='%s'",
                            bi, (int)parentIdx, fname_idx, fname_num, nameBuf);
                }
            }
        }
    }
#endif

    u64 psArr = 0; i32 psNum = 0;
    RpmRead64(hDev, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
    RpmReadVirtual(hDev, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
    if (psNum > DH_MAX_PLAYERS) psNum = DH_MAX_PLAYERS;
    if (psNum <= 0) goto commit;

    int cnt = 0;
    int haveMy = 0;

    // Per-PS cache: name/team/isBot/pawn/root/isLocal are stable per session.
    // Refresh full every 1000ms; per-tick only re-read mutable fields (bDead).
    typedef struct {
        u64      ps;           // key
        u64      pawn;         // stable while pawn alive
        u64      root;         // stable while root alive
        wchar_t  wname[32];
        i32      teamID;
        u8       isBot;
        u8       isLocal;      // relEnc.EncHandler.Index == 0xFFFF sentinel
        u64      last_refresh_ms;
    } PSCache;
    #define PSCACHE_SIZE 128
    static PSCache s_pscache[PSCACHE_SIZE] = {0};

    u64 now_tick = GetTickCount64();

    for (i32 pi = 0; pi < psNum && cnt < DH_MAX_PLAYERS; pi++) {
        u64 ps = 0;
        RpmRead64(hDev, procCR3, psArr + (u64)pi * 8, &ps);
        if (!ps) continue;

        // Find/allocate cache slot for this ps pointer
        PSCache* pc = NULL;
        for (int c = 0; c < PSCACHE_SIZE; c++) {
            if (s_pscache[c].ps == ps) { pc = &s_pscache[c]; break; }
        }
        if (!pc) {
            for (int c = 0; c < PSCACHE_SIZE; c++) {
                if (s_pscache[c].ps == 0 || (now_tick - s_pscache[c].last_refresh_ms) > 5000) {
                    pc = &s_pscache[c];
                    memset(pc, 0, sizeof(*pc));
                    pc->ps = ps;
                    break;
                }
            }
        }

        u64 pawn = 0;
        u64 root = 0;
        wchar_t wname[32] = {0};
        i32 teamID = 0;
        int isBot = 0;

        // Refresh cache if empty or older than 1 sec
        if (!pc || pc->pawn == 0 || (now_tick - pc->last_refresh_ms) > 1000) {
            RpmRead64(hDev, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
            if (!pawn) continue;
            RpmReadVirtual(hDev, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
            u64 rootRaw = 0;
            RpmRead64(hDev, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
            root = rootRaw & DF_ENC_PTR_MASK;
            if (!root || root < 0x100000) continue;
            // Bot detection — verified via Dumper-7 2026-09-20 SDK:
            //   pawn + 0xE5F  = AGPCharacterBase.bIsAILab
            //   ps   + 0x519  = AGPPlayerState.bIsAILabAI
            //   ps   + 0x518  = AGPPlayerState.bIsPlayerAI
            // Any bit set → mark as bot. Removed pawn+0x2A9 guess — it read
            // junk from an unrelated struct byte and mis-flagged teammates
            // as bots, dropping them out of the Players group entirely.
            u8 aiA = 0, aiB = 0, aiC = 0;
            RpmReadVirtual(hDev, procCR3, pawn + 0xE5F, &aiA, 1);
            RpmReadVirtual(hDev, procCR3, ps + 0x519,   &aiB, 1);
            RpmReadVirtual(hDev, procCR3, ps + 0x518,   &aiC, 1);
            isBot = (aiA || aiB || aiC) ? 1 : 0;

            u64 nameData = 0; i32 nameLen = 0;
            RpmRead64(hDev, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
            RpmReadVirtual(hDev, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
            if (nameData && nameLen > 0 && nameLen < 31)
                RpmReadVirtual(hDev, procCR3, nameData, wname, nameLen * 2);

            // is_local: match pawn against the pawn we resolved via
            // GameInstance→LocalPlayer[0]→PlayerController→AcknowledgedPawn.
            // Sentinel Index==0xFFFF was unreliable (fires for teammates in
            // the same relevance group too).
            u8 is_local_now = (s_local_pawn != 0 && pawn == s_local_pawn) ? 1 : 0;

            if (pc) {
                pc->pawn = pawn; pc->root = root;
                pc->teamID = teamID; pc->isBot = (u8)isBot;
                pc->isLocal = is_local_now;
                memcpy(pc->wname, wname, sizeof(wname));
                pc->last_refresh_ms = now_tick;
            }
        } else {
            // Use cached stable fields — saves 6 RPMs per pawn per tick
            pawn = pc->pawn;
            root = pc->root;
            teamID = pc->teamID;
            isBot = pc->isBot;
            memcpy(wname, pc->wname, sizeof(wname));
        }

        // Mutable field: bDead — 1 RPM per tick (fast path)
        u8 psDead = 0;
        RpmReadVirtual(hDev, procCR3, ps + DF_GPPS_BDEAD, &psDead, 1);
        int isDead = psDead ? 1 : 0;

        // ★ CHUNK-READ upfront: one 8KB RPM covers all direct pawn fields.
        // Later code extracts values from this buffer instead of many small
        // RPMs. Cuts per-pawn IOCTL count 10x.
        static u8 pawn_chunk[0x2000];
        int have_chunk = RpmReadVirtual(hDev, procCR3, pawn, pawn_chunk,
                                         sizeof(pawn_chunk));

        // For local player only: re-read relEnc every tick to get live coords
        // (Index=0xFFFF sentinel → RelativeLocation is plaintext for our own actor).
        // Non-local players skip this read (saves 1 RPM per pawn).
        DH_ENC_VECTOR relEnc = {0};
        u8 is_local = pc ? pc->isLocal : 0;
        if (is_local) {
            if (!RpmReadVirtual(hDev, procCR3, root + 0x168, &relEnc, sizeof(relEnc))) continue;
        }

        float px = 0, py = 0, pz = 0;
        int gotPos = 0, isLocal = 0;
        if (is_local) {
            // Local player — RelativeLocation plaintext (Index=0xFFFF sentinel).
            px = relEnc.X; py = relEnc.Y; pz = relEnc.Z;
            gotPos = 1; isLocal = 1;
            if (local.myTeam < 0) local.myTeam = teamID;
        } else {
            // ★★★ PRODUCTION DECRYPT ★★★
            // Source: pawn + 0x1D10 = LastFrameWorldPosition (FEncVector).
            // Key: DeriveKey walks Delta's LOOKUP+0x278 → key_obj → linked-list.
            // Cipher: VTBL_DECRYPT_120 shellcode (Feistel-20) called locally.
            //
            // Per-Handler.Index position cache smooths the ~10% frames where
            // decrypt fails (stale key_obj / RPM inconsistency). If decrypt
            // fails this tick, we use last-good-position up to 500 ms old.
            static struct { float x, y, z; u64 last_ok_ms; } s_poscache[0x2000] = {0};

            DH_ENC_VECTOR worldEnc = {0};
            int decrypt_ok = 0;
            float dx = 0, dy = 0, dz = 0;
            u16 idx = 0;

            // Read worldEnc from chunk if available (saves 1 RPM).
            int have_enc = 0;
            if (have_chunk) {
                memcpy(&worldEnc, (const void*)(pawn_chunk + 0x1D10), sizeof(worldEnc));
                have_enc = 1;
            } else {
                have_enc = RpmReadVirtual(hDev, procCR3, pawn + 0x1D10, &worldEnc, sizeof(worldEnc));
            }
            if (have_enc) idx = worldEnc.EncHandler.Index;

            // Fast plaintext path — teammates & non-relevanted actors have
            // Index == 0xFFFF, meaning LastFrameWorldPosition.{X,Y,Z} are
            // literal floats and MUST NOT be run through VTBL_DECRYPT
            // (Feistel over plaintext = garbage). This is why teammates
            // came out as either zero-position or nonsense before.
            if (have_enc && worldEnc.EncHandler.Index == 0xFFFF) {
                dx = worldEnc.X; dy = worldEnc.Y; dz = worldEnc.Z;
                if (dx == dx && dy == dy && dz == dz &&
                    fabsf(dx) < 200000.f && fabsf(dy) < 200000.f && fabsf(dz) < 20000.f &&
                    (fabsf(dx) + fabsf(dy)) > 10.f) {
                    decrypt_ok = 1;
                }
            }
            else if (have_enc && g_vtbl_ready) {
                // Decrypt cache — per-Handler.Index cache of (input16, output12).
                // If raw encrypted bytes match last-seen for this idx, skip
                // the expensive shellcode call. Positions rarely change more
                // than 1-2 units per tick when stationary → high hit rate.
                static struct {
                    u8   in16[16];
                    float ox, oy, oz;
                    u8   valid;
                } s_dec_cache[0x2000] = {0};

                if (idx < 0x2000 && s_dec_cache[idx].valid &&
                    memcmp(s_dec_cache[idx].in16, &worldEnc, 16) == 0)
                {
                    dx = s_dec_cache[idx].ox;
                    dy = s_dec_cache[idx].oy;
                    dz = s_dec_cache[idx].oz;
                    if (dx == dx && dy == dy && dz == dz &&
                        fabsf(dx) < 200000.f && fabsf(dy) < 200000.f && fabsf(dz) < 20000.f &&
                        (fabsf(dx) + fabsf(dy)) > 10.f) {
                        decrypt_ok = 1;
                    }
                }
                if (!decrypt_ok) {
                    u64 key = 0;
                    if (DeriveKey(hDev, procCR3, idx, &key)) {
                        __declspec(align(16)) u8 fv_in[16];
                        __declspec(align(16)) u8 fv_out[16];
                        memcpy(fv_in, &worldEnc, 16);
                        memset(fv_out, 0, 16);
                        CallVtblDecryptSpray(GetVtblShellcode(), fv_in, 0, key, fv_out);
                        memcpy(&dx, fv_out+0, 4);
                        memcpy(&dy, fv_out+4, 4);
                        memcpy(&dz, fv_out+8, 4);
                        if (dx == dx && dy == dy && dz == dz &&
                            fabsf(dx) < 200000.f && fabsf(dy) < 200000.f && fabsf(dz) < 20000.f &&
                            (fabsf(dx) + fabsf(dy)) > 10.f) {
                            decrypt_ok = 1;
                            if (idx < 0x2000) {
                                memcpy(s_dec_cache[idx].in16, &worldEnc, 16);
                                s_dec_cache[idx].ox = dx;
                                s_dec_cache[idx].oy = dy;
                                s_dec_cache[idx].oz = dz;
                                s_dec_cache[idx].valid = 1;
                            }
                        }
                    }
                }
            }

            u64 now_ms = GetTickCount64();
            if (decrypt_ok) {
                px = dx; py = dy; pz = dz; gotPos = 1;
                if (idx < 0x2000) {
                    s_poscache[idx].x = dx;
                    s_poscache[idx].y = dy;
                    s_poscache[idx].z = dz;
                    s_poscache[idx].last_ok_ms = now_ms;
                }
            } else if (idx > 0 && idx < 0x2000 &&
                       s_poscache[idx].last_ok_ms != 0 &&
                       (now_ms - s_poscache[idx].last_ok_ms) < 500) {
                // Fresh cached position — smooth over transient decrypt fail
                px = s_poscache[idx].x;
                py = s_poscache[idx].y;
                pz = s_poscache[idx].z;
                gotPos = 1;
            }

            // Last-resort fallback: pawn+0x1C2C (LastCrouchLocation, stale)
            if (!gotPos) {
                float grx = 0, gry = 0, grz = 0;
                if (RpmReadVirtual(hDev, procCR3, pawn + 0x1C2C, &grx, 4) &&
                    RpmReadVirtual(hDev, procCR3, pawn + 0x1C30, &gry, 4) &&
                    RpmReadVirtual(hDev, procCR3, pawn + 0x1C34, &grz, 4) &&
                    grx == grx && gry == gry && grz == grz &&
                    fabsf(grx) < 100000.f && fabsf(gry) < 100000.f && fabsf(grz) < 10000.f &&
                    (fabsf(grx) + fabsf(gry)) > 10.f) {
                    px = grx; py = gry; pz = grz; gotPos = 1;
                }
            }
        }
        if (!gotPos) continue;
        (void)root;

        // Distance sanity vs local player — decrypt garbage passes the
        // absolute-bounds filter (fits in +/-200000) but lands 10-100+ km
        // away from us, producing the "boxes miss" bug when uc_ready=0 and
        // the VTBL Feistel fallback returns a plausible-but-wrong point.
        // Delta maps top out ~4-5 km wide → anything > 6000 m from local
        // player position is decrypt-broken garbage, skip.
        //
        // Skip check for local + when we don't yet have our own position
        // (first frames until haveMy is set).
        if (!isLocal && g_shmem->myX != 0.0f && g_shmem->myY != 0.0f) {
            float _dxm = px - g_shmem->myX;
            float _dym = py - g_shmem->myY;
            float _dzm = pz - g_shmem->myZ;
            float _dist2 = _dxm*_dxm + _dym*_dym + _dzm*_dzm;
            // 6000m in Delta units (1 unit = 1 cm) = 600000 cm; squared = 3.6e11
            if (_dist2 > 3.6e11f) continue;
        }

        // SKELETON REMOVED 2026-09-26 — was one-shot mesh/refBoneInfo dump
        // + g_bone_parents init. No longer needed since bones are cut.

#if 0
        // Retained but disabled: candidate-slot scan used during offset hunt.
        {
            // Enemy: try multiple LIVE-updated sources in priority order.
            // Mesh.CTW.Translation is written every render frame for skinning,
            // so it moves with the character. Root.CTW at +0x220 might be
            // encrypted-mirror of RelLoc. pawn+0x1C2C often static (spawn).
            struct { u64 base; u32 off; const char* tag; } cands[8] = {0};
            int cn = 0;

            // FRepMovement layout in UE4.24: LinearVelocity(0x0)+AngVel(0xC)+
            // Location(0x18)+Rotation(0x24). Our earlier scan showed pawn+0x1C2C
            // has FVector-like data → that's LinearVelocity slot. Location =
            // pawn+0x1C2C + 0x18 = pawn+0x1C44.
            cands[cn].base = pawn; cands[cn].off = 0x1C44; cands[cn].tag = "rep.Loc";  cn++;
            cands[cn].base = pawn; cands[cn].off = 0x1C50; cands[cn].tag = "rep.Rot";  cn++;

            u64 meshRaw = 0;
            RpmRead64(hDev, procCR3, pawn + 0x3D0, &meshRaw);
            u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
            if (mesh && mesh >= 0x100000) {
                cands[cn].base = mesh; cands[cn].off = 0x220; cands[cn].tag = "mesh+220"; cn++;
                cands[cn].base = mesh; cands[cn].off = 0x168; cands[cn].tag = "mesh+168"; cn++;
            }
            // Fallback slots
            cands[cn].base = pawn; cands[cn].off = 0x1C2C; cands[cn].tag = "pawn+1C2C"; cn++;
            cands[cn].base = pawn; cands[cn].off = 0x1C38; cands[cn].tag = "pawn+1C38"; cn++;
            cands[cn].base = root; cands[cn].off = 0x220; cands[cn].tag = "root+220";  cn++;

            for (int c = 0; c < cn; c++) {
                float x, y, z;
                if (!RpmReadVirtual(hDev, procCR3, cands[c].base + cands[c].off, &x, 4)) continue;
                if (!RpmReadVirtual(hDev, procCR3, cands[c].base + cands[c].off + 4, &y, 4)) continue;
                if (!RpmReadVirtual(hDev, procCR3, cands[c].base + cands[c].off + 8, &z, 4)) continue;
                if (x != x || y != y || z != z) continue;
                if (fabsf(x) < 500.f && fabsf(y) < 500.f) continue;
                if (fabsf(x) > 100000.f || fabsf(y) > 100000.f) continue;
                if (fabsf(z) > 10000.f) continue;
                if (fabsf(fabsf(y) - fabsf(z)) < 5.f) continue;
                px = x; py = y; pz = z; gotPos = 1;
                break;
            }
        }
#endif
        // Per-pawn velocity tracker (shared with bot Phase A below).
        float vxr = 0, vyr = 0, vzr = 0;
        u64 now_v_ms = compute_velocity(pawn, px, py, pz, &vxr, &vyr, &vzr);

        // Chunk read moved to top of pawn iteration — extract direct fields here.
        u64  root_enc  = have_chunk ? *(u64*)(pawn_chunk + 0x180)  : 0;
        u64  mesh_enc  = have_chunk ? *(u64*)(pawn_chunk + 0x3D0)  : 0;
        u8   dbg_c     = have_chunk ? *(pawn_chunk + 0x480)         : 0;
        i32  dbg_p     = have_chunk ? *(i32*)(pawn_chunk + 0x7A0)  : 0;
        float rr_v     = have_chunk ? *(float*)(pawn_chunk + 0xE64): 0.0f;
        float hh_base  = have_chunk ? *(float*)(pawn_chunk + 0xE68): 0.0f;
        u8   dbg_pose  = have_chunk ? *(pawn_chunk + 0x1B48)        : 0;

        float cap_hh = 88.0f, cap_r = 34.0f;
        if (hh_base == hh_base && hh_base > 20.0f && hh_base < 200.0f)
            cap_hh = hh_base;
        if (rr_v == rr_v && rr_v > 8.0f && rr_v < 120.0f)
            cap_r = rr_v;
        if (dbg_pose == 3)      cap_hh *= 0.35f;
        else if (dbg_pose == 2) cap_hh *= 0.55f;

        // Live status still comes from PlayerState (separate object).
        i32 live_status = 0;
        RpmReadVirtual(hDev, procCR3, ps + 0x94C, &live_status, 4);
        if (live_status == 3) cap_hh = (cap_hh < 30.0f) ? cap_hh : 30.0f;
        if (live_status == 2) cap_hh = (cap_hh < 22.0f) ? cap_hh : 22.0f;

        float dbg_cap_root = 0.0f;
        float dbg_mesh_rel_z = 0.0f;
        // COMPONENT PTR CACHE — root/mesh/HC/HS stable per pawn lifetime.
        // Cache in LRU keyed by pawn ptr. Saves 3-4 IOCTLs per pawn per tick.
        static struct {
            u64 pawn;
            u64 root_va;    // decrypted root ptr
            u64 mesh_va;    // decrypted mesh ptr
            u64 hc_va;      // health comp ptr (already in chunk, but cache anyway)
            u64 hs_va;      // AttributeSet ptr (follow HC+0x280 — this is what matters)
            u64 last_ts;
        } s_comp_cache[256] = {0};
        int ch = -1, clru = 0;
        u64 clru_ts = ~0ULL;
        for (int j = 0; j < 256; j++) {
            if (s_comp_cache[j].pawn == pawn) { ch = j; break; }
            if (s_comp_cache[j].last_ts < clru_ts) {
                clru_ts = s_comp_cache[j].last_ts; clru = j;
            }
        }
        int cs = ch >= 0 ? ch : clru;
        u64 now_cc = GetTickCount64();
        // Refresh pointer cache every 5 sec — Delta may reallocate components
        // (respawn/replacement). Stale ptr → garbage HP → flicker.
        int cache_stale = ch < 0 ||
                          (now_cc - s_comp_cache[cs].last_ts) > 5000;
        if (cache_stale) {
            s_comp_cache[cs].pawn = pawn;
            s_comp_cache[cs].root_va = root_enc & DF_ENC_PTR_MASK;
            s_comp_cache[cs].mesh_va = mesh_enc & DF_ENC_PTR_MASK;
            s_comp_cache[cs].hc_va = 0;
            s_comp_cache[cs].hs_va = 0;   // re-resolve HP chain
        }
        s_comp_cache[cs].last_ts = now_cc;
        u64 rootD_cached = s_comp_cache[cs].root_va;
        u64 meshD_cached = s_comp_cache[cs].mesh_va;

        // Cap_hh + mesh_z change slowly (crouch/stand transitions) — 10Hz
        // per-pawn cache saves 2 RPMs per pawn per tick.
        static struct {
            u64  pawn;
            u64  refresh_ms;
            float cap_hh;
            float mesh_z;
            float yaw;      // root.RelativeRotation.Yaw (deg)
        } s_slow_cache[512] = {0};
        int sh = -1, slru = 0; u64 slru_ts = ~0ULL;
        for (int j = 0; j < 512; j++) {
            if (s_slow_cache[j].pawn == pawn) { sh = j; break; }
            if (s_slow_cache[j].refresh_ms < slru_ts) {
                slru_ts = s_slow_cache[j].refresh_ms; slru = j;
            }
        }
        int ss = sh >= 0 ? sh : slru;
        if (sh < 0) {
            s_slow_cache[ss].pawn = pawn;
            s_slow_cache[ss].refresh_ms = 0;
            s_slow_cache[ss].cap_hh = 0;
            s_slow_cache[ss].mesh_z = 0;
        }
        u64 sc_now = GetTickCount64();
        if (sc_now - s_slow_cache[ss].refresh_ms >= 100) {
            if (rootD_cached >= 0x100000) {
                float hh = 0;
                if (RpmReadVirtual(hDev, procCR3, rootD_cached + 0x5D0, &hh, 4) &&
                    hh == hh && hh > 5.0f && hh < 300.0f)
                    s_slow_cache[ss].cap_hh = hh;
                // Root+0x178 FRotator (Pitch,Yaw,Roll) — grab Yaw @ +0x17C
                float yv = 0;
                if (RpmReadVirtual(hDev, procCR3, rootD_cached + 0x17C, &yv, 4) &&
                    yv == yv && yv > -720.0f && yv < 720.0f)
                    s_slow_cache[ss].yaw = yv;
            }
            if (meshD_cached >= 0x100000) {
                float rz = 0;
                if (RpmReadVirtual(hDev, procCR3, meshD_cached + 0x11C + 8, &rz, 4) &&
                    rz == rz && fabsf(rz) < 500.0f)
                    s_slow_cache[ss].mesh_z = rz;
            }
            s_slow_cache[ss].refresh_ms = sc_now;
        }
        dbg_cap_root  = s_slow_cache[ss].cap_hh;
        dbg_mesh_rel_z = s_slow_cache[ss].mesh_z;
        float pawn_yaw = s_slow_cache[ss].yaw;

        // HP chain — with HS pointer cache per pawn lifetime.
        // Saves 1 RPM per pawn per tick (HC→HS lookup).
        float hp_cur = 0.0f, hp_max_v = 0.0f;
        {
            u64 hs = s_comp_cache[cs].hs_va;
            if (hs == 0) {
                u64 hcRaw = have_chunk ? *(u64*)(pawn_chunk + 0x10B8) : 0;
                u64 hc = hcRaw & DF_ENC_PTR_MASK;
                s_comp_cache[cs].hc_va = hc;
                if (hc >= 0x100000) {
                    u64 hsRaw = 0;
                    RpmRead64(hDev, procCR3, hc + 0x280, &hsRaw);
                    hs = hsRaw & DF_ENC_PTR_MASK;
                    s_comp_cache[cs].hs_va = hs;
                }
            }
            if (hs >= 0x100000) {
                u8 hpbuf[28] = {0};
                if (RpmReadVirtual(hDev, procCR3, hs + 0x3C, hpbuf, 28)) {
                    memcpy(&hp_cur,   hpbuf + 0x00, 4);
                    memcpy(&hp_max_v, hpbuf + 0x18, 4);
                    if (!(hp_cur == hp_cur)   || hp_cur < 0   || hp_cur > 10000)   hp_cur = 0;
                    if (!(hp_max_v == hp_max_v) || hp_max_v < 1 || hp_max_v > 10000) hp_max_v = 0;
                }
            }
        }

        int slot_idx = cnt;
        DH_SHMEM_PLAYER* p = &local.players[cnt++];
        p->pawn = pawn;   // stable key for cam thread's pos updates
        if (slot_idx < DH_MAX_PLAYERS) {
            local_pawn_track[slot_idx] = pawn;
            local_root_track[slot_idx] = root;
        }
        wcsncpy(p->name, wname, 31);
        p->team = teamID;

        // Dead-position latch — flicker fix.
        // Delta occasionally publishes the DEATH ragdoll's LastFrameWorldPosition
        // (encrypted, sometimes decoded stale) on odd ticks while the primary
        // path returns the true death-site coords. Result: corpse teleports
        // ~200m between ticks → visual flicker.
        //
        // Once we see a pawn tagged is_dead=1, freeze its position to the
        // FIRST observed death coordinate. Ragdolls do not walk; the true
        // corpse position never legitimately changes, so latching is safe.
        //
        // Cache is per-pawn, small LRU. Entries evict after ~30s (900 ticks
        // @30Hz) of the pawn not being seen — handles respawns cleanly.
        static struct {
            u64   pawn;
            float x, y, z;
            u64   last_tick;
        } s_dead_pos_lock[64] = {0};
        static u64 s_dead_tick = 0;
        s_dead_tick++;
        if (isDead && pawn) {
            int lslot = -1, empty = -1;
            u64 oldest_t = ~0ULL; int oldest_i = 0;
            for (int k = 0; k < 64; k++) {
                if (s_dead_pos_lock[k].pawn == pawn) { lslot = k; break; }
                if (!s_dead_pos_lock[k].pawn && empty < 0) empty = k;
                if (s_dead_pos_lock[k].last_tick < oldest_t) {
                    oldest_t = s_dead_pos_lock[k].last_tick;
                    oldest_i = k;
                }
            }
            if (lslot >= 0) {
                // Cached — overwrite with locked death position.
                px = s_dead_pos_lock[lslot].x;
                py = s_dead_pos_lock[lslot].y;
                pz = s_dead_pos_lock[lslot].z;
                s_dead_pos_lock[lslot].last_tick = s_dead_tick;
            } else {
                // First sight — commit current position as the death site.
                int use = empty >= 0 ? empty : oldest_i;
                s_dead_pos_lock[use].pawn = pawn;
                s_dead_pos_lock[use].x = px;
                s_dead_pos_lock[use].y = py;
                s_dead_pos_lock[use].z = pz;
                s_dead_pos_lock[use].last_tick = s_dead_tick;
            }
        }

        p->x = px; p->y = py; p->z = pz;
        p->vx = vxr; p->vy = vyr; p->vz = vzr;
        p->pos_ts_ms = now_v_ms;
        p->cap_hh = cap_hh; p->cap_r = cap_r;
        p->yaw = pawn_yaw;
        p->hp = hp_cur; p->hp_max = hp_max_v;
        p->dbg_crouch = dbg_c; p->dbg_proned = dbg_p; p->dbg_pose = dbg_pose;
        p->dbg_cap_root = dbg_cap_root; p->dbg_mesh_rel_z = dbg_mesh_rel_z;
        p->live_status = live_status;
        // SKELETON REMOVED 2026-09-26 — cut hot-path 3.8 KB RPM per pawn.
        // Equipment (helmet + body armor tier + durability). 10 Hz per-pawn
        // cache — armor rarely changes and reads walk 5+ RPMs through
        // CharacterEquipComponent. Free budget for higher main-tick rate.
        {
            static struct {
                u64   pawn;
                u64   refresh_ms;
                u8    helmet_tier, armor_tier;
                float helmet_dura, armor_dura;
            } s_eq_cache[512] = {0};
            u64 eq_now = GetTickCount64();
            int eh = -1, elru = 0;
            u64 elru_ts = ~0ULL;
            for (int j = 0; j < 512; j++) {
                if (s_eq_cache[j].pawn == pawn) { eh = j; break; }
                if (s_eq_cache[j].refresh_ms < elru_ts) {
                    elru_ts = s_eq_cache[j].refresh_ms; elru = j;
                }
            }
            int es = eh >= 0 ? eh : elru;
            if (eh < 0) {
                s_eq_cache[es].pawn = pawn;
                s_eq_cache[es].refresh_ms = 0;
                s_eq_cache[es].helmet_tier = s_eq_cache[es].armor_tier = 0;
                s_eq_cache[es].helmet_dura = s_eq_cache[es].armor_dura = 0.0f;
            }
            if (eq_now - s_eq_cache[es].refresh_ms >= 100) {
                read_equipment_for_slot(hDev, procCR3, pawn, p);
                s_eq_cache[es].helmet_tier = p->helmet_tier;
                s_eq_cache[es].helmet_dura = p->helmet_durability;
                s_eq_cache[es].armor_tier  = p->armor_tier;
                s_eq_cache[es].armor_dura  = p->armor_durability;
                s_eq_cache[es].refresh_ms  = eq_now;
            } else {
                p->helmet_tier       = s_eq_cache[es].helmet_tier;
                p->helmet_durability = s_eq_cache[es].helmet_dura;
                p->armor_tier        = s_eq_cache[es].armor_tier;
                p->armor_durability  = s_eq_cache[es].armor_dura;
            }
        }
        p->valid = 1; p->local = isLocal;
        p->is_bot = isBot;
        p->is_dead = isDead;

        if (isLocal && !haveMy) {
            haveMy = 1;
            u64 now_c = GetTickCount64();
            if (!g_cam_cache.pcm || (now_c - g_cam_cache.last_refresh_ms) > 1000) {
                u64 ctrlRaw = 0;
                RpmRead64(hDev, procCR3, pawn + 0x3A8, &ctrlRaw);
                u64 ctrl = ctrlRaw & DF_ENC_PTR_MASK;
                u64 pcm = 0;
                if (ctrl && ctrl >= 0x100000) {
                    u64 pcmRaw = 0;
                    RpmRead64(hDev, procCR3, ctrl + 0x408, &pcmRaw);
                    pcm = pcmRaw & DF_ENC_PTR_MASK;
                    if (pcm < 0x100000) pcm = 0;
                }
                g_cam_cache.ctrl = ctrl;
                g_cam_cache.pcm  = pcm;
                g_cam_cache.pawn = pawn;
                g_cam_cache.root = root;
                g_cam_cache.last_refresh_ms = now_c;
            }
            // Inline cam refresh — fallback for when the dedicated cam thread
            // failed to spawn (err=193 seen on 25H2). Writes local.myX/Y/Z +
            // yaw/pitch/roll/fov directly so shmem gets cam data every tick
            // instead of staying at zero.
            u64 pcm = g_cam_cache.pcm;
            u64 ctrl = g_cam_cache.ctrl;
            if (pcm) {
                u8 pov_buf[0x20];
                if (RpmReadVirtual(hDev, procCR3, pcm + 0x31DB0, pov_buf, sizeof(pov_buf))) {
                    DH_ENC_VECTOR pov;
                    memcpy(&pov, pov_buf, sizeof(pov));
                    if (pov.EncHandler.Index == 0xFFFF) {
                        local.myX = pov.X; local.myY = pov.Y; local.myZ = pov.Z;
                    } else {
                        // pawn-space fallback: use decrypted enemy pos of local
                        local.myX = px; local.myY = py; local.myZ = pz + 90.f;
                    }
                    float rot[3];
                    memcpy(rot, pov_buf + 0x10, 12);
                    if (rot[0] == rot[0]) local.myPitch = rot[0];
                    if (rot[1] == rot[1]) local.myYaw   = rot[1];
                    if (rot[2] == rot[2]) local.myRoll  = rot[2];
                    float f;
                    memcpy(&f, pov_buf + 0x1C, 4);
                    if (f == f && f > 30.f && f < 170.f) local.fov = f;
                }
            }
            // Rotation fallback via ControlRotation if PCM POV is unavail
            if (!local.myYaw && ctrl) {
                float pi_r = 0, yaw_r = 0, roll_r = 0;
                if (RpmReadVirtual(hDev, procCR3, ctrl + 0x380, &pi_r,  4) &&
                    RpmReadVirtual(hDev, procCR3, ctrl + 0x384, &yaw_r, 4) &&
                    RpmReadVirtual(hDev, procCR3, ctrl + 0x388, &roll_r,4)) {
                    if (pi_r  == pi_r)  local.myPitch = pi_r;
                    if (yaw_r == yaw_r) local.myYaw   = yaw_r;
                    if (roll_r== roll_r) local.myRoll = roll_r;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // AI BOT WALKER — two-phase for speed:
    //   PHASE A (fast, EVERY tick): re-read positions of already-known bots
    //   PHASE B (slow, every ~250ms): full Level.Actors scan for new bots
    //
    // Bot positions are plaintext at pawn+0x1D10 (no decrypt needed).
    // ------------------------------------------------------------------
    static u64 s_bot_pawns[DH_MAX_PLAYERS];      // pawn ptrs of confirmed bots
    static int s_bot_count = 0;
    static u64 s_bot_last_scan_ms = 0;

    // PHASE A: 60Hz-throttled position refresh of KNOWN bots + velocity.
    // Players run at daemon-cap (120Hz), bots half that per user spec.
    // On skip-ticks we still emit bot entries so overlay doesn't briefly
    // lose all bots between refreshes — we just don't re-RPM them.
    static u64 s_bot_last_refresh_ms = 0;
    int refresh_bots = ((now_tick - s_bot_last_refresh_ms) >= 16);   // 62.5Hz gate
    if (refresh_bots) s_bot_last_refresh_ms = now_tick;

    // Cache last-known bot positions so skip-ticks can still emit valid entries.
    static struct {
        u64 pawn;
        float x, y, z, vx, vy, vz;
        u64 ts_ms;
        float cap_hh, cap_r;
        float hp, hp_max;
        u8  dbg_c; i32 dbg_p; u8 dbg_pose;
        float dbg_cap_root; float dbg_mesh_rel_z;
        float yaw;   // root.RelativeRotation.Yaw
    } s_bot_last[DH_MAX_PLAYERS] = {0};

    for (int b = 0; b < s_bot_count && cnt < DH_MAX_PLAYERS; b++) {
        u64 pawnB = s_bot_pawns[b];
        float bx=0, by=0, bz=0, bvx=0, bvy=0, bvz=0;
        float bhh = 88.0f, br = 34.0f;
        float bhp = 0.0f, bhp_max = 0.0f;
        float byaw = 0.0f;
        u8  bdbg_c = 0; i32 bdbg_p = 0; u8 bdbg_pose = 0;
        float bdbg_cap_root = 0.0f, bdbg_mesh_rel_z = 0.0f;
        u64 bts = 0;
        int have_pos = 0;

        if (refresh_bots) {
            u8 posBuf[12];
            if (!RpmReadVirtual(hDev, procCR3, pawnB + 0x1D10, posBuf, 12)) goto use_last;
            memcpy(&bx, posBuf + 0, 4);
            memcpy(&by, posBuf + 4, 4);
            memcpy(&bz, posBuf + 8, 4);
            if (!(bx == bx && by == by && bz == bz)) goto use_last;
            if (fabsf(bx) < 50.f && fabsf(by) < 50.f) goto use_last;
            if (fabsf(bx) > 500000.f || fabsf(by) > 500000.f) goto use_last;
            if (bz < -5000.f || bz > 15000.f) goto use_last;

            bts = compute_velocity(pawnB, bx, by, bz, &bvx, &bvy, &bvz);
            have_pos = 1;

            // Stance-aware capsule: base HH from AGPCharacterBase+0xE68,
            // then scale by crouch/prone flags. Same math as the player
            // branch above.
            {
                float hh_base = 0, rr = 0;
                if (RpmReadVirtual(hDev, procCR3, pawnB + 0xE68, &hh_base, 4) &&
                    hh_base == hh_base && hh_base > 20.0f && hh_base < 200.0f)
                    bhh = hh_base;
                if (RpmReadVirtual(hDev, procCR3, pawnB + 0xE64, &rr, 4) &&
                    rr == rr && rr > 8.0f  && rr < 120.0f) br  = rr;

                u8 crouch_byte = 0;
                i32 proned_i32 = 0;
                u8 pose_byte = 0;
                RpmReadVirtual(hDev, procCR3, pawnB + 0x480, &crouch_byte, 1);
                RpmReadVirtual(hDev, procCR3, pawnB + 0x7A0, &proned_i32, 4);
                RpmReadVirtual(hDev, procCR3, pawnB + 0x1B48, &pose_byte, 1);
                bdbg_c = crouch_byte;
                bdbg_p = proned_i32;
                bdbg_pose = pose_byte;
                // Same visual-source probes as player branch
                {
                    u64 rootRawBot = 0;
                    RpmRead64(hDev, procCR3, pawnB + 0x180, &rootRawBot);
                    u64 rootBot = rootRawBot & DF_ENC_PTR_MASK;
                    if (rootBot >= 0x100000) {
                        float hh = 0;
                        if (RpmReadVirtual(hDev, procCR3, rootBot + 0x5D0, &hh, 4) &&
                            hh == hh && hh > 5.0f && hh < 300.0f)
                            bdbg_cap_root = hh;
                        // Yaw @ root+0x17C (FRotator = P,Y,R * float)
                        float yv = 0;
                        if (RpmReadVirtual(hDev, procCR3, rootBot + 0x17C, &yv, 4) &&
                            yv == yv && yv > -720.0f && yv < 720.0f)
                            byaw = yv;
                    }
                    u64 meshRawBot = 0;
                    RpmRead64(hDev, procCR3, pawnB + 0x3D0, &meshRawBot);
                    u64 meshBot = meshRawBot & DF_ENC_PTR_MASK;
                    if (meshBot >= 0x100000) {
                        float rz = 0;
                        if (RpmReadVirtual(hDev, procCR3, meshBot + 0x11C + 8, &rz, 4) &&
                            rz == rz && fabsf(rz) < 500.0f)
                            bdbg_mesh_rel_z = rz;
                    }
                }
                if (proned_i32)              bhh *= 0.40f;
                else if (crouch_byte & 0x01) bhh *= 0.55f;
            }

            // HP chain (same as player branch — verified 2026-09-21 SDK).
            {
                u64 hcRaw = 0;
                RpmRead64(hDev, procCR3, pawnB + 0x10B8, &hcRaw);
                u64 hc = hcRaw & DF_ENC_PTR_MASK;
                if (hc >= 0x100000) {
                    u64 hsRaw = 0;
                    RpmRead64(hDev, procCR3, hc + 0x280, &hsRaw);
                    u64 hs = hsRaw & DF_ENC_PTR_MASK;
                    if (hs >= 0x100000) {
                        float hp = 0, hpm = 0;
                        RpmReadVirtual(hDev, procCR3, hs + 0x3C, &hp, 4);
                        RpmReadVirtual(hDev, procCR3, hs + 0x54, &hpm, 4);
                        if (hp == hp && hp >= 0 && hp <= 10000) bhp = hp;
                        if (hpm == hpm && hpm > 0 && hpm <= 10000) bhp_max = hpm;
                    }
                }
            }

            if (b < DH_MAX_PLAYERS) {
                s_bot_last[b].pawn = pawnB;
                s_bot_last[b].x = bx; s_bot_last[b].y = by; s_bot_last[b].z = bz;
                s_bot_last[b].vx = bvx; s_bot_last[b].vy = bvy; s_bot_last[b].vz = bvz;
                s_bot_last[b].ts_ms = bts;
                s_bot_last[b].cap_hh = bhh; s_bot_last[b].cap_r = br;
                s_bot_last[b].hp = bhp; s_bot_last[b].hp_max = bhp_max;
                s_bot_last[b].dbg_c = bdbg_c; s_bot_last[b].dbg_p = bdbg_p; s_bot_last[b].dbg_pose = bdbg_pose;
                s_bot_last[b].dbg_cap_root = bdbg_cap_root;
                s_bot_last[b].dbg_mesh_rel_z = bdbg_mesh_rel_z;
                s_bot_last[b].yaw = byaw;
            }
        }
use_last:
        if (!have_pos) {
            if (b >= DH_MAX_PLAYERS) continue;
            if (s_bot_last[b].pawn != pawnB) continue;
            bx = s_bot_last[b].x; by = s_bot_last[b].y; bz = s_bot_last[b].z;
            bvx = s_bot_last[b].vx; bvy = s_bot_last[b].vy; bvz = s_bot_last[b].vz;
            bts = s_bot_last[b].ts_ms;
            bhh = s_bot_last[b].cap_hh > 0 ? s_bot_last[b].cap_hh : 88.0f;
            br  = s_bot_last[b].cap_r  > 0 ? s_bot_last[b].cap_r  : 34.0f;
            bhp = s_bot_last[b].hp;
            bhp_max = s_bot_last[b].hp_max;
            bdbg_c = s_bot_last[b].dbg_c;
            bdbg_p = s_bot_last[b].dbg_p;
            bdbg_pose = s_bot_last[b].dbg_pose;
            bdbg_cap_root = s_bot_last[b].dbg_cap_root;
            bdbg_mesh_rel_z = s_bot_last[b].dbg_mesh_rel_z;
            byaw = s_bot_last[b].yaw;
        }

        // Skip fake/unresolvable bots: no HP struct means the pawn entry is
        // spurious (invalid class chain, stale/killed remnant, or the HP
        // component pointer never resolved). Draws would show as 0/0 —
        // user 2026-09-23: don't emit these.
        if (!(bhp_max > 0.5f)) continue;

        int slot_idx = cnt;
        DH_SHMEM_PLAYER* p = &local.players[cnt++];
        p->pawn = pawnB;
        if (slot_idx < DH_MAX_PLAYERS) {
            local_pawn_track[slot_idx] = pawnB;
            local_root_track[slot_idx] = 0;   // cam thread reads root fresh
        }
        _snwprintf(p->name, 31, L"AI_%llX", (unsigned long long)(pawnB & 0xFFFFFF));
        p->team = 99;
        p->x = bx; p->y = by; p->z = bz;
        p->vx = bvx; p->vy = bvy; p->vz = bvz;
        p->pos_ts_ms = bts;
        p->cap_hh = bhh; p->cap_r = br;
        p->yaw = byaw;
        p->hp = bhp; p->hp_max = bhp_max;
        p->dbg_crouch = bdbg_c; p->dbg_proned = bdbg_p; p->dbg_pose = bdbg_pose;
        p->dbg_cap_root = bdbg_cap_root;
        p->dbg_mesh_rel_z = bdbg_mesh_rel_z;
        p->valid = 1;
        p->local = 0;
        p->is_bot = 1;
        // Bots have no PlayerState.bDead flag; infer death from health.
        p->is_dead = (bhp_max > 0.5f && bhp <= 0.5f) ? 1 : 0;
        // SKELETON REMOVED 2026-09-26 — same reason as PMC branch above.
        read_equipment_for_slot(hDev, procCR3, pawnB, p);
    }

    // PHASE B: full Level.Actors scan for NEW bots — only every 250ms
    if ((now_tick - s_bot_last_scan_ms) > 250) {
        s_bot_last_scan_ms = now_tick;

        do {
            u64 persLvlRaw = 0;
            if (!RpmRead64(hDev, procCR3, uworld + DF_WORLD_PERSISTENTLEVEL, &persLvlRaw)) break;
            u64 persLvl = persLvlRaw & DF_ENC_PTR_MASK;
            if (!persLvl || persLvl < 0x100000) break;

            u64 actArrData = 0;
            i32 actArrNum  = 0;
            if (!RpmRead64(hDev, procCR3, persLvl + 0x98, &actArrData)) break;
            if (!RpmReadVirtual(hDev, procCR3, persLvl + 0xA0, &actArrNum, 4)) break;
            if (actArrNum <= 0 || actArrNum > 4096) break;
            if (!actArrData || actArrData < 0x100000) break;

            static u64 actorPtrs[2048];
            int actMax = actArrNum > 2048 ? 2048 : actArrNum;
            if (!RpmReadVirtual(hDev, procCR3, actArrData, actorPtrs,
                                (u32)(actMax * sizeof(u64)))) break;

            // Build player pawn set for dedupe
            u64 seen_pawns[DH_MAX_PLAYERS];
            int seen_n = 0;
            for (int c = 0; c < PSCACHE_SIZE && seen_n < DH_MAX_PLAYERS; c++) {
                if (s_pscache[c].pawn) seen_pawns[seen_n++] = s_pscache[c].pawn;
            }

            // One-shot class-name dumper — logs UNIQUE class names of the
            // first tranche of level actors so we can identify Delta's
            // loot/container classes. Fires once per daemon lifetime.
            #define LOOT_CLS_HASH_SLOTS 512
            static u32 s_loot_cls_hashes[LOOT_CLS_HASH_SLOTS] = {0};
            static int s_loot_scan_done = 0;
            static int s_loot_scan_logged = 0;
            if (!s_loot_scan_done) {
                u64 gNamesVA = base + DF_RVA_GNAMES;
                for (int ai = 0; ai < actMax && s_loot_scan_logged < 300; ai++) {
                    u64 actor = actorPtrs[ai] & DF_ENC_PTR_MASK;
                    if (!actor || actor < 0x100000) continue;
                    char cls[64] = {0};
                    if (!RpmGetObjectClassName(hDev, procCR3, gNamesVA,
                                               actor, cls, sizeof(cls))) continue;
                    if (!cls[0]) continue;
                    // djb2 hash for de-dupe
                    u32 h = 5381;
                    for (const char* p = cls; *p; p++) h = ((h << 5) + h) + (u8)*p;
                    int slot = (int)(h % LOOT_CLS_HASH_SLOTS);
                    if (s_loot_cls_hashes[slot] == h) continue;
                    s_loot_cls_hashes[slot] = h;
                    DH_INFO("LOOTCLS actor=%llx cls=\"%s\"",
                            (unsigned long long)actor, cls);
                    s_loot_scan_logged++;
                }
                if (s_loot_scan_logged >= 300 || actMax > 0)
                    s_loot_scan_done = 1;
            }
            #undef LOOT_CLS_HASH_SLOTS

            #if 0  // superseded by AInventoryPickup Category filter below
            static int s_price_hunt_done = 0;
            if (!s_price_hunt_done) {
                s_price_hunt_done = 1;
                // UWorld.Levels @ 0x0158 = TArray<ULevel*> plaintext.
                u64 lvlArrData = 0;
                i32 lvlNum = 0;
                RpmRead64(hDev, procCR3, uworld + 0x158, &lvlArrData);
                RpmReadVirtual(hDev, procCR3, uworld + 0x160, &lvlNum, 4);
                DH_INFO("UWORLD uworld=%llx Levels@0x158 data=%llx num=%d",
                        (unsigned long long)uworld,
                        (unsigned long long)lvlArrData, lvlNum);
                if (lvlArrData >= 0x100000 && lvlNum > 0 && lvlNum <= 1024)
                {
                    int total_actors = 0, total_hits = 0;
                    for (int li = 0; li < lvlNum; li++) {
                        u64 lvl = 0;
                        if (!RpmReadVirtual(hDev, procCR3,
                                            lvlArrData + (u64)li * 8ULL,
                                            &lvl, 8) || !lvl) continue;
                        // Level might have encrypted top bits.
                        lvl = lvl & DF_ENC_PTR_MASK;
                        if (lvl < 0x100000) continue;
                        u64 lvlActArr = 0;
                        i32 lvlActNum = 0;
                        if (!RpmRead64(hDev, procCR3, lvl + 0x98, &lvlActArr)) continue;
                        if (!RpmReadVirtual(hDev, procCR3, lvl + 0xA0, &lvlActNum, 4)) continue;
                        if (lvlActNum <= 0 || lvlActNum > 4096) continue;
                        if (!lvlActArr || lvlActArr < 0x100000) continue;
                        static u64 lvlActorPtrs[2048];
                        int probeMax = lvlActNum > 2048 ? 2048 : lvlActNum;
                        if (!RpmReadVirtual(hDev, procCR3, lvlActArr, lvlActorPtrs,
                                            (u32)(probeMax * sizeof(u64)))) continue;
                        for (int ai = 0; ai < probeMax; ai++) {
                            u64 actor = lvlActorPtrs[ai] & DF_ENC_PTR_MASK;
                            if (!actor || actor < 0x100000) continue;
                            total_actors++;
                            for (u32 poff = 0; poff < 0x1000; poff += 4) {
                                u32 v = 0;
                                if (!RpmReadVirtual(hDev, procCR3,
                                                    actor + poff, &v, 4)) break;
                                if (v == 57741u) {
                                    DH_INFO("PROBE_PRICE lvl=%d actor=%llx +%04X = 57741",
                                            li, (unsigned long long)actor, poff);
                                    total_hits++;
                                }
                            }
                        }
                    }
                    DH_INFO("PROBE_PRICE done: %d levels, %d actors, %d hits",
                            lvlNum, total_actors, total_hits);
                } else {
                    DH_INFO("PROBE_PRICE: UWorld.Levels read FAILED");
                    s_price_hunt_done = 0;  // retry next tick
                }
            }
            #endif

            // ---- LOOT WALKER DISABLED per user 2026-09-22 ----
            // Ripped out — false-positive dots + no reliable BP FItemID offset
            // found across builds. Re-enable by removing the #if 0 wrap.
#if 0
            DH_SHMEM_LOOT tmp_loot[DH_MAX_LOOT];
            static u64 tmp_loot_actor[DH_MAX_LOOT];   // parallel: source actor per slot for stable sort
            int loot_n = 0;

            // NEAR-ME PROBE: scan all levels' actors for anything WITHIN
            // 2000 UU (~20m) of local player Klinochek. Dump raw uint32s
            // at "field-likely" ranges so we can identify ammo/item offsets.
            // Uses local.myX/Y from the current tick.
            #define NM_SEEN_MAX 32
            static u64 s_nm_seen[NM_SEEN_MAX] = {0};
            static int s_nm_seen_n = 0;
            if (local.myX != 0.0f && s_nm_seen_n < NM_SEEN_MAX) {
                float mx = local.myX, my = local.myY;
                // Iterate levels (persistent + streaming).
                u64 nmLvlData = 0; i32 nmLvlNum = 0;
                RpmRead64(hDev, procCR3, uworld + 0x158, &nmLvlData);
                RpmReadVirtual(hDev, procCR3, uworld + 0x160, &nmLvlNum, 4);
                if (nmLvlData >= 0x100000 && nmLvlNum > 0 && nmLvlNum <= 1024) {
                    static u64 nmActorPtrs[2048];
                    int total_near = 0;
                    for (int li = 0; li < nmLvlNum && total_near < 3; li++) {
                        u64 lvl = 0;
                        if (!RpmReadVirtual(hDev, procCR3,
                                            nmLvlData + (u64)li * 8ULL, &lvl, 8) || !lvl)
                            continue;
                        lvl &= DF_ENC_PTR_MASK;
                        if (lvl < 0x100000) continue;
                        u64 lActArr = 0; i32 lActNum = 0;
                        if (!RpmRead64(hDev, procCR3, lvl + 0x98, &lActArr)) continue;
                        if (!RpmReadVirtual(hDev, procCR3, lvl + 0xA0, &lActNum, 4)) continue;
                        if (lActArr < 0x100000 || lActNum <= 0 || lActNum > 4096) continue;
                        int probeMax = lActNum > 2048 ? 2048 : lActNum;
                        if (!RpmReadVirtual(hDev, procCR3, lActArr, nmActorPtrs,
                                            (u32)(probeMax * sizeof(u64)))) continue;
                        for (int ai = 0; ai < probeMax && total_near < 3; ai++) {
                            u64 actor = nmActorPtrs[ai] & DF_ENC_PTR_MASK;
                            if (!actor || actor < 0x100000) continue;
                            // Skip pawns (players/bots)
                            int is_pawn = 0;
                            for (int s = 0; s < seen_n; s++)
                                if (seen_pawns[s] == actor) { is_pawn = 1; break; }
                            if (is_pawn) continue;
                            // Read Root + decrypt position.
                            u64 rr = 0;
                            if (!RpmRead64(hDev, procCR3, actor + 0x180, &rr)) continue;
                            u64 root = rr & DF_ENC_PTR_MASK;
                            if (root < 0x100000) continue;
                            DH_ENC_VECTOR pv = {0};
                            if (!RpmReadVirtual(hDev, procCR3, root + 0x168, &pv, 16)) continue;
                            float px = 0, py = 0, pz = 0;
                            if (pv.EncHandler.Index == 0xFFFF) {
                                px = pv.X; py = pv.Y; pz = pv.Z;
                            } else if (g_vtbl_ready) {
                                u64 key = 0;
                                if (!DeriveKey(hDev, procCR3, pv.EncHandler.Index, &key)) continue;
                                __declspec(align(16)) u8 fi[16];
                                __declspec(align(16)) u8 fo[16];
                                memcpy(fi, &pv, 16); memset(fo, 0, 16);
                                CallVtblDecryptSpray(GetVtblShellcode(), fi, 0, key, fo);
                                memcpy(&px, fo+0, 4);
                                memcpy(&py, fo+4, 4);
                                memcpy(&pz, fo+8, 4);
                            } else continue;
                            if (!(px == px && py == py)) continue;
                            float dx = px - mx, dy = py - my;
                            float distsq = dx*dx + dy*dy;
                            if (distsq > 3000.f * 3000.f) continue;   // >30m
                            // Dedupe by actor address.
                            int seen = 0;
                            for (int j = 0; j < s_nm_seen_n; j++)
                                if (s_nm_seen[j] == actor) { seen = 1; break; }
                            if (seen) continue;
                            if (s_nm_seen_n < NM_SEEN_MAX)
                                s_nm_seen[s_nm_seen_n++] = actor;
                            total_near++;
                            DH_INFO("NEARME actor=%llx lvl=%d dist=%.0f pos=(%.0f,%.0f,%.0f)",
                                    (unsigned long long)actor, li,
                                    sqrtf(distsq), px, py, pz);
                            // Selective scan — max 15 "ID-shape" u32 hits per
                            // actor, avoid mesh-vertex float spam.
                            int u32_hits = 0;
                            for (u32 pf = 0; pf < 0x2000 && u32_hits < 15; pf += 4) {
                                u32 v = 0;
                                if (!RpmReadVirtual(hDev, procCR3, actor + pf, &v, 4)) break;
                                if (v < 100000u || v == 0xFFFFFFFFu) continue;
                                // Skip mesh-float bit patterns.
                                u32 top8 = (v >> 24);
                                if (top8 == 0x3Fu || top8 == 0xBFu ||
                                    top8 == 0x3Eu || top8 == 0xBEu ||
                                    top8 == 0x3Du || top8 == 0xBDu ||
                                    top8 == 0x40u || top8 == 0xC0u ||
                                    top8 == 0x41u || top8 == 0xC1u ||
                                    top8 == 0x42u || top8 == 0xC2u ||
                                    top8 == 0x43u || top8 == 0xC3u) continue;
                                DH_INFO("NEARME_U32 actor=%llx +%04X = %u (0x%X)",
                                        (unsigned long long)actor, pf, v, v);
                                u32_hits++;
                            }
                            // Big-u64 scan — max 8 hits.
                            int u64_hits = 0;
                            for (u32 pf = 0; pf < 0x2000 && u64_hits < 8; pf += 8) {
                                u64 g = 0;
                                if (!RpmRead64(hDev, procCR3, actor + pf, &g)) break;
                                if (g < 0x100000000ULL) continue;
                                if (g > 0xFFFF000000000000ULL) continue;
                                // Skip encoded-ptr shape (top byte 0x80..0x84 = heap in encoded-property form).
                                u8 top = (u8)(g >> 56);
                                if (top >= 0x80 && top <= 0x84) continue;
                                DH_INFO("NEARME_U64 actor=%llx +%04X = %llx",
                                        (unsigned long long)actor, pf,
                                        (unsigned long long)g);
                                u64_hits++;
                            }
                        }
                    }
                    (void)total_near;
                }
            }
            #undef NM_SEEN_MAX

            // Enumerate all loaded levels.
            u64 wLvlData = 0; i32 wLvlNum = 0;
            RpmRead64(hDev, procCR3, uworld + 0x158, &wLvlData);
            RpmReadVirtual(hDev, procCR3, uworld + 0x160, &wLvlNum, 4);
            if (wLvlData < 0x100000 || wLvlNum <= 0 || wLvlNum > 1024) {
                // Fallback: persistent level only (already have actorPtrs).
                wLvlNum = 0;   // marker for fallback below
            }

            // Two-level iteration: outer walks UWorld.Levels, inner walks
            // each ULevel.Actors — accumulates into tmp_loot with APickupBase filter.
            static u64 lvlActorPtrsBuf[2048];
            int level_max = wLvlNum > 0 ? wLvlNum : 1;
            u64 gNamesVA_loot = base + DF_RVA_GNAMES;
            for (int li = 0; li < level_max && loot_n < DH_MAX_LOOT; li++) {
                u64 lActArr = 0;
                i32 lActNum = 0;
                if (wLvlNum > 0) {
                    u64 lvl = 0;
                    if (!RpmReadVirtual(hDev, procCR3,
                                        wLvlData + (u64)li * 8ULL, &lvl, 8) || !lvl)
                        continue;
                    lvl &= DF_ENC_PTR_MASK;
                    if (lvl < 0x100000) continue;
                    if (!RpmRead64(hDev, procCR3, lvl + 0x98, &lActArr)) continue;
                    if (!RpmReadVirtual(hDev, procCR3, lvl + 0xA0, &lActNum, 4)) continue;
                    if (lActArr < 0x100000 || lActNum <= 0 || lActNum > 4096) continue;
                } else {
                    // Fallback: use already-loaded persistent-level actor array.
                    lActArr = actArrData;
                    lActNum = actMax;
                }
                int probeMax = lActNum > 2048 ? 2048 : lActNum;
                if (!RpmReadVirtual(hDev, procCR3, lActArr, lvlActorPtrsBuf,
                                    (u32)(probeMax * sizeof(u64)))) continue;

                for (int ai = 0; ai < probeMax && loot_n < DH_MAX_LOOT; ai++) {
                    u64 actor = lvlActorPtrsBuf[ai] & DF_ENC_PTR_MASK;
                    if (!actor || actor < 0x100000) continue;

                    // dedupe against player/bot pawns
                    int is_pawn = 0;
                    for (int s = 0; s < seen_n; s++) {
                        if (seen_pawns[s] == actor) { is_pawn = 1; break; }
                    }
                    if (is_pawn) continue;

                    // PRICEHUNT — for any actor near player, scan actor+0..0x2000
                    // as u32 grid for a specific known price. When user drops
                    // an item at known cost (e.g. Talcum Powder 22263), we log
                    // any actor whose memory contains that u32 anywhere in the
                    // header band — tells us the price offset AND the actor
                    // class instantly.
                    // Scan ALL actors' first 0x2000 bytes for the u32.
                    // No distance / no plaintext-position gate.
                    #define PRICEHUNT_VAL 15000u
                    {
                        static int s_ph_hits = 0;
                        static int s_ph_done = 0;
                        if (!s_ph_done && s_ph_hits < 30) {
                            static u32 s_band[0x2000/4];
                            if (RpmReadVirtual(hDev, procCR3, actor,
                                               s_band, sizeof(s_band))) {
                                u32 clsFnH = 0;
                                char clsH[64] = {0};
                                u64 clsRawH = 0;
                                RpmRead64(hDev, procCR3, actor + 8, &clsRawH);
                                u64 clsPtrH = clsRawH & DF_ENC_PTR_MASK;
                                if (clsPtrH >= 0x100000ULL) {
                                    if (RpmReadVirtual(hDev, procCR3,
                                            clsPtrH + UOBJ_NAME, &clsFnH, 4)
                                        && clsFnH)
                                        RpmResolveFName(hDev, procCR3,
                                            gNamesVA_loot, clsFnH,
                                            clsH, sizeof(clsH));
                                }
                                for (u32 wo = 0; wo < 0x2000/4; wo++) {
                                    if (s_band[wo] == PRICEHUNT_VAL) {
                                        DH_INFO("PRICEHUNT #%d actor=%llx "
                                                "cls=\"%s\" off=+0x%04X val=%u",
                                                ++s_ph_hits,
                                                (unsigned long long)actor,
                                                clsH[0] ? clsH : "?",
                                                wo * 4, PRICEHUNT_VAL);
                                        if (s_ph_hits >= 30) break;
                                    }
                                }
                            }
                            if (s_ph_hits >= 30) s_ph_done = 1;
                        }
                    }

                    // CLASSHUNT — logs actors with loot-shaped class names,
                    // regardless of filter status. Reads Class via actor+8
                    // directly so we don't depend on the later clsPtr calc.
                    {
                        static int s_ch_hits = 0;
                        static int s_ch_done = 0;
                        if (!s_ch_done && s_ch_hits < 60) {
                            u64 clsRawH = 0;
                            RpmRead64(hDev, procCR3, actor + 8, &clsRawH);
                            u64 clsPtrH = clsRawH & DF_ENC_PTR_MASK;
                            if (clsPtrH >= 0x100000ULL &&
                                clsPtrH < 0x0001000000000000ULL) {
                                u32 clsFn = 0;
                                char cbuf[64] = {0};
                                if (RpmReadVirtual(hDev, procCR3,
                                                   clsPtrH + UOBJ_NAME,
                                                   &clsFn, 4) && clsFn) {
                                    RpmResolveFName(hDev, procCR3, gNamesVA_loot,
                                                    clsFn, cbuf, sizeof(cbuf));
                                }
                                if (cbuf[0] && (
                                    strstr(cbuf, "Pickup") ||
                                    strstr(cbuf, "Loot")   ||
                                    strstr(cbuf, "Drop")   ||
                                    strstr(cbuf, "Ammo")   ||
                                    strstr(cbuf, "Inventory") ||
                                    strstr(cbuf, "WeaponModular") ||
                                    strstr(cbuf, "AssembleWeap")))
                                {
                                    u8 band[0x20] = {0};
                                    RpmReadVirtual(hDev, procCR3, actor + 0x1240,
                                                   band, sizeof(band));
                                    DH_INFO("CLASSHUNT #%d actor=%llx cls=\"%s\" "
                                            "band+0x1240=%02x%02x%02x%02x%02x%02x%02x%02x "
                                            "cat=%u seq=%u",
                                            ++s_ch_hits,
                                            (unsigned long long)actor, cbuf,
                                            band[0],band[1],band[2],band[3],
                                            band[4],band[5],band[6],band[7],
                                            *(u32*)(band + 0x10),
                                            *(u32*)(band + 0x14));
                                }
                            }
                            if (s_ch_hits >= 60) s_ch_done = 1;
                        }
                    }

                    // NEARSCAN — periodic diagnostic (rearms every 60 ticks
                    // so we can catch newly-spawned actors when the player
                    // drops items). Logs ANY actor within 5m — bypasses
                    // structural filter so we see rejected classes too.
                    static int s_ns_hits = 0;
                    static u32 s_ns_tick_last = 0;
                    static u32 s_ns_tick_now = 0;
                    if (ai == 0) s_ns_tick_now++;
                    if (s_ns_tick_now - s_ns_tick_last >= 60) {
                        s_ns_hits = 0;
                        s_ns_tick_last = s_ns_tick_now;
                    }
                    if (s_ns_hits < 20) {
                        u64 rootR = 0;
                        if (RpmRead64(hDev, procCR3, actor + 0x180, &rootR)) {
                            u64 rN = rootR & DF_ENC_PTR_MASK;
                            if (rN >= 0x100000 && rN < 0x0001000000000000ULL) {
                                DH_ENC_VECTOR pvn;
                                if (RpmReadVirtual(hDev, procCR3, rN + 0x148, &pvn, 16)) {
                                    float nx = pvn.X, ny = pvn.Y, nz = pvn.Z;
                                    int ok_plain = (pvn.EncHandler.Index == 0xFFFF);
                                    if (ok_plain) {
                                        float dxm = nx - g_shmem->myX;
                                        float dym = ny - g_shmem->myY;
                                        float dzm = nz - g_shmem->myZ;
                                        float d2m = dxm*dxm + dym*dym + dzm*dzm;
                                        if (d2m < 500.0f * 500.0f) {
                                            u64 vtn = 0, clsn = 0;
                                            RpmRead64(hDev, procCR3, actor + 0, &vtn);
                                            RpmRead64(hDev, procCR3, actor + 8, &clsn);
                                            u32 nameFnI = 0;
                                            RpmReadVirtual(hDev, procCR3, actor + 0xFF0, &nameFnI, 4);
                                            char resName[64] = {0};
                                            if (nameFnI)
                                                RpmResolveFName(hDev, procCR3, gNamesVA_loot,
                                                                nameFnI, resName, sizeof(resName));
                                            // Resolve Class name via Class+0x1C = FName ComparisonIndex.
                                            char clsName[64] = {0};
                                            u32 clsFnI = 0;
                                            u64 clsN = clsn & DF_ENC_PTR_MASK;
                                            if (clsN >= 0x100000 && clsN < 0x0001000000000000ULL) {
                                                if (RpmReadVirtual(hDev, procCR3,
                                                                   clsN + UOBJ_NAME, &clsFnI, 4)
                                                    && clsFnI) {
                                                    RpmResolveFName(hDev, procCR3, gNamesVA_loot,
                                                                    clsFnI, clsName, sizeof(clsName));
                                                }
                                            }
                                            DH_INFO("NEARSCAN #%d d=%.1fm actor=%llx vt=%llx "
                                                    "class=\"%s\" pos=(%.0f,%.0f,%.0f) invIdx=%u",
                                                    ++s_ns_hits, sqrtf(d2m)/100.0f,
                                                    (unsigned long long)actor,
                                                    (unsigned long long)vtn,
                                                    clsName[0] ? clsName : "?",
                                                    nx, ny, nz, nameFnI);
                                            (void)resName;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // STRUCTURAL FILTER — class-hierarchy gate (primary).
                    //
                    // The prior heuristic (invGID/nameIdx/stackCount/dur/
                    // unitScale bounds on +0xFC0..+0x1020) admitted AActor
                    // derivatives whose fields happened to co-populate that
                    // band with pickup-shaped bytes — LOD proxies and
                    // dense-cluster decoration actors sharing an ancestor
                    // vtable. Structural fix: test the actor's UClass
                    // ancestry against APickupBase's UClass*. Only true
                    // APickupBase descendants pass. Field-shape checks are
                    // retained ONLY as a fallback when class lookup fails.
                    static u64 s_pickup_base_cls   = 0;
                    static u64 s_deadbody_cls      = 0;
                    static int s_pickup_init       = 0;
                    static u64 s_cls_pass[64]      = {0};
                    static int s_cls_pass_n        = 0;
                    static u64 s_cls_fail[128]     = {0};
                    static int s_cls_fail_n        = 0;
                    if (!s_pickup_init) {
                        s_pickup_init = 1;
                        // GObjects walk — one-shot at daemon boot (~10s).
                        // Find both APickupBase (primary filter) and
                        // AInventoryPickup_DeadBody (skip = corpses).
                        s_pickup_base_cls = RpmFindUClassByName(
                            hDev, procCR3,
                            base + DF_RVA_GOBJECTS, gNamesVA_loot,
                            "PickupBase");
                        s_deadbody_cls = RpmFindUClassByName(
                            hDev, procCR3,
                            base + DF_RVA_GOBJECTS, gNamesVA_loot,
                            "InventoryPickup_DeadBody");
                        DH_INFO("PICKUP filter armed: APickupBase=0x%llx "
                                "DeadBody=0x%llx",
                                (unsigned long long)s_pickup_base_cls,
                                (unsigned long long)s_deadbody_cls);
                    }

                    // ONE 40B UObject header read: vtable(+0), Class(+8), Flags(+0x18).
                    u8 uohdr[0x28] = {0};
                    if (!RpmReadVirtual(hDev, procCR3, actor, uohdr, sizeof(uohdr)))
                        continue;
                    u64 vt     = *(u64*)(uohdr + UOBJ_VTABLE);
                    u64 clsRaw = *(u64*)(uohdr + UOBJ_CLASS);
                    u32 oFlags = *(u32*)(uohdr + UOBJ_FLAGS);

                    // Vtable must sit inside Delta image .rdata.
                    if (vt < base || vt >= (base + 0x20000000ULL)) continue;
                    // ClassDefaultObject templates share vtable + hierarchy
                    // but have no meaningful RootComponent — reject explicitly.
                    if (oFlags & RF_CLASS_DEFAULT_OBJECT) continue;

                    u64 clsPtr = clsRaw & DF_ENC_PTR_MASK;
                    if (clsPtr < 0x100000ULL) continue;

                    // is_native_pickup = actor's Class inherits from APickupBase.
                    // Only for these can we trust the SDK-anchored field
                    // reads (+0x1240 FInventoryItemInfo, +0x1C98 WhoDrop,
                    // +0xFD8 InventoryGID). Name-matched-only BP classes
                    // (BP_Loot_RandomObj_C etc.) have different layouts —
                    // reading those offsets on them yields random garbage
                    // (floats, pointers), which is what produced fake
                    // multi-million "prices" in the last raid.
                    // ABI-port: iterate ALL Level.Actors. Detect item actors
                    // via FInventoryItemInfo shape at +0x1240:
                    //   +0x1250 u32 Category (Delta bucket 1..99)
                    //   +0x1254 u32 Sequence (1..99999999)
                    //   +0x1278 i32 ItemCount (1..999)
                    //   +0x1268 u64 ItemGid (nonzero)
                    // Skip character-owned items — ABI reads Owner at +0x118
                    // and rejects if Owner is a live character (has WM/DC).
                    // CATALOG LOOKUP: read FItemID from actor+0x1250, pack
                    // Cat*1e9+Seq, lookup in GameItem DataTable hashmap built
                    // at boot. Only accept actors whose FItemID resolves to
                    // a real catalog row — pre-spawn junk / random props fail.
                    int is_native_pickup = 1;
                    u64 rowPtrHit = 0;
                    u32 pCat = 0, pSeq = 0;
                    i32 bp_price = 0, bp_quality = 0;
                    {
                        // STAGE 1: skip DeadBody descendants (corpses) — trupы юзер не хочет.
                        if (s_deadbody_cls) {
                            if (RpmIsClassDescendantOf(hDev, procCR3, clsPtr,
                                                      s_deadbody_cls))
                                continue;
                        }
                        // STAGE 2 (APickupBase ancestor) DISABLED — Delta's
                        // descendant chain didn't match reliably in live raid.
                        // Fallback: rely on Cat/Seq catalog hit OR replicated
                        // Price+Quality at fixed BP offsets.
                        // STAGE 3: direct row_ptr from actor+0x1200 (SDK-verified
                        // 2026-09-22 via cheetah44/CN leak — AInventoryPickup layout).
                        // Delta stores FDFMCommonItemRow* here, not FItemID tuple.
                        // Vtable 0x0158D57200 is const across all catalog rows.
                        u64 direct_row = 0;
                        if (RpmRead64(hDev, procCR3, actor + 0x1200, &direct_row)) {
                            u64 rp = direct_row & DF_ENC_PTR_MASK;
                            if (rp >= 0x100000ULL && rp < 0x0001000000000000ULL) {
                                u64 rvt = 0;
                                if (RpmRead64(hDev, procCR3, rp, &rvt) &&
                                    rvt == 0x0158D57200ULL) {
                                    rowPtrHit = rp;
                                    is_native_pickup = 1;
                                }
                            }
                        }
                        // Legacy catalog-lookup fallback via +0x1250.
                        if (!rowPtrHit) {
                            RpmReadVirtual(hDev, procCR3, actor + 0x1250, &pCat, 4);
                            RpmReadVirtual(hDev, procCR3, actor + 0x1254, &pSeq, 4);
                            if (g_item_catalog_ready &&
                                pCat > 0u && pCat <= 200u &&
                                pSeq > 0u && pSeq <= 999999999u)
                            {
                                u64 packed = (u64)pCat * 1000000000ULL + (u64)pSeq;
                                rowPtrHit = DhItemCatalogLookup(&g_item_catalog, packed);
                                if (rowPtrHit) is_native_pickup = 1;
                            }
                        }
                        // BP fallback via wide u32 scan — check actor+0x800..0x2100
                        // for any u32 that's a plausible price. Uses first one
                        // found as the price. 20m user-distance gate limits
                        // candidates to what's near player (prevents scan cost).
                        // No pre-position gate. Class whitelist for BP path.
                        if (!rowPtrHit) {
                            u32 clsFnBP = 0;
                            char cbBP[64] = {0};
                            if (RpmReadVirtual(hDev, procCR3,
                                clsPtr + UOBJ_NAME, &clsFnBP, 4) && clsFnBP)
                                RpmResolveFName(hDev, procCR3,
                                    gNamesVA_loot, clsFnBP,
                                    cbBP, sizeof(cbBP));
                            int loot_class = 0;
                            if (cbBP[0]) {
                                if (strstr(cbBP, "InventoryPickup") ||
                                    strstr(cbBP, "WeaponModular")   ||
                                    strstr(cbBP, "WeaponMeleeNo")   ||
                                    strstr(cbBP, "WeaponRagdoll")   ||
                                    strstr(cbBP, "DroppedItem")     ||
                                    strstr(cbBP, "AssembleWeapon"))
                                    loot_class = 1;
                            }
                            if (!loot_class) continue;
                            static u32 scanBuf[0x1900/4];
                            if (!RpmReadVirtual(hDev, procCR3, actor + 0x800,
                                               scanBuf, sizeof(scanBuf))) continue;
                            int found_price = 0;
                            u32 best_val = 0;   // largest price-shape wins
                            u32 best_off = 0;
                            // Dedup per-actor to avoid log spam.
                            static u64 s_seen[512] = {0};
                            static int s_seen_n = 0;
                            int already = 0;
                            for (int k = 0; k < s_seen_n; k++)
                                if (s_seen[k] == actor) { already = 1; break; }
                            if (!already && s_seen_n < 512) s_seen[s_seen_n++] = actor;
                            for (u32 wo = 0; wo < 0x1900/4; wo++) {
                                u32 v = scanBuf[wo];
                                if (v >= 500u && v <= 5000000u) {
                                    found_price = 1;
                                    if (v > best_val) {
                                        best_val = v;
                                        best_off = 0x800u + wo * 4u;
                                    }
                                    if (!already) {
                                        DH_INFO("BPCAND actor=%llx cls=\"%s\" "
                                                "off=+0x%04X val=%u",
                                                (unsigned long long)actor,
                                                cbBP, (0x800u + wo*4u), v);
                                    }
                                }
                            }
                            if (!found_price) continue;
                            bp_price = (i32)best_val;
                            (void)best_off;
                            is_native_pickup = 0;
                            bp_quality = 0;
                        }
                        // STAGE 4: owner-skip — reject items held by characters.
                        u64 e_owner = 0;
                        RpmReadVirtual(hDev, procCR3, actor + 0x118, &e_owner, 8);
                        if (e_owner >= 0x100000ULL &&
                            e_owner < 0x0001000000000000ULL)
                        {
                            u64 wm = 0;
                            RpmReadVirtual(hDev, procCR3, e_owner + 0x2650, &wm, 8);
                            if (wm != 0ULL) continue;
                        }
                        (void)s_cls_pass; (void)s_cls_pass_n;
                        (void)s_cls_fail; (void)s_cls_fail_n;
                    }

                    // REJECT COUNTERS — diagnostic for post-accept filter chain.
                    // Prints once per 200 ticks so we see where whitelisted
                    // BP actors fall off.
                    static u32 rj_pbase = 0, rj_root_r = 0, rj_root_v = 0;
                    static u32 rj_atc_r = 0, rj_atc_n = 0, rj_atc_d = 0;
                    static u32 rj_pv_r = 0, rj_pv_nan = 0, rj_pv_map = 0;
                    static u32 rj_dec = 0, rj_ok = 0;
                    static u32 s_diag_cyc = 0;
                    s_diag_cyc++;
                    if (s_diag_cyc >= 500) {
                        s_diag_cyc = 0;
                        DH_INFO("LOOT_REJ pbase=%u root_r=%u root_v=%u "
                                "atc_r=%u atc_n=%u atc_d=%u "
                                "pv_r=%u nan=%u map=%u dec=%u ok=%u",
                                rj_pbase, rj_root_r, rj_root_v,
                                rj_atc_r, rj_atc_n, rj_atc_d,
                                rj_pv_r, rj_pv_nan, rj_pv_map, rj_dec, rj_ok);
                        rj_pbase = rj_root_r = rj_root_v = 0;
                        rj_atc_r = rj_atc_n = rj_atc_d = 0;
                        rj_pv_r = rj_pv_nan = rj_pv_map = 0;
                        rj_dec = rj_ok = 0;
                    }

                    // APickupBase field block — read for label + shmem population,
                    // and (only when structural filter is off) as fallback sanity.
                    u8 pbase[0x50];
                    if (!RpmReadVirtual(hDev, procCR3, actor + 0xFD8, pbase, sizeof(pbase)))
                        { rj_pbase++; continue; }
                    u64 invGID       = *(u64*)(pbase + 0x00);         // +0xFD8
                    u32 nameIdx      = *(u32*)(pbase + 0x18);         // +0xFF0
                    u32 nameNum      = *(u32*)(pbase + 0x1C);         // +0xFF4
                    u64 invTypeCls   = *(u64*)(pbase + 0x20);         // +0xFF8
                    i32 stackCount   = *(i32*)(pbase + 0x28);         // +0x1000
                    i32 durability   = *(i32*)(pbase + 0x30);         // +0x1008
                    float unitScale  = *(float*)(pbase + 0x44);       // +0x101C

                    if (!s_pickup_base_cls) {
                        // HEURISTIC FALLBACK — preserved verbatim from prior
                        // filter so a resolver miss doesn't regress ESP.
                        if (invGID == 0ULL) continue;
                        if (invGID == 0xFFFFFFFFFFFFFFFFULL) continue;
                        if (nameIdx == 0u || nameIdx > 0x00200000u) continue;
                        if (nameNum > 0x0000FFFFu) continue;
                        if (stackCount <= 0 || stackCount > 999) continue;
                        if (durability < 0 || durability > 500) continue;
                        if (invTypeCls != 0ULL) {
                            if (invTypeCls < 0x100000ULL) continue;
                            if (invTypeCls >= 0x0001000000000000ULL) continue;
                            u64 invCls_vt = 0;
                            if (!RpmRead64(hDev, procCR3, invTypeCls + 0, &invCls_vt))
                                continue;
                            if (invCls_vt < base || invCls_vt >= (base + 0x20000000ULL))
                                continue;
                        }
                        if (!(unitScale == unitScale)) continue;
                        if (unitScale < -100.0f || unitScale > 100.0f) continue;
                    }
                    (void)nameNum;
                    (void)invTypeCls;
                    (void)unitScale;

                    // Position via Root+0x168 FEncVector (Feistel or plaintext).
                    u64 rootRaw = 0;
                    if (!RpmRead64(hDev, procCR3, actor + 0x180, &rootRaw)) { rj_root_r++; continue; }
                    u64 root = rootRaw & DF_ENC_PTR_MASK;
                    if (root < 0x100000 || root >= 0x1000000000000ULL) { rj_root_v++; continue; }
                    // Cheap "is this really a USceneComponent" gate.
                    // AttachChildren @+0x118 is TArray<USC*> — Num/Max fit
                    // sane bounds on real components; junk actors fail this.
                    // RELAXED for BP-whitelisted (non-native) pickups — their
                    // Root layout differs; skip the AttachChildren sanity gate.
                    if (is_native_pickup) {
                        struct { u64 data; i32 num; i32 max; } atc = {0};
                        if (!RpmReadVirtual(hDev, procCR3, root + 0x118, &atc, sizeof(atc)))
                            { rj_atc_r++; continue; }
                        if (atc.num < 0 || atc.num > 64) { rj_atc_n++; continue; }
                        if (atc.max < atc.num || atc.max > 128) { rj_atc_n++; continue; }
                        if (atc.num > 0 && (atc.data < 0x100000ULL || atc.data >= 0x0001000000000000ULL))
                            { rj_atc_d++; continue; }
                    }
                    // Delta USceneComponent (reordered) puts FEncVector at
                    // root+0x148, NOT +0x168 (verified via ROOTDUMP 2026-09-22).
                    // Layout: X:f @0, Y:f @4, Z:f @8, Index:u16 @0xC,
                    // bEncrypted:u8 @0xE, flags:u8 @0xF.
                    // Index==0xFFFF → plaintext. Else decrypt via Feistel.
                    float lx = 0, ly = 0, lz = 0;
                    DH_ENC_VECTOR pv = {0};
                    if (!RpmReadVirtual(hDev, procCR3, root + 0x148, &pv, 16))
                        { rj_pv_r++; continue; }
                    if (pv.EncHandler.Index == 0xFFFF) {
                        lx = pv.X; ly = pv.Y; lz = pv.Z;
                    } else if (g_vtbl_ready) {
                        u64 key = 0;
                        if (!DeriveKey(hDev, procCR3, pv.EncHandler.Index, &key))
                            { rj_dec++; continue; }
                        __declspec(align(16)) u8 fv_in[16];
                        __declspec(align(16)) u8 fv_out[16];
                        memcpy(fv_in, &pv, 16); memset(fv_out, 0, 16);
                        CallVtblDecryptSpray(GetVtblShellcode(), fv_in, 0, key, fv_out);
                        memcpy(&lx, fv_out+0, 4);
                        memcpy(&ly, fv_out+4, 4);
                        memcpy(&lz, fv_out+8, 4);
                    } else { rj_dec++; continue; }
                    if (!(lx == lx && ly == ly && lz == lz)) { rj_pv_nan++; continue; }
                    // Sanity — reject only obvious garbage FPs (very far / NaN).
                    // No z-cap — Delta interiors range from basements to rooftops.
                    if (fabsf(lx) > 200000.f || fabsf(ly) > 200000.f) { rj_pv_map++; continue; }
                    // Drop origin (0,0,0) and near-origin — CDOs cluster there.
                    if (fabsf(lx) < 100.f && fabsf(ly) < 100.f) { rj_pv_map++; continue; }
                    // 20m distance cap from local player — user asked.
                    {
                        float _dx = lx - g_shmem->myX;
                        float _dy = ly - g_shmem->myY;
                        float _dz = lz - g_shmem->myZ;
                        float _d2 = _dx*_dx + _dy*_dy + _dz*_dz;
                        if (_d2 > 2000.0f * 2000.0f) { rj_pv_map++; continue; }
                    }
                    rj_ok++;

                    // FName resolve — try InventoryIdName first; if empty/None
                    // (typical for BP-generated dropped items), fall back to
                    // resolving the ACTOR CLASS name instead so the overlay
                    // shows "Loot_RandomObj" instead of "None".
                    char resolved[64] = {0};
                    if (nameIdx) {
                        RpmResolveFName(hDev, procCR3, gNamesVA_loot,
                                        nameIdx, resolved, sizeof(resolved));
                    }
                    // If InventoryIdName didn't yield anything useful, use
                    // the actor's UClass name. Strip common prefixes.
                    int have_asciiname = 0;
                    if (resolved[0]) {
                        int alnum = 0, ok = 1;
                        for (int k = 0; resolved[k] && k < 40; k++) {
                            unsigned char c = (unsigned char)resolved[k];
                            if (c < 0x20 || c >= 0x7F) { ok = 0; break; }
                            if ((c >= '0' && c <= '9') ||
                                (c >= 'A' && c <= 'Z') ||
                                (c >= 'a' && c <= 'z') ||
                                c == '_')
                                alnum++;
                        }
                        if (ok && alnum >= 3) have_asciiname = 1;
                    }
                    if (!have_asciiname) {
                        // Fetch class FName from Class+UOBJ_NAME
                        u32 clsFn = 0;
                        if (RpmReadVirtual(hDev, procCR3,
                                           clsPtr + UOBJ_NAME, &clsFn, 4)
                            && clsFn)
                        {
                            char cnbuf[64] = {0};
                            RpmResolveFName(hDev, procCR3, gNamesVA_loot,
                                            clsFn, cnbuf, sizeof(cnbuf));
                            if (cnbuf[0]) {
                                // Trim UE naming garnish.
                                const char* cs = cnbuf;
                                if (strncmp(cs, "BP_", 3) == 0) cs += 3;
                                // Drop trailing "_C" (BP class marker).
                                size_t cl = strlen(cs);
                                if (cl > 2 && cs[cl-2] == '_' && cs[cl-1] == 'C')
                                    ((char*)cs)[cl-2] = 0;
                                strncpy(resolved, cs, sizeof(resolved) - 1);
                                resolved[sizeof(resolved) - 1] = 0;
                            }
                        }
                        // Last resort: label with hex of vt low
                        if (resolved[0] == 0) {
                            snprintf(resolved, sizeof(resolved),
                                     "vt_%08llx", (unsigned long long)(vt & 0xFFFFFFFF));
                        }
                    }

                    // AInventoryPickup catalog + drop-tag pull.
                    // Layout (SDK-verified 2026-09-22 DFMGameplay_classes.hpp:9950):
                    //   PickupItemInfo (FInventoryItemInfo, 0x800) @ actor+0x1240
                    //     FItemID { u32 Category @+0x00, u32 Sequence @+0x04 } @ +0x10
                    //       → absolute catId u64 @ actor+0x1250
                    //     u64 ItemGid                                  @ +0x28 → actor+0x1268
                    //     i32 ItemCount                                @ +0x38 → actor+0x1278
                    //   u64 LastOwnedPlayerId (Net)                    @ actor+0x1C90
                    //   u64 WhoDropThisPlayerId (Net, non-zero == player-dropped) @ actor+0x1C98
                    // AInventoryPickup_WeaponModule inherits AInventoryPickup
                    // unchanged (line 33938), so +0x1250 is valid for the
                    // WeaponModular_3p BP-wrapped drops the user sees too.
                    // BP-derived subclassing does NOT shift native offsets.
                    u64  catId64        = 0;
                    u64  itemGidActor   = 0;
                    i32  pickupCount    = 0;
                    u64  whoDropUid     = 0;
                    u32  catCategory    = 0;
                    u32  catSequence    = 0;
                    int  player_dropped = 0;
                    // ONLY read AInventoryPickup-layout fields when actor is
                    // a real APickupBase descendant. BP classes admitted by
                    // name-match (BP_Loot_RandomObj_C etc.) have unrelated
                    // layouts — reading +0x1250/+0x1C98 there yields random
                    // floats/pointers, which is what produced fake million-
                    // value "prices" in the previous raid.
                    // Universal FItemID.Category sanity — applied to EVERY
                    // accepted actor (native and empirical). Category must
                    // be a real Delta bucket (99=consumables, 14=weapons,
                    // 12=armor, 3=ammo, …). Anything > 200 means the
                    // +0x1250 field is not FItemID for this actor
                    // (BP_Loot_RandomObj_C has floats/pointers there).
                    RpmReadVirtual(hDev, procCR3, actor + 0x1250, &catId64,      8);
                    RpmReadVirtual(hDev, procCR3, actor + 0x1268, &itemGidActor, 8);
                    RpmReadVirtual(hDev, procCR3, actor + 0x1278, &pickupCount,  4);
                    catCategory = (u32)(catId64        & 0xFFFFFFFFu);
                    catSequence = (u32)((catId64 >> 32) & 0xFFFFFFFFu);
                    // Delta uses a small closed set of Category buckets.
                    // Anything else = random data at +0x1250 (not FItemID).
                    // Empirically observed valid buckets:
                    //   3   ammo (small caliber)
                    //   4   ammo (rifle+)
                    //   8   keys / documents
                    //   9   quest / consumable trinkets
                    //   11  weapon attachments
                    //   12  armor (helmet/vest)
                    //   14  weapons
                    //   99  consumables (food, meds, batteries)
                    // Strict FInventoryItemInfo sanity applies ONLY to native
                    // AInventoryPickup descendants. For BP-whitelisted actors
                    // (BP_WeaponModular_*, BP_InventoryPickup_C, DroppedItem)
                    // the +0x1240 layout is different — skip and rely on the
                    // class-name gate + position sanity we already passed.
                    if (is_native_pickup) {
                        if (catCategory == 0u || catCategory > 200u) goto _reject_actor;
                        if (catSequence == 0u) goto _reject_actor;
                        if (pickupCount  <= 0) goto _reject_actor;
                        if (catSequence == 0u || catSequence > 999999999u) goto _reject_actor;
                        if (pickupCount <= 0 || pickupCount > 9999) goto _reject_actor;
                        if (itemGidActor == 0ULL) goto _reject_actor;
                    }
                    goto _accept_actor;
                    _reject_actor: continue;
                    _accept_actor:;
                    i32 rowQuality = 0;
                    i32 rowPrice   = 0;
                    i32 rowMallPrice = 0;
                    if (rowPtrHit) {
                        RpmReadVirtual(hDev, procCR3, rowPtrHit + 0x68, &rowQuality,   4);
                        RpmReadVirtual(hDev, procCR3, rowPtrHit + 0xDC, &rowPrice,     4);
                        RpmReadVirtual(hDev, procCR3, rowPtrHit + 0xEC, &rowMallPrice, 4);
                    } else {
                        // BP path — use replicated actor fields.
                        rowQuality = bp_quality;
                        rowPrice   = bp_price;
                    }
                    RpmReadVirtual(hDev, procCR3, actor + 0x1C98, &whoDropUid, 8);
                    player_dropped = (whoDropUid != 0ULL) ? 1 : 0;

                    tmp_loot_actor[loot_n] = actor;
                    DH_SHMEM_LOOT* L = &tmp_loot[loot_n++];
                    L->x = lx; L->y = ly; L->z = lz;
                    // rarity: 5 == red flag = player-dropped (visually distinct
                    // in overlay palette). 0 for prespawned floor loot.
                    L->rarity = player_dropped ? 5 : 0;
                    L->is_corpse = 0;

                    // Effective stack count: PickupItemInfo.ItemCount takes
                    // precedence over APickupBase.stackCount when non-zero —
                    // dropped-inventory pickups populate the FInventoryItemInfo
                    // path, containers use APickupBase.
                    i32 effCount = (pickupCount > 0 && pickupCount <= 9999)
                                   ? pickupCount : stackCount;

                    // Label: Quality + Price from FDFMCommonItemRow.
                    // Prefer MallRecyclePrice (real cash-out) over InitialGuidePrice
                    // (hint value); some items only populate one of the two.
                    i32 usePrice = rowMallPrice > 0 ? rowMallPrice : rowPrice;
                    u32 priceU = (usePrice > 0 && usePrice < 100000000)
                                 ? (u32)usePrice : 0;
                    L->value = priceU;
                    L->rarity = (u8)((rowQuality >= 1 && rowQuality <= 6)
                                     ? rowQuality : 0);
                    if (player_dropped) L->rarity = 5;
                    char tag = player_dropped ? '*' : ' ';
                    if (priceU > 0) {
                        if (effCount > 1)
                            snprintf(L->name, sizeof(L->name),
                                     "%cQ%d $%u x%d",
                                     tag, rowQuality, priceU, effCount);
                        else
                            snprintf(L->name, sizeof(L->name),
                                     "%cQ%d $%u",
                                     tag, rowQuality, priceU);
                    } else if (catCategory != 0u) {
                        u64 packed = (u64)catCategory * 1000000000ULL
                                     + (u64)catSequence;
                        snprintf(L->name, sizeof(L->name),
                                 "%c%llu",
                                 tag, (unsigned long long)packed);
                    } else if (0) {
                        // Container / corpse / non-Inventory pickup — fall back
                        // to invGID + class name (old behavior).
                        L->value = (u32)(invGID & 0xFFFFFFFFu);
                        const char* s = resolved;
                        if (strncmp(s, "Item_",    5) == 0) s += 5;
                        else if (strncmp(s, "InvItem_", 8) == 0) s += 8;
                        else if (strncmp(s, "Pickup_", 7) == 0) s += 7;
                        else if (strncmp(s, "BP_",     3) == 0) s += 3;
                        if (effCount > 1)
                            snprintf(L->name, sizeof(L->name),
                                     "%.14s x%d", s, effCount);
                        else
                            snprintf(L->name, sizeof(L->name), "%.23s", s);
                    }
                    L->valid = 1;

                    // Player-drop diagnostic (rate-limited by actor identity —
                    // reuses LOOTHIT dedup below). Confirms detection lit up
                    // when the operator drops something in raid.
                    if (player_dropped) {
                        static u64 s_drop_seen[32] = {0};
                        static int s_drop_n = 0;
                        int dseen = 0;
                        for (int j = 0; j < s_drop_n; j++)
                            if (s_drop_seen[j] == actor) { dseen = 1; break; }
                        if (!dseen && s_drop_n < 32) {
                            s_drop_seen[s_drop_n++] = actor;
                            DH_INFO("DROPPED_ITEM actor=%llx cat=%u seq=%u gid=%llx cnt=%d whoDrop=%llx class=\"%s\" pos=(%.0f,%.0f,%.0f)",
                                    (unsigned long long)actor,
                                    catCategory, catSequence,
                                    (unsigned long long)itemGidActor,
                                    effCount,
                                    (unsigned long long)whoDropUid,
                                    resolved[0] ? resolved : "?",
                                    lx, ly, lz);
                        }
                    }
                    (void)itemGidActor;

                    // INNER-ITEM enumeration for Container/DeadBody/OpenBox.
                    // Verified via cold-RE 2026-09-22: FItemArray sits at
                    // actor+0x1F38 (Container-level offset, inherited by
                    // ALL container subclasses); its inner
                    // TArray<FInventoryItemInfo> Items sits at
                    //   Data @ actor+0x2040
                    //   Num  @ actor+0x2048 (int32)
                    //   Max  @ actor+0x204C (int32)
                    // Element size 0x800. FInventoryItemInfo layout:
                    //   ItemID(u64 catalog) @ 0x10 (inside FItemID)
                    //   ItemGid             @ 0x28
                    //   ItemCount           @ 0x38
                    //   ItemDurability      @ 0x40
                    {
                        struct { u64 data; i32 num; i32 max; } iarr = {0};
                        if (RpmReadVirtual(hDev, procCR3,
                                           actor + 0x2040,
                                           &iarr, sizeof(iarr)))
                        {
                            if (iarr.num > 0 && iarr.num <= 64 &&
                                iarr.max >= iarr.num && iarr.max <= 128 &&
                                iarr.data >= 0x100000ULL &&
                                iarr.data < 0x0001000000000000ULL)
                            {
                                int cap = iarr.num;
                                if (cap > 24) cap = 24;
                                for (int ii = 0; ii < cap && loot_n < DH_MAX_LOOT; ii++) {
                                    u64 iva = iarr.data + (u64)ii * 0x800ULL;
                                    u64  itemCatId = 0; // FItemID.ItemID uint64 catalog
                                    u64  itemGid   = 0;
                                    i32  itemCount = 0;
                                    float itemDur  = 0.0f;
                                    RpmReadVirtual(hDev, procCR3, iva + 0x10, &itemCatId, 8);
                                    if (!RpmReadVirtual(hDev, procCR3, iva + 0x28, &itemGid, 8))
                                        continue;
                                    if (itemGid == 0ULL && itemCatId == 0ULL) continue;
                                    RpmReadVirtual(hDev, procCR3, iva + 0x38, &itemCount, 4);
                                    RpmReadVirtual(hDev, procCR3, iva + 0x40, &itemDur,   4);
                                    if (itemCount <= 0 || itemCount > 9999) continue;
                                    // Same Category sanity as outer path:
                                    // inner FItemID.Category must be <= 200.
                                    u32 icat = (u32)(itemCatId & 0xFFFFFFFFu);
                                    u32 iseq = (u32)((itemCatId >> 32) & 0xFFFFFFFFu);
                                    if (icat == 0u || icat > 200u) continue;
                                    if (iseq == 0u || iseq > 999999999u) continue;

                                    // Stable per-item key based on actor + slot index.
                                    tmp_loot_actor[loot_n] = actor + (u64)(ii + 1) * 0x800ULL;
                                    DH_SHMEM_LOOT* IL = &tmp_loot[loot_n++];
                                    IL->x = lx; IL->y = ly; IL->z = lz;
                                    IL->rarity = 0;
                                    IL->is_corpse = 1;   // marker: inside container
                                    // Prefer catalog ItemID (stable across sessions)
                                    // over GID (per-instance).
                                    u64 packed_inner = (u64)icat * 1000000000ULL + (u64)iseq;
                                    IL->value = (u32)(packed_inner & 0xFFFFFFFFu);
                                    if (itemCount > 1)
                                        snprintf(IL->name, sizeof(IL->name),
                                                 "%llu x%d",
                                                 (unsigned long long)packed_inner, itemCount);
                                    else
                                        snprintf(IL->name, sizeof(IL->name),
                                                 "%llu",
                                                 (unsigned long long)packed_inner);
                                    IL->valid = 1;
                                }
                            }
                        }
                    }

                    // One-shot per-actor discovery log (first 30 pass'ed
                    // through all gates — should be REAL pickups only).
                    #define LOOTHIT_SLOTS 64
                    static u64 s_loot_hit_actors[LOOTHIT_SLOTS] = {0};
                    static int s_loot_hit_n = 0;
                    if (s_loot_hit_n < 30) {
                        int already = 0;
                        for (int j = 0; j < s_loot_hit_n; j++)
                            if (s_loot_hit_actors[j] == actor) { already = 1; break; }
                        if (!already) {
                            s_loot_hit_actors[s_loot_hit_n++] = actor;
                            DH_INFO("LOOTHIT actor=%llx lvl=%d vt=%llx gid=%llx name=\"%s\"(idx=%u) cnt=%d dur=%d pos=(%.0f,%.0f,%.0f)",
                                    (unsigned long long)actor, li,
                                    (unsigned long long)vt,
                                    (unsigned long long)invGID,
                                    resolved[0] ? resolved : "?",
                                    nameIdx, stackCount, durability,
                                    lx, ly, lz);
                        }
                    }
                    #undef LOOTHIT_SLOTS
                }
            }

            // (legacy per-actor walker removed — new all-levels loop above)

            // Sort tmp_loot by actor address for deterministic per-actor
            // ordering. Overlay indexes shmem entries directly — reshuffling
            // emission order between ticks visually looks like dots teleport
            // even when actor positions are stable. Actor address is stable
            // across the actor's lifetime → same actor always at same slot.
            for (int a = 1; a < loot_n; a++) {
                DH_SHMEM_LOOT keyL = tmp_loot[a];
                u64          keyA = tmp_loot_actor[a];
                int b = a - 1;
                while (b >= 0 && tmp_loot_actor[b] > keyA) {
                    tmp_loot[b + 1]       = tmp_loot[b];
                    tmp_loot_actor[b + 1] = tmp_loot_actor[b];
                    b--;
                }
                tmp_loot[b + 1]       = keyL;
                tmp_loot_actor[b + 1] = keyA;
            }

            g_shmem->loot_seq = g_shmem->loot_seq + 1;
            MemoryBarrier();
            memcpy((void*)g_shmem->loot, tmp_loot,
                   sizeof(DH_SHMEM_LOOT) * loot_n);
            g_shmem->loot_count = (u32)loot_n;
            MemoryBarrier();
            g_shmem->loot_seq = g_shmem->loot_seq + 1;

            static u32 s_loot_tick = 0;
            if (((s_loot_tick++) % 8) == 0) {
                if (loot_n > 0) {
                    DH_INFO("LOOT_PUB %d entries, first=[cat=%u pos=(%.0f,%.0f,%.0f)] shmem_count=%u",
                            loot_n, tmp_loot[0].value,
                            tmp_loot[0].x, tmp_loot[0].y, tmp_loot[0].z,
                            g_shmem->loot_count);
                } else {
                    DH_INFO("LOOT_PUB 0 entries (shmem_count=%u)",
                            g_shmem->loot_count);
                }
                // NEARBY diagnostic — list all loot dots within 500u (~5m).
                float mx = g_shmem->myX, my = g_shmem->myY, mz = g_shmem->myZ;
                DH_INFO("MYPOS=(%.0f, %.0f, %.0f)", mx, my, mz);
                int nearN = 0;
                for (int q = 0; q < loot_n; q++) {
                    float dx = tmp_loot[q].x - mx;
                    float dy = tmp_loot[q].y - my;
                    float dz = tmp_loot[q].z - mz;
                    float d2 = dx*dx + dy*dy + dz*dz;
                    if (d2 <= 1500.0f * 1500.0f) {
                        float d = sqrtf(d2);
                        DH_INFO("  NEAR15 %.2fm actor=%llx cat=%u pos=(%.0f,%.0f,%.0f) name=\"%s\" corpse=%d",
                                d / 100.0f,
                                (unsigned long long)tmp_loot_actor[q],
                                tmp_loot[q].value,
                                tmp_loot[q].x, tmp_loot[q].y, tmp_loot[q].z,
                                tmp_loot[q].name, tmp_loot[q].is_corpse);
                        nearN++;
                    }
                }
                if (nearN == 0)
                    DH_INFO("  NEAR5 (nothing within 5m)");
            }
#endif  // loot walker disabled
            g_shmem->loot_count = 0;
            MemoryBarrier();
            g_shmem->loot_seq   = g_shmem->loot_seq + 1;

            // Rebuild bot list from scratch each rescan
            int new_bot_n = 0;
            int cnt_ok=0, cnt_sanity=0;
            for (int ai = 0; ai < actMax && new_bot_n < DH_MAX_PLAYERS; ai++) {
                u64 actor = actorPtrs[ai] & DF_ENC_PTR_MASK;
                if (!actor || actor < 0x100000) continue;

                int dup = 0;
                for (int s = 0; s < seen_n; s++) {
                    if (seen_pawns[s] == actor) { dup = 1; break; }
                }
                if (dup) continue;

                u8 posBuf[12];
                if (!RpmReadVirtual(hDev, procCR3, actor + 0x1D10, posBuf, 12)) continue;
                float bx, by, bz;
                memcpy(&bx, posBuf + 0, 4);
                memcpy(&by, posBuf + 4, 4);
                memcpy(&bz, posBuf + 8, 4);
                if (!(bx == bx && by == by && bz == bz)) { cnt_sanity++; continue; }
                if (fabsf(bx) < 50.f && fabsf(by) < 50.f) { cnt_sanity++; continue; }
                if (fabsf(bx) > 500000.f || fabsf(by) > 500000.f) { cnt_sanity++; continue; }
                if (bz < -5000.f || bz > 15000.f) { cnt_sanity++; continue; }

                s_bot_pawns[new_bot_n++] = actor;
                cnt_ok++;
            }
            s_bot_count = new_bot_n;

            static u32 dbg_tick = 0;
            if ((dbg_tick++ % 4) == 0) {
                DH_INFO("actor rescan @4Hz: %d actors -> %d bots (rejected %d)",
                        actMax, cnt_ok, cnt_sanity);
            }
        } while (0);
    }

    local.count = cnt;

commit:
    // Publish entity + cam block under primary seqlock. Main tick also
    // updates cam fields inline as a fallback for when the dedicated cam
    // thread failed to spawn (err=193 seen on 25H2). Both seqlocks track
    // consistency; overlay reads under either.
    g_shmem->sequence = g_shmem->sequence + 1;    // odd
    MemoryBarrier();
    g_shmem->count  = local.count;
    g_shmem->myTeam = local.myTeam;
    // Cam fields — OWNED by CamThreadBody @120Hz under cam_seq.
    // Main tick (~14Hz effective) writing them here creates temporal
    // skew that causes box-flicker on smooth camera pan (main writes
    // 70ms-stale cam over fresh cam-thread data without bumping cam_seq).
    // Left as read-only fallback comment; do NOT touch myX/Yaw/Fov here.
    memcpy((void*)g_shmem->players, (void*)local.players, sizeof(local.players));
    g_shmem->frame_id++;
    MemoryBarrier();
    g_shmem->sequence = g_shmem->sequence + 1;    // even

    // FAST-TRACK: publish (pawn, root, slot) so cam thread can refresh
    // positions @120Hz between main ticks. Only remote non-dead entities.
    DH_FAST_ENTRY ft[DH_FAST_TRACK_MAX];
    int ft_n = 0;
    for (u32 i = 0; i < local.count && ft_n < DH_FAST_TRACK_MAX; i++) {
        DH_SHMEM_PLAYER* pp = &local.players[i];
        if (!pp->valid || pp->local || pp->is_dead) continue;
        if (!local_pawn_track[i]) continue;
        ft[ft_n].pawn    = local_pawn_track[i];
        ft[ft_n].root    = local_root_track[i];
        ft[ft_n].slot    = i;
        ft[ft_n].active  = 1;
        ft[ft_n].is_dead = 0;
        ft_n++;
    }
    while (InterlockedCompareExchange(&g_fast_lock, 1, 0) != 0) { /* spin */ }
    memcpy((void*)g_fast_track, ft, sizeof(DH_FAST_ENTRY) * ft_n);
    // Zero old entries.
    for (int i = ft_n; i < g_fast_track_n; i++) {
        g_fast_track[i].active = 0;
        g_fast_prev[i].valid = 0;
    }
    g_fast_track_n = ft_n;
    InterlockedExchange(&g_fast_lock, 0);
}

// Thread-entry wrapper for combined `run` command in main.c. The struct
// layout matches main.c's local RunCtx {hDev, cr3, base}.
DWORD WINAPI DaemonEspRun_ThreadEntry(LPVOID param)
{
    struct { HANDLE hDev; u64 cr3; u64 base; } *ctx = param;
    return (DWORD)DaemonEspRun(ctx->hDev, ctx->cr3, ctx->base);
}

extern void dh_diag_line(const char* fmt, ...);

int DaemonEspRun(HANDLE hDev, u64 procCR3, u64 base)
{
    dh_diag_line("daemon: DaemonEspRun ENTER hDev=%p procCR3=0x%llX base=0x%llX",
                 hDev, (unsigned long long)procCR3, (unsigned long long)base);
    if (!create_shmem()) {
        dh_diag_line("daemon: create_shmem FAILED gle=%lu", (unsigned long)GetLastError());
        return 1;
    }
    dh_diag_line("daemon: shmem OK");

    // Publish RPM handles for the fast cam thread.
    g_hDev = hDev; g_procCR3 = procCR3; g_base = base;
    g_cam_stop = 0;
    g_cam_thread = CreateThread(NULL, 0, CamThreadBody, NULL, 0, NULL);
    if (g_cam_thread) {
        // Cam thread runs at 250Hz — bump it above main to keep camera responsive
        // even under bridge_read backpressure.
        SetThreadPriority(g_cam_thread, THREAD_PRIORITY_HIGHEST);
        DH_INFO("cam thread spawned @250Hz — camera decoupled from entity walker");
    } else {
        DH_WARN("cam thread spawn failed err=%lu — camera will lag entity walker",
                GetLastError());
    }

    // Primary path: Unicorn-emulated Delta DecVector via GObjects walk.
    // Falls back to hard-coded FENCVEC_WRAPPER VA if the SDK walk misses.
    u64 gObjectsVA = base + DF_RVA_GOBJECTS;
    u64 gNamesVA   = base + DF_RVA_GNAMES;
    if (UcDecryptInit(hDev, procCR3, base, gObjectsVA, gNamesVA, 0)) {
        g_uc_ready = 1;
        dh_diag_line("daemon: UcDecrypt READY @0x%llX (GObjects+GNames resolved)",
                     (unsigned long long)UcDecryptGetFnVa());
        DH_INFO("Unicorn DecVector emulator ready @0x%llX",
                (unsigned long long)UcDecryptGetFnVa());
    } else {
        dh_diag_line("daemon: UcDecrypt FAILED — RPM GObjects sanity fail; enemy decrypt OFF, "
                     "ESP will show only teammates + plaintext-relevance-group");
        DH_WARN("Unicorn init failed — enemy decrypt disabled, falling back "
                "to pawn+0x1C2C FRepMovement only");
    }

    // Init Scheme-B XORPS decrypt (kept as secondary path for the L1 case).
    if (AceDecryptXorpsInit(hDev, procCR3, base, 0x20300000ULL)) {
        g_xorps_ready = 1;
        DH_INFO("XORPS Scheme-B decrypt ready as backup");
    }
    // VTBL kept as diagnostic fallback (not used per default anymore).
    if (VtblDecryptInitStatic()) g_vtbl_ready = 1;

    // Loot pipeline DISABLED per user request 2026-09-22. Catalog init +
    // per-tick loot walker cut to remove ~22 sec boot cost and stop the
    // false-positive dots. Re-enable by defining DH_ENABLE_LOOT.

    // Raise Windows timer resolution to 1ms for accurate Sleep(1).
    // Default is 15.6ms; without this our poll loop hard-caps at ~64Hz.
    timeBeginPeriod(1);

    // Named event so overlay can graceful-signal daemon shutdown, or restart.
    HANDLE stop_ev = CreateEventW(NULL, TRUE, FALSE, L"Global\\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}");
    (void)stop_ev;

    DH_INFO("polling at 120Hz");
    // Main tick rate meter — updates shmem->main_hz every 30 ticks.
    LARGE_INTEGER hzFreq = {0}, hzMark = {0};
    QueryPerformanceFrequency(&hzFreq);
    QueryPerformanceCounter(&hzMark);
    for (u32 tick = 0; ; tick++) {
        RpmBumpGeneration();   // invalidate VA→PA cache — safe per-tick reuse
        if ((tick % 30) == 0 && tick > 0) {
            LARGE_INTEGER now_qpc;
            QueryPerformanceCounter(&now_qpc);
            double secs = (double)(now_qpc.QuadPart - hzMark.QuadPart) / (double)hzFreq.QuadPart;
            if (secs > 0.001) g_shmem->main_hz = (float)(30.0 / secs);
            hzMark = now_qpc;
        }
        // Periodic diag snapshot every 300 ticks (~5-10s) — enemy count,
        // decrypt state, tick rate. Server side can chart these to spot
        // "overlay attached but zero enemies for entire raid" broken states.
        if ((tick % 300) == 0 && tick > 0) {
            int n_valid = 0, n_local = 0, n_bot = 0, n_alive = 0, n_ready_pos = 0;
            for (int i = 0; i < DH_MAX_PLAYERS; i++) {
                DH_SHMEM_PLAYER* p = &g_shmem->players[i];
                if (!p->valid) continue;
                n_valid++;
                if (p->local)  n_local++;
                if (p->is_bot) n_bot++;
                if (!p->is_dead) n_alive++;
                if (p->x != 0.0f || p->y != 0.0f) n_ready_pos++;
            }
            dh_diag_line("stats: tick=%u hz=%.1f count=%u valid=%d alive=%d bot=%d local=%d "
                         "with_pos=%d uc_ready=%d xorps_ready=%d vtbl_ready=%d "
                         "myX=%.0f myY=%.0f myZ=%.0f",
                         tick, g_shmem->main_hz, (unsigned)g_shmem->count,
                         n_valid, n_alive, n_bot, n_local, n_ready_pos,
                         g_uc_ready, g_xorps_ready, g_vtbl_ready,
                         g_shmem->myX, g_shmem->myY, g_shmem->myZ);
        }
        if (stop_ev && WaitForSingleObject(stop_ev, 0) == WAIT_OBJECT_0) {
            DH_INFO("daemon-esp stop signal received");
            ResetEvent(stop_ev);
            break;
        }
        // Delta-alive health check: every 60 ticks (~500ms), read the MZ
        // header at the image base. Delta exit → CR3 stale, page unmapped,
        // read fails. Three consecutive misses = process gone, return so
        // main.c can signal overlay and shut the whole stack down.
        if ((tick % 60) == 0 && tick > 0) {
            static int s_dead_reads = 0;
            u16 mz = 0;
            if (!RpmReadVirtual(hDev, procCR3, base, &mz, 2) || mz != 0x5A4D) {
                s_dead_reads++;
                DH_INFO("Delta health check miss %d/3 (mz=0x%04X)", s_dead_reads, mz);
                if (s_dead_reads >= 3) {
                    DH_INFO("Delta gone — 3 consecutive MZ read failures, exiting");
                    break;
                }
            } else if (s_dead_reads > 0) {
                s_dead_reads = 0;   // reset on first successful read
            }
        }
        poll_and_publish(hDev, procCR3, base);
        if ((tick % 100) == 0) {
            DH_INFO("tick %u  players=%u  frame=%u  myT=T%d",
                    tick, g_shmem->count, g_shmem->frame_id, g_shmem->myTeam);
            // Stream first 8 players' positions so operator can tell if enemy
            // pos actually updates or is static (spawn point).
            for (u32 i = 0; i < g_shmem->count && i < 8; i++) {
                DH_SHMEM_PLAYER* p = &g_shmem->players[i];
                char nameA[64] = {0};
                WideCharToMultiByte(CP_UTF8, 0, p->name, -1, nameA, sizeof(nameA), NULL, NULL);
                DH_INFO("  [%u] T%d %s %s %-14s (%9.1f, %9.1f, %8.1f)",
                        i, p->team,
                        p->is_bot ? "BOT" : "PL ",
                        p->is_dead ? "DED" : "ALV",
                        nameA, p->x, p->y, p->z);
            }
        }
        // 120Hz cap — matches overlay render rate.
        static LARGE_INTEGER qpcFreq = {0}, qpcLast = {0};
        if (qpcFreq.QuadPart == 0) {
            QueryPerformanceFrequency(&qpcFreq);
            QueryPerformanceCounter(&qpcLast);
        }
        const double target = 1.0 / 120.0;  // 8.33 ms per tick = 120 Hz
        while (1) {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            double elapsed = (double)(now.QuadPart - qpcLast.QuadPart) / (double)qpcFreq.QuadPart;
            if (elapsed >= target) { qpcLast = now; break; }
            if (target - elapsed > 0.002) Sleep(1);
        }
    }
    // Stop cam thread first — it uses g_shmem/g_hDev.
    InterlockedExchange(&g_cam_stop, 1);
    if (g_cam_thread) {
        WaitForSingleObject(g_cam_thread, 200);
        CloseHandle(g_cam_thread);
        g_cam_thread = NULL;
    }
    if (stop_ev) CloseHandle(stop_ev);
    UnmapViewOfFile(g_shmem); g_shmem = NULL;
    CloseHandle(g_mapping); g_mapping = NULL;
    return 0;
}
