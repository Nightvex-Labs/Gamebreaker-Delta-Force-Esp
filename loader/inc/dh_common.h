// DeltaHack loader — shared types/macros.
// Target: Win11 24H2/25H2, Intel+AMD, HVCI ON, Hyper-V ON.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _CRT_SECURE_NO_WARNINGS
// UNICODE / _UNICODE are supplied by the build script (build.bat), not here.

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef int8_t    i8;
typedef int16_t   i16;
typedef int32_t   i32;
typedef int64_t   i64;

#define DH_ARR_LEN(x)   (sizeof(x) / sizeof((x)[0]))
#define DH_UNUSED(x)    ((void)(x))

// Log levels — routed to stderr for now; later switch to log-to-file + optional
// gh push once we wire the private log repo.
typedef enum {
    DH_LOG_TRACE = 0,
    DH_LOG_INFO  = 1,
    DH_LOG_WARN  = 2,
    DH_LOG_ERROR = 3,
    DH_LOG_FATAL = 4
} dh_log_level;

void dh_log(dh_log_level lvl, const char* fmt, ...);

#define DH_TRACE(...) dh_log(DH_LOG_TRACE, __VA_ARGS__)
#define DH_INFO(...)  dh_log(DH_LOG_INFO,  __VA_ARGS__)
#define DH_WARN(...)  dh_log(DH_LOG_WARN,  __VA_ARGS__)
#define DH_ERROR(...) dh_log(DH_LOG_ERROR, __VA_ARGS__)
#define DH_FATAL(...) do { dh_log(DH_LOG_FATAL, __VA_ARGS__); ExitProcess(1); } while (0)

// Result codes used throughout the loader.
typedef enum {
    DH_OK               = 0,
    DH_ERR_GENERIC      = 1,
    DH_ERR_BAD_ARG      = 2,
    DH_ERR_NOT_ADMIN    = 3,
    DH_ERR_SVC_INSTALL  = 10,
    DH_ERR_SVC_START    = 11,
    DH_ERR_SVC_STOP     = 12,
    DH_ERR_SVC_REMOVE   = 13,
    DH_ERR_DEV_OPEN     = 20,
    DH_ERR_DEV_IOCTL    = 21,
    DH_ERR_DB_UNPACK    = 30,
    DH_ERR_DRV_WRITE    = 31,
    DH_ERR_TARGET_NOT_FOUND = 40,
    DH_ERR_RPM_FAIL     = 41,
    DH_ERR_SPAWN        = 50
} dh_status;

// Version marker — bumped on any behavior change.
#define DH_LOADER_VERSION_MAJOR  0
#define DH_LOADER_VERSION_MINOR  0
#define DH_LOADER_VERSION_PATCH  1
#define DH_LOADER_VERSION_STR    "0.0.1"

// ============================================================
// Delta Force offsets — Global/NA build, image base 0x140000000.
// Struct offsets from UC forum leak (packmax2 2026-09-04). Global RVAs
// from Dumper-7 09-17 run.
// ACE encrypts c2w.translation with XOR 0x0E per byte (12-byte FVector).
// ============================================================

// Global RVAs (from Dumper-7 output for this build)
#define DF_RVA_GOBJECTS            0x1E689F18
#define DF_RVA_GWORLD              0x1DA98608
#define DF_RVA_FNAMEPOOL           0x1E661B40

// UObject (Delta reordered)
#define DF_UOBJ_VTABLE             0x00
#define DF_UOBJ_CLASS              0x08
#define DF_UOBJ_OUTER              0x10
#define DF_UOBJ_FLAGS              0x18
#define DF_UOBJ_NAME               0x1C
#define DF_UOBJ_INDEX              0x24

// UStruct — for Class hierarchy walk
#define DF_USTRUCT_SUPER           0x48

// AActor
#define DF_ACTOR_ROOTCOMPONENT     0x180
#define DF_ACTOR_INSTIGATOR        0x168

// USceneComponent/UPrimitiveComponent
// ComponentToWorld @ 0x210 (in UPrimitiveComponent) — FTransform
// FTransform layout: FQuat Rot@0x00 (16B), FVector Trans@0x10 (12B, ENCRYPTED XOR 0x0E), FVector Scale@0x20 (12B)
#define DF_PRIMCOMP_C2W            0x210
#define DF_PRIMCOMP_RENDER         0x310
#define DF_PRIMCOMP_RENDER2        0x314
#define DF_FTRANSFORM_TRANSLATION  0x10
#define DF_FTRANSFORM_ROTATION     0x00
#define DF_FTRANSFORM_SCALE        0x20

// APawn
#define DF_PAWN_PLAYERSTATE        0x390
#define DF_PAWN_CONTROLLER         0x3A8

// ACharacter
#define DF_CHAR_MESH               0x3D0
#define DF_CHAR_MOVEMENT           0x3D8

// APlayerController
#define DF_PC_ACKPAWN              0x3F0
#define DF_PC_MYHUD                0x400
#define DF_PC_CAMERAMANAGER        0x408

// UWorld
#define DF_WORLD_NETDRIVER         0x30
#define DF_WORLD_GAMESTATE         0x140    // encrypted OR XOR 0x0E on ptr bytes
#define DF_WORLD_OWNINGGAMEINST    0x190
#define DF_WORLD_PERSISTENTLEVEL   0x520    // cached raw pointer (0xF8 is encrypted version)
#define DF_WORLD_WORLDPOS          0x640

// AGameStateBase
#define DF_GAMESTATE_PLAYERARRAY   0x388    // TArray<APlayerState*>

// APlayerState
#define DF_PLAYERSTATE_PAWNPRIVATE 0x3F8
#define DF_PLAYERSTATE_NAMEPRIV    0x478    // FString

// GPPlayerState (Delta gameplay layer)
#define DF_GPPS_BFINISHGAME        0x4C8
#define DF_GPPS_TEAMID             0x660
#define DF_GPPS_CAMP               0x664

// DFMPlayerState
#define DF_DFMPS_HEROID            0x9F8

// GPCharacterBase
#define DF_GPCHAR_BLACKBOARD       0x1020
#define DF_GPCHAR_ATTRCENTER       0x1050
#define DF_GPCHAR_CURWEAPON        0x1788

// GPBlackboardComponent
#define DF_GPBB_CHARMOVEMENT       0x168

// DFMBlackboardComponent
#define DF_DFMBB_INTERACTOR        0x19D0
#define DF_DFMBB_HEALTHDATA        0x1A08
#define DF_DFMBB_EQUIPCOMP         0x1A30

// GPHealthDataComponent
#define DF_GPHD_RESCUETARGET       0x940
#define DF_GPHD_RESCUESTART        0xA3C
#define DF_GPHD_RESCUEEND          0xA40

// DFMCharacterAttributeCenterComponent
#define DF_DFMATTR_HEALTH          0x2F0    // AttributeSetHealth

// GPAttributeSetHealth
#define DF_HEALTH_CURRENT          0x3C
#define DF_HEALTH_MAX              0x50

// GPWeaponBase
#define DF_WEAPON_MESH             0x370
#define DF_WEAPON_FIRING           0x4B8

// CharacterEquipComponent
#define DF_EQUIP_INFOARRAY         0x1D8

// USkinnedMeshComponent
#define DF_MESH_SKELETALMESH       0x728
#define DF_MESH_BONEARRAY          0x760
#define DF_MESH_BONEARRAY2         0x770

// UCharacterMovementComponent
#define DF_MOVE_VELOCITY           0x2B0

// APlayerCameraManager
#define DF_PCM_VIEWTARGET          0x30860
#define DF_PCM_CAMERACACHE         0x31DA0   // private cache (real)

// ULevel
#define DF_LEVEL_ACTORS            0x98

// UGameInstance
#define DF_GAMEINST_LOCALPLAYERS   0x38

// UPlayer
#define DF_PLAYER_PC               0x30

// ACE decrypt: XOR 0x0E per byte, applied to encrypted buffers.
// Used on:
//   - UPrimitiveComponent.ComponentToWorld.Translation (12 bytes @ +0x210+0x10)
//   - Possibly other encrypted pointers (test per-field)
#define DF_ACE_XOR_KEY             0x0E
