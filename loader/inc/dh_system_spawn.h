// dh_system_spawn.h — SYSTEM (S-1-5-18) self-elevation via Task Scheduler.
// See dh_system_spawn.c for method + rationale (ACE decoy filter bypass).
#pragma once

#include "dh_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// TRUE iff current process is running as NT AUTHORITY\SYSTEM.
BOOL DhIsSystem(void);

// Register + run + delete a temp Task Scheduler entry that spawns our own
// exe as SYSTEM with argument `daemon-esp`. Returns TRUE on scheduling
// success (does NOT verify the daemon actually reached shmem creation —
// use DhWaitForDaemonShmem for that).
BOOL DhSpawnSelfAsSystemDaemon(void);

// Poll for the daemon-esp shmem (Global\{7A9F3B21-...}) up to timeout_ms.
// TRUE if it appears (i.e. SYSTEM daemon reached DaemonEspRun + create_shmem).
BOOL DhWaitForDaemonShmem(DWORD timeout_ms);

#ifdef __cplusplus
}
#endif
