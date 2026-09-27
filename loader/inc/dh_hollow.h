#pragma once
#include "dh_common.h"
#include <windows.h>

// Process-hollow into %SystemRoot%\System32\dllhost.exe.
//
// Flow:
//   Original dh_loader.exe (or whatever we're named) → HollowSelfIntoDllhost()
//   → spawns C:\Windows\System32\dllhost.exe SUSPENDED
//   → unmaps target's dllhost image, allocs at same base, writes our PE bytes
//   → fixes PEB.ImageBaseAddress, patches thread context RIP to our entry
//   → ResumeThread, exits self.
//
// The hollowed dllhost.exe now runs our code. Task Manager sees it as a
// signed Microsoft binary (name+path+authenticode all legit) — user cannot
// distinguish from real COM Surrogate instances without deep memory scan.
//
// Mode signaling: the child receives DH_MODE env var (daemon-esp/overlay-imgui)
// and dispatches from wmain on that. Env inheritance handled via
// lpEnvironment in CreateProcessW.
//
// Return: 0 on success (parent has ALREADY called ExitProcess by the time
// caller sees anything — this is fire-and-forget). Non-zero on failure —
// caller falls back to running unhollowed.

int  HollowSelfIntoDllhost(const wchar_t* mode);

// Are we the hollowed dllhost instance? True when process image name matches
// "dllhost.exe" (case-insensitive) AND DH_MODE env is set. Used by wmain
// to decide: dispatch from env vs from argv.
BOOL AmIHollowed(void);

// Read DH_MODE env var (set by parent before CreateProcessW). Returns
// pointer to static wide buffer, NULL if unset. Used only when AmIHollowed().
const wchar_t* GetHollowMode(void);
