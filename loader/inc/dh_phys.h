#pragma once
#include "dh_common.h"

// WinIo-style physical memory I/O via EneIo64 IOCTLs.
// Map → memcpy → unmap per read; no persistent mapping.

BOOL PhysRead(HANDLE hDev, u64 physAddr, void* buf, u32 size);
BOOL PhysWrite(HANDLE hDev, u64 physAddr, const void* buf, u32 size);
