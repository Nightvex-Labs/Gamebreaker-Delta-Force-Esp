#pragma once
#include "dh_common.h"

// Unpack a kdu DBPACK '.bin' payload (PA30 MSDelta blob XOR'd with rolling key)
// back into the original .sys driver bytes.
//
// Caller frees *OutBuf via HeapFree(GetProcessHeap(), 0, *OutBuf).
BOOL DbUnpack(const void* InBuf, DWORD InSize, void** OutBuf, DWORD* OutSize);
