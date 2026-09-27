// DeltaHack VMProtect marker wrapper — pulled in wherever we want to mark
// hot functions for Ultra virtualization. Compiles to no-ops in non-VMP
// builds so dev iterations don't need the SDK on disk.
#pragma once

#include <stdbool.h>  // required by VMProtectSDK.h (C99 bool)

#ifdef DH_VMPROTECT
#  include "../deps/vmprotect/inc/VMProtectSDK.h"
#else
#  define VMProtectBegin(name)         ((void)0)
#  define VMProtectBeginVirtualization(name)  ((void)0)
#  define VMProtectBeginMutation(name)        ((void)0)
#  define VMProtectBeginUltra(name)           ((void)0)
#  define VMProtectEnd()                      ((void)0)
#endif
