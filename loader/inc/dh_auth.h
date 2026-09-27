// dh_auth.h — payload-side token validation against koenflow backend.
//
// Phase 1: DhAuthCheckStart() — validates the launcher-issued KOENFLOW_LAUNCH_TOKEN
// against the /api/public/launch-tokens/preview endpoint. Blocks standalone execution
// of a leaked (KFPL-decrypted) dh_loader.exe: no launcher context → no valid token →
// backend returns Valid=false → silent exit.
//
// The launcher sets these env vars before spawn (KOENFLOW_ and KEONFLOW_ prefixes,
// both supported):
//   KOENFLOW_LAUNCH_TOKEN — 36-char UUID, TTL ~2 min
//   KOENFLOW_BACKEND_URL  — https://koenflow.com:23932
//   KOENFLOW_REQUIRE_HTTPS — "true" / "false"
//   KOENFLOW_PINNED_CERTIFICATE_SHA256 — optional pin
//   KOENFLOW_PINNED_PUBLIC_KEY_SHA256  — optional pin
#pragma once

#include "dh_common.h"

// Returns TRUE iff the current process was spawned by the launcher with a valid
// launchToken that the backend confirms is still non-consumed and non-expired.
// Source order:
//   1. env KOENFLOW_LAUNCH_TOKEN / KEONFLOW_LAUNCH_TOKEN (unelevated path)
//   2. --koenflow-launch-context <path> / --keonflow-launch-context <path>
//      argv (elevated path — UseShellExecute=true blocks env inheritance
//      through UAC, so KoenFlow writes a JSON/KFPC file instead)
// Silent by design — no MessageBox, no log surface in DH_RELEASE builds.
// Callers should silently ExitProcess on FALSE.
BOOL DhAuthCheckStart(int argc, wchar_t** argv);

// Presence-only variant — TRUE iff KoenFlow context is provided (env var or
// --koenflow-launch-context argv). Does NOT hit the backend, so it's safe to
// call every start; the backend's /preview endpoint consumes the token on
// first call (KoenFlow itself already called it during LaunchProductAsync,
// so any second call from us returns valid:false). License validity is
// enforced server-side inside KoenFlow before our spawn — presence of a
// context here means KoenFlow already accepted the license.
// Standalone pirate run: no env, no --koenflow-launch-context → returns FALSE.
BOOL DhAuthPresenceCheck(int argc, wchar_t** argv);
