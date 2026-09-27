// dh_diag.h — telemetry-friendly diag writers. See dh_diag.c for detail.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Append one printf-style line to C:\Users\Public\dh_reader.log.
// Silent on failure. Auto-rotates at 2 MB. Safe to call from any thread.
void dh_diag_line(const char* fmt, ...);

// Kick off background thread that snapshots the process list every 30 sec
// to C:\Users\Public\dh_procs.log. Idempotent (safe to call from anywhere).
void dh_diag_start_procs_snapshot_thread(void);

#ifdef __cplusplus
}
#endif
