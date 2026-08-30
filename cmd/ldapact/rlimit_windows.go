//go:build windows

package main

import "log/slog"

// disableCoreDumps is a no-op on Windows: crash-dump behavior is controlled
// by the OS/local policy, not an RLIMIT-style per-process limit.
func disableCoreDumps(_ *slog.Logger) {}
