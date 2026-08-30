//go:build !windows

package main

import (
	"log/slog"
	"syscall"
)

// disableCoreDumps sets RLIMIT_CORE to zero so secrets never leak through
// crash artifacts (KTD 17). Best-effort: some platforms refuse to lower the
// limit, which is logged but not fatal.
func disableCoreDumps(logger *slog.Logger) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		logger.Warn("cannot read RLIMIT_CORE", "event", "core_dump.limit_unavailable", "error", err)
		return
	}
	lim.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		logger.Warn("cannot disable core dumps", "event", "core_dump.disable_failed", "error", err)
	}
}
