//go:build windows

package probe

import (
	"os"
	"strconv"
	"time"
)

func pingCommand(targetIP string, timeout time.Duration) (string, []string) {
	ms := maxInt(1, int(timeout/time.Millisecond))
	return "ping", []string{"-n", "1", "-w", strconv.Itoa(ms), targetIP}
}

func traceCommand(targetIP string, maxHops int, timeout time.Duration) (string, []string) {
	ms := maxInt(1, int(timeout/time.Millisecond))
	return "tracert", []string{"-d", "-w", strconv.Itoa(ms), "-h", strconv.Itoa(maxHops), targetIP}
}

func stableLocaleEnv() []string { return os.Environ() }

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
