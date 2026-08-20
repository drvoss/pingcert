//go:build !windows

package probe

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func pingCommand(targetIP string, timeout time.Duration) (string, []string) {
	return "ping", []string{"-c", "1", "-W", strconv.Itoa(durationSecondsCeil(timeout)), "-n", targetIP}
}

func traceCommand(targetIP string, maxHops int, timeout time.Duration) (string, []string) {
	return "traceroute", []string{
		"-n", "-q", "3", "-w", strconv.Itoa(durationSecondsCeil(timeout)),
		"-m", strconv.Itoa(maxHops), targetIP,
	}
}

func stableLocaleEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "LC_ALL=") || strings.HasPrefix(value, "LANG=") {
			continue
		}
		env = append(env, value)
	}
	return append(env, "LC_ALL=C", "LANG=C")
}
