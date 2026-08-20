package probe

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

type TraceSample struct {
	TTL         int
	Responder   string
	RTTMs       float64
	OK          bool
	Unreachable bool
	Note        string
}

var (
	hopLineRe  = regexp.MustCompile(`^\s*(\d{1,3})\s+(.*)$`)
	msRe       = regexp.MustCompile(`^(<)?([0-9]+(?:\.[0-9]+)?)\s*ms$`)
	pingTimeRe = regexp.MustCompile(`(?i)(?:time|시간)[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms`)
)

func ParseTraceOutput(out string) []TraceSample {
	var samples []TraceSample
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		match := hopLineRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		ttl, err := strconv.Atoi(match[1])
		if err != nil || ttl < 1 {
			continue
		}
		samples = append(samples, parseHopLine(ttl, match[2])...)
	}
	return samples
}

func parseHopLine(ttl int, rest string) []TraceSample {
	var out []TraceSample
	fields := strings.Fields(rest)
	current := ""
	var pending []float64
	unreachable := false
	note := ""

	flush := func(ip string) {
		for _, rtt := range pending {
			out = append(out, TraceSample{TTL: ttl, Responder: ip, RTTMs: rtt, OK: true})
		}
		pending = nil
	}

	for i := 0; i < len(fields); i++ {
		field := fields[i]
		if field == "*" {
			out = append(out, TraceSample{TTL: ttl})
			continue
		}
		if strings.HasPrefix(field, "!") {
			unreachable = true
			note = unreachableNote(field)
			continue
		}
		if i+1 < len(fields) && strings.EqualFold(fields[i+1], "ms") {
			if rtt, ok := parseMs(field + " ms"); ok {
				if current == "" {
					pending = append(pending, rtt)
				} else {
					out = append(out, TraceSample{TTL: ttl, Responder: current, RTTMs: rtt, OK: true})
				}
				i++
				continue
			}
		}
		if rtt, ok := parseMs(field); ok {
			if current == "" {
				pending = append(pending, rtt)
			} else {
				out = append(out, TraceSample{TTL: ttl, Responder: current, RTTMs: rtt, OK: true})
			}
			continue
		}
		if ip := extractIP(field); ip != "" {
			current = ip
			flush(ip)
		}
	}
	flush("")
	if unreachable {
		for i := range out {
			if out[i].OK {
				out[i].Unreachable = true
				out[i].Note = note
			}
		}
	}
	return out
}

func ParsePingRTT(out string) (float64, bool) {
	match := pingTimeRe.FindStringSubmatch(out)
	if match == nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, false
	}
	lower := strings.ToLower(out)
	if (strings.Contains(lower, "time<") || strings.Contains(out, "시간<")) && value == 1 {
		return 0.5, true
	}
	return value, true
}

func parseMs(s string) (float64, bool) {
	match := msRe.FindStringSubmatch(strings.ToLower(s))
	if match == nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return 0, false
	}
	if match[1] == "<" {
		return 0.5, true
	}
	return value, true
}

func extractIP(token string) string {
	token = strings.Trim(token, "()[],:")
	if ip := net.ParseIP(token); ip != nil {
		return ip.String()
	}
	return ""
}

func unreachableNote(token string) string {
	switch token {
	case "!H":
		return "host unreachable"
	case "!N":
		return "network unreachable"
	case "!P":
		return "protocol unreachable"
	case "!X", "!A":
		return "administratively prohibited"
	default:
		return "unreachable " + token
	}
}
