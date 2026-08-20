package probe

import "testing"

func TestParsePingLocalizedAndSubMillisecond(t *testing.T) {
	tests := []string{
		"Reply from 1.2.3.4: bytes=32 time<1ms TTL=64",
		"1.2.3.4의 응답: 바이트=32 시간<1ms TTL=64",
	}
	for _, input := range tests {
		got, ok := ParsePingRTT(input)
		if !ok || got != 0.5 {
			t.Fatalf("ParsePingRTT(%q) = %v, %v", input, got, ok)
		}
	}
}

func TestParseWindowsAndUnixTrace(t *testing.T) {
	input := `
  1    <1 ms    1 ms    2 ms  192.168.0.1
  2     *        *       *
  3  10.0.0.1  8.1 ms  10.0.0.2  8.9 ms  10.0.0.1  8.3 ms
`
	got := ParseTraceOutput(input)
	if len(got) != 9 {
		t.Fatalf("got %d samples: %+v", len(got), got)
	}
	if got[0].Responder != "192.168.0.1" || got[0].RTTMs != 0.5 {
		t.Fatalf("windows hop: %+v", got[0])
	}
	if got[3].OK || got[4].OK || got[5].OK {
		t.Fatalf("timeout hop parsed as reply: %+v", got[3:6])
	}
	if got[6].Responder != "10.0.0.1" || got[7].Responder != "10.0.0.2" {
		t.Fatalf("ECMP attribution failed: %+v", got[6:])
	}
}

func TestParseGarbageDoesNotInventHops(t *testing.T) {
	for _, input := range []string{"", "not a trace", "  1 localized prose only"} {
		if got := ParseTraceOutput(input); len(got) != 0 {
			t.Fatalf("invented hops from %q: %+v", input, got)
		}
	}
}
