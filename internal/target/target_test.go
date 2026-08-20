package target

import "testing"

func TestParseTargets(t *testing.T) {
	tests := []struct {
		input      string
		port       int
		host       string
		serverName string
	}{
		{"example.com", 443, "example.com", "example.com"},
		{"example.com:8443", 8443, "example.com", "example.com"},
		{"https://example.com:9443/path", 9443, "example.com", "example.com"},
		{"[2001:db8::1]:443", 443, "2001:db8::1", ""},
	}
	for _, test := range tests {
		got, err := Parse(test.input, 443, "")
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.input, err)
		}
		if got.Host != test.host || got.Port != test.port || got.ServerName != test.serverName {
			t.Fatalf("Parse(%q) = %+v", test.input, got)
		}
	}
}

func TestParseRejectsInvalidPort(t *testing.T) {
	if _, err := Parse("example.com:99999", 443, ""); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestParseRejectsUnsupportedSchemeAndCredentials(t *testing.T) {
	for _, input := range []string{
		"http://example.com",
		"ftp://example.com",
		"https://user:password@example.com",
	} {
		if _, err := Parse(input, 443, ""); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", input)
		}
	}
}

func TestParseHonorsExplicitServerName(t *testing.T) {
	got, err := Parse("192.0.2.10", 443, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "192.0.2.10" || got.ServerName != "example.com" {
		t.Fatalf("Parse() = %+v", got)
	}
}
