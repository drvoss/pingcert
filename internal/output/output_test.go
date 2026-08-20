package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/drvoss/pingcert/internal/model"
)

func TestNDJSONProducesOneCompleteObjectPerEvent(t *testing.T) {
	var buffer bytes.Buffer
	emitter := NewEmitter("ndjson", &buffer)
	event := model.Event{
		SchemaVersion: model.SchemaVersion,
		Type:          "summary",
		Summary:       &model.Summary{Status: model.StatusOK},
	}
	if err := emitter.Emit(event); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines", len(lines))
	}
	var got model.Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if got.SchemaVersion != "1" || got.Type != "summary" {
		t.Fatalf("unexpected event: %+v", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken output")
}

func TestEmitterRetainsOutputFailure(t *testing.T) {
	emitter := NewEmitter("ndjson", failingWriter{})
	err := emitter.Emit(model.Event{SchemaVersion: "1", Type: "summary"})
	if err == nil || emitter.Err() == nil {
		t.Fatal("output error was discarded")
	}
}

func TestSkippedCertificateOmitsZeroDates(t *testing.T) {
	report := model.Report{
		SchemaVersion: "1",
		Certificate:   &model.CertificateResult{Status: model.StatusSkipped},
	}
	var buffer bytes.Buffer
	if err := WriteReport(&buffer, report); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"not_before", "not_after", "days_remaining", "hostname_match", "chain_valid"} {
		if strings.Contains(buffer.String(), field) {
			t.Fatalf("skipped field %q leaked into JSON: %s", field, buffer.String())
		}
	}
}

func TestTextDoesNotUseColorAsMeaning(t *testing.T) {
	var buffer bytes.Buffer
	emitter := NewEmitter("text", &buffer)
	result := model.TCPResult{Status: model.StatusFail, Address: "127.0.0.1:443", Error: "refused"}
	if err := emitter.Emit(model.Event{Type: "tcp", TCP: &result}); err != nil {
		t.Fatal(err)
	}
	if got := buffer.String(); !strings.Contains(got, "FAIL") || strings.Contains(got, "\x1b[") {
		t.Fatalf("unexpected text output: %q", got)
	}
}
