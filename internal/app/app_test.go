package app

import (
	"testing"

	"github.com/drvoss/pingcert/internal/model"
)

func TestEvaluateCheckTreatsICMPAsAdvisory(t *testing.T) {
	report := model.Report{
		Mode:        "check",
		TCP:         &model.TCPResult{Status: model.StatusOK},
		TLS:         &model.TLSResult{Status: model.StatusOK},
		Certificate: &model.CertificateResult{Status: model.StatusOK},
		Ping:        &model.PingResult{Status: model.StatusFail},
		Trace:       &model.TraceResult{Status: model.StatusFail},
	}
	if code, stage := evaluate(report); code != 0 || stage != "" {
		t.Fatalf("ICMP advisory failed check: code=%d stage=%q", code, stage)
	}
}

func TestEvaluateCertificateWarningPassesButFailureDoesNot(t *testing.T) {
	report := model.Report{
		Mode:        "cert",
		TCP:         &model.TCPResult{Status: model.StatusOK},
		TLS:         &model.TLSResult{Status: model.StatusOK},
		Certificate: &model.CertificateResult{Status: model.StatusWarn},
	}
	if code, _ := evaluate(report); code != 0 {
		t.Fatalf("warning returned %d", code)
	}
	report.Certificate.Status = model.StatusFail
	if code, stage := evaluate(report); code != 1 || stage != "certificate" {
		t.Fatalf("failure returned code=%d stage=%q", code, stage)
	}
}

func TestEvaluateMissingBackendIsLocalFailure(t *testing.T) {
	report := model.Report{
		Mode:  "trace",
		Trace: &model.TraceResult{Status: model.StatusFail, ErrorKind: "backend_unavailable"},
	}
	if code, stage := evaluate(report); code != 3 || stage != "trace" {
		t.Fatalf("got code=%d stage=%q", code, stage)
	}
}
