package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/drvoss/pingcert/internal/diagnose"
	"github.com/drvoss/pingcert/internal/model"
	"github.com/drvoss/pingcert/internal/output"
	"github.com/drvoss/pingcert/internal/probe"
)

type Options struct {
	Mode       string
	Target     model.Target
	Family     diagnose.Family
	Count      int
	Timeout    time.Duration
	MaxHops    int
	NoTrace    bool
	WarnBefore time.Duration
	FailBefore time.Duration
}

type Result struct {
	Report   model.Report
	ExitCode int
}

func Run(ctx context.Context, options Options, emitter output.Emitter) Result {
	start := time.Now()
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Mode:          options.Mode,
		Target:        options.Target,
	}
	emit(emitter, model.Event{
		SchemaVersion: model.SchemaVersion,
		Type:          "start",
		Mode:          options.Mode,
		Target:        &report.Target,
	})

	network := diagnose.NewNetwork(options.Timeout)
	dns := network.Resolve(ctx, &report.Target, options.Family)
	report.DNS = &dns
	emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "dns", DNS: &dns})
	if dns.Status != model.StatusOK {
		return finish(report, start, "dns", 1, emitter)
	}

	if options.Mode == "check" || options.Mode == "cert" {
		tcp, tlsResult, certificate := network.TCPAndTLS(
			ctx, report.Target, options.WarnBefore, options.FailBefore,
		)
		report.TCP, report.TLS, report.Certificate = &tcp, &tlsResult, &certificate
		emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "tcp", TCP: &tcp})
		emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "tls", TLS: &tlsResult})
		emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "certificate", Certificate: &certificate})
	}

	runPing := func() {
		ping := probe.Ping(ctx, report.Target.IP, options.Count, options.Timeout, func(sample model.PingSample) {
			emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "ping_sample", PingSample: &sample})
		})
		report.Ping = &ping
		emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "ping", Ping: &ping})
	}
	runTrace := func() {
		trace := probe.Trace(ctx, report.Target.IP, options.MaxHops, options.Timeout, func(hop model.TraceHop) {
			emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "trace_hop", TraceHop: &hop})
		})
		report.Trace = &trace
		emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "trace", Trace: &trace})
	}

	switch {
	case options.Mode == "check" && !options.NoTrace:
		var wait sync.WaitGroup
		wait.Add(2)
		go func() { defer wait.Done(); runPing() }()
		go func() { defer wait.Done(); runTrace() }()
		wait.Wait()
	case options.Mode == "check" || options.Mode == "ping":
		runPing()
	case options.Mode == "trace":
		runTrace()
	}

	exitCode, failed := evaluate(report)
	return finish(report, start, failed, exitCode, emitter)
}

func evaluate(report model.Report) (int, string) {
	required := func(stage string, status model.Status, errorKind string, warningPasses bool) (int, string) {
		if status == model.StatusOK || (warningPasses && status == model.StatusWarn) {
			return 0, ""
		}
		if errorKind == "backend_unavailable" {
			return 3, stage
		}
		return 1, stage
	}

	switch report.Mode {
	case "ping":
		return required("ping", report.Ping.Status, report.Ping.ErrorKind, false)
	case "trace":
		return required("trace", report.Trace.Status, report.Trace.ErrorKind, false)
	default:
		if code, stage := required("tcp", report.TCP.Status, "", false); code != 0 {
			return code, stage
		}
		if code, stage := required("tls", report.TLS.Status, "", false); code != 0 {
			return code, stage
		}
		if code, stage := required("certificate", report.Certificate.Status, "", true); code != 0 {
			return code, stage
		}
		return 0, ""
	}
}

func finish(report model.Report, start time.Time, failed string, exitCode int, emitter output.Emitter) Result {
	summary := model.Summary{
		Status:      model.StatusOK,
		FailedStage: failed,
		Elapsed:     time.Since(start).Milliseconds(),
	}
	if exitCode != 0 {
		summary.Status = model.StatusFail
	}
	if report.Mode == "check" {
		if report.Ping != nil && report.Ping.Status != model.StatusOK {
			summary.Warnings = append(summary.Warnings, "ICMP destination probe did not receive a reply")
		}
		if report.Trace != nil && report.Trace.Status != model.StatusOK {
			summary.Warnings = append(summary.Warnings, "route trace was incomplete")
		}
	}
	if (report.Mode == "check" || report.Mode == "cert") &&
		report.Certificate != nil && report.Certificate.Status == model.StatusWarn {
		summary.Warnings = append(summary.Warnings, report.Certificate.Error)
	}
	if exitCode == 0 && len(summary.Warnings) > 0 {
		summary.Status = model.StatusWarn
	}
	report.Summary = summary
	emit(emitter, model.Event{SchemaVersion: model.SchemaVersion, Type: "summary", Summary: &summary})
	return Result{Report: report, ExitCode: exitCode}
}

func emit(emitter output.Emitter, event model.Event) {
	if emitter == nil {
		return
	}
	if err := emitter.Emit(event); err != nil {
		// Output failures are intentionally not allowed to mutate diagnostic
		// state. The CLI checks its final write separately.
		_ = fmt.Sprintf("%v", err)
	}
}
