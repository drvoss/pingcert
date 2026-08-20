package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/drvoss/pingcert/internal/model"
)

type Emitter interface {
	Emit(model.Event) error
}

type StreamEmitter struct {
	format string
	writer io.Writer
	mu     sync.Mutex
	err    error
}

func NewEmitter(format string, writer io.Writer) *StreamEmitter {
	return &StreamEmitter{format: format, writer: writer}
}

func (e *StreamEmitter) Emit(event model.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	var err error
	switch e.format {
	case "json":
		return nil
	case "ndjson":
		err = json.NewEncoder(e.writer).Encode(event)
	default:
		err = e.emitText(event)
	}
	if err != nil {
		e.err = err
	}
	return err
}

func (e *StreamEmitter) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

func WriteReport(writer io.Writer, report model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (e *StreamEmitter) emitText(event model.Event) error {
	switch event.Type {
	case "start":
		target := event.Target.Host
		if event.Mode == "check" || event.Mode == "cert" {
			target = fmt.Sprintf("%s:%d", event.Target.Host, event.Target.Port)
		}
		_, err := fmt.Fprintf(e.writer, "PINGCERT %s %s\n\n",
			strings.ToUpper(event.Mode), target)
		return err
	case "dns":
		r := event.DNS
		if r.Status == model.StatusOK {
			_, err := fmt.Fprintf(e.writer, "DNS   %-5s %s -> %s (%s, %dms)\n",
				label(r.Status), r.Host, r.Selected, strings.ToUpper(r.Family), r.Elapsed)
			return err
		}
		_, err := fmt.Fprintf(e.writer, "DNS   %-5s %s (%s)\n", label(r.Status), r.Host, r.Error)
		return err
	case "tcp":
		r := event.TCP
		if r.Status == model.StatusOK {
			_, err := fmt.Fprintf(e.writer, "TCP   %-5s %s open (%dms)\n", label(r.Status), r.Address, r.Elapsed)
			return err
		}
		_, err := fmt.Fprintf(e.writer, "TCP   %-5s %s (%s)\n", label(r.Status), r.Address, r.Error)
		return err
	case "tls":
		r := event.TLS
		if r.Status == model.StatusSkipped {
			return nil
		}
		if r.Status == model.StatusOK {
			alpn := ""
			if r.ALPN != "" {
				alpn = " alpn=" + r.ALPN
			}
			_, err := fmt.Fprintf(e.writer, "TLS   %-5s %s / %s%s (%dms)\n",
				label(r.Status), r.Version, r.CipherSuite, alpn, r.Elapsed)
			return err
		}
		_, err := fmt.Fprintf(e.writer, "TLS   %-5s %s\n", label(r.Status), dash(r.Error))
		return err
	case "certificate":
		r := event.Certificate
		if r.Status == model.StatusSkipped {
			return nil
		}
		host := "-"
		if r.HostnameMatch != nil && *r.HostnameMatch {
			host = "match"
		} else if r.HostnameMatch != nil {
			host = "mismatch"
		}
		expires := "-"
		if r.NotAfter != nil {
			expires = r.NotAfter.Format("2006-01-02")
		}
		days := "-"
		if r.DaysRemaining != nil {
			days = fmt.Sprintf("%d", *r.DaysRemaining)
		}
		_, err := fmt.Fprintf(e.writer,
			"CERT  %-5s subject=%s issuer=%s expires=%s (%s days) hostname=%s%s\n",
			label(r.Status), dash(r.Subject), dash(r.Issuer),
			expires, days, host, errorSuffix(r.Error))
		return err
	case "ping_sample":
		r := event.PingSample
		if r.Status == model.StatusOK {
			if r.RTTMs != nil {
				_, err := fmt.Fprintf(e.writer, "PING  seq=%d time=%.2fms\n", r.Sequence, *r.RTTMs)
				return err
			}
			_, err := fmt.Fprintf(e.writer, "PING  seq=%d reply time=-\n", r.Sequence)
			return err
		}
		_, err := fmt.Fprintf(e.writer, "PING  seq=%d * %s\n", r.Sequence, dash(r.Error))
		return err
	case "ping":
		r := event.Ping
		stats := "-"
		if r.MinMs != nil {
			stats = fmt.Sprintf("%.2f/%.2f/%.2fms", *r.MinMs, *r.AvgMs, *r.MaxMs)
		}
		_, err := fmt.Fprintf(e.writer,
			"PING  %-5s sent=%d received=%d loss=%.1f%% min/avg/max=%s backend=%s degraded=%t%s\n",
			label(r.Status), r.Sent, r.Received, r.LossPct, stats, r.Backend, r.Degraded, errorSuffix(r.Error))
		return err
	case "trace_hop":
		r := event.TraceHop
		var probes []string
		for _, probe := range r.Probes {
			if probe.RTTMs == nil {
				probes = append(probes, "*")
				continue
			}
			value := fmt.Sprintf("%.2fms", *probe.RTTMs)
			if probe.Responder != "" {
				value += " " + probe.Responder
			}
			probes = append(probes, value)
		}
		_, err := fmt.Fprintf(e.writer, "TRACE %2d  %s\n", r.TTL, strings.Join(probes, "  "))
		return err
	case "trace":
		r := event.Trace
		_, err := fmt.Fprintf(e.writer, "TRACE %-5s hops=%d backend=%s degraded=%t%s\n",
			label(r.Status), len(r.Hops), r.Backend, r.Degraded, errorSuffix(r.Error))
		return err
	case "summary":
		r := event.Summary
		failed := ""
		if r.FailedStage != "" {
			failed = " failed_stage=" + r.FailedStage
		}
		warnings := ""
		if len(r.Warnings) > 0 {
			warnings = fmt.Sprintf(" warnings=%d", len(r.Warnings))
		}
		_, err := fmt.Fprintf(e.writer, "\nRESULT %s%s%s elapsed=%dms\n",
			label(r.Status), failed, warnings, r.Elapsed)
		return err
	}
	return nil
}

func label(status model.Status) string {
	return strings.ToUpper(string(status))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func errorSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}
