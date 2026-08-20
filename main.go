package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/drvoss/pingcert/internal/app"
	"github.com/drvoss/pingcert/internal/diagnose"
	"github.com/drvoss/pingcert/internal/output"
	"github.com/drvoss/pingcert/internal/target"
)

const version = "0.1.0"

type durationValue struct {
	value *time.Duration
}

func (d durationValue) String() string {
	if d.value == nil {
		return ""
	}
	return d.value.String()
}

func (d durationValue) Set(raw string) error {
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil || days < 0 {
			return fmt.Errorf("invalid duration %q", raw)
		}
		*d.value = time.Duration(days * float64(24*time.Hour))
		return nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < 0 {
		return fmt.Errorf("invalid duration %q", raw)
	}
	*d.value = value
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	mode := "check"
	if len(args) > 0 && isMode(args[0]) {
		mode = args[0]
		args = args[1:]
	}

	flags := flag.NewFlagSet("pingcert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		ipv4           = flags.Bool("4", false, "use IPv4 only")
		ipv6           = flags.Bool("6", false, "use IPv6 only")
		count          = flags.Int("count", 4, "number of destination ping probes")
		timeout        = 1500 * time.Millisecond
		overallTimeout = 10 * time.Second
		maxHops        = flags.Int("max-hops", 30, "maximum trace hops")
		port           = flags.Int("port", 443, "default TCP/TLS port")
		serverName     = flags.String("server-name", "", "TLS SNI and verification name")
		noTrace        = flags.Bool("no-trace", false, "skip route tracing in check mode")
		format         = flags.String("format", "text", "output format: text, json, or ndjson")
		jsonAlias      = flags.Bool("json", false, "alias for --format json")
		warnBefore     = 30 * 24 * time.Hour
		failBefore     time.Duration
		showVersion    = flags.Bool("version", false, "print version and exit")
	)
	flags.Var(durationValue{&timeout}, "timeout", "per-operation timeout (e.g. 1500ms)")
	flags.Var(durationValue{&timeout}, "W", "alias for --timeout")
	flags.Var(durationValue{&overallTimeout}, "overall-timeout", "whole-run deadline (e.g. 10s)")
	flags.Var(durationValue{&warnBefore}, "warn-before", "warn when certificate expires within this duration")
	flags.Var(durationValue{&failBefore}, "fail-before", "fail when certificate expires within this duration")
	flags.Usage = func() { usage(stderr, flags) }
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			usage(stdout, flags)
			return 0
		}
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "pingcert %s\n", version)
		return 0
	}
	if *jsonAlias {
		*format = "json"
	}
	if *format != "text" && *format != "json" && *format != "ndjson" {
		fmt.Fprintf(stderr, "pingcert: unsupported format %q\n", *format)
		return 2
	}
	if *ipv4 && *ipv6 {
		fmt.Fprintln(stderr, "pingcert: -4 and -6 are mutually exclusive")
		return 2
	}
	if *count < 1 || *count > 100 {
		fmt.Fprintln(stderr, "pingcert: --count must be between 1 and 100")
		return 2
	}
	if *maxHops < 1 || *maxHops > 255 {
		fmt.Fprintln(stderr, "pingcert: --max-hops must be between 1 and 255")
		return 2
	}
	if timeout <= 0 || overallTimeout <= 0 {
		fmt.Fprintln(stderr, "pingcert: timeout values must be positive")
		return 2
	}
	if flags.NArg() != 1 {
		usage(stderr, flags)
		return 2
	}

	parsed, err := target.Parse(flags.Arg(0), *port, *serverName)
	if err != nil {
		fmt.Fprintln(stderr, "pingcert:", err)
		return 2
	}

	family := diagnose.FamilyAny
	if *ipv4 {
		family = diagnose.FamilyIPv4
	} else if *ipv6 {
		family = diagnose.FamilyIPv6
	}

	signalCtx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignal()
	ctx, cancel := context.WithTimeout(signalCtx, overallTimeout)
	defer cancel()

	emitter := output.NewEmitter(*format, stdout)
	result := app.Run(ctx, app.Options{
		Mode:       mode,
		Target:     parsed,
		Family:     family,
		Count:      *count,
		Timeout:    timeout,
		MaxHops:    *maxHops,
		NoTrace:    *noTrace,
		WarnBefore: warnBefore,
		FailBefore: failBefore,
	}, emitter)

	if err := emitter.Err(); err != nil {
		fmt.Fprintln(stderr, "pingcert: write output:", err)
		return 3
	}
	if *format == "json" {
		if err := output.WriteReport(stdout, result.Report); err != nil {
			fmt.Fprintln(stderr, "pingcert: write output:", err)
			return 3
		}
	}
	if signalCtx.Err() != nil {
		return 130
	}
	return result.ExitCode
}

func isMode(value string) bool {
	switch value {
	case "check", "ping", "trace", "cert":
		return true
	default:
		return false
	}
}

func usage(writer io.Writer, flags *flag.FlagSet) {
	flags.SetOutput(writer)
	fmt.Fprintf(writer, `pingcert %s - DNS, path, TCP, and TLS certificate diagnostics

usage:
  pingcert [flags] <host|host:port|https://url>
  pingcert check [flags] <target>
  pingcert ping  [flags] <target>
  pingcert trace [flags] <target>
  pingcert cert  [flags] <target>

flags:
`, version)
	flags.PrintDefaults()
}
