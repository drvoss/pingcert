package probe

import (
	"context"
	"errors"
	"math"
	"os/exec"
	"sort"
	"time"

	"github.com/drvoss/pingcert/internal/model"
)

func Ping(ctx context.Context, targetIP string, count int, timeout time.Duration, emit func(model.PingSample)) model.PingResult {
	result := model.PingResult{
		Status:   model.StatusFail,
		Backend:  "command",
		Degraded: true,
	}
	var values []float64
	for seq := 1; seq <= count; seq++ {
		result.Sent++
		sample := model.PingSample{Sequence: seq, Status: model.StatusFail}
		name, args := pingCommand(targetIP, timeout)
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = stableLocaleEnv()
		out, err := cmd.CombinedOutput()
		if rtt, ok := ParsePingRTT(string(out)); ok {
			sample.Status = model.StatusOK
			sample.RTTMs = &rtt
			result.Received++
			values = append(values, rtt)
		} else if err == nil {
			// Windows localizes the "time" label. A successful command exit is
			// still a reply even when this locale-agnostic parser cannot extract
			// the optional RTT number.
			sample.Status = model.StatusOK
			result.Received++
		} else if isExecutableError(err) {
			sample.Error = err.Error()
			result.ErrorKind = "backend_unavailable"
			result.Error = err.Error()
		} else if ctx.Err() != nil {
			sample.Error = "cancelled"
		} else {
			sample.Error = "timeout or no ICMP reply"
		}
		result.Samples = append(result.Samples, sample)
		if emit != nil {
			copy := sample
			emit(copy)
		}
		if ctx.Err() != nil || result.Error != "" {
			break
		}
	}

	if result.Sent > 0 {
		result.LossPct = float64(result.Sent-result.Received) * 100 / float64(result.Sent)
	}
	if result.Received > 0 {
		result.Status = model.StatusOK
	}
	if len(values) > 0 {
		sort.Float64s(values)
		min, max := values[0], values[len(values)-1]
		var total float64
		for _, value := range values {
			total += value
		}
		avg := total / float64(len(values))
		result.MinMs, result.AvgMs, result.MaxMs = &min, &avg, &max
		result.Status = model.StatusOK
	}
	return result
}

func Trace(ctx context.Context, targetIP string, maxHops int, timeout time.Duration, emit func(model.TraceHop)) model.TraceResult {
	result := model.TraceResult{
		Status:   model.StatusFail,
		Backend:  "command",
		Degraded: true,
	}
	name, args := traceCommand(targetIP, maxHops, timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = stableLocaleEnv()
	out, err := cmd.CombinedOutput()
	samples := ParseTraceOutput(string(out))
	if len(samples) == 0 {
		switch {
		case isExecutableError(err):
			result.ErrorKind = "backend_unavailable"
			result.Error = err.Error()
		case ctx.Err() != nil:
			result.Error = "trace deadline exceeded"
		case err != nil:
			result.Error = err.Error()
		default:
			result.Error = "no trace hops parsed"
		}
		return result
	}

	byTTL := map[int][]model.TraceProbe{}
	var ttls []int
	reachedDestination := false
	for _, sample := range samples {
		if _, ok := byTTL[sample.TTL]; !ok {
			ttls = append(ttls, sample.TTL)
		}
		probe := model.TraceProbe{Status: model.StatusFail, Responder: sample.Responder, Note: sample.Note}
		if sample.OK {
			value := sample.RTTMs
			probe.RTTMs = &value
			probe.Status = model.StatusOK
			if sample.Responder == targetIP {
				reachedDestination = true
			}
		} else {
			probe.Note = "no ICMP reply"
		}
		if sample.Unreachable {
			probe.Status = model.StatusWarn
		}
		byTTL[sample.TTL] = append(byTTL[sample.TTL], probe)
	}
	sort.Ints(ttls)
	for _, ttl := range ttls {
		hop := model.TraceHop{TTL: ttl, Probes: byTTL[ttl]}
		result.Hops = append(result.Hops, hop)
		if emit != nil {
			emit(hop)
		}
	}
	switch {
	case ctx.Err() != nil:
		result.Status = model.StatusWarn
		result.Error = "partial trace: deadline exceeded"
	case !reachedDestination:
		result.Status = model.StatusWarn
		result.Error = "destination was not reached"
	case err != nil:
		result.Status = model.StatusWarn
		result.Error = "trace command reported an error after producing partial output"
	default:
		result.Status = model.StatusOK
	}
	return result
}

func isExecutableError(err error) bool {
	var execErr *exec.Error
	return errors.As(err, &execErr)
}

func durationSecondsCeil(d time.Duration) int {
	return int(math.Max(1, math.Ceil(d.Seconds())))
}
