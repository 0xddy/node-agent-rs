package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

var errProbeCleanup = errors.New("independent probe monitor cleanup")

type probeSummary struct {
	count, errors int
	maxLatency    time.Duration
}

type probeMonitor struct {
	cancel    context.CancelFunc
	done      chan struct{}
	once      sync.Once
	mu        sync.Mutex
	summaries map[string]probeSummary
}

func startProbeMonitor(ctx context.Context, options options, label *atomic.Value) (*probeMonitor, error) {
	probeCtx, cancelCause := context.WithCancelCause(ctx)
	cancel := func() { cancelCause(errProbeCleanup) }
	client, err := newClient(probeCtx, options.server, options.probePassword)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create independent client: %w", err)
	}
	joinCancellation := closeOnCancellation(probeCtx, client)
	monitor := &probeMonitor{cancel: cancel, done: make(chan struct{}), summaries: make(map[string]probeSummary)}
	// Verify credentials and target before load. A short run cannot silently
	// pass with an empty probe summary, and later samples reuse this QUIC.
	started := time.Now()
	err = probeOnce(probeCtx, client, options.target, options.probeTimeout)
	monitor.record(label.Load().(string), time.Since(started), err)
	if err != nil {
		cancel()
		joinCancellation()
		_ = client.CloseWithError(context.Canceled)
		_ = monitor.report()
		return nil, fmt.Errorf("independent baseline probe: %w", err)
	}
	go func() {
		defer close(monitor.done)
		defer client.CloseWithError(context.Canceled)
		defer joinCancellation()
		ticker := time.NewTicker(options.probeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				phase := label.Load().(string)
				started := time.Now()
				err := probeOnce(probeCtx, client, options.target, options.probeTimeout)
				elapsed := time.Since(started)
				if !monitor.recordCompleted(phase, elapsed, context.Cause(probeCtx), err) {
					return
				}
			}
		}
	}()
	return monitor, nil
}

// Context cancellation can race with a completed probe result. Keep successes,
// timeouts, remote closes and unrelated IO errors even when cleanup has begun.
func (p *probeMonitor) recordCompleted(label string, latency time.Duration, cause, err error) bool {
	if cause == errProbeCleanup && isLocalProbeCleanupError(err) {
		fmt.Printf("independent_probe %s latency=%s status=cancelled\n", label, latency)
		return false
	}
	p.record(label, latency, err)
	return true
}

func isLocalProbeCleanupError(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled {
		return true
	}
	// CloseWithError in this pinned sing-quic version closes the QUIC with
	// local application code 0 and an empty message. Do not accept generic
	// net.ErrClosed, an EOF mapping, or a remote QUIC close as evidence.
	if appErr, ok := err.(*quic.ApplicationError); ok {
		return !appErr.Remote && appErr.ErrorCode == 0 && appErr.ErrorMessage == ""
	}
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multiple.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !isLocalProbeCleanupError(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return isLocalProbeCleanupError(wrapped.Unwrap())
	}
	return false
}

func (p *probeMonitor) record(label string, latency time.Duration, err error) {
	p.mu.Lock()
	summary := p.summaries[label]
	summary.count++
	summary.maxLatency = max(summary.maxLatency, latency)
	if err != nil {
		summary.errors++
	}
	p.summaries[label] = summary
	p.mu.Unlock()
	if err != nil {
		fmt.Printf("independent_probe %s latency=%s status=error eof=false error=%q\n", label, latency, err.Error())
	} else {
		fmt.Printf("independent_probe %s latency=%s status=ok eof=true\n", label, latency)
	}
}

func (p *probeMonitor) stop() {
	p.once.Do(p.cancel)
	<-p.done
}

func (p *probeMonitor) report() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	labels := make([]string, 0, len(p.summaries))
	for label := range p.summaries {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	var count, failures int
	for _, label := range labels {
		summary := p.summaries[label]
		count += summary.count
		failures += summary.errors
		fmt.Printf("independent_probe_summary %s samples=%d errors=%d max_latency=%s\n", label, summary.count, summary.errors, summary.maxLatency)
	}
	if count == 0 {
		return fmt.Errorf("independent probe completed no samples")
	}
	if failures > 0 {
		return fmt.Errorf("independent probe failed %d of %d samples", failures, count)
	}
	return nil
}
