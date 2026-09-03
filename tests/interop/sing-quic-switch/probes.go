package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

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
	probeCtx, cancel := context.WithCancel(ctx)
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
				if probeCtx.Err() != nil {
					fmt.Printf("independent_probe %s latency=%s status=cancelled\n", phase, elapsed)
					return
				}
				monitor.record(phase, elapsed, err)
			}
		}
	}()
	return monitor, nil
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
