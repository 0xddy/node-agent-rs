package main

import (
	"fmt"
	"sync"
	"time"
)

type progressClock struct {
	last          time.Time
	maxGap        time.Duration
	bytes         int64
	finished, eof bool
}

func (p *progressClock) record(bytes int64, now time.Time) {
	if bytes <= 0 || p.finished {
		return
	}
	// Concurrent workers may acquire the phase mutex in a different order
	// from their timestamps. Never move the aggregate clock backwards.
	if now.Before(p.last) {
		now = p.last
	}
	p.maxGap = max(p.maxGap, now.Sub(p.last))
	p.last = now
	p.bytes += bytes
}

func (p *progressClock) gap(now time.Time) time.Duration {
	if p.finished {
		return p.maxGap
	}
	return max(p.maxGap, now.Sub(p.last))
}

func (p *progressClock) finish(now time.Time, eof bool) {
	p.maxGap = p.gap(now)
	p.finished, p.eof = true, eof
}

type phaseProgress struct {
	mu      sync.Mutex
	started time.Time
	all     progressClock
	streams []progressClock
}

type progressSnapshot struct {
	bytes                int64
	maxGap, maxStreamGap time.Duration
	eofs                 int
}

func newPhaseProgress(started time.Time, streams int) *phaseProgress {
	p := &phaseProgress{started: started, all: progressClock{last: started}, streams: make([]progressClock, streams)}
	for index := range p.streams {
		p.streams[index].last = started
	}
	return p
}

func (p *phaseProgress) record(stream int, bytes int64, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.all.record(bytes, now)
	p.streams[stream].record(bytes, now)
}

func (p *phaseProgress) finishStream(stream int, now time.Time, eof bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.streams[stream].finish(now, eof)
}

func (p *phaseProgress) snapshot(now time.Time) progressSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := progressSnapshot{bytes: p.all.bytes, maxGap: p.all.gap(now)}
	for index := range p.streams {
		result.maxStreamGap = max(result.maxStreamGap, p.streams[index].gap(now))
		if p.streams[index].eof {
			result.eofs++
		}
	}
	return result
}

func (p *phaseProgress) print(prefix string, round int, name string, now time.Time, status string) {
	snapshot := p.snapshot(now)
	elapsed := now.Sub(p.started)
	var mbps float64
	if elapsed > 0 {
		mbps = float64(snapshot.bytes) * 8 / elapsed.Seconds() / 1e6
	}
	fmt.Printf("%s round=%d phase=%s streams=%d bytes=%d elapsed=%s mbps=%.3f max_no_progress=%s max_stream_no_progress=%s eof=%d/%d status=%s\n",
		prefix, round, name, len(p.streams), snapshot.bytes, elapsed, mbps, snapshot.maxGap, snapshot.maxStreamGap, snapshot.eofs, len(p.streams), status)
}

func (p *phaseProgress) printStreams(round int, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index, stream := range p.streams {
		fmt.Printf("stream_summary round=%d phase=%s stream=%d bytes=%d max_no_progress=%s eof=%t\n", round, name, index+1, stream.bytes, stream.maxGap, stream.eof)
	}
}
