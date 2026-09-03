package main

import (
	"testing"
	"time"
)

func TestProgressReportsStalledStreamWhileSiblingMoves(t *testing.T) {
	start := time.Unix(0, 0)
	stats := newPhaseProgress(start, 1, 2)
	stats.record(0, 10, start.Add(time.Second))
	stats.record(1, 20, start.Add(2*time.Second))
	stats.record(1, 30, start.Add(3*time.Second))
	snapshot := stats.snapshot(start.Add(4 * time.Second))
	if snapshot.bytes != 60 || snapshot.maxGap != time.Second || snapshot.maxStreamGap != 3*time.Second || snapshot.eofs != 0 {
		t.Fatalf("sibling progress masked stream stall: %+v", snapshot)
	}
}

func TestProgressIncludesEOFTailAndFreezesFinishedStream(t *testing.T) {
	start := time.Unix(0, 0)
	stats := newPhaseProgress(start, 1, 2)
	stats.record(0, 10, start.Add(time.Second))
	stats.finishStream(0, start.Add(4*time.Second), true)
	stats.record(1, 20, start.Add(5*time.Second))
	stats.finishStream(1, start.Add(6*time.Second), false)
	snapshot := stats.snapshot(start.Add(10 * time.Second))
	if snapshot.bytes != 30 || snapshot.maxStreamGap != 5*time.Second || snapshot.eofs != 1 {
		t.Fatalf("finished stream or EOF accounting incorrect: %+v", snapshot)
	}
	if stats.streams[0].maxGap != 3*time.Second {
		t.Fatalf("EOF tail not included: %+v", stats.streams[0])
	}
}

func TestProgressOutOfOrderTimestampDoesNotInflateAggregateGap(t *testing.T) {
	start := time.Unix(0, 0)
	stats := newPhaseProgress(start, 1, 2)
	stats.record(0, 10, start.Add(2*time.Second))
	stats.record(1, 20, start.Add(time.Second))
	stats.record(0, 30, start.Add(4*time.Second))
	stats.record(0, 0, start.Add(5*time.Second))
	snapshot := stats.snapshot(start.Add(5 * time.Second))
	if snapshot.bytes != 60 || snapshot.maxGap != 2*time.Second {
		t.Fatalf("out-of-order or empty progress changed accounting: %+v", snapshot)
	}
}

func TestProgressSeparatesQUICConnectionsAndFinishedStreams(t *testing.T) {
	start := time.Unix(0, 0)
	stats := newPhaseProgress(start, 2, 2)
	stats.record(0, 10, start.Add(time.Second))
	stats.finishStream(0, start.Add(2*time.Second), true)
	stats.record(1, 20, start.Add(3*time.Second))
	stats.record(2, 30, start.Add(2*time.Second))
	stats.record(3, 40, start.Add(4*time.Second))
	snapshot := stats.snapshot(start.Add(6 * time.Second))
	if snapshot.bytes != 100 || snapshot.maxConnectionGap != 3*time.Second || snapshot.maxStreamGap != 4*time.Second || snapshot.eofs != 1 {
		t.Fatalf("connection and stream stalls were conflated: %+v", snapshot)
	}
	if stats.connections[0].bytes != 30 || stats.connections[1].bytes != 70 || stats.connections[0].finished {
		t.Fatalf("connection finished before all its streams: %+v", stats.connections)
	}
	stats.finishStream(1, start.Add(7*time.Second), true)
	if !stats.connections[0].finished || !stats.connections[0].eof || stats.connections[0].gap(start.Add(20*time.Second)) != 4*time.Second {
		t.Fatalf("completed connection did not freeze: %+v", stats.connections[0])
	}
}

func TestProbeSummaryRejectsMissingOrFailedSamples(t *testing.T) {
	for _, test := range []struct {
		name      string
		summaries map[string]probeSummary
		wantError bool
	}{
		{"missing", nil, true},
		{"success", map[string]probeSummary{"round=0 phase=setup": {count: 1}}, false},
		{"later-error", map[string]probeSummary{"round=0 phase=setup": {count: 1}, "round=1 phase=upload": {count: 2, errors: 1}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			monitor := &probeMonitor{summaries: test.summaries}
			if err := monitor.report(); (err != nil) != test.wantError {
				t.Fatalf("report() = %v, want error %t", err, test.wantError)
			}
		})
	}
}
