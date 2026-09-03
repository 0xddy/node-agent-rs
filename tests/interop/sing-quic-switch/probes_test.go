package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
)

func TestProbeResultRaceWithCleanupKeepsCompletedErrorsAndSuccess(t *testing.T) {
	localClose := qtls.WrapError(&quic.ApplicationError{ErrorCode: 0, Remote: false})
	for _, test := range []struct {
		name       string
		cause, err error
		recorded   bool
	}{
		{"success-after-cleanup", errProbeCleanup, nil, true},
		{"probe-deadline-after-cleanup", errProbeCleanup, context.DeadlineExceeded, true},
		{"socket-deadline-after-cleanup", errProbeCleanup, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}, true},
		{"io-error-after-cleanup", errProbeCleanup, io.ErrUnexpectedEOF, true},
		{"closed-socket-after-cleanup", errProbeCleanup, net.ErrClosed, true},
		{"remote-close-after-cleanup", errProbeCleanup, qtls.WrapError(&quic.ApplicationError{ErrorCode: 0, Remote: true}), true},
		{"wrapped-local-cleanup", errProbeCleanup, fmt.Errorf("probe read: %w", localClose), false},
		{"dial-cancelled-by-cleanup", errProbeCleanup, fmt.Errorf("dial: %w", context.Canceled), false},
		{"main-deadline-is-not-cleanup", context.DeadlineExceeded, localClose, true},
		{"external-cancel-is-not-cleanup", context.Canceled, context.Canceled, true},
		{"no-cleanup-marker", nil, localClose, true},
		{"mixed-timeout-and-cancellation", errProbeCleanup, errors.Join(context.Canceled, context.DeadlineExceeded), true},
		{"mixed-io-error-and-cancellation", errProbeCleanup, errors.Join(context.Canceled, io.ErrUnexpectedEOF), true},
		{"unrelated-local-close", errProbeCleanup, &quic.ApplicationError{ErrorCode: 0, Remote: false, ErrorMessage: "different close"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			monitor := &probeMonitor{summaries: make(map[string]probeSummary)}
			recorded := monitor.recordCompleted("round=1 phase=upload", time.Millisecond, test.cause, test.err)
			if recorded != test.recorded {
				t.Fatalf("recorded=%t, want %t", recorded, test.recorded)
			}
			summary, exists := monitor.summaries["round=1 phase=upload"]
			if exists != test.recorded {
				t.Fatalf("result missing or unexpectedly counted: %+v", monitor.summaries)
			}
			if test.recorded {
				expectedErrors := 0
				if test.err != nil {
					expectedErrors = 1
				}
				if summary.count != 1 || summary.errors != expectedErrors {
					t.Fatalf("completed error/success accounting: %+v", summary)
				}
			}
		})
	}
}

func TestProbeEOFTailPreservesErrorAndRejectsTrailingData(t *testing.T) {
	localClose := qtls.WrapError(&quic.ApplicationError{ErrorCode: 0, Remote: false})
	err := expectEOF(&cancelTestReader{err: localClose})
	if !isLocalProbeCleanupError(err) {
		t.Fatalf("EOF tail lost typed cleanup cause: %v", err)
	}
	err = expectEOF(&cancelTestReader{err: os.ErrDeadlineExceeded})
	if !errors.Is(err, os.ErrDeadlineExceeded) || isLocalProbeCleanupError(err) {
		t.Fatalf("EOF tail lost or ignored real deadline: %v", err)
	}
	err = expectEOF(&cancelTestReader{data: []byte{'x'}, err: localClose})
	if err == nil || isLocalProbeCleanupError(err) {
		t.Fatalf("cleanup masked trailing data: %v", err)
	}
}
