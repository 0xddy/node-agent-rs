package main

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
)

type cancelTestReader struct {
	data []byte
	err  error
}

func (r *cancelTestReader) Read(buffer []byte) (int, error) {
	n := copy(buffer, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestCancelledDownloadRequiresTypedLocalCancellation(t *testing.T) {
	localCancel := qtls.WrapError(&quic.StreamError{ErrorCode: 0, Remote: false})
	if !errors.Is(localCancel, io.EOF) {
		t.Fatal("upstream EOF mapping changed; revisit cancellation classification")
	}
	for _, test := range []struct {
		name, data    string
		err           error
		requested     bool
		limit         int64
		wantBytes     int64
		wantCancelled bool
	}{
		{"normal-local-close", "yyy", localCancel, true, 100, 3, true},
		{"premature-eof", "yyy", io.EOF, true, 100, 3, false},
		{"first-read-failed", "", io.ErrUnexpectedEOF, false, 100, 0, false},
		{"no-payload-before-close", "", localCancel, true, 100, 0, false},
		{"unrequested-local-close", "yyy", localCancel, false, 100, 3, false},
		{"remote-reset-zero", "yyy", qtls.WrapError(&quic.StreamError{ErrorCode: 0, Remote: true}), true, 100, 3, false},
		{"nonzero-local-error", "yyy", qtls.WrapError(&quic.StreamError{ErrorCode: 1, Remote: false}), true, 100, 3, false},
		{"connection-closed", "yyy", net.ErrClosed, true, 100, 3, false},
		{"remote-application-close-zero", "yyy", qtls.WrapError(&quic.ApplicationError{ErrorCode: 0, Remote: true}), true, 100, 3, false},
		{"byte-cap-before-cancel", "yyy", localCancel, true, 3, 3, false},
		{"bad-content", "xyy", localCancel, true, 100, 0, false},
		{"empty-read", "", nil, false, 100, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var progressBytes int64
			bytes, cancelled, err := readUntilDownloadCancelled(&cancelTestReader{[]byte(test.data), test.err}, make([]byte, chunkBytes), test.limit, func() bool { return test.requested }, func(n int) { progressBytes += int64(n) })
			if bytes != test.wantBytes || progressBytes != bytes || cancelled != test.wantCancelled || (err == nil) != test.wantCancelled {
				t.Fatalf("bytes=%d progress=%d cancelled=%t err=%v; want bytes=%d cancelled=%t", bytes, progressBytes, cancelled, err, test.wantBytes, test.wantCancelled)
			}
		})
	}
}
