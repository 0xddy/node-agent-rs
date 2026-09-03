package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic/hysteria2"
)

type cancelDownloadStream struct {
	conn      net.Conn
	requested atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (s *cancelDownloadStream) close(intentional bool) error {
	if intentional {
		s.requested.Store(true)
	}
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	return s.closeErr
}

type preparedDownload struct {
	index  int
	stream *cancelDownloadStream
}

type cancelledDownloadResult struct {
	index     int
	bytes     int64
	cancelled bool
	err       error
}

// This phase closes only logical download streams when the timer fires. The
// retained official Clients then service the ordinary upload phase unchanged.
func cancelDownloadPhase(ctx context.Context, clients []*hysteria2.Client, options options, round int) error {
	phaseCtx, cancelPhase := context.WithCancel(ctx)
	defer cancelPhase()
	count := options.totalStreams()
	progress := newPhaseProgress(time.Now(), options.connections, options.streams)
	prepared := make(chan preparedDownload, count)
	results := make(chan cancelledDownloadResult, count)
	closeResults := make(chan error, count)
	start := make(chan struct{})
	streams := make([]*cancelDownloadStream, count)
	for index := 0; index < count; index++ {
		go func(index int) {
			result := cancelledDownloadResult{index: index}
			defer func() {
				progress.finishStream(index, time.Now(), false)
				results <- result
			}()
			conn, err := dial(phaseCtx, clients[index/options.streams], options.target, options.streamTimeout)
			if err != nil {
				result.err = fmt.Errorf("dial: %w", err)
				return
			}
			stream := &cancelDownloadStream{conn: conn}
			defer stream.close(false)
			buffer := make([]byte, chunkBytes)
			prepared <- preparedDownload{index, stream}
			select {
			case <-start:
			case <-phaseCtx.Done():
				result.err = phaseCtx.Err()
				return
			}
			if err := phaseCtx.Err(); err != nil {
				result.err = err
				return
			}
			if err := writeAll(conn, []byte(fmt.Sprintf("0 %d\n", options.download)), nil); err != nil {
				result.err = fmt.Errorf("command: %w", err)
				return
			}
			result.bytes, result.cancelled, result.err = readUntilDownloadCancelled(conn, buffer, options.download, stream.requested.Load, func(n int) {
				progress.record(index, int64(n), time.Now())
			})
		}(index)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	var cancelTimer <-chan time.Time
	var started, closeStarted time.Time
	var firstErr error
	preparedCount, cancelledCount, remainingWorkers, remainingCloses := 0, 0, count, 0
	ctxDone := ctx.Done()
	preparedEvents := (<-chan preparedDownload)(prepared)
	fail := func(err error) {
		if firstErr != nil {
			return
		}
		firstErr = err
		cancelPhase()
		closeClients(clients, err)
		if timer != nil {
			timer.Stop()
		}
		cancelTimer = nil
	}
	for remainingWorkers > 0 || remainingCloses > 0 {
		select {
		case ready := <-preparedEvents:
			streams[ready.index] = ready.stream
			preparedCount++
			if preparedCount == count {
				preparedEvents = nil
				if firstErr == nil {
					started = time.Now()
					timer = time.NewTimer(options.cancelDownloadAfter)
					cancelTimer = timer.C
					close(start)
				}
			}
		case <-cancelTimer:
			cancelTimer = nil
			closeStarted = time.Now()
			remainingCloses = count
			for index, stream := range streams {
				go func(index int, stream *cancelDownloadStream) {
					err := stream.close(true)
					if err != nil {
						err = fmt.Errorf("connection %d stream %d Close: %w", index/options.streams+1, index%options.streams+1, err)
					}
					closeResults <- err
				}(index, stream)
			}
		case err := <-closeResults:
			remainingCloses--
			if err != nil {
				fail(err)
			}
		case result := <-results:
			remainingWorkers--
			if result.cancelled {
				cancelledCount++
			}
			fmt.Printf("cancel_stream_summary round=%d phase=cancel-download connection=%d stream=%d bytes=%d cancelled=%t\n", round, result.index/options.streams+1, result.index%options.streams+1, result.bytes, result.cancelled)
			if result.err != nil {
				fail(fmt.Errorf("connection %d stream %d: %w", result.index/options.streams+1, result.index%options.streams+1, result.err))
			}
		case <-ctxDone:
			ctxDone = nil
			fail(ctx.Err())
		case <-ticker.C:
			progress.print("progress", round, "cancel-download", time.Now(), "running")
		}
	}
	if firstErr == nil && cancelledCount != count {
		fail(fmt.Errorf("only %d of %d downloads were cancelled", cancelledCount, count))
	}
	status := "cancelled"
	if firstErr != nil {
		status = "error"
	}
	progress.print("phase_summary", round, "cancel-download", time.Now(), status)
	progress.printConnections(round, "cancel-download")
	progress.printStreams(round, "cancel-download")
	var timerElapsed time.Duration
	if !closeStarted.IsZero() {
		timerElapsed = closeStarted.Sub(started)
	}
	fmt.Printf("cancel_download_summary round=%d cancelled=%d/%d cancel_after=%s timer_elapsed=%s status=%s\n", round, cancelledCount, count, options.cancelDownloadAfter, timerElapsed, status)
	if firstErr != nil {
		return fmt.Errorf("round %d cancel-download: %w", round, firstErr)
	}
	return nil
}

func readUntilDownloadCancelled(reader io.Reader, buffer []byte, limit int64, cancellationRequested func() bool, progress func(int)) (int64, bool, error) {
	var received int64
	for received < limit {
		n, err := reader.Read(buffer[:min(int64(len(buffer)), limit-received)])
		for _, value := range buffer[:n] {
			if value != 'y' {
				return received, false, fmt.Errorf("unexpected target data after %d bytes", received)
			}
		}
		if n > 0 {
			received += int64(n)
			progress(n)
		}
		if received == limit {
			break
		}
		if err != nil {
			// sing-quic also maps a local StreamError(0) to io.EOF and
			// net.ErrClosed. Inspect the actual typed error to reject an
			// early remote EOF, reset, or connection-wide close instead.
			var streamErr *quic.StreamError
			if cancellationRequested() && errors.As(err, &streamErr) && !streamErr.Remote && streamErr.ErrorCode == 0 {
				if received == 0 {
					return 0, false, errors.New("download cancelled before any payload was received")
				}
				return received, true, nil
			}
			return received, false, fmt.Errorf("download ended without requested local cancellation after %d bytes: %w", received, err)
		}
		if n == 0 {
			return received, false, io.ErrNoProgress
		}
	}
	return received, false, fmt.Errorf("download reached the %d-byte cap before local cancellation; increase --download or shorten --cancel-download-after", limit)
}
