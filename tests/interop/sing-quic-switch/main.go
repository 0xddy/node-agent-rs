// sing-quic-switch exercises normal file transfers through one official HY2
// client. All addresses must be numeric loopback addresses.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const chunkBytes = 64 * 1024

func main() {
	options, err := parseOptions(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Println(usage)
		return
	}
	if err == nil {
		err = run(options)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sing-quic-switch:", err)
		os.Exit(1)
	}
}

func run(options options) (runErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	client, err := newClient(ctx, options.server, options.password)
	if err != nil {
		return fmt.Errorf("create main client: %w", err)
	}
	defer client.CloseWithError(context.Canceled)
	defer closeOnCancellation(ctx, client)()

	fmt.Printf("config streams=%d download_bytes_per_stream=%d upload_bytes_per_stream=%d rounds=%d timeout=%s stream_timeout=%s chunk_bytes=%d independent_probe=%t\n",
		options.streams, options.download, options.upload, options.rounds, options.timeout, options.streamTimeout, chunkBytes, options.probePassword != "")
	var label atomic.Value
	label.Store("round=0 phase=setup")
	if options.probePassword != "" {
		monitor, err := startProbeMonitor(ctx, options, &label)
		if err != nil {
			return err
		}
		defer func() {
			monitor.stop()
			if err := monitor.report(); err != nil && runErr == nil {
				runErr = err
			}
		}()
	}

	for round := 1; round <= options.rounds; round++ {
		for _, stage := range []struct {
			name          string
			send, receive int64
		}{
			{"download", 0, options.download},
			{"upload", options.upload, 1},
		} {
			if (stage.name == "download" && options.download == 0) || (stage.name == "upload" && options.upload == 0) {
				continue
			}
			label.Store(fmt.Sprintf("round=%d phase=%s", round, stage.name))
			if err := phase(ctx, client, options, round, stage.name, stage.send, stage.receive); err != nil {
				return err
			}
		}
		// No sleep or new main Client between phases or rounds.
	}
	label.Store(fmt.Sprintf("round=%d phase=final", options.rounds))
	started := time.Now()
	if err := probeOnce(ctx, client, options.target, options.probeTimeout); err != nil {
		return fmt.Errorf("main final probe: %w", err)
	}
	fmt.Printf("probe=bounded-peer user=main latency=%s eof=ok\n", time.Since(started))
	return ctx.Err()
}

func newClient(ctx context.Context, server M.Socksaddr, password string) (*hysteria2.Client, error) {
	return hysteria2.NewClient(hysteria2.ClientOptions{
		Context: ctx, Dialer: &singleTransportDialer{}, Logger: logger.NOP(),
		ServerAddress: server, Password: password,
		TLSConfig: &testTLSConfig{
			config:  &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}, // Loopback test certificates only.
			timeout: 15 * time.Second,
		},
		// Zero bandwidth selects automatic congestion control. The QUIC
		// transport uses UDP; application UDP forwarding is unused.
		UDPDisabled: true,
	})
}

// Join a started cancellation callback so it cannot outlive run/monitor cleanup.
func closeOnCancellation(ctx context.Context, client *hysteria2.Client) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = client.CloseWithError(ctx.Err())
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

// Refuse a second UDP transport: the SDK's automatic reconnect must not hide
// a failed existing QUIC connection. The actual socket uses SystemDialer.
type singleTransportDialer struct{ dials atomic.Uint32 }

func (d *singleTransportDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "udp" || !destination.Addr.IsLoopback() {
		return nil, errors.New("only loopback UDP transport is permitted")
	}
	if d.dials.Add(1) != 1 {
		return nil, errors.New("HY2 attempted to reconnect during direction-switch test")
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (*singleTransportDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("port hopping and realm sockets are not used by this test")
}

func dial(ctx context.Context, client *hysteria2.Client, target M.Socksaddr, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := client.DialConn(dialCtx, target)
	if err != nil {
		return nil, err
	}
	deadline, _ := dialCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func phase(ctx context.Context, client *hysteria2.Client, options options, round int, name string, sendBytes, receiveBytes int64) error {
	progress := newPhaseProgress(time.Now(), options.streams)
	results := make(chan error, options.streams)
	for stream := 0; stream < options.streams; stream++ {
		go func(index int) {
			err := transfer(ctx, client, options.target, options.streamTimeout, sendBytes, receiveBytes, func(n int) {
				progress.record(index, int64(n), time.Now())
			})
			progress.finishStream(index, time.Now(), err == nil)
			results <- err
		}(stream)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var firstErr error
	ctxDone := ctx.Done()
	for remaining := options.streams; remaining > 0; {
		select {
		case err := <-results:
			remaining--
			if err != nil && firstErr == nil {
				firstErr = err
				_ = client.CloseWithError(err)
			}
		case <-ctxDone:
			ctxDone = nil
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			_ = client.CloseWithError(ctx.Err())
		case <-ticker.C:
			progress.print("progress", round, name, time.Now(), "running")
		}
	}
	// All workers have exited, including siblings after any failure or timeout.
	status := "ok"
	if firstErr != nil {
		status = "error"
	}
	progress.print("phase_summary", round, name, time.Now(), status)
	progress.printStreams(round, name)
	if firstErr != nil {
		return fmt.Errorf("round %d %s: %w", round, name, firstErr)
	}
	return nil
}

func transfer(ctx context.Context, client *hysteria2.Client, target M.Socksaddr, timeout time.Duration, sendBytes, receiveBytes int64, progress func(int)) error {
	conn, err := dial(ctx, client, target, timeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := writeAll(conn, []byte(fmt.Sprintf("%d %d\n", sendBytes, receiveBytes)), nil); err != nil {
		return fmt.Errorf("command: %w", err)
	}
	buffer := make([]byte, chunkBytes)
	for index := range buffer {
		buffer[index] = 'x'
	}
	for remaining := sendBytes; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		if err := writeAll(conn, buffer[:n], progress); err != nil {
			return fmt.Errorf("upload after at least %d bytes: %w", sendBytes-remaining, err)
		}
		remaining -= n
	}
	sawEOF := false
	for remaining := receiveBytes; remaining > 0; {
		n, err := conn.Read(buffer[:min(int64(len(buffer)), remaining)])
		for _, value := range buffer[:n] {
			if value != 'y' {
				return fmt.Errorf("unexpected target data after %d bytes", receiveBytes-remaining)
			}
		}
		remaining -= int64(n)
		if sendBytes == 0 && n > 0 {
			progress(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && remaining == 0 {
				sawEOF = true
				break
			}
			return fmt.Errorf("receive after %d bytes: %w", receiveBytes-remaining, err)
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	if !sawEOF {
		if err := expectEOF(conn); err != nil {
			return fmt.Errorf("transfer: %w", err)
		}
	}
	return nil
}

func probeOnce(ctx context.Context, client *hysteria2.Client, target M.Socksaddr, timeout time.Duration) error {
	conn, err := dial(ctx, client, target, timeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := writeAll(conn, []byte("who\n"), nil); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	reader := bufio.NewReaderSize(conn, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(line) != "bounded-peer\n" {
		return fmt.Errorf("unexpected response: %q", line)
	}
	return expectEOF(reader)
}

func expectEOF(reader io.Reader) error {
	var tail [1]byte
	if n, err := reader.Read(tail[:]); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected EOF, got bytes=%d err=%v", n, err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte, progress func(int)) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 && progress != nil {
			progress(n)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// Minimal adapter for sing's TLS interface; no sing-box configuration machinery.
type testTLSConfig struct {
	config  *tls.Config
	timeout time.Duration
}

func (c *testTLSConfig) ServerName() string                      { return c.config.ServerName }
func (c *testTLSConfig) SetServerName(value string)              { c.config.ServerName = value }
func (c *testTLSConfig) NextProtos() []string                    { return c.config.NextProtos }
func (c *testTLSConfig) SetNextProtos(value []string)            { c.config.NextProtos = value }
func (c *testTLSConfig) HandshakeTimeout() time.Duration         { return c.timeout }
func (c *testTLSConfig) SetHandshakeTimeout(value time.Duration) { c.timeout = value }
func (c *testTLSConfig) STDConfig() (*aTLS.STDConfig, error)     { return c.config, nil }
func (c *testTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}
func (c *testTLSConfig) Clone() aTLS.Config {
	return &testTLSConfig{config: c.config.Clone(), timeout: c.timeout}
}
