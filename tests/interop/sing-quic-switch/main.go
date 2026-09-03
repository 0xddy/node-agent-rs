// sing-quic-switch exercises a normal download-to-upload transition through one
// official sing-quic HY2 client. All addresses must be numeric loopback addresses.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const (
	streams       = 4
	downloadBytes = 128 * 1024 * 1024
	uploadBytes   = 32 * 1024 * 1024
	chunkBytes    = 64 * 1024
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sing-quic-switch:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return errors.New("usage: sing-quic-switch HY2_LOOPBACK_ADDR TCP_LOOPBACK_ADDR TEST_PASSWORD")
	}
	server, err := loopbackAddress(os.Args[1])
	if err != nil {
		return fmt.Errorf("HY2 server: %w", err)
	}
	target, err := loopbackAddress(os.Args[2])
	if err != nil {
		return fmt.Errorf("TCP target: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        &singleTransportDialer{},
		Logger:        logger.NOP(),
		ServerAddress: server,
		Password:      os.Args[3],
		TLSConfig: &testTLSConfig{
			config: &tls.Config{
				ServerName:         "localhost",
				InsecureSkipVerify: true, // Test certificates, loopback destinations only.
			},
			timeout: 15 * time.Second,
		},
		// Zero bandwidth selects automatic congestion control. UDP forwarding
		// is unused; the QUIC transport remains UDP as required by HY2.
		UDPDisabled: true,
	})
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer client.CloseWithError(context.Canceled)
	stopCancel := context.AfterFunc(ctx, func() { _ = client.CloseWithError(ctx.Err()) })
	defer stopCancel()

	if err := phase(ctx, client, target, "download", 0, downloadBytes); err != nil {
		return err
	}
	// No sleep or new HY2 Client between phases: exercise immediate direction change.
	if err := phase(ctx, client, target, "upload", uploadBytes, 1); err != nil {
		return err
	}
	conn, err := dial(ctx, client, target)
	if err != nil {
		return fmt.Errorf("probe dial: %w", err)
	}
	defer conn.Close()
	if err := writeAll(conn, []byte("who\n")); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	line, err := bufio.NewReaderSize(conn, 4096).ReadSlice('\n')
	if err != nil {
		return fmt.Errorf("probe read: %w", err)
	}
	if string(line) != "bounded-peer\n" {
		return fmt.Errorf("unexpected probe response: %q", line)
	}
	fmt.Printf("probe=%s\n", strings.TrimSuffix(string(line), "\n"))
	return nil
}

func loopbackAddress(value string) (M.Socksaddr, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return M.Socksaddr{}, errors.New("expected a numeric loopback IP with a nonzero port")
	}
	return M.SocksaddrFromNetIP(address), nil
}

// The SDK normally reconnects transparently. Refuse a second underlying UDP
// transport so a closed QUIC connection cannot silently turn this into a new-
// connection test. The actual socket implementation is sing's SystemDialer.
type singleTransportDialer struct {
	dials atomic.Uint32
}

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

func dial(ctx context.Context, client *hysteria2.Client, target M.Socksaddr) (net.Conn, error) {
	conn, err := client.DialConn(ctx, target)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(90 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func phase(ctx context.Context, client *hysteria2.Client, target M.Socksaddr, name string, sendBytes, receiveBytes int64) error {
	started := time.Now()
	results := make(chan error, streams)
	for stream := 0; stream < streams; stream++ {
		go func() {
			results <- transfer(ctx, client, target, sendBytes, receiveBytes)
		}()
	}
	for stream := 0; stream < streams; stream++ {
		select {
		case err := <-results:
			if err != nil {
				_ = client.CloseWithError(err)
				return fmt.Errorf("%s: %w", name, err)
			}
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", name, ctx.Err())
		}
	}
	bytes := receiveBytes
	if sendBytes > 0 {
		bytes = sendBytes
	}
	fmt.Printf("%s streams=%d bytes=%d elapsed=%s\n", name, streams, streams*bytes, time.Since(started))
	return nil
}

func transfer(ctx context.Context, client *hysteria2.Client, target M.Socksaddr, sendBytes, receiveBytes int64) error {
	conn, err := dial(ctx, client, target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	command := fmt.Sprintf("%d %d\n", sendBytes, receiveBytes)
	if err := writeAll(conn, []byte(command)); err != nil {
		return fmt.Errorf("command: %w", err)
	}
	buffer := make([]byte, chunkBytes)
	for index := range buffer {
		buffer[index] = 'x'
	}
	for remaining := sendBytes; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		if err := writeAll(conn, buffer[:n]); err != nil {
			return fmt.Errorf("upload after %d bytes: %w", sendBytes-remaining, err)
		}
		remaining -= n
	}
	for remaining := receiveBytes; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		if _, err := io.ReadFull(conn, buffer[:n]); err != nil {
			return fmt.Errorf("download after %d bytes: %w", receiveBytes-remaining, err)
		}
		for _, value := range buffer[:n] {
			if value != 'y' {
				return fmt.Errorf("unexpected target data after %d bytes", receiveBytes-remaining)
			}
		}
		remaining -= n
	}
	if n, err := conn.Read(buffer[:1]); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected transfer EOF, got bytes=%d err=%v", n, err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
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

// Minimal adapter for sing's TLS interface; no sing-box configuration machinery
// or forked transport is required for this official-client interoperability test.
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
