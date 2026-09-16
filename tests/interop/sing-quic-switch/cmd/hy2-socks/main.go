// hy2-socks exposes a loopback-only SOCKS5 CONNECT proxy backed by one
// Hysteria2 client session. It is a test adapter for GUI FTP clients.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type event struct {
	Event      string `json:"event"`
	Connection uint64 `json:"connection,omitempty"`
	Target     string `json:"target,omitempty"`
	Upload     int64  `json:"upload_bytes,omitempty"`
	Download   int64  `json:"download_bytes,omitempty"`
	Error      string `json:"error,omitempty"`
}

var logMu sync.Mutex

func emit(value event) {
	logMu.Lock()
	defer logMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func main() {
	var listen, server, password string
	flag.StringVar(&listen, "listen", "127.0.0.1:1080", "loopback SOCKS5 listen address")
	flag.StringVar(&server, "server", "127.0.0.1:18443", "loopback Hysteria2 UDP server")
	flag.StringVar(&password, "password", "fixture-alice", "Hysteria2 password")
	flag.Parse()

	listenAddr, err := netip.ParseAddrPort(listen)
	if err != nil || !listenAddr.Addr().IsLoopback() || listenAddr.Port() == 0 {
		fatal(errors.New("--listen must be a numeric loopback address with a nonzero port"))
	}
	serverAddr, err := netip.ParseAddrPort(server)
	if err != nil || !serverAddr.Addr().IsLoopback() || serverAddr.Port() == 0 {
		fatal(errors.New("--server must be a numeric loopback address with a nonzero port"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        &oneTransportDialer{},
		Logger:        logger.NOP(),
		ServerAddress: M.SocksaddrFromNetIP(serverAddr),
		Password:      password,
		TLSConfig: &testTLSConfig{config: &tls.Config{
			ServerName: "localhost", InsecureSkipVerify: true, // Loopback fixture only.
		}, timeout: 15 * time.Second},
		UDPDisabled: true,
	})
	if err != nil {
		fatal(err)
	}
	var closeClientOnce sync.Once
	closeClient := func(reason error) {
		closeClientOnce.Do(func() {
			emit(event{Event: "stopping", Error: reason.Error()})
			_ = client.CloseWithError(reason)
		})
	}
	defer closeClient(context.Canceled)

	listener, err := net.Listen("tcp", listenAddr.String())
	if err != nil {
		fatal(err)
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		closeClient(ctx.Err())
		_ = listener.Close()
	}()
	emit(event{Event: "ready", Target: listenAddr.String()})

	var nextID atomic.Uint64
	var workers sync.WaitGroup
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			emit(event{Event: "accept_error", Error: err.Error()})
			continue
		}
		id := nextID.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			handle(ctx, client, id, local)
		}()
	}
	workers.Wait()
	emit(event{Event: "stopped"})
}

func handle(ctx context.Context, client *hysteria2.Client, id uint64, local net.Conn) {
	defer local.Close()
	target, err := negotiate(local)
	if err != nil {
		emit(event{Event: "rejected", Connection: id, Error: err.Error()})
		return
	}
	remote, err := client.DialConn(ctx, M.SocksaddrFromNetIP(target))
	if err != nil {
		_ = socksReply(local, 0x05)
		emit(event{Event: "dial_error", Connection: id, Target: target.String(), Error: err.Error()})
		return
	}
	defer remote.Close()
	if _, err := remote.Write(nil); err != nil {
		_ = socksReply(local, 0x01)
		emit(event{Event: "dial_error", Connection: id, Target: target.String(), Error: err.Error()})
		return
	}
	if _, err := remote.Read(nil); err != nil {
		_ = socksReply(local, 0x01)
		emit(event{Event: "dial_error", Connection: id, Target: target.String(), Error: err.Error()})
		return
	}
	if err := socksReply(local, 0x00); err != nil {
		return
	}
	emit(event{Event: "connected", Connection: id, Target: target.String()})

	type result struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan result, 2)
	go func() {
		n, err := io.Copy(remote, local)
		err = cleanEOF(err)
		if closeWriter, ok := remote.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, cleanEOF(closeWriter.CloseWrite()))
		}
		results <- result{direction: "upload", bytes: n, err: err}
	}()
	go func() {
		n, err := io.Copy(local, remote)
		err = cleanEOF(err)
		if closeWriter, ok := local.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, cleanEOF(closeWriter.CloseWrite()))
		}
		results <- result{direction: "download", bytes: n, err: err}
	}()
	first := <-results
	if first.err != nil {
		_ = local.SetDeadline(time.Now())
		_ = remote.SetDeadline(time.Now())
	}
	second := <-results
	var upload, download int64
	var copyErr error
	for _, item := range []result{first, second} {
		if item.direction == "upload" {
			upload = item.bytes
		} else {
			download = item.bytes
		}
		copyErr = errors.Join(copyErr, item.err)
	}
	e := event{Event: "closed", Connection: id, Target: target.String(), Upload: upload, Download: download}
	if copyErr != nil {
		e.Error = copyErr.Error()
	}
	emit(e)
}

func cleanEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func negotiate(conn net.Conn) (netip.AddrPort, error) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return netip.AddrPort{}, err
	}
	if header[0] != 5 || header[1] == 0 {
		return netip.AddrPort{}, errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return netip.AddrPort{}, err
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return netip.AddrPort{}, errors.New("SOCKS5 client did not offer no-auth")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return netip.AddrPort{}, err
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return netip.AddrPort{}, err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return netip.AddrPort{}, errors.New("only SOCKS5 CONNECT is supported")
	}
	var host string
	switch request[3] {
	case 1:
		value := make([]byte, 4)
		if _, err := io.ReadFull(conn, value); err != nil {
			return netip.AddrPort{}, err
		}
		host = net.IP(value).String()
	case 4:
		value := make([]byte, 16)
		if _, err := io.ReadFull(conn, value); err != nil {
			return netip.AddrPort{}, err
		}
		host = net.IP(value).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return netip.AddrPort{}, err
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, value); err != nil {
			return netip.AddrPort{}, err
		}
		host = string(value)
	default:
		return netip.AddrPort{}, errors.New("unsupported SOCKS5 address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if host == "localhost" {
		host = "127.0.0.1"
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("non-loopback target rejected: %s:%d", host, port)
	}
	if port != 2121 && (port < 30000 || port > 30100) {
		return netip.AddrPort{}, fmt.Errorf("target port outside FTP fixture range: %d", port)
	}
	_ = conn.SetDeadline(time.Time{})
	return netip.AddrPortFrom(address, port), nil
}

func socksReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func fatal(err error) {
	emit(event{Event: "fatal", Error: err.Error()})
	os.Exit(1)
}

type oneTransportDialer struct{ dials atomic.Uint32 }

func (d *oneTransportDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "udp" || !destination.Addr.IsLoopback() {
		return nil, errors.New("only loopback UDP transport is permitted")
	}
	if d.dials.Add(1) != 1 {
		return nil, errors.New("HY2 attempted automatic reconnect")
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (*oneTransportDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("port hopping is disabled")
}

type testTLSConfig struct {
	config  *tls.Config
	timeout time.Duration
}

func (c *testTLSConfig) ServerName() string                  { return c.config.ServerName }
func (c *testTLSConfig) SetServerName(v string)              { c.config.ServerName = v }
func (c *testTLSConfig) NextProtos() []string                { return c.config.NextProtos }
func (c *testTLSConfig) SetNextProtos(v []string)            { c.config.NextProtos = v }
func (c *testTLSConfig) HandshakeTimeout() time.Duration     { return c.timeout }
func (c *testTLSConfig) SetHandshakeTimeout(v time.Duration) { c.timeout = v }
func (c *testTLSConfig) STDConfig() (*aTLS.STDConfig, error) { return c.config, nil }
func (c *testTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}
func (c *testTLSConfig) Clone() aTLS.Config {
	return &testTLSConfig{config: c.config.Clone(), timeout: c.timeout}
}
