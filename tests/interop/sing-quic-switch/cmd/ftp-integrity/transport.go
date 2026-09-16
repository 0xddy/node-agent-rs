package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type transport struct {
	ftpTLS *tls.Config
	client *hysteria2.Client
	stop   func() bool
	done   chan struct{}
}

func newTransport(ctx context.Context, o options) (*transport, error) {
	t := &transport{}
	if o.ftps {
		t.ftpTLS = &tls.Config{
			ServerName: "localhost", InsecureSkipVerify: true, // Loopback fixture certificate only.
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(128),
		}
	}
	if o.mode == "direct" {
		return t, nil
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context: ctx, Dialer: &singleTransportDialer{}, Logger: logger.NOP(),
		ServerAddress: M.SocksaddrFromNetIP(o.server), Password: o.password,
		TLSConfig: &testTLSConfig{config: &tls.Config{
			ServerName: "localhost", InsecureSkipVerify: true, // Loopback fixture certificate only.
		}, timeout: 15 * time.Second}, UDPDisabled: true,
	})
	if err != nil {
		return nil, err
	}
	t.client = client
	t.done = make(chan struct{})
	t.stop = context.AfterFunc(ctx, func() {
		defer close(t.done)
		_ = client.CloseWithError(ctx.Err())
	})
	return t, nil
}

func (t *transport) Close() {
	if t.client == nil {
		return
	}
	if !t.stop() {
		<-t.done
	}
	_ = t.client.CloseWithError(context.Canceled)
}

// deadlineCtx bounds connect/handshake. lifetimeCtx owns the returned socket;
// a control connection survives individual round contexts but not the run.
func (t *transport) Dial(deadlineCtx, lifetimeCtx context.Context, target netip.AddrPort, fastOpen bool) (net.Conn, error) {
	if !target.Addr().IsLoopback() || target.Port() == 0 {
		return nil, errors.New("non-loopback FTP target rejected")
	}
	var raw net.Conn
	var err error
	if t.client == nil {
		raw, err = (&net.Dialer{}).DialContext(deadlineCtx, "tcp", target.String())
	} else {
		raw, err = t.client.DialConn(deadlineCtx, M.SocksaddrFromNetIP(target))
	}
	if err != nil {
		return nil, err
	}
	conn := &managedConn{Conn: raw, done: make(chan struct{})}
	conn.stop = context.AfterFunc(lifetimeCtx, func() {
		defer close(conn.done)
		_ = raw.SetDeadline(time.Now())
		_ = raw.Close()
	})
	deadline, _ := deadlineCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if t.client != nil {
		// sing-quic DialConn is lazy. FTP reads the greeting first, and a
		// passive FTP server may await TCP accept before replying to STOR.
		// A zero-byte Write starts HY2's request without application bytes.
		if _, err := conn.Write(nil); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("HY2 TCP request: %w", err)
		}
		if !fastOpen {
			// The locked sing-quic implementation parses TCPResponse before
			// reading payload. A zero-length read consumes only that response.
			if _, err := conn.Read(nil); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("HY2 TCP response: %w", err)
			}
		}
	}
	return conn, nil
}

type managedConn struct {
	net.Conn
	stop func() bool
	done chan struct{}
	once sync.Once
	err  error
}

// Normalize clean wrapped EOF below TLS as well as application copy loops.
// quic-go may return the final bytes together with EOF; crypto/tls uses exact
// EOF comparisons while collecting encrypted records, and a wrapped EOF can
// otherwise make it abandon the final complete record already in its buffer.
func (c *managedConn) Read(p []byte) (int, error) {
	return (eofReader{Reader: c.Conn}).Read(p)
}

func (c *managedConn) Close() error {
	c.once.Do(func() {
		if !c.stop() {
			<-c.done
		}
		c.err = c.Conn.Close()
	})
	return c.err
}

// Refuse automatic reconnect so a failed QUIC connection cannot be hidden by
// the official SDK opening another transport for the next FTP stream.
type singleTransportDialer struct{ dials atomic.Uint32 }

func (d *singleTransportDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "udp" || !destination.Addr.IsLoopback() {
		return nil, errors.New("only loopback UDP transport is permitted")
	}
	if d.dials.Add(1) != 1 {
		return nil, errors.New("HY2 attempted automatic reconnect during FTP integrity test")
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (*singleTransportDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("port hopping and realm sockets are not used by this test")
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
