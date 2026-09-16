package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
)

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestCleanWrappedEOFOnly(t *testing.T) {
	if _, err := io.Copy(io.Discard, eofReader{errorReader{qtls.WrapError(io.EOF)}}); err != nil {
		t.Fatalf("clean EOF: %v", err)
	}
	for _, original := range []error{io.ErrUnexpectedEOF, &quic.StreamError{StreamID: 0, ErrorCode: 0, Remote: false}, context.Canceled} {
		wrapped := qtls.WrapError(original)
		if _, err := io.Copy(io.Discard, eofReader{errorReader{wrapped}}); err != wrapped {
			t.Fatalf("masked %T: got %v", original, err)
		}
	}
}

// Emulate quic-go's final Read returning data + EOF, followed by sing-quic
// wrapping the EOF. Applying eofReader only outside TLS loses a final record;
// applying it below TLS must preserve all plaintext and its close_notify.
func TestWrappedEOFBelowTLSPreservesFinalRecord(t *testing.T) {
	for _, normalizeBelowTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("normalize_below_tls=%t", normalizeBelowTLS), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			deadline, _ := ctx.Deadline()
			_ = clientRaw.SetDeadline(deadline)
			_ = serverRaw.SetDeadline(deadline)
			payload := bytes.Repeat([]byte{0x47, 0x80, 0xff}, 1448)
			serverTLS := fixtureTLSConfig(t)
			serverDone := make(chan error, 1)
			go func() {
				defer serverRaw.Close()
				server := tls.Server(serverRaw, serverTLS)
				if err := server.HandshakeContext(ctx); err != nil {
					serverDone <- err
					return
				}
				if _, err := server.Write(payload); err != nil {
					serverDone <- err
					return
				}
				serverDone <- server.CloseWrite()
			}()
			wrapped := &terminalWrappedEOFConn{Conn: clientRaw}
			var underlying net.Conn = wrapped
			if normalizeBelowTLS {
				underlying = &managedConn{Conn: wrapped, stop: func() bool { return true }}
			}
			client := tls.Client(underlying, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			wrapped.collectFinalRecords = true
			actual, err := io.ReadAll(eofReader{Reader: client})
			if err != nil {
				t.Fatal(err)
			}
			if normalizeBelowTLS && !bytes.Equal(actual, payload) {
				t.Fatalf("lost TLS final record: got %d want %d", len(actual), len(payload))
			}
			if !normalizeBelowTLS && bytes.Equal(actual, payload) {
				t.Fatal("negative control did not reproduce wrapped-EOF record loss")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type terminalWrappedEOFConn struct {
	net.Conn
	collectFinalRecords bool
	final               *bytes.Reader
}

func (c *terminalWrappedEOFConn) Read(p []byte) (int, error) {
	if !c.collectFinalRecords {
		return c.Conn.Read(p)
	}
	if c.final == nil {
		data, err := io.ReadAll(c.Conn)
		if err != nil {
			return 0, err
		}
		c.final = bytes.NewReader(data)
	}
	n, err := c.final.Read(p)
	if c.final.Len() == 0 {
		return n, qtls.WrapError(io.EOF)
	}
	return n, err
}

func TestFTPResponseAndPassiveParsing(t *testing.T) {
	t.Run("multiline", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("220-first\r\n123 unrelated\r\n220 ready\r\n226 done\r\n"))
		code, message, err := readResponse(reader)
		if err != nil || code != 220 || message != "ready" {
			t.Fatalf("got %d %q %v", code, message, err)
		}
		if code, _, err := readResponse(reader); err != nil || code != 226 {
			t.Fatalf("trailing response lost: %d %v", code, err)
		}
	})
	for _, invalid := range []string{"not FTP\r\n", "999 impossible\r\n", "220 missing CRLF\n", "220-unterminated\r\n", "220 " + strings.Repeat("x", 8192) + "\r\n"} {
		if _, _, err := readResponse(bufio.NewReaderSize(strings.NewReader(invalid), 4096)); err == nil {
			t.Fatalf("accepted malformed reply %q", invalid[:min(len(invalid), 40)])
		}
	}
	for _, valid := range []string{"Entering Extended Passive Mode (|||30000|).", "EPSV (!!!2121!)."} {
		if _, err := parseEPSV(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{"EPSV (|||0|)", "EPSV (|||65536|)", "EPSV (||21|)", "missing"} {
		if _, err := parseEPSV(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	address, err := parsePASV("Entering Passive Mode (127,0,0,1,117,48).")
	if err != nil || address.String() != "127.0.0.1:30000" {
		t.Fatalf("got %v %v", address, err)
	}
	for _, invalid := range []string{"PASV (192,168,1,1,117,48)", "PASV (127,0,0,1,0,0)", "PASV (127,0,0,1,256,1)"} {
		if _, err := parsePASV(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

// A server can legitimately send 226 after seeing a clean but prematurely
// shortened stream. Ensure the harness rejects that case and retains its RETR.
func TestTransferIntegrity(t *testing.T) {
	for _, tc := range []struct{ ftps, truncate bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("ftps=%t/truncate=%t", tc.ftps, tc.truncate), func(t *testing.T) {
			truncate := tc.truncate
			dir := t.TempDir()
			source := bytes.Repeat([]byte{0x47, 0, 0, 0, 0xff, 0x12, 0x80}, 1000)
			input := filepath.Join(dir, "source.ts")
			if err := os.WriteFile(input, source, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var serverTLS *tls.Config
			if tc.ftps {
				serverTLS = fixtureTLSConfig(t)
			}
			address, serverDone := startFTPFixture(t, ctx, truncate, serverTLS)
			dialer, err := newTransport(ctx, options{mode: "direct", ftps: tc.ftps})
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			ftp, err := login(ctx, ctx, dialer, address)
			if err != nil {
				t.Fatal(err)
			}
			defer ftp.Close()
			hash := sha256.Sum256(source)
			r := result{RemoteFile: "sample.ts", RetrievedFile: filepath.Join(dir, "retrieved.ts"), ExpectedBytes: int64(len(source)), ExpectedSHA256: hex.EncodeToString(hash[:])}
			err = ftp.transfer(ctx, dialer, options{file: input}, &r)
			if truncate {
				if err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
					t.Fatalf("truncated upload must fail integrity: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if r.STORCode != 226 || r.RETRCode != 226 || r.UploadedBytes != int64(len(source)) {
				t.Fatalf("unexpected transfer evidence: %+v", r)
			}
			retrieved, err := os.ReadFile(r.RetrievedFile)
			if err != nil {
				t.Fatal(err)
			}
			expected := source
			if truncate {
				expected = source[:len(source)-17]
			}
			if !bytes.Equal(retrieved, expected) {
				t.Fatal("retrieved file does not retain actual server bytes")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func fixtureTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func startFTPFixture(t *testing.T, ctx context.Context, truncate bool, serverTLS *tls.Config) (netip.AddrPort, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				return err
			}
			reader := bufio.NewReader(conn)
			tlsActive, pbsz, protected := false, false, false
			var passive *net.TCPListener
			defer func() {
				if passive != nil {
					_ = passive.Close()
				}
			}()
			var stored []byte
			if _, err := io.WriteString(conn, "220 fixture\r\n"); err != nil {
				return err
			}
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				command := strings.TrimSpace(line)
				switch {
				case command == "AUTH TLS" && serverTLS != nil && !tlsActive:
					if _, err := io.WriteString(conn, "234 AUTH TLS\r\n"); err != nil {
						return err
					}
					secured := tls.Server(conn, serverTLS)
					if err := secured.HandshakeContext(ctx); err != nil {
						return err
					}
					conn = secured
					reader = bufio.NewReader(conn)
					tlsActive = true
				case command == "USER fixture":
					if serverTLS != nil && !tlsActive {
						return errors.New("FTPS USER preceded TLS")
					}
					_, err = io.WriteString(conn, "331 password\r\n")
				case command == "PASS fixture":
					_, err = io.WriteString(conn, "230 logged in\r\n")
				case command == "TYPE I":
					_, err = io.WriteString(conn, "200 binary\r\n")
				case command == "PBSZ 0" && tlsActive:
					pbsz = true
					_, err = io.WriteString(conn, "200 PBSZ\r\n")
				case command == "PROT P" && tlsActive && pbsz:
					protected = true
					_, err = io.WriteString(conn, "200 PROT\r\n")
				case command == "EPSV":
					passive, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						return err
					}
					if err := passive.SetDeadline(deadline); err != nil {
						return err
					}
					_, err = fmt.Fprintf(conn, "229 passive (|||%d|)\r\n", passive.Addr().(*net.TCPAddr).Port)
				case command == "STOR sample.ts" || command == "RETR sample.ts":
					if passive == nil {
						return errors.New("data command without passive listener")
					}
					data, err := passive.Accept()
					if err != nil {
						return err
					}
					_ = passive.Close()
					passive = nil
					if err := data.SetDeadline(deadline); err != nil {
						_ = data.Close()
						return err
					}
					if _, err := io.WriteString(conn, "150 data\r\n"); err != nil {
						_ = data.Close()
						return err
					}
					if serverTLS != nil {
						if !protected {
							_ = data.Close()
							return errors.New("FTPS data without PROT P")
						}
						secured := tls.Server(data, serverTLS)
						if err := secured.HandshakeContext(ctx); err != nil {
							_ = data.Close()
							return err
						}
						data = secured
					}
					if strings.HasPrefix(command, "STOR") {
						stored, err = io.ReadAll(data)
						if truncate && len(stored) >= 17 {
							stored = stored[:len(stored)-17]
						}
					} else {
						_, err = data.Write(stored)
					}
					_ = data.Close()
					if err != nil {
						return err
					}
					if _, err := io.WriteString(conn, "226 complete\r\n"); err != nil {
						return err
					}
					if strings.HasPrefix(command, "RETR") {
						return nil
					}
				case command == "SIZE sample.ts":
					_, err = fmt.Fprintf(conn, "213 %d\r\n", len(stored))
				default:
					return fmt.Errorf("unexpected fixture command %q", command)
				}
				if err != nil {
					return err
				}
			}
		}()
	}()
	return listener.Addr().(*net.TCPAddr).AddrPort(), done
}
