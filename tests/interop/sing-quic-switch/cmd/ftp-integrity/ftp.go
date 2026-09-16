package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type ftpSession struct {
	tlsConfig *tls.Config
	conn      net.Conn
	reader    *bufio.Reader
	target    netip.AddrPort
}

func login(ctx, lifetimeCtx context.Context, dialer *transport, target netip.AddrPort) (*ftpSession, error) {
	conn, err := dialer.Dial(ctx, lifetimeCtx, target, false)
	if err != nil {
		return nil, err
	}
	f := &ftpSession{conn: conn, reader: bufio.NewReaderSize(conn, 4096), target: target, tlsConfig: dialer.ftpTLS}
	err = func() error {
		if _, err := f.expect(220); err != nil {
			return err
		}
		if f.tlsConfig != nil {
			if err := f.send("AUTH TLS"); err != nil {
				return err
			}
			if _, err := f.expect(234); err != nil {
				return err
			}
			secured, err := f.secureData(ctx, f.conn)
			if err != nil {
				return fmt.Errorf("AUTH TLS handshake: %w", err)
			}
			f.conn = secured
			f.reader = bufio.NewReaderSize(secured, 4096)
		}
		if err := f.send("USER fixture"); err != nil {
			return err
		}
		code, message, err := readResponse(f.reader)
		if err != nil {
			return err
		}
		switch code {
		case 331:
			if err := f.send("PASS fixture"); err != nil {
				return err
			}
			if _, err := f.expect(230); err != nil {
				return err
			}
		case 230:
		default:
			return fmt.Errorf("USER: unexpected FTP response %d %s", code, message)
		}
		if f.tlsConfig != nil {
			for _, command := range []string{"PBSZ 0", "PROT P"} {
				if err := f.send(command); err != nil {
					return err
				}
				if _, err := f.expect(200); err != nil {
					return err
				}
			}
		}
		if err := f.send("TYPE I"); err != nil {
			return err
		}
		_, err = f.expect(200)
		return err
	}()
	if err != nil {
		_ = f.conn.Close()
		return nil, err
	}
	return f, nil
}

func (f *ftpSession) Close() error { return f.conn.Close() }

func (f *ftpSession) send(command string) error {
	if strings.ContainsAny(command, "\r\n") {
		return errors.New("FTP command contains line break")
	}
	_, err := io.WriteString(f.conn, command+"\r\n")
	return err
}

func (f *ftpSession) expect(expected ...int) (string, error) {
	code, message, err := readResponse(f.reader)
	if err != nil {
		return "", err
	}
	for _, want := range expected {
		if code == want {
			return message, nil
		}
	}
	return message, fmt.Errorf("expected FTP %v, got %d %s", expected, code, message)
}

// FTP multiline replies end only at the original code followed by a space.
// Bound lines/reply size so a malformed fixture cannot grow memory indefinitely.
func readResponse(reader *bufio.Reader) (int, string, error) {
	line, err := responseLine(reader)
	if err != nil {
		return 0, "", fmt.Errorf("read FTP response: %w", err)
	}
	if len(line) > 4096 || len(line) < 5 || !strings.HasSuffix(line, "\r\n") {
		return 0, "", errors.New("malformed or oversized FTP response line")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 599 || (line[3] != ' ' && line[3] != '-') {
		return 0, "", errors.New("malformed FTP response code")
	}
	message := strings.TrimSuffix(line[4:], "\r\n")
	if line[3] == ' ' {
		return code, message, nil
	}
	terminator := line[:3] + " "
	for count := 0; count < 128; count++ {
		line, err = responseLine(reader)
		if err != nil {
			return 0, "", fmt.Errorf("read multiline FTP response: %w", err)
		}
		if len(line) > 4096 || !strings.HasSuffix(line, "\r\n") {
			return 0, "", errors.New("malformed or oversized FTP response line")
		}
		if strings.HasPrefix(line, terminator) {
			return code, strings.TrimSuffix(line[4:], "\r\n"), nil
		}
	}
	return 0, "", errors.New("FTP multiline response exceeds 128 lines")
}

func responseLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func (f *ftpSession) passive() (netip.AddrPort, error) {
	if err := f.send("EPSV"); err != nil {
		return netip.AddrPort{}, err
	}
	code, message, err := readResponse(f.reader)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if code == 229 {
		port, err := parseEPSV(message)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(f.target.Addr(), port), nil
	}
	if code != 500 && code != 501 && code != 502 && code != 504 && code != 522 {
		return netip.AddrPort{}, fmt.Errorf("EPSV failed: %d %s", code, message)
	}
	if err := f.send("PASV"); err != nil {
		return netip.AddrPort{}, err
	}
	message, err = f.expect(227)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return parsePASV(message)
}

func parenthesized(message string) (string, error) {
	start := strings.IndexByte(message, '(')
	end := strings.LastIndexByte(message, ')')
	if start < 0 || end <= start+1 {
		return "", errors.New("FTP passive response lacks address tuple")
	}
	return message[start+1 : end], nil
}

func parseEPSV(message string) (uint16, error) {
	tuple, err := parenthesized(message)
	if err != nil {
		return 0, err
	}
	delim := tuple[0]
	fields := strings.Split(tuple, string(delim))
	if len(fields) != 5 || fields[0] != "" || fields[1] != "" || fields[2] != "" || fields[4] != "" {
		return 0, errors.New("invalid EPSV tuple")
	}
	port, err := strconv.ParseUint(fields[3], 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("invalid EPSV port")
	}
	return uint16(port), nil
}

func parsePASV(message string) (netip.AddrPort, error) {
	tuple, err := parenthesized(message)
	if err != nil {
		return netip.AddrPort{}, err
	}
	fields := strings.Split(tuple, ",")
	if len(fields) != 6 {
		return netip.AddrPort{}, errors.New("invalid PASV tuple")
	}
	var parts [6]byte
	for i, field := range fields {
		value, err := strconv.ParseUint(strings.TrimSpace(field), 10, 8)
		if err != nil {
			return netip.AddrPort{}, errors.New("invalid PASV address or port")
		}
		parts[i] = byte(value)
	}
	address := netip.AddrPortFrom(netip.AddrFrom4([4]byte{parts[0], parts[1], parts[2], parts[3]}), uint16(parts[4])<<8|uint16(parts[5]))
	if !address.Addr().IsLoopback() || address.Port() == 0 {
		return netip.AddrPort{}, errors.New("PASV returned non-loopback address or zero port")
	}
	return address, nil
}

func (f *ftpSession) data(ctx context.Context, dialer *transport, fastOpen bool) (net.Conn, error) {
	address, err := f.passive()
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx, ctx, address, fastOpen)
}

func (f *ftpSession) secureData(ctx context.Context, raw net.Conn) (net.Conn, error) {
	if f.tlsConfig == nil {
		return raw, nil
	}
	secured := tls.Client(raw, f.tlsConfig)
	if err := secured.HandshakeContext(ctx); err != nil {
		return raw, err
	}
	return secured, nil
}

func (f *ftpSession) transfer(ctx context.Context, dialer *transport, o options, r *result) error {
	started := time.Now()
	err := func() error {
		source, err := os.Open(o.file)
		if err != nil {
			return err
		}
		defer source.Close()
		data, err := f.data(ctx, dialer, o.fastOpen)
		if err != nil {
			return fmt.Errorf("STOR data connect: %w", err)
		}
		defer func() { _ = data.Close() }()
		if err := f.send("STOR " + r.RemoteFile); err != nil {
			return err
		}
		if _, err := f.expect(125, 150); err != nil {
			return err
		}
		data, err = f.secureData(ctx, data)
		if err != nil {
			return fmt.Errorf("STOR TLS handshake: %w", err)
		}
		r.UploadedBytes, err = io.Copy(data, source)
		if err != nil {
			return fmt.Errorf("STOR io.Copy after %d bytes: %w", r.UploadedBytes, err)
		}
		// Do not read the data socket to EOF and do not substitute CloseWrite:
		// plain FTP preserves official sing-quic Close behavior. FTPS normally
		// completes TLS shutdown first: unread session tickets or close_notify
		// can otherwise cause TCP RST and discard buffered upload data even in
		// direct mode. Immediate mode deliberately keeps that stress case.
		if secured, ok := data.(*tls.Conn); ok && o.closeMode != "immediate" {
			if err := secured.CloseWrite(); err != nil {
				return fmt.Errorf("STOR TLS close_notify: %w", err)
			}
			if _, err := io.Copy(io.Discard, eofReader{Reader: secured}); err != nil {
				return fmt.Errorf("STOR TLS shutdown response: %w", err)
			}
		}
		if err := data.Close(); err != nil {
			return fmt.Errorf("STOR Close: %w", err)
		}
		code, message, err := readResponse(f.reader)
		r.STORCode = code
		if err != nil {
			return fmt.Errorf("STOR completion: %w", err)
		}
		if code != 226 {
			return fmt.Errorf("STOR expected 226, got %d %s", code, message)
		}
		return nil
	}()
	r.UploadMS = time.Since(started).Milliseconds()
	if err != nil {
		return err
	}
	if err := f.send("SIZE " + r.RemoteFile); err != nil {
		return err
	}
	message, err := f.expect(213)
	if err != nil {
		return fmt.Errorf("SIZE: %w", err)
	}
	r.RemoteBytes, err = strconv.ParseInt(strings.TrimSpace(message), 10, 64)
	if err != nil || r.RemoteBytes < 0 {
		return fmt.Errorf("invalid SIZE response: %q", message)
	}
	// Even when SIZE differs, retrieve the actual server file for hashing and
	// ffmpeg examination; a successful 226 alone is not an integrity check.
	started = time.Now()
	err = func() error {
		data, err := f.data(ctx, dialer, false)
		if err != nil {
			return fmt.Errorf("RETR data connect: %w", err)
		}
		defer func() { _ = data.Close() }()
		if err := f.send("RETR " + r.RemoteFile); err != nil {
			return err
		}
		if _, err := f.expect(125, 150); err != nil {
			return err
		}
		data, err = f.secureData(ctx, data)
		if err != nil {
			return fmt.Errorf("RETR TLS handshake: %w", err)
		}
		output, err := os.Create(r.RetrievedFile)
		if err != nil {
			return err
		}
		hash := sha256.New()
		r.RetrievedBytes, err = io.CopyBuffer(io.MultiWriter(output, hash), eofReader{Reader: data}, make([]byte, 64*1024))
		r.RetrievedSHA256 = hex.EncodeToString(hash.Sum(nil))
		closeErr := output.Close()
		if err != nil {
			return fmt.Errorf("RETR io.Copy after %d bytes: %w", r.RetrievedBytes, err)
		}
		if closeErr != nil {
			return closeErr
		}
		if err := data.Close(); err != nil {
			return fmt.Errorf("RETR Close: %w", err)
		}
		code, message, err := readResponse(f.reader)
		r.RETRCode = code
		if err != nil {
			return fmt.Errorf("RETR completion: %w", err)
		}
		if code != 226 {
			return fmt.Errorf("RETR expected 226, got %d %s", code, message)
		}
		return nil
	}()
	r.DownloadMS = time.Since(started).Milliseconds()
	if err != nil {
		return err
	}
	if r.UploadedBytes != r.ExpectedBytes || r.RemoteBytes != r.ExpectedBytes || r.RetrievedBytes != r.ExpectedBytes || r.RetrievedSHA256 != r.ExpectedSHA256 {
		return fmt.Errorf("integrity mismatch: source=%d uploaded=%d SIZE=%d retrieved=%d source_sha256=%s retrieved_sha256=%s", r.ExpectedBytes, r.UploadedBytes, r.RemoteBytes, r.RetrievedBytes, r.ExpectedSHA256, r.RetrievedSHA256)
	}
	return nil
}

// sing-quic wraps even a clean io.EOF in quicError, whereas io.Copy only
// recognizes the exact io.EOF sentinel. Normalize only a wrapper whose final
// unwrapped cause is io.EOF. Do not use errors.Is: quicError also declares a
// locally cancelled QUIC stream equivalent to EOF, which would hide failures.
type eofReader struct{ io.Reader }

func (r eofReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil {
		cause := err
		for errors.Unwrap(cause) != nil {
			cause = errors.Unwrap(cause)
		}
		if cause == io.EOF {
			err = io.EOF
		}
	}
	return n, err
}
