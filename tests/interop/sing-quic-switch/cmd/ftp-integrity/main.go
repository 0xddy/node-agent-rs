// ftp-integrity uploads and retrieves a binary file through real FTP sessions.
// It deliberately uses the official sing-quic stream Close after STOR: FIN on
// the upload side and STOP_SENDING on the otherwise unused download side.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type options struct {
	closeMode                       string
	ftps                            bool
	server, target                  netip.AddrPort
	password, file, outputDir, mode string
	rounds, parallel                int
	fastOpen                        bool
	timeout, transferTimeout        time.Duration
}

type result struct {
	CloseMode       string `json:"close_mode"`
	FTPS            bool   `json:"ftps"`
	Mode            string `json:"mode"`
	FastOpen        bool   `json:"fast_open"`
	Worker          int    `json:"worker"`
	Round           int    `json:"round"`
	RemoteFile      string `json:"remote_file"`
	RetrievedFile   string `json:"retrieved_file"`
	ExpectedBytes   int64  `json:"expected_bytes"`
	ExpectedSHA256  string `json:"expected_sha256"`
	UploadedBytes   int64  `json:"uploaded_bytes"`
	STORCode        int    `json:"stor_code"`
	RemoteBytes     int64  `json:"remote_bytes"`
	RetrievedBytes  int64  `json:"retrieved_bytes"`
	RetrievedSHA256 string `json:"retrieved_sha256"`
	RETRCode        int    `json:"retr_code"`
	UploadMS        int64  `json:"upload_ms"`
	DownloadMS      int64  `json:"download_ms"`
	DurationMS      int64  `json:"duration_ms"`
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
}

func main() {
	o, err := parseOptions(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err == nil {
		err = run(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ftp-integrity:", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var o options
	var server, target string
	flags := flag.NewFlagSet("ftp-integrity", flag.ContinueOnError)
	flags.StringVar(&server, "server", "127.0.0.1:18443", "numeric loopback HY2 UDP address")
	flags.StringVar(&target, "target", "127.0.0.1:2121", "numeric loopback FTP TCP address as seen by proxy (or direct client)")
	flags.StringVar(&o.password, "password", "fixture-alice", "HY2 authentication password; FTP credentials are fixture/fixture")
	flags.StringVar(&o.file, "file", "", "source TS or other binary file")
	flags.StringVar(&o.outputDir, "output-dir", "ftp-integrity-output", "directory retaining latest RETR file per worker")
	flags.StringVar(&o.mode, "mode", "hy2", "hy2 or direct")
	flags.IntVar(&o.rounds, "rounds", 1, "upload + SIZE + RETR rounds per worker (1..1000)")
	flags.IntVar(&o.parallel, "parallel", 1, "parallel FTP sessions sharing one HY2 connection (1..16)")
	flags.BoolVar(&o.fastOpen, "fast-open", false, "skip HY2 TCP-response wait for STOR data streams")
	flags.BoolVar(&o.ftps, "ftps", false, "explicit FTPS: AUTH TLS, PBSZ 0, PROT P with loopback test certificates")
	flags.StringVar(&o.closeMode, "close-mode", "graceful", "FTPS upload TLS shutdown: graceful waits for peer close_notify; immediate closes transport immediately")
	flags.DurationVar(&o.timeout, "timeout", 5*time.Minute, "whole run deadline")
	flags.DurationVar(&o.transferTimeout, "transfer-timeout", 90*time.Second, "deadline for each upload + SIZE + RETR round and initial login")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.mode != "hy2" && o.mode != "direct" {
		return o, errors.New("--mode must be direct or hy2")
	}
	if o.closeMode != "graceful" && o.closeMode != "immediate" {
		return o, errors.New("--close-mode must be graceful or immediate")
	}
	if o.file == "" {
		return o, errors.New("--file is required")
	}
	if o.rounds < 1 || o.rounds > 1000 || o.parallel < 1 || o.parallel > 16 {
		return o, errors.New("--rounds must be 1..1000 and --parallel must be 1..16")
	}
	if o.timeout <= 0 || o.transferTimeout <= 0 {
		return o, errors.New("timeouts must be positive")
	}
	if o.fastOpen && o.mode != "hy2" {
		return o, errors.New("--fast-open requires --mode hy2")
	}
	var err error
	if o.server, err = loopbackAddress(server); err != nil {
		return o, fmt.Errorf("--server: %w", err)
	}
	if o.target, err = loopbackAddress(target); err != nil {
		return o, fmt.Errorf("--target: %w", err)
	}
	return o, nil
}

func loopbackAddress(value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return netip.AddrPort{}, errors.New("expected numeric loopback IP with nonzero port")
	}
	return address, nil
}

func run(o options) error {
	source, err := os.Open(o.file)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, source)
	closeErr := source.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if err := os.MkdirAll(o.outputDir, 0755); err != nil {
		return err
	}
	outputDir, err := filepath.Abs(o.outputDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	dialer, err := newTransport(ctx, o)
	if err != nil {
		return err
	}
	defer dialer.Close()
	var lock sync.Mutex
	encoder := json.NewEncoder(os.Stdout)
	report := func(r result) error {
		lock.Lock()
		defer lock.Unlock()
		return encoder.Encode(r)
	}
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	workerErrors := make(chan error, o.parallel)
	var workers sync.WaitGroup
	for worker := 1; worker <= o.parallel; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			var ftp *ftpSession
			defer func() {
				if ftp != nil {
					_ = ftp.Close()
				}
			}()
			for round := 1; round <= o.rounds; round++ {
				started := time.Now()
				r := result{
					Mode: o.mode, FastOpen: o.fastOpen, FTPS: o.ftps, CloseMode: o.closeMode, Worker: worker, Round: round,
					RemoteFile:    fmt.Sprintf("integrity-%s-w%02d.ts", runID, worker),
					RetrievedFile: filepath.Join(outputDir, fmt.Sprintf("retrieved-w%02d.ts", worker)),
					ExpectedBytes: size, ExpectedSHA256: digest, RemoteBytes: -1,
				}
				err := func() error {
					roundCtx, cancelRound := context.WithTimeout(ctx, o.transferTimeout)
					defer cancelRound()
					if ftp == nil {
						var err error
						ftp, err = login(roundCtx, ctx, dialer, o.target)
						if err != nil {
							return fmt.Errorf("login: %w", err)
						}
					}
					deadline, _ := roundCtx.Deadline()
					if err := ftp.conn.SetDeadline(deadline); err != nil {
						return err
					}
					return ftp.transfer(roundCtx, dialer, o, &r)
				}()
				r.DurationMS = time.Since(started).Milliseconds()
				r.OK = err == nil
				if err != nil {
					r.Error = err.Error()
				}
				if reportErr := report(r); reportErr != nil {
					workerErrors <- fmt.Errorf("write JSONL: %w", reportErr)
					return
				}
				if err != nil {
					workerErrors <- fmt.Errorf("worker %d round %d: %w", worker, round, err)
					return
				}
			}
			workerErrors <- nil
		}(worker)
	}
	var allErrors []error
	for range o.parallel {
		if err := <-workerErrors; err != nil {
			allErrors = append(allErrors, err)
		}
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		allErrors = append(allErrors, err)
	}
	return errors.Join(allErrors...)
}
