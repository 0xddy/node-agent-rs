package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const usage = `usage: sing-quic-switch HY2_LOOPBACK_ADDR TCP_LOOPBACK_ADDR TEST_PASSWORD [options]
  --streams N             Parallel streams per phase, 1..64 (default 4)
  --download SIZE         Download bytes PER STREAM; 0 skips (default 128MiB)
  --upload SIZE           Upload bytes PER STREAM; 0 skips (default 32MiB)
  --rounds N              Download then upload rounds, 1..1000 (default 1)
  --timeout DURATION      Whole run deadline (default 120s)
  --stream-timeout DURATION  Each transfer deadline (default 90s)
  --probe-password VALUE  Optional different user on a separate QUIC connection
  --probe-interval DURATION  Independent probe interval (default 1s)
  --probe-timeout DURATION   Each probe deadline (default 5s)
SIZE is an integer byte count or an integer with B, KiB, MiB, GiB suffix.
Both addresses must be numeric loopback addresses with nonzero ports.`

type options struct {
	server, target              M.Socksaddr
	password                    string
	streams                     int
	download, upload            int64
	rounds                      int
	timeout, streamTimeout      time.Duration
	probePassword               string
	probeInterval, probeTimeout time.Duration
}

func parseOptions(args []string) (options, error) {
	var result options
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return result, flag.ErrHelp
	}
	if len(args) < 3 {
		return result, errors.New(usage)
	}
	var err error
	result.server, err = loopbackAddress(args[0])
	if err != nil {
		return result, fmt.Errorf("HY2 server: %w", err)
	}
	result.target, err = loopbackAddress(args[1])
	if err != nil {
		return result, fmt.Errorf("TCP target: %w", err)
	}
	result.password = args[2]
	flags := flag.NewFlagSet("sing-quic-switch", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var download, upload string
	flags.IntVar(&result.streams, "streams", 4, "parallel streams per phase")
	flags.StringVar(&download, "download", "128MiB", "download size per stream")
	flags.StringVar(&upload, "upload", "32MiB", "upload size per stream")
	flags.IntVar(&result.rounds, "rounds", 1, "number of rounds")
	flags.DurationVar(&result.timeout, "timeout", 120*time.Second, "whole run deadline")
	flags.DurationVar(&result.streamTimeout, "stream-timeout", 90*time.Second, "transfer deadline")
	flags.StringVar(&result.probePassword, "probe-password", "", "separate user password")
	flags.DurationVar(&result.probeInterval, "probe-interval", time.Second, "probe interval")
	flags.DurationVar(&result.probeTimeout, "probe-timeout", 5*time.Second, "probe deadline")
	if err := flags.Parse(args[3:]); err != nil {
		return result, err
	}
	if flags.NArg() != 0 {
		return result, errors.New("unexpected positional argument after options")
	}
	if result.streams < 1 || result.streams > 64 {
		return result, errors.New("streams must be in 1..64")
	}
	if result.rounds < 1 || result.rounds > 1000 {
		return result, errors.New("rounds must be in 1..1000")
	}
	if result.timeout <= 0 || result.streamTimeout <= 0 || result.probeInterval <= 0 || result.probeTimeout <= 0 {
		return result, errors.New("all durations must be positive")
	}
	result.download, err = parseSize(download)
	if err != nil {
		return result, fmt.Errorf("download: %w", err)
	}
	result.upload, err = parseSize(upload)
	if err != nil {
		return result, fmt.Errorf("upload: %w", err)
	}
	if result.download == 0 && result.upload == 0 {
		return result, errors.New("at least one transfer size must be positive")
	}
	if result.download > math.MaxInt64/int64(result.streams) || result.upload > math.MaxInt64/int64(result.streams) {
		return result, errors.New("per-phase byte total exceeds int64")
	}
	if result.probePassword != "" && result.probePassword == result.password {
		return result, errors.New("probe-password must identify a different test user")
	}
	return result, nil
}

func parseSize(value string) (int64, error) {
	value = strings.TrimSpace(value)
	multiplier := uint64(1)
	for _, suffix := range []struct {
		text       string
		multiplier uint64
	}{
		{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1},
	} {
		if strings.HasSuffix(value, suffix.text) {
			value = strings.TrimSuffix(value, suffix.text)
			multiplier = suffix.multiplier
			break
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > math.MaxInt64/multiplier {
		return 0, errors.New("expected a nonnegative integer byte count with optional B/KiB/MiB/GiB suffix")
	}
	return int64(n * multiplier), nil
}

func loopbackAddress(value string) (M.Socksaddr, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return M.Socksaddr{}, errors.New("expected a numeric loopback IP with a nonzero port")
	}
	return M.SocksaddrFromNetIP(address), nil
}
