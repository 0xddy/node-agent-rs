package main

import (
	"errors"
	"flag"
	"testing"
	"time"
)

func testArgs(extra ...string) []string {
	return append([]string{"127.0.0.1:18443", "127.0.0.1:19091", "alice"}, extra...)
}

func TestOptionsOriginalInvocation(t *testing.T) {
	options, err := parseOptions(testArgs())
	if err != nil {
		t.Fatal(err)
	}
	if options.connections != 1 || options.streams != 4 || options.download != 128<<20 || options.upload != 32<<20 || options.rounds != 1 || options.timeout != 120*time.Second || options.streamTimeout != 90*time.Second || options.cancelDownloadAfter != 0 || options.probePassword != "" {
		t.Fatalf("original three-argument defaults changed: %+v", options)
	}
}

func TestOptionsDockerTransfers(t *testing.T) {
	for _, test := range []struct {
		name     string
		args     []string
		streams  int
		down, up int64
		rounds   int
	}{
		{"single-upload", testArgs("--streams", "1", "--download", "0", "--upload", "2GiB", "--timeout", "10m", "--stream-timeout", "8m"), 1, 0, 2 << 30, 1},
		{"repeated-switch", testArgs("--streams", "4", "--download", "512MiB", "--upload", "256MiB", "--rounds", "3", "--probe-password", "bob", "--probe-interval", "500ms"), 4, 512 << 20, 256 << 20, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseOptions(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if options.streams != test.streams || options.download != test.down || options.upload != test.up || options.rounds != test.rounds {
				t.Fatalf("sizes must be per stream: %+v", options)
			}
		})
	}
}

func TestOptionsEqualTotalBytesAcrossConnectionLayouts(t *testing.T) {
	for _, test := range []struct {
		name, connections, streams, size string
		wantConnections, wantStreams     int
	}{
		{"single", "1", "1", "1GiB", 1, 1},
		{"multiplexed", "1", "16", "64MiB", 1, 16},
		{"multiple-quic", "8", "2", "64MiB", 8, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseOptions(testArgs("--connections", test.connections, "--streams", test.streams, "--download", test.size, "--upload", test.size, "--probe-password", "bob"))
			if err != nil {
				t.Fatal(err)
			}
			if options.connections != test.wantConnections || options.streams != test.wantStreams || options.download*int64(options.totalStreams()) != 1<<30 || options.upload*int64(options.totalStreams()) != 1<<30 {
				t.Fatalf("layouts do not carry equal per-phase bytes: %+v", options)
			}
		})
	}
}

func TestOptionsConcurrentStreamBoundary(t *testing.T) {
	for _, args := range [][]string{
		testArgs("--connections", "8", "--streams", "4"),
		testArgs("--connections", "32", "--streams", "1"),
		testArgs("--connections", "31", "--streams", "1", "--probe-password", "bob"),
	} {
		if _, err := parseOptions(args); err != nil {
			t.Fatalf("rejected permitted boundary %q: %v", args, err)
		}
	}
}

func TestOptionsRejectUnsafeOrUnboundedInputs(t *testing.T) {
	for _, args := range [][]string{
		{"localhost:18443", "127.0.0.1:19091", "alice"},
		{"192.0.2.1:18443", "127.0.0.1:19091", "alice"},
		{"127.0.0.1:18443", "192.0.2.1:19091", "alice"},
		{"127.0.0.1:0", "127.0.0.1:19091", "alice"},
		testArgs("--streams", "0"), testArgs("--streams", "33"),
		testArgs("--connections", "0"), testArgs("--connections", "33"),
		testArgs("--connections", "8", "--streams", "5"),
		testArgs("--connections", "8", "--streams", "4", "--probe-password", "bob"),
		testArgs("--connections", "8", "--streams", "2", "--upload", "576460752303423488"), // Only total across connections overflows.
		testArgs("--rounds", "0"), testArgs("--rounds", "1001"),
		testArgs("--timeout", "0s"), testArgs("--stream-timeout", "-1s"),
		testArgs("--probe-interval", "0s"), testArgs("--probe-timeout", "-1s"),
		testArgs("--cancel-download-after", "-1s"),
		testArgs("--cancel-download-after", "90s"),
		testArgs("--cancel-download-after", "3s", "--timeout", "2s"),
		testArgs("--cancel-download-after", "3s", "--download", "0"),
		testArgs("--cancel-download-after", "3s", "--upload", "0"),
		testArgs("--download", "0", "--upload", "0"),
		testArgs("--download", "-1"), testArgs("--upload", "1.5GiB"),
		testArgs("--download", "9223372036854775807"), // Total over four streams would overflow.
		testArgs("--upload", "9223372036854775808"),
		testArgs("--upload", "18446744073709551615GiB"),
		testArgs("--probe-password", "alice"), testArgs("extra"),
	} {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("accepted invalid arguments %q", args)
		}
	}
}

func TestOptionsCancelDownloadsThenUpload(t *testing.T) {
	options, err := parseOptions(testArgs("--connections", "1", "--streams", "15", "--download", "128MiB", "--upload", "16MiB", "--cancel-download-after", "3s", "--rounds", "3", "--probe-password", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if options.cancelDownloadAfter != 3*time.Second || options.download != 128<<20 || options.upload*int64(options.totalStreams()) != 240<<20 || options.rounds != 3 {
		t.Fatalf("unexpected cancellation comparison: %+v", options)
	}
	if _, err := parseOptions(testArgs("--download", "0", "--cancel-download-after", "0s")); err != nil {
		t.Fatalf("explicitly disabled cancellation changed normal behavior: %v", err)
	}
}

func TestCancellationCapacityIncludesOldDownloadsAndNewUploads(t *testing.T) {
	for _, test := range []struct {
		name    string
		flags   []string
		allowed bool
	}{
		{"fifteen-plus-bob", []string{"--connections", "1", "--streams", "15", "--probe-password", "bob"}, true},
		{"sixteen-without-bob", []string{"--connections", "8", "--streams", "2"}, true},
		{"sixteen-plus-bob", []string{"--connections", "8", "--streams", "2", "--probe-password", "bob"}, false},
		{"seventeen-without-bob", []string{"--connections", "1", "--streams", "17"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append(testArgs("--cancel-download-after", "3s"), test.flags...)
			_, err := parseOptions(args)
			if (err == nil) != test.allowed {
				t.Fatalf("allowed=%t, parseOptions error=%v", test.allowed, err)
			}
		})
	}
}

func TestSizesAndIPv6Loopback(t *testing.T) {
	for value, expected := range map[string]int64{"0": 0, "1B": 1, "65536": 65536, "64KiB": 65536, "2GiB": 2 << 30, "9223372036854775807": 1<<63 - 1} {
		actual, err := parseSize(value)
		if err != nil || actual != expected {
			t.Errorf("parseSize(%q) = %d, %v; want %d", value, actual, err, expected)
		}
	}
	if _, err := parseOptions([]string{"[::1]:18443", "[::1]:19091", "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOptions([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help: %v", err)
	}
}
