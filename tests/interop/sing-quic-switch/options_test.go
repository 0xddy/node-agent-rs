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
	if options.streams != 4 || options.download != 128<<20 || options.upload != 32<<20 || options.rounds != 1 || options.timeout != 120*time.Second || options.streamTimeout != 90*time.Second || options.probePassword != "" {
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

func TestOptionsRejectUnsafeOrUnboundedInputs(t *testing.T) {
	for _, args := range [][]string{
		{"localhost:18443", "127.0.0.1:19091", "alice"},
		{"192.0.2.1:18443", "127.0.0.1:19091", "alice"},
		{"127.0.0.1:18443", "192.0.2.1:19091", "alice"},
		{"127.0.0.1:0", "127.0.0.1:19091", "alice"},
		testArgs("--streams", "0"), testArgs("--streams", "65"),
		testArgs("--rounds", "0"), testArgs("--rounds", "1001"),
		testArgs("--timeout", "0s"), testArgs("--stream-timeout", "-1s"),
		testArgs("--probe-interval", "0s"), testArgs("--probe-timeout", "-1s"),
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
