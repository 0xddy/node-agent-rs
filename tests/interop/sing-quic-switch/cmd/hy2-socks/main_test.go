package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestNegotiateAllowsOnlyFixtureTargets(t *testing.T) {
	tests := []struct {
		name       string
		address    []byte
		port       uint16
		wantTarget string
		wantError  bool
	}{
		{name: "control", address: []byte{1, 127, 0, 0, 1}, port: 2121, wantTarget: "127.0.0.1:2121"},
		{name: "passive", address: append([]byte{3, 9}, []byte("localhost")...), port: 30042, wantTarget: "127.0.0.1:30042"},
		{name: "non-loopback", address: []byte{1, 192, 0, 2, 1}, port: 2121, wantError: true},
		{name: "other-port", address: []byte{1, 127, 0, 0, 1}, port: 22, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			type result struct {
				target string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				target, err := negotiate(server)
				done <- result{target: target.String(), err: err}
			}()
			if _, err := client.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			method := make([]byte, 2)
			if _, err := io.ReadFull(client, method); err != nil {
				t.Fatal(err)
			}
			request := append([]byte{5, 1, 0}, test.address...)
			port := make([]byte, 2)
			binary.BigEndian.PutUint16(port, test.port)
			request = append(request, port...)
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if (got.err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", got.err, test.wantError)
			}
			if !test.wantError && got.target != test.wantTarget {
				t.Fatalf("target = %q, want %q", got.target, test.wantTarget)
			}
		})
	}
}

func TestCleanEOF(t *testing.T) {
	if err := cleanEOF(errors.New("other")); err == nil {
		t.Fatal("non-EOF error was discarded")
	}
	if err := cleanEOF(fmt.Errorf("wrapped: %w", io.EOF)); err != nil {
		t.Fatalf("wrapped EOF was not normalized: %v", err)
	}
}
