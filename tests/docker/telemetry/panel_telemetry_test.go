// Injected with go test -overlay into the real panel grpcapi package. Production
// panel sources stay untouched; only the authenticated test session is seeded.
package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	acpv1 "github.com/acp/node-agent/api/acp/v1"
	"github.com/acp/panel-api-server/internal/domain"
	"github.com/acp/panel-api-server/internal/repository"
	rs "github.com/acp/panel-api-server/internal/service/runtimestatus"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type dockerTelemetryFrame struct {
	Stream     int32                    `json:"stream"`
	ReceivedAt time.Time                `json:"received_at"`
	Snapshot   *acpv1.TelemetrySnapshot `json:"snapshot"`
}

type dockerTelemetryReceiver struct {
	grpc.ServerStream
	stream int32
	count  int
	delay  time.Duration
	record func(dockerTelemetryFrame)
}

func (s *dockerTelemetryReceiver) SendHeader(md metadata.MD) error {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-s.Context().Done():
			return s.Context().Err()
		}
	}
	return s.ServerStream.SendHeader(md)
}

func (s *dockerTelemetryReceiver) RecvMsg(v any) error {
	// Fault injection surrounds, and always delegates successful frames to,
	// the real gRPC handler, monotonic clock and strict runtime repository.
	if s.stream == 1 && s.count == 4 {
		return status.Error(codes.Unavailable, "fixture reconnect")
	}
	if s.stream == 2 && s.count == 10 {
		return status.Error(codes.Unauthenticated, "fixture expired session")
	}
	if err := s.ServerStream.RecvMsg(v); err != nil {
		return err
	}
	s.count++
	if snapshot, ok := v.(*acpv1.TelemetrySnapshot); ok {
		s.record(dockerTelemetryFrame{s.stream, time.Now(), proto.Clone(snapshot).(*acpv1.TelemetrySnapshot)})
	}
	return nil
}

func dockerTelemetryPanel(t *testing.T, delay time.Duration) (*Server, *grpc.Server, net.Listener, *[]dockerTelemetryFrame, *sync.Mutex) {
	t.Helper()
	api := NewServer(newRuntimeServiceForTest(t, controlStreamRuntimeStore(t)), nil)
	var streams atomic.Int32
	var mu sync.Mutex
	frames := new([]dockerTelemetryFrame)
	server := grpc.NewServer(grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		id := streams.Add(1)
		wait := time.Duration(0)
		if id == 1 {
			wait = delay
		}
		return handler(srv, &dockerTelemetryReceiver{ServerStream: stream, stream: id, delay: wait, record: func(frame dockerTelemetryFrame) {
			mu.Lock()
			defer mu.Unlock()
			*frames = append(*frames, frame)
		}})
	}))
	acpv1.RegisterTelemetryServiceServer(server, api)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return api, server, listener, frames, &mu
}

func dockerTelemetryRunProbe(t *testing.T, api *Server, server *grpc.Server, listener net.Listener, mode string) {
	t.Helper()
	session, err := api.newSession("machine-example", "node-vless-1", "docker-telemetry-probe", "probe-runtime", 1)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer func() {
			if value := recover(); value != nil {
				t.Errorf("fixture server panic: %v", value)
			}
		}()
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("serve: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	binary := os.Getenv("ACP_RUST_TELEMETRY_PROBE")
	if binary == "" {
		t.Fatal("ACP_RUST_TELEMETRY_PROBE must point to the freshly built Linux probe")
	}
	output, err := exec.CommandContext(ctx, binary, listener.Addr().String(), session.SessionId, mode).CombinedOutput()
	t.Logf("Rust probe (%s):\n%s", mode, output)
	if err != nil {
		t.Fatalf("Rust probe failed: %v", err)
	}
}

func TestDockerRustTelemetry(t *testing.T) {
	if os.Getenv("ACP_TELEMETRY_DOCKER") != "1" {
		t.Skip("run tests/docker/telemetry/run.ps1")
	}
	db, err := gorm.Open(mysql.Open("root:fixture-only@tcp(mysql:3306)/telemetry_fixture?charset=utf8mb4&parseTime=True&loc=UTC"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&domain.Machine{}, &domain.Node{}, &domain.MachineRuntimeStatus{}, &domain.NodeRuntimeStatus{}); err != nil {
		t.Fatal(err)
	}
	machine := domain.Machine{MachineID: "machine-example", Secret: "secret", Status: domain.RuntimeStatusWaiting}
	node := domain.Node{MachineID: machine.MachineID, NodeID: "node-vless-1", Status: domain.RuntimeStatusWaiting}
	if err := db.Create(&machine).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: "redis:6379"})
	defer client.Close()
	repo, err := repository.NewLiveRuntimeRepository(db, client, 2*time.Minute, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	repo.Start(t.Context())
	defer repo.Stop()
	api, server, listener, frames, mu := dockerTelemetryPanel(t, 1200*time.Millisecond)
	api.WithRuntimeStatus(rs.NewServiceWithOptions(repo, 2*time.Minute, time.Now))
	dockerTelemetryRunProbe(t, api, server, listener, "auth")
	probeExitedAt := time.Now()
	mu.Lock()
	got := append([]dockerTelemetryFrame(nil), (*frames)...)
	mu.Unlock()
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("ACP_TELEMETRY_ARTIFACTS"), "received-frames.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if len(got) != 14 {
		t.Fatalf("received %d frames, expected 4 + 10", len(got))
	}
	if delay := probeExitedAt.Sub(got[len(got)-1].ReceivedAt); delay > 2*time.Second {
		t.Fatalf("authentication failure did not return promptly: %s", delay)
	}
	span := got[len(got)-1].ReceivedAt.Sub(got[0].ReceivedAt)
	if span < 36*time.Second {
		t.Fatalf("reporter did not stay live past 30s: %s", span)
	}
	first := got[0].Snapshot
	if first.AgentInstanceId == "" || first.SampleSeq == 0 {
		t.Fatal("missing process identity/sequence")
	}
	var previous dockerTelemetryFrame
	for i, frame := range got {
		s := frame.Snapshot
		if s.AgentInstanceId != first.AgentInstanceId {
			t.Fatal("instance changed on reconnect")
		}
		if s.SampleElapsedMs < s.StreamStartedElapsedMs {
			t.Fatalf("sample predates handshake: %+v", s)
		}
		if !s.MemoryValid || !s.ConnectionStatsValid || !s.NetworkInterfacesValid || !s.DiskValid {
			t.Fatalf("Linux collection validity absent: %+v", s)
		}
		if s.ActiveConnections != 7 || s.OnlineUsers != 3 {
			t.Fatalf("runtime counters lost: %+v", s)
		}
		if s.DiskCollectedAtUnixMs <= 0 || frame.ReceivedAt.Sub(time.UnixMilli(s.DiskCollectedAtUnixMs)) > 90*time.Second {
			t.Fatalf("missing/stale independent disk collection timestamp: %+v", s)
		}
		for _, nic := range s.NetworkInterfaces {
			if nic.InterfaceIndex == 0 || !nic.CountersValid {
				t.Fatalf("invalid NIC identity/counters: %+v", nic)
			}
		}
		if i > 0 {
			if s.SampleSeq <= previous.Snapshot.SampleSeq || s.SampleElapsedMs <= previous.Snapshot.SampleElapsedMs {
				t.Fatal("sample sequence/monotonic time reset")
			}
			if frame.Stream == previous.Stream {
				gap := frame.ReceivedAt.Sub(previous.ReceivedAt)
				if gap < 2*time.Second || gap > 4*time.Second {
					t.Fatalf("cadence %s is not 3 seconds", gap)
				}
				if s.StreamStartedElapsedMs != previous.Snapshot.StreamStartedElapsedMs {
					t.Fatal("baseline changed inside stream")
				}
			} else if s.StreamStartedElapsedMs <= previous.Snapshot.StreamStartedElapsedMs {
				t.Fatal("reconnect reused old header baseline")
			}
		}
		previous = frame
	}
	if !got[len(got)-1].Snapshot.CpuValid {
		t.Fatal("CPU delta sample never became valid")
	}
	if got[4].Snapshot.SampleSeq <= got[3].Snapshot.SampleSeq+1 {
		t.Fatal("samples taken during the 7s outage were replayed instead of replaced")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		live, found, err := repo.FindNodeRuntimeStatus(t.Context(), "node-vless-1")
		if err != nil {
			t.Fatal(err)
		}
		if found && live.Status == domain.RuntimeStatusOnline && live.Fresh && live.ActiveConnections == 7 && live.OnlineUsers == 3 {
			t.Logf("strict live repository: online=%v fresh=%v active=%d users=%d span=%s samples=%d", live.Status, live.Fresh, live.ActiveConnections, live.OnlineUsers, span, len(got))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("node not live in actual repository: found=%v value=%+v", found, live)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Log(fmt.Sprintf("process instance remains stable across %d streams; second baseline=%d, sequence=%d", 2, got[4].Snapshot.StreamStartedElapsedMs, got[4].Snapshot.SampleSeq))
}

func TestDockerRustTelemetryHandshakeTimeout(t *testing.T) {
	if os.Getenv("ACP_TELEMETRY_DOCKER") != "1" {
		t.Skip("run tests/docker/telemetry/run.ps1")
	}
	api, server, listener, frames, mu := dockerTelemetryPanel(t, 11*time.Second)
	start := time.Now()
	dockerTelemetryRunProbe(t, api, server, listener, "timeout")
	elapsed := time.Since(start)
	if elapsed < 9*time.Second || elapsed > 11500*time.Millisecond {
		t.Fatalf("expected independent 10s header deadline; got %s", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*frames) != 0 {
		t.Fatal("sample sent before ready header handshake")
	}
	t.Logf("blocked header canceled in %s without sending a sample", elapsed)
}
