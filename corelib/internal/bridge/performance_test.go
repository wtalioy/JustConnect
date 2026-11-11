package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativePerformanceHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_PROTOCOL_HOST")
	if host == "" {
		t.Skip("native performance host is exercised by Core ABI CTest")
	}
	var reports []map[string]any
	for _, delay := range []time.Duration{0, 5 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			g := newGateway(t)
			g.delay.Store(int64(delay))
			c := g.config(t)
			c.Listeners.SOCKS, c.Listeners.HTTP = freeAddress(t), freeAddress(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, host, "--baseline", string(configBytes(t, c)))
			var stderr bytes.Buffer
			command.Stderr = &stderr
			pipe, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			// Always reap the child, including a failed or missing startup marker.
			reader := bufio.NewReader(pipe)
			marker, markerErr := reader.ReadString('\n')
			startup := float64(time.Since(started).Nanoseconds()) / 1e6
			output, readErr := io.ReadAll(reader)
			waitErr := command.Wait()
			if markerErr != nil || strings.TrimSpace(marker) != "BASELINE_READY" || readErr != nil || waitErr != nil {
				t.Fatalf("baseline marker=%q read=%v/%v process=%v\n%s\n%s", marker, markerErr, readErr, waitErr, output, stderr.String())
			}
			var report struct {
				Core struct {
					TestDriver   bool `json:"test_driver"`
					Capabilities struct {
						EmbeddedVPN bool `json:"embedded_vpn"`
					} `json:"capabilities"`
				} `json:"core"`
				Connect []float64 `json:"connect_ms"`
				Stop    []float64 `json:"stop_ms"`
				TCP     struct {
					PayloadBytes int       `json:"payload_bytes"`
					RTT          []float64 `json:"rtt_ms"`
				} `json:"tcp"`
				UDP struct {
					PayloadBytes int       `json:"payload_bytes"`
					RTT          []float64 `json:"rtt_ms"`
				} `json:"udp"`
				Resources struct {
					PeakRSS float64 `json:"peak_rss_bytes"`
				} `json:"resources"`
			}
			if err := json.Unmarshal(output, &report); err != nil {
				t.Fatalf("baseline JSON: %v\n%s", err, output)
			}
			if report.Core.TestDriver || !report.Core.Capabilities.EmbeddedVPN || len(report.Connect) != 20 || len(report.Stop) != 20 ||
				report.TCP.PayloadBytes != 65536*32 || len(report.TCP.RTT) != 16 || report.UDP.PayloadBytes != 1200*128 || len(report.UDP.RTT) != 16 ||
				report.Resources.PeakRSS <= 0 || g.authCount.Load() != 20 || g.tcpCount.Load() != 1 || g.udpCount.Load() != 144 {
				t.Fatalf("incomplete native workload: auth=%d TCP=%d UDP=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), output)
			}
			reports = append(reports, map[string]any{"node_delay_ms": delay.Milliseconds(), "startup_ms": startup,
				"process_cpu_ms": float64((command.ProcessState.UserTime() + command.ProcessState.SystemTime()).Nanoseconds()) / 1e6,
				"host":           json.RawMessage(output)})
		})
	}
	if t.Failed() {
		return
	}
	data, err := json.MarshalIndent(map[string]any{"scenario": "loopback TLS gateway, one outstanding echo; no campus or production TLS claim",
		"os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "cases": reports}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("JC_NATIVE_BASELINE_OUTPUT"); output != "" {
		if err := os.WriteFile(output, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}
