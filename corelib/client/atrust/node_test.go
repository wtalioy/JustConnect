package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/ping"
)

func TestParseResourceSeparatesWANAndLANNodes(t *testing.T) {
	client := NewClient(ClientOptions{})
	client.serverAddress = "vpn.example.com"
	resource := []byte(`{
		"data": {
			"appList": {
				"data": {
					"config": {
						"nodeGroupConf": {
							"majorNodeGroup": {"id": "group"},
							"nodeGroupList": [{
								"id": "group",
								"addressInfo": [
									{"address": "wan.example.com:441", "type": "wan"},
									{"address": "lan.example.com:441", "type": "lan"}
								]
							}]
						}
					}
				}
			}
		}
	}`)

	if err := client.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	if got, want := client.NodeGroups["group"].WAN, []string{"wan.example.com:441"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("WAN nodes = %v, want %v", got, want)
	}
	if got, want := client.NodeGroups["group"].LAN, []string{"lan.example.com:441"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LAN nodes = %v, want %v", got, want)
	}
}

func TestNodeProbeScoreAcceptsPartialReachabilityWithLossPenalty(t *testing.T) {
	target := &ping.Target{Counter: 3, Timeout: time.Second}
	partial := &ping.Result{Counter: 3, SuccessCounter: 2, TotalDuration: 40 * time.Millisecond, Target: target}
	stable := &ping.Result{Counter: 3, SuccessCounter: 3, TotalDuration: 150 * time.Millisecond, Target: target}
	partialScore, reachable := nodeProbeScore(partial)
	if !reachable {
		t.Fatal("partially reachable node was rejected")
	}
	stableScore, reachable := nodeProbeScore(stable)
	if !reachable {
		t.Fatal("stable node was rejected")
	}
	if partialScore <= stableScore {
		t.Fatalf("partial score %s should be worse than stable score %s", partialScore, stableScore)
	}
	if _, reachable := nodeProbeScore(&ping.Result{Counter: 3, Target: target}); reachable {
		t.Fatal("unreachable node was accepted")
	}
}

func TestSelectBestNodesPrefersReachableWAN(t *testing.T) {
	nodeGroups := map[string]NodeGroup{
		"group": {
			WAN: []string{"wan-a:441", "wan-b:441"},
			LAN: []string{"lan-a:441"},
		},
	}
	wanNodeGroups := map[string][]string{"group": {"wan-a:441", "wan-b:441"}}
	var probed []map[string][]string

	got := selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		probed = append(probed, nodeGroups)
		return map[string]string{"group": "wan-b:441"}
	})

	if got["group"] != "wan-b:441" {
		t.Fatalf("selected node = %q, want reachable WAN node", got["group"])
	}
	if len(probed) != 1 || !reflect.DeepEqual(probed[0], wanNodeGroups) {
		t.Fatalf("probed node groups = %v, want only WAN nodes", probed)
	}
}

func TestSelectBestNodesFallsBackToLANWhenWANUnreachable(t *testing.T) {
	nodeGroups := map[string]NodeGroup{
		"group": {
			WAN: []string{"wan-a:441"},
			LAN: []string{"lan-a:441", "lan-b:441"},
		},
	}
	wanNodeGroups := map[string][]string{"group": {"wan-a:441"}}
	lanNodeGroups := map[string][]string{"group": {"lan-a:441", "lan-b:441"}}
	var probed []map[string][]string

	got := selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		probed = append(probed, nodeGroups)
		if reflect.DeepEqual(nodeGroups, lanNodeGroups) {
			return map[string]string{"group": "lan-b:441"}
		}
		return map[string]string{}
	})

	if got["group"] != "lan-b:441" {
		t.Fatalf("selected node = %q, want reachable LAN node", got["group"])
	}
	wantProbed := []map[string][]string{wanNodeGroups, lanNodeGroups}
	if !reflect.DeepEqual(probed, wantProbed) {
		t.Fatalf("probed node groups = %v, want %v", probed, wantProbed)
	}
}

func TestSelectBestNodesOmitsGroupWhenNoNodeReachable(t *testing.T) {
	got := selectBestNodes(
		map[string]NodeGroup{
			"group": {
				WAN: []string{"wan-a:441"},
				LAN: []string{"lan-a:441"},
			},
		},
		func(map[string][]string) map[string]string {
			return map[string]string{}
		},
	)

	if _, ok := got["group"]; ok {
		t.Fatalf("selected unreachable node %q", got["group"])
	}
}

func TestNodeProbeSkipsMalformedEndpointsAndKeepsIPv6(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	got, err := getBestReachableNodes(ctx, map[string][]string{"group": {"missing-port", "host:bad", "host:0", "[::1]:443"}}, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "[::1]:443" {
			t.Errorf("probe = %s %s", network, address)
		}
		calls.Add(1)
		cancel()
		return nil, context.Canceled
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || calls.Load() != 1 {
		t.Fatalf("nodes = %v, calls = %d", got, calls.Load())
	}
}

func TestNodeProbePanicReturnsToSetup(t *testing.T) {
	_, err := getBestNodes(context.Background(), map[string]NodeGroup{"fixture": {WAN: []string{"127.0.0.1:443"}}}, func(context.Context, string, string) (net.Conn, error) { panic("private transport detail") }, nil)
	if err == nil || err.Error() != "node probe panicked" {
		t.Fatalf("probe panic = %v", err)
	}
}

func TestNodeProbePreservesTrustFailureAndAllowsTrustedLANFallback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	address := server.Listener.Addr().String()
	groups := map[string]NodeGroup{"fixture": {WAN: []string{address}}}
	_, err := getBestNodes(t.Context(), groups, (&net.Dialer{}).DialContext, nil)
	var certificate *tls.CertificateVerificationError
	if !errors.As(err, &certificate) {
		t.Fatalf("missing node certificate error: %v", err)
	}
	groups["fixture"] = NodeGroup{WAN: []string{"127.0.0.1:0"}, LAN: []string{address}}
	policy := server.Client().Transport.(*http.Transport).TLSClientConfig
	best, err := getBestNodes(t.Context(), groups, (&net.Dialer{}).DialContext, policy)
	if err != nil || best["fixture"] != address {
		t.Fatalf("trusted fallback=%v, error=%v", best, err)
	}
}
