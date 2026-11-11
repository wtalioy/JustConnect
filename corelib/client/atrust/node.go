package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ping"
)

const (
	pingNum          = 3
	nodeProbeTimeout = time.Second
)

type NodeGroup struct {
	WAN []string
	LAN []string
}

type nodeGroupsProbeFunc func(map[string][]string) map[string]string

func getBestNodes(ctx context.Context, nodeGroups map[string]NodeGroup, dialContext client.DialContextFunc, tlsPolicy *tls.Config) (map[string]string, error) {
	var probeErr error
	best := selectBestNodes(nodeGroups, func(groups map[string][]string) map[string]string {
		nodes, err := getBestReachableNodes(ctx, groups, dialContext, tlsPolicy)
		probeErr = errors.Join(probeErr, err)
		return nodes
	})
	if len(best) > 0 {
		return best, nil
	}
	return best, probeErr
}

func selectBestNodes(nodeGroups map[string]NodeGroup, probe nodeGroupsProbeFunc) map[string]string {
	wanNodeGroups := make(map[string][]string, len(nodeGroups))
	for group, nodes := range nodeGroups {
		wanNodeGroups[group] = nodes.WAN
	}
	bestNodes := probe(wanNodeGroups)

	fallbackNodeGroups := make(map[string][]string)
	for group, nodes := range nodeGroups {
		if bestNodes[group] == "" && len(nodes.LAN) > 0 {
			fallbackNodeGroups[group] = nodes.LAN
		}
	}

	if len(fallbackNodeGroups) == 0 {
		return bestNodes
	}
	for group, node := range probe(fallbackNodeGroups) {
		bestNodes[group] = node
	}
	return bestNodes
}

func getBestReachableNodes(ctx context.Context, nodeGroups map[string][]string, dialContext client.DialContextFunc, tlsPolicy *tls.Config) (map[string]string, error) {
	bestNodes := make(map[string]string)
	var probeErr error
	for group, nodes := range nodeGroups {
		if len(nodes) > 0 {
			probes := make([]struct {
				node   string
				result ping.Result
			}, len(nodes))
			var pending sync.WaitGroup
			for i, node := range nodes {
				host, portText, err := net.SplitHostPort(node)
				if err != nil {
					continue
				}
				port, err := strconv.Atoi(portText)
				if err != nil || port < 1 || port > 65535 {
					continue
				}
				probe := &probes[i]
				probe.node = node
				pending.Go(func() {
					probe.result = ping.Probe(ctx, ping.Target{
						Address: net.JoinHostPort(host, strconv.Itoa(port)), Counter: pingNum,
						Interval: 500 * time.Millisecond, Timeout: nodeProbeTimeout,
					}, dialContext, tlsPolicy)
				})
			}
			pending.Wait()

			bestScore := time.Duration(0)
			bestNode := ""
			for _, probe := range probes {
				result := probe.result
				if result.Err != nil {
					probeErr = errors.Join(probeErr, result.Err)
					continue
				}
				score, reachable := nodeProbeScore(result)
				if reachable && (bestScore == 0 || score < bestScore) {
					bestNode = probe.node
					bestScore = score
				}
			}

			if bestNode != "" {
				bestNodes[group] = bestNode

			}
		}
	}

	if len(bestNodes) > 0 {
		return bestNodes, nil
	}
	return bestNodes, probeErr
}

func nodeProbeScore(result ping.Result) (time.Duration, bool) {
	if result.SuccessCounter == 0 {
		return 0, false
	}
	return result.Avg() + time.Duration(result.Failed())*nodeProbeTimeout, true
}

func (c *Client) updateBestNodes(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		c.report("nodes", "running")
		bestNodes, err := getBestNodes(ctx, c.NodeGroups, c.underlayDialer.DialContext, c.nodeTLSPolicy)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.report("nodes", "failed")
			c.fail(err)
			return
		}
		c.report("nodes", "succeeded")
		c.BestNodesRWMutex.Lock()
		c.BestNodes = bestNodes
		c.BestNodesRWMutex.Unlock()

		c.l3TunnelMu.Lock()
		tunnel := c.l3Tunnel
		c.l3TunnelMu.Unlock()
		if tunnel != nil {
			tunnel.evictStaleConns(bestNodes, c.MajorNodeGroup)
		}
	}
}
