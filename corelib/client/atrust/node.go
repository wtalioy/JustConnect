package atrust

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ping"
)

const pingNum = 3

type NodeGroup struct {
	WAN []string
	LAN []string
}

type nodeGroupsProbeFunc func(map[string][]string) map[string]string

func getBestNodes(ctx context.Context, nodeGroups map[string]NodeGroup, dialContext client.DialContextFunc, keyLogWriter io.Writer) (map[string]string, error) {
	var probeErr error
	best := selectBestNodes(nodeGroups, func(groups map[string][]string) map[string]string {
		if probeErr != nil {
			return nil
		}
		nodes, err := getBestReachableNodes(ctx, groups, dialContext, keyLogWriter)
		probeErr = errors.Join(probeErr, err)
		return nodes
	})
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

func getBestReachableNodes(ctx context.Context, nodeGroups map[string][]string, dialContext client.DialContextFunc, keyLogWriter io.Writer) (map[string]string, error) {
	bestNodes := make(map[string]string)
	for group, nodes := range nodeGroups {
		if len(nodes) > 0 {
			var pingList []*ping.TCPing
			var probedNodes []string
			var chList []<-chan struct{}

			for _, node := range nodes {
				host, portText, err := net.SplitHostPort(node)
				if err != nil {
					continue
				}
				port, err := strconv.Atoi(portText)
				if err != nil || port < 1 || port > 65535 {
					continue
				}

				tcping := ping.NewTCPing()
				tcping.SetDialContext(dialContext)
				tcping.SetKeyLogWriter(keyLogWriter)
				target := ping.Target{

					Host:     host,
					Port:     port,
					Counter:  pingNum,
					Interval: time.Duration(0.5 * float64(time.Second)),
					Timeout:  time.Duration(1 * float64(time.Second)),
				}
				tcping.SetTarget(&target)

				pingList = append(pingList, tcping)
				probedNodes = append(probedNodes, node)
				ch := tcping.StartWithContext(ctx)
				chList = append(chList, ch)
			}

			for _, ch := range chList {
				<-ch
			}

			bestScore := time.Duration(0)
			bestNode := ""
			for i, tcping := range pingList {
				result := tcping.Result()
				if result.Err != nil {
					return nil, result.Err
				}
				score, reachable := nodeProbeScore(result)
				if reachable && (bestScore == 0 || score < bestScore) {
					bestNode = probedNodes[i]
					bestScore = score
				}
			}

			if bestNode != "" {
				bestNodes[group] = bestNode

			}
		}
	}

	return bestNodes, nil
}

func nodeProbeScore(result *ping.Result) (time.Duration, bool) {
	if result == nil || result.SuccessCounter == 0 {
		return 0, false
	}
	penalty := time.Second
	if result.Target != nil && result.Target.Timeout > 0 {
		penalty = result.Target.Timeout
	}
	return result.Avg() + time.Duration(result.Failed())*penalty, true
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

		bestNodes, err := getBestNodes(ctx, c.NodeGroups, c.underlayDialer.DialContext, c.tlsKeyLogWriter)
		if err != nil {
			c.fail(err)
			return
		}
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
