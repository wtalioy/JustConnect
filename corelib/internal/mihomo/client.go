// Package mihomo reads an identified local controller; it never changes its configuration.
package mihomo

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

const maxResponseBytes = 1 << 20

type Client struct {
	endpoint endpoint
	http     *http.Client
	// These are actual controller facts, not platform/interface-name defaults.
	TunEnabled                   bool
	TunDevice, OutboundInterface string
}

func newClient(e endpoint) *Client {
	transport := &http.Transport{Proxy: nil, MaxResponseHeaderBytes: maxResponseBytes}
	if e.scheme == "https" && e.serverName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: e.serverName, MinVersion: tls.VersionTLS12}
	}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !validProcess(e.process) {
			return nil, ErrUnavailable
		}
		if e.network != "tcp" {
			return dialIPC(ctx, e.process, e.address)
		}
		address, err := netip.ParseAddrPort(e.address)
		if err != nil {
			return nil, ErrUnavailable
		}
		return dialOwnedTCP(ctx, e.process, address)
	}
	return &Client{endpoint: e, http: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) read(ctx context.Context, path string, query url.Values, target any) error {
	if !validProcess(c.endpoint.process) {
		return ErrUnavailable
	}
	host := c.endpoint.address
	if c.endpoint.network != "tcp" {
		host = "localhost"
	}
	address := url.URL{Scheme: c.endpoint.scheme, Host: host, Path: path, RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return ErrUnavailable
	}
	if c.endpoint.secret != "" {
		request.Header.Set("Authorization", "Bearer "+c.endpoint.secret)
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return ErrUnavailable
	}
	if json.Unmarshal(data, target) != nil {
		return ErrUnavailable
	}
	return nil
}

func Discover(ctx context.Context) (*Client, error) {
	processes, err := Processes(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	var selected *Client
	for _, process := range processes {
		if ctx.Err() != nil {
			if selected != nil {
				selected.Close()
			}
			return nil, ctx.Err()
		}
		candidate, err := Inspect(ctx, process)
		if err != nil {
			continue
		}
		if selected != nil {
			candidate.Close()
			selected.Close()
			return nil, ErrAmbiguous
		}
		selected = candidate
	}
	if selected == nil && len(processes) != 0 {
		return nil, ErrUnavailable
	}
	return selected, nil
}

// Inspect verifies one process's actual controller and current listener facts.
func Inspect(ctx context.Context, process model.Process) (*Client, error) {
	list, err := endpoints(process)
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		candidate := newClient(e)
		var version struct {
			Meta    bool
			Version string
		}
		if candidate.read(ctx, "/version", nil, &version) != nil || !version.Meta || version.Version == "" {
			candidate.Close()
			continue
		}
		facts, err := candidate.ReadState(ctx)
		if err != nil {
			candidate.Close()
			continue
		}
		candidate.TunEnabled = facts.TunEnabled
		candidate.TunDevice = facts.TunDevice
		candidate.OutboundInterface = facts.OutboundInterface
		return candidate, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, ErrUnavailable
}

func (c *Client) Close()      { c.http.CloseIdleConnections() }
func (c *Client) Alive() bool { return validProcess(c.endpoint.process) }

func (c *Client) Query(ctx context.Context, question dns.Question) (*dns.Msg, error) {
	if _, valid := dns.IsDomainName(question.Name); !valid || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) || question.Qclass != dns.ClassINET {
		return nil, ErrUnavailable
	}
	var result struct {
		Status             *int
		TC, RD, RA, AD, CD bool
		Answer             []struct {
			Name string
			Type uint16
			TTL  uint32
			Data string
		}
	}
	if err := c.read(ctx, "/dns/query", url.Values{"name": {question.Name}, "type": {dns.TypeToString[question.Qtype]}}, &result); err != nil {
		return nil, err
	}
	if result.Status == nil || *result.Status < 0 || *result.Status > dns.RcodeNotZone || len(result.Answer) > 4096 {
		return nil, ErrUnavailable
	}
	response := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: *result.Status, Truncated: result.TC, RecursionDesired: result.RD, RecursionAvailable: result.RA, AuthenticatedData: result.AD, CheckingDisabled: result.CD}, Question: []dns.Question{question}}
	for _, answer := range result.Answer {
		if _, valid := dns.IsDomainName(answer.Name); !valid {
			return nil, ErrUnavailable
		}
		header := dns.RR_Header{Name: dns.Fqdn(answer.Name), Rrtype: answer.Type, Class: dns.ClassINET, Ttl: answer.TTL}
		switch answer.Type {
		case dns.TypeA, dns.TypeAAAA:
			ip, err := netip.ParseAddr(answer.Data)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() || (answer.Type == dns.TypeA) != ip.Is4() {
				return nil, ErrUnavailable
			}
			if answer.Type == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(ip.AsSlice())})
			} else {
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IP(ip.AsSlice())})
			}
		case dns.TypeCNAME:
			if _, valid := dns.IsDomainName(answer.Data); !valid {
				return nil, ErrUnavailable
			}
			response.Answer = append(response.Answer, &dns.CNAME{Hdr: header, Target: dns.Fqdn(answer.Data)})
		}
	}
	return response, nil
}

// Adapt the local JSON API to Go's resolver, preserving its CNAME, IPv6 and address-racing behavior.
func (c *Client) Resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(parent context.Context, _, _ string) (net.Conn, error) {
		ctx, cancel := context.WithCancel(parent)
		client, server := net.Pipe()
		go func() {
			defer cancel()
			defer server.Close()
			for {
				var length [2]byte
				if _, err := io.ReadFull(server, length[:]); err != nil {
					return
				}
				data := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(server, data); err != nil {
					return
				}
				var request dns.Msg
				if request.Unpack(data) != nil || len(request.Question) != 1 {
					return
				}
				response, err := c.Query(ctx, request.Question[0])
				if err != nil {
					return
				}
				response.Id = request.Id
				data, err = response.Pack()
				if err != nil || len(data) > 65535 {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(data)))
				if _, err = server.Write(append(length[:], data...)); err != nil {
					return
				}
			}
		}()
		return &resolverConnection{Conn: client, cancel: cancel}, nil
	}}
}

type resolverConnection struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *resolverConnection) Close() error { c.cancel(); return c.Conn.Close() }

func IsControllerError(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAmbiguous)
}

func SameInterface(left, right string) bool {
	return left != "" && (left == right || runtime.GOOS == "windows" && strings.EqualFold(left, right))
}
