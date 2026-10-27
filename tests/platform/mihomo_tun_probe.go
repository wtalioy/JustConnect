//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

type peerFacts struct {
	Address, DNS, Certificate, Interface, Source, FakeDNS, FakeRange string
}

func peer(address string) error {
	fmt.Println("namespace")
	if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil || line != "start\n" {
		return fmt.Errorf("peer startup barrier: %v", err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		return err
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" {
			http.Error(w, "wrong logical TLS host", http.StatusBadRequest)
			return
		}
		io.WriteString(w, "original-exit:"+r.URL.Path)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	udp, err := net.ListenPacket("udp4", net.JoinHostPort(address, "0"))
	if err != nil {
		return err
	}
	dnsServer := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		for _, q := range request.Question {
			if q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 37}, A: net.ParseIP(address)})
			}
		}
		w.WriteMsg(reply)
	})}
	go dnsServer.ActivateAndServe()
	defer dnsServer.Shutdown()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := json.NewEncoder(os.Stdout).Encode(peerFacts{Address: listener.Addr().String(), DNS: udp.LocalAddr().String(), Certificate: string(certificate)}); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

func control(mode, path string) error {
	status, err := os.ReadFile("/proc/self/status")
	groups, groupErr := os.Getgroups()
	if err != nil || os.Getuid() == 0 || os.Geteuid() == 0 || !strings.Contains(string(status), "CapEff:\t0000000000000000") || groupErr != nil || len(groups) != 0 {
		return fmt.Errorf("control probe must have ordinary uid and no capabilities or supplementary groups")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var facts peerFacts
	if err = json.Unmarshal(data, &facts); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(facts.Certificate)) {
		return fmt.Errorf("missing owned peer CA")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	var systemQueries atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemQueries.Add(1)
		return nil, fmt.Errorf("system DNS must not supply the VPN control address")
	}}
	var dialer *underlay.Dialer
	if mode == "captured" {
		question := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(question, facts.FakeDNS)
		if err != nil || len(answer.Answer) != 1 {
			return fmt.Errorf("live Mihomo Fake-IP listener: %v", err)
		}
		prefix, err := netip.ParsePrefix(facts.FakeRange)
		address, ok := answer.Answer[0].(*dns.A)
		if err != nil || !ok || !prefix.Contains(netip.MustParseAddr(address.A.String())) {
			return fmt.Errorf("live Mihomo did not return its configured Fake-IP range")
		}
		fmt.Println("PASS: live Mihomo DNS returned Fake-IP for the same control hostname")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", facts.Address)
		}
	} else {
		dialer, err = underlay.New(underlay.Options{AutoDetect: false})
		if err != nil {
			return err
		}
		defer dialer.Close()
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err == nil {
				host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
				if host != facts.Source {
					conn.Close()
					return nil, fmt.Errorf("control socket selected a source outside the original exit: %s", host)
				}
			}
			return conn, err
		}
	}
	_, port, _ := net.SplitHostPort(facts.Address)
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	for _, stage := range []string{"auth-methods", "login", "gateway", "reconnect"} {
		response, err := client.Get("https://example.com:" + port + "/" + stage)
		if mode == "captured" {
			if err == nil {
				response.Body.Close()
				return fmt.Errorf("unbound control unexpectedly bypassed the rejecting Mihomo TUN")
			}
			fmt.Println("PASS: unbound TLS was captured and rejected by the live Mihomo TUN")
			return nil
		}
		if err != nil {
			return err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "original-exit:/"+stage {
			return fmt.Errorf("original TLS exchange failed at %s: %v", stage, err)
		}
		transport.CloseIdleConnections()
	}
	if systemQueries.Load() != 0 || dialer.InterfaceName() != facts.Interface {
		return fmt.Errorf("control did not retain its verified DNS source and original interface")
	}
	fmt.Println("PASS: ordinary Go control retained original source, real DNS and TLS for auth-methods/login/gateway/reconnect beneath live Mihomo TUN")
	return nil
}

func main() {
	var err error
	if len(os.Args) != 3 {
		err = fmt.Errorf("requires peer/captured/control and an address or owned facts file")
	} else if os.Args[1] == "peer" {
		err = peer(os.Args[2])
	} else if os.Args[1] == "captured" || os.Args[1] == "control" {
		err = control(os.Args[1], os.Args[2])
	} else {
		err = fmt.Errorf("unknown probe mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
