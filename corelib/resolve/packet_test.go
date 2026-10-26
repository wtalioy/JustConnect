package resolve

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

func TestCampusDNSPacketsPreserveRecordsAndRejectOriginalNames(t *testing.T) {
	r := NewResolver(nil, "203.0.113.53", "", 30, client.DomainResources{"*.campus.test": {{Protocol: "all", PortMin: 1, PortMax: 65535}}},
		map[string][]net.IP{"static.campus.test": {net.IPv4(203, 0, 113, 7), net.ParseIP("2001:db8::7")}}, true)
	defer r.Close()
	var calls atomic.Int32
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		calls.Add(1)
		reply := new(dns.Msg).SetReply(request)
		reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 10}, Target: "target.campus.test."},
			&dns.A{Hdr: dns.RR_Header{Name: "target.campus.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.IPv4(203, 0, 113, 9)}}
		_ = w.WriteMsg(reply)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "203.0.113.53:53" {
			t.Errorf("wrong campus DNS route %s %s", network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, "udp", udp.LocalAddr().String())
	}
	request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
	reply, err := r.ExchangeCampus(t.Context(), request, "udp", dial, nil)
	if err != nil || len(reply.Answer) != 2 || reply.Answer[0].Header().Rrtype != dns.TypeCNAME || reply.Answer[0].Header().Ttl != 5 || reply.Answer[1].Header().Ttl != 5 || reply.Id != request.Id {
		t.Fatalf("records lost: %v %v", reply, err)
	}
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply, err := r.ExchangeCampus(t.Context(), new(dns.Msg).SetQuestion("static.campus.test.", kind), "udp", dial, nil)
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != kind || reply.Answer[0].Header().Ttl != 30 {
			t.Fatalf("static records: %v %v", reply, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("static records unnecessarily queried the campus", calls.Load())
	}
	for _, host := range []string{"public.test.", "localhost."} {
		if _, err := r.ExchangeCampus(t.Context(), new(dns.Msg).SetQuestion(host, dns.TypeA), "udp", dial, nil); !errors.Is(err, ErrOriginalDNSRequired) {
			t.Fatal("ungranted name queried campus", host, err)
		}
	}
	protection, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "campus.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protection }
	if _, err := r.ExchangeCampus(t.Context(), request, "udp", dial, nil); !errors.Is(err, policy.ErrProtectedTarget) {
		t.Fatal("protected name escaped to campus", err)
	}
	if calls.Load() != 1 {
		t.Fatal("refused name generated network traffic")
	}
	bad := request.Copy()
	bad.Question = append(bad.Question, bad.Question[0])
	if _, err := r.ExchangeCampus(t.Context(), bad, "udp", dial, nil); !errors.Is(err, ErrInvalidDNSQuestion) {
		t.Fatal("multi-question request accepted", err)
	}
}

func TestCampusDNSPacketCancellationAndCloseJoinNetworkIO(t *testing.T) {
	for _, closeResolver := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "resolver"}[closeResolver], func(t *testing.T) {
			r := NewResolver(nil, "203.0.113.53", "", 30, client.DomainResources{"campus.test": {{Protocol: "tcp", PortMin: 1, PortMax: 65535}}}, nil, true)
			defer r.Close()
			left, right := net.Pipe()
			defer right.Close()
			started := make(chan struct{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := r.ExchangeCampus(ctx, new(dns.Msg).SetQuestion("campus.test.", dns.TypeA), "tcp",
					func(context.Context, string, string) (net.Conn, error) { close(started); return left, nil }, nil)
				done <- err
			}()
			<-started
			if closeResolver {
				r.Close()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("network I/O outlived cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("DNS cancellation did not interrupt packet I/O")
			}
		})
	}
}

func TestCampusDNSRejectsMismatchedUpstreamQuestion(t *testing.T) {
	r := NewResolver(nil, "203.0.113.53", "", 30, client.DomainResources{"campus.test": {{Protocol: "all", PortMin: 1, PortMax: 65535}}}, nil, true)
	defer r.Close()
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan error, 1)
	go func() {
		wire := &dns.Conn{Conn: right}
		request, err := wire.ReadMsg()
		if err == nil {
			reply := new(dns.Msg).SetReply(request)
			reply.Question[0].Name = "unrelated.test."
			err = wire.WriteMsg(reply)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.ExchangeCampus(ctx, new(dns.Msg).SetQuestion("campus.test.", dns.TypeA), "tcp",
		func(context.Context, string, string) (net.Conn, error) { return left, nil }, nil); !errors.Is(err, ErrInvalidDNSResponse) {
		t.Fatal("mismatched upstream question accepted", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
