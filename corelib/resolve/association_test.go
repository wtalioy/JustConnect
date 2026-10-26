package resolve

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

func bindingResolver() *Resolver {
	return NewResolver(nil, "", "", 30, client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, false)
}

func TestCampusDNSBindingsFollowCNAMEExpiryAndCurrentProtection(t *testing.T) {
	r := bindingResolver()
	defer r.Close()
	request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	reply.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 30}, A: net.IPv4(203, 0, 113, 9)},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.campus.test.", Class: dns.ClassINET, Rrtype: dns.TypeCNAME, Ttl: 1}, Target: "target.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "target.test.", Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 30}, A: net.IPv4(203, 0, 113, 7)},
	}
	ip := netip.MustParseAddr("203.0.113.7")
	if addresses, err := r.bindCampusAnswer(request, reply, nil); err != nil || len(addresses) != 1 || addresses[0] != ip {
		t.Fatal("publication addresses must use only the validated answer chain", addresses, err)
	}
	if len(r.CampusResourcesForIP(t.Context(), ip)) != 1 || len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("203.0.113.9"))) != 0 {
		t.Fatal("CNAME destination or unrelated record granted the wrong address")
	}
	if records := r.CampusDNSRecords(); len(records) != 1 || len(records["alias.campus.test"]) != 1 || records["alias.campus.test"][0] != ip.String() {
		t.Fatal("resource snapshot lost the validated CNAME owner or included unrelated answers", records)
	}
	sharedRequest := new(dns.Msg).SetQuestion("other.campus.test.", dns.TypeA)
	sharedReply := new(dns.Msg).SetReply(sharedRequest)
	sharedReply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "other.campus.test.", Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 1}, A: net.IPv4(203, 0, 113, 7)}}
	if _, err := r.bindCampusAnswer(sharedRequest, sharedReply, nil); err != nil {
		t.Fatal(err)
	}
	blocked, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "exact", Value: "alias.campus.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &blocked }
	if len(r.CampusResourcesForIP(t.Context(), ip)) != 0 {
		t.Fatal("a shared-IP name bypassed new name protection")
	}
	var original *policy.ProtectionPolicy
	ctx := context.WithValue(t.Context(), ContextKeyProtectionPolicy, original)
	if len(r.CampusResourcesForIP(ctx, ip)) != 1 {
		t.Fatal("in-flight request lost its captured policy")
	}
	time.Sleep(1100 * time.Millisecond)
	if len(r.CampusResourcesForIP(ctx, ip)) != 0 {
		t.Fatal("A TTL outlived the shorter CNAME TTL")
	}
	if records := r.CampusDNSRecords(); len(records) != 0 {
		t.Fatal("expired binding remained in the resource snapshot", records)
	}
	reply.Answer[1].Header().Ttl = 0
	if _, err := r.bindCampusAnswer(request, reply, nil); err != nil || len(r.CampusResourcesForIP(ctx, ip)) != 1 {
		t.Fatal("zero-TTL answer could not hand off its first flow", err)
	}
	r.Close()
	if len(r.CampusResourcesForIP(ctx, ip)) != 0 || len(r.CampusDNSRecords()) != 0 {
		t.Fatal("closed session retained an address grant")
	}
}

func TestCampusDNSBindingCapacityRejectsAtomicallyAndReclaimsExpiry(t *testing.T) {
	r := bindingResolver()
	defer r.Close()
	for group := 0; group < 4; group++ {
		host := fmt.Sprintf("h%d.campus.test.", group)
		request := new(dns.Msg).SetQuestion(host, dns.TypeA)
		reply := new(dns.Msg).SetReply(request)
		for n := group * 1024; n < (group+1)*1024; n++ {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: host, Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 30}, A: net.IPv4(198, 19, byte(n>>8), byte(n))})
		}
		if _, err := r.bindCampusAnswer(request, reply, nil); err != nil {
			t.Fatal(err)
		}
	}
	request := new(dns.Msg).SetQuestion("next.campus.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "next.campus.test.", Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 30}, A: net.IPv4(192, 0, 2, 7)}}
	if _, err := r.bindCampusAnswer(request, reply, nil); !errors.Is(err, ErrCampusDNSCapacity) {
		t.Fatal("full cache accepted another binding", err)
	}
	if len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("192.0.2.7"))) != 0 {
		t.Fatal("failed insertion published a partial grant")
	}
	for address, bindings := range r.dnsBindings {
		for i := range bindings {
			bindings[i].expires = time.Time{}
		}
		r.dnsBindings[address] = bindings
	}
	if _, err := r.bindCampusAnswer(request, reply, nil); err != nil || len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("192.0.2.7"))) != 1 {
		t.Fatal("expired capacity was not reclaimed", err)
	}
}

func TestCampusDNSBindingsRejectAliasCyclesAndForeignClasses(t *testing.T) {
	r := bindingResolver()
	defer r.Close()
	request := new(dns.Msg).SetQuestion("loop.campus.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	reply.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "loop.campus.test.", Class: dns.ClassINET, Rrtype: dns.TypeCNAME, Ttl: 30}, Target: "target.test."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "target.test.", Class: dns.ClassINET, Rrtype: dns.TypeCNAME, Ttl: 30}, Target: "loop.campus.test."},
	}
	if _, err := r.bindCampusAnswer(request, reply, nil); !errors.Is(err, ErrInvalidDNSResponse) {
		t.Fatal("alias cycle accepted", err)
	}
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "loop.campus.test.", Class: dns.ClassCHAOS, Rrtype: dns.TypeA, Ttl: 30}, A: net.IPv4(203, 0, 113, 7)}}
	if _, err := r.bindCampusAnswer(request, reply, nil); err != nil || len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("203.0.113.7"))) != 0 {
		t.Fatal("non-IN record granted a campus flow", err)
	}
}

func TestCampusDNSBindingsConcurrentLookupAndClose(t *testing.T) {
	records := make(map[string][]net.IP)
	for n := 0; n < 64; n++ {
		records[fmt.Sprintf("h%d.campus.test", n)] = []net.IP{net.IPv4(203, 0, 113, 7)}
	}
	r := NewResolver(nil, "", "", 30, client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, records, false)
	defer r.Close()
	ready, proceed := make(chan struct{}, 64), make(chan struct{})
	var workers sync.WaitGroup
	for host := range records {
		workers.Go(func() {
			request := new(dns.Msg).SetQuestion(host+".", dns.TypeA)
			if _, err := r.ExchangeCampus(t.Context(), request, "udp", nil, nil); err != nil {
				t.Error(err)
			}
			if len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("203.0.113.7"))) != 1 {
				t.Error("concurrent names lost or duplicated their shared domain authorization")
			}
			ready <- struct{}{}
			<-proceed
			for range 16 {
				_, err := r.ExchangeCampus(t.Context(), request, "udp", nil, nil)
				if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
				_ = r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("203.0.113.7"))
			}
		})
	}
	for range records {
		<-ready
	}
	close(proceed)
	r.Close()
	workers.Wait()
	if len(r.CampusResourcesForIP(t.Context(), netip.MustParseAddr("203.0.113.7"))) != 0 {
		t.Fatal("closed resolver exposed a live grant")
	}
}

func TestCampusDNSPublicationPrecedesAuthorizationLifetime(t *testing.T) {
	r := bindingResolver()
	defer r.Close()
	request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	address := netip.MustParseAddr("203.0.113.7")
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 0}, A: net.IPv4(203, 0, 113, 7)}}
	refused := errors.New("route publication failed")
	if _, err := r.bindCampusAnswer(request, reply, func([]netip.Addr) error { return refused }); !errors.Is(err, refused) {
		t.Fatal("publication failure ignored", err)
	}
	if len(r.CampusResourcesForIP(t.Context(), address)) != 0 {
		t.Fatal("failed publication granted a captured address")
	}
	var published time.Time
	if _, err := r.bindCampusAnswer(request, reply, func(addresses []netip.Addr) error {
		if len(addresses) != 1 || addresses[0] != address || len(r.CampusResourcesForIP(t.Context(), address)) != 0 {
			t.Fatal("address authorized before publication", addresses)
		}
		published = time.Now()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(r.CampusResourcesForIP(t.Context(), address)) != 1 || r.dnsBindings[address][0].expires.Before(published.Add(time.Second)) {
		t.Fatal("publication consumed the zero-TTL first-flow lifetime")
	}
}

func TestCampusDNSCacheTTLFollowsBindingLifetime(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range []uint32{0, 1, 30} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			r := NewResolver(nil, "", "", uint64(configured), client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, false)
			defer r.Close()
			request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
			alias := &dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 10}, Target: "target.cdn.test."}
			answer := &dns.A{Hdr: dns.RR_Header{Name: alias.Target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.IPv4(203, 0, 113, 7)}
			signature := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: answer.Hdr.Ttl}, Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
				Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
			if err := signature.Sign(private.(crypto.Signer), []dns.RR{answer}); err != nil {
				t.Fatal(err)
			}
			originalSignature, originalTTL := signature.Signature, signature.OrigTtl
			reply := new(dns.Msg).SetReply(request)
			unrelated := &dns.A{Hdr: dns.RR_Header{Name: "public.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 40}, A: net.IPv4(203, 0, 113, 9)}
			reply.Answer = []dns.RR{alias, answer, signature, unrelated}
			reply.SetEdns0(1232, true)
			want := min(configured, alias.Hdr.Ttl, answer.Hdr.Ttl)
			before := time.Now()
			if _, err := r.bindCampusAnswer(request, reply, nil); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			wire, err := reply.Pack()
			if err != nil {
				t.Fatal(err)
			}
			observed := new(dns.Msg)
			if err := observed.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			for _, record := range observed.Answer[:3] {
				if record.Header().Ttl != want {
					t.Fatalf("downstream cache TTL %d exceeds binding lifetime %d", record.Header().Ttl, want)
				}
			}
			if observed.Answer[3].String() != unrelated.String() {
				t.Fatal("unrelated DNS record was rewritten")
			}
			if observed.Answer[0].(*dns.CNAME).Target != alias.Target || !observed.Answer[1].(*dns.A).A.Equal(answer.A) || !observed.IsEdns0().Do() {
				t.Fatal("TTL adjustment changed DNS records or EDNS flags")
			}
			signed := observed.Answer[2].(*dns.RRSIG)
			if signed.OrigTtl != originalTTL || signed.Signature != originalSignature {
				t.Fatal("TTL adjustment rewrote signed data")
			}
			if err := signed.Verify(key, []dns.RR{observed.Answer[1]}); err != nil {
				t.Fatal("bounded DNS answer lost signature validity", err)
			}
			address := netip.MustParseAddr(answer.A.String())
			binding := r.dnsBindings[address][0]
			lifetime := time.Duration(max(want, 1)) * time.Second
			if binding.expires.Before(before.Add(lifetime)) || binding.expires.After(after.Add(lifetime)) || len(r.CampusResourcesForIP(t.Context(), address)) != 1 {
				t.Fatal("wire lifetime and actual transparent authorization disagree")
			}
		})
	}
}
