package bridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
	"golang.org/x/net/proxy"
)

func TestTLSFailureDiagnosticsAfterAuthentication(t *testing.T) {
	for _, scenario := range []string{"tls_unknown_authority", "tls_hostname_mismatch", "tls_certificate_time_invalid", "trusted", "unknown_authority_and_timeout", "untrusted_issuer_leaf_only", "untrusted_issuer_with_chain", "unverified_nodes_allowed"} {
		t.Run(scenario, func(t *testing.T) {
			reason := scenario
			if scenario == "unknown_authority_and_timeout" || strings.HasPrefix(scenario, "untrusted_issuer_") || scenario == "unverified_nodes_allowed" {
				reason = "tls_unknown_authority"
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private-certificate-subject"},
				NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if reason == "tls_hostname_mismatch" {
				certificate.IPAddresses = nil
				certificate.DNSNames = []string{"private-node.invalid"}
			}
			if reason == "tls_certificate_time_invalid" {
				certificate.NotAfter = time.Now().Add(-time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			chain := [][]byte{der}
			selfSigned := true
			if strings.HasPrefix(scenario, "untrusted_issuer_") {
				issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				issuer := *certificate
				issuer.SerialNumber = big.NewInt(2)
				issuer.Subject.CommonName = "private-untrusted-issuer"
				issuerDER, err := x509.CreateCertificate(rand.Reader, &issuer, &issuer, &issuerKey.PublicKey, issuerKey)
				if err != nil {
					t.Fatal(err)
				}
				certificate.IsCA = false
				der, err = x509.CreateCertificate(rand.Reader, certificate, &issuer, &key.PublicKey, issuerKey)
				if err != nil {
					t.Fatal(err)
				}
				chain = [][]byte{der}
				if scenario == "untrusted_issuer_with_chain" {
					chain = append(chain, issuerDER)
				}
				selfSigned = false
			}
			g := newGatewayWithNodeTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
			if scenario == "unknown_authority_and_timeout" {
				// A TCP listener that never accepts stalls each TLS probe until its deadline.
				silent, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = silent.Close() })
				g.extraWANNode.Store(silent.Addr().String())
			}
			c := g.config(t)
			c.TLS.AllowUnverifiedNodes = scenario == "unverified_nodes_allowed"
			if c.TLS.AllowUnverifiedNodes {
				c.Listeners.SOCKS = freeAddress(t)
			}
			if reason != "tls_unknown_authority" {
				c.TLS.CAPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			}
			e := New(RunProtocol)
			h := create(t, e)
			if c.TLS.AllowUnverifiedNodes {
				if _, status := e.Start(h, configBytes(t, c)); status != OK {
					t.Fatal(status)
				}
				if ev := next(t, e, h); ev.State != "starting" {
					t.Fatal(ev)
				}
				data, _, status := e.Read(h, MaxOutput, 5000)
				var warning event
				if status != OK || json.Unmarshal(data, &warning) != nil || warning.Code != "tls_node_verification_disabled" {
					t.Fatalf("missing explicit node policy diagnostic: %s (%v)", data, status)
				}
				authenticate(t, e, h)
			} else {
				startProtocol(t, e, h, c)
			}
			codes := map[string]bool{}
			for count := 0; count < 16; count++ {
				data, _, status := e.Read(h, MaxOutput, 5000)
				if status != OK {
					t.Fatalf("read = %v", status)
				}
				if strings.Contains(string(data), "private-") {
					t.Fatalf("diagnostics disclosed certificate or session material: %s", data)
				}
				var event event
				if err := json.Unmarshal(data, &event); err != nil {
					t.Fatal(err)
				}
				if event.Type == "observation" {
					continue
				}
				if event.Type == "diagnostic" {
					codes[event.Code] = true
					continue
				}
				if reason == "trusted" || c.TLS.AllowUnverifiedNodes {
					if event.State != "ready" || len(codes) != 1 || !codes["transport_connected"] {
						t.Fatalf("trusted node = %+v, diagnostics = %v", event, codes)
					}
					if c.TLS.AllowUnverifiedNodes {
						checkNodeTraffic(t, c.Listeners.SOCKS)
						if g.tcpCount.Load() != 1 || g.udpCount.Load() != 1 {
							t.Fatal("missing real TCP/L3 UDP traffic")
						}
					}
					e.Stop(h, MaxWaitMS)
					next(t, e, h)
					return
				}
				codeCount := 2
				if len(chain) == 1 {
					codeCount++
				}
				if selfSigned {
					codeCount++
				}
				if event.Type != "terminal" || event.Status != TLSTrust || len(codes) != codeCount || !codes["tls_node_probe_failed"] || !codes[reason] || codes["tls_peer_chain_leaf_only"] != (len(chain) == 1) || codes["tls_peer_self_signed"] != selfSigned || g.authCount.Load() != 1 {
					t.Fatalf("event = %+v, diagnostics = %v, authentications = %d", event, codes, g.authCount.Load())
				}
				return
			}
			t.Fatal("missing TLS result")
		})
	}
}

func TestUnverifiedNodesDoNotBypassAuthenticationTLS(t *testing.T) {
	for _, operation := range []string{"auth_methods", "connect"} {
		t.Run(operation, func(t *testing.T) {
			g := newGateway(t)
			c := g.config(t)
			c.Operation, c.TLS.CAPEM = operation, ""
			c.TLS.AllowUnverifiedNodes = true
			e := New(RunProtocol)
			h := create(t, e)
			if _, status := e.Start(h, configBytes(t, c)); status != OK {
				t.Fatal(status)
			}
			next(t, e, h)
			codes := map[string]bool{}
			for count := 0; count < 8; count++ {
				data, _, status := e.Read(h, MaxOutput, 5000)
				if status != OK {
					t.Fatal(status)
				}
				var event event
				if err := json.Unmarshal(data, &event); err != nil {
					t.Fatal(err)
				}
				if event.Type == "observation" {
					continue
				}
				if event.Type == "diagnostic" {
					codes[event.Code] = true
					continue
				}
				expectedCodes := 4
				if operation == "connect" {
					expectedCodes += 2
					if !codes["authentication_started"] || !codes["tls_node_verification_disabled"] {
						t.Fatal("missing connect policy diagnostics")
					}
				}
				if event.Type != "terminal" || event.Status != TLSTrust || len(codes) != expectedCodes || !codes["tls_authentication_failed"] || !codes["tls_unknown_authority"] || !codes["tls_peer_chain_leaf_only"] || !codes["tls_peer_self_signed"] || g.authCount.Load() != 0 {
					t.Fatalf("event = %+v, diagnostics = %v, authentications = %d", event, codes, g.authCount.Load())
				}
				return
			}
			t.Fatal("missing query certificate failure")
		})
	}
}

func checkNodeTraffic(t *testing.T, address string) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := dialer.Dial("tcp", "192.0.2.10:80")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	echo(t, tcp)
	control, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("SOCKS greeting: %v %v", greeting, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("UDP associate: %v %v", reply, err)
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	datagram, err := statute.NewDatagram("192.0.2.10:53", []byte("owned node TLS payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(datagram.Bytes()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := udp.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], datagram.Bytes()) {
		t.Fatalf("L3 UDP echo: %x %v", buffer[:n], err)
	}
}
