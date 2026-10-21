package bridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSFailureDiagnosticsAfterAuthentication(t *testing.T) {
	for _, reason := range []string{"tls_unknown_authority", "tls_hostname_mismatch", "tls_certificate_time_invalid", "trusted"} {
		t.Run(reason, func(t *testing.T) {
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
			g := newGatewayWithNodeTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			c := g.config(t)
			if reason != "tls_unknown_authority" {
				c.TLS.CAPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			}
			e := New(RunProtocol)
			h := create(t, e)
			startProtocol(t, e, h, c)
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
				if event.Type == "diagnostic" {
					codes[event.Code] = true
					continue
				}
				if reason == "trusted" {
					if event.State != "ready" || len(codes) != 1 || !codes["transport_connected"] {
						t.Fatalf("trusted node = %+v, diagnostics = %v", event, codes)
					}
					e.Stop(h, MaxWaitMS)
					next(t, e, h)
					return
				}
				if event.Type != "terminal" || event.Status != TLSTrust || len(codes) != 2 || !codes["tls_node_probe_failed"] || !codes[reason] || g.authCount.Load() != 1 {
					t.Fatalf("event = %+v, diagnostics = %v, authentications = %d", event, codes, g.authCount.Load())
				}
				return
			}
			t.Fatal("missing TLS result")
		})
	}
}

func TestAuthenticationQueryTLSFailureDiagnostics(t *testing.T) {
	g := newGateway(t)
	c := g.config(t)
	c.Operation, c.TLS.CAPEM = "auth_methods", ""
	e := New(RunProtocol)
	h := create(t, e)
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	next(t, e, h)
	codes := map[string]bool{}
	for count := 0; count < 4; count++ {
		data, _, status := e.Read(h, MaxOutput, 5000)
		if status != OK {
			t.Fatal(status)
		}
		var event event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "diagnostic" {
			codes[event.Code] = true
			continue
		}
		if event.Type != "terminal" || event.Status != TLSTrust || len(codes) != 2 || !codes["tls_authentication_failed"] || !codes["tls_unknown_authority"] || g.authCount.Load() != 0 {
			t.Fatalf("event = %+v, diagnostics = %v, authentications = %d", event, codes, g.authCount.Load())
		}
		return
	}
	t.Fatal("missing query certificate failure")
}
