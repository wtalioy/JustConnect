//go:build linux

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

const testOwner = "0d3aa2a7-5f4b-4a13-8db9-51e2c5b70c81"
const testRequest = "7f7ef2ea-0cf3-4d43-a2e2-5d4e56d0e89f"

func envelope(op string) map[string]any {
	return map[string]any{
		"version":    helperProtocol,
		"operation":  op,
		"owner":      testOwner,
		"request_id": testRequest,
	}
}

func TestParseRequestAcceptsEnvelopeOnlyOperations(t *testing.T) {
	for _, op := range []string{opProbe, opRestore, opCleanup, opClose} {
		request, err := parseRequest(mustJSON(t, envelope(op)))
		if err != nil {
			t.Fatalf("parse %s: %v", op, err)
		}
		if request.Operation != op {
			t.Fatalf("operation %q, expected %q", request.Operation, op)
		}
	}
}

func TestParseRequestAcceptsApply(t *testing.T) {
	payload := envelope(opApply)
	payload["address"] = "10.22.4.1"
	payload["peer"] = "10.22.4.2"
	payload["mtu"] = 1400
	payload["prefixes"] = []string{"10.50.0.0/16"}
	payload["dns_domains"] = []string{"campus.edu"}
	request, err := parseRequest(mustJSON(t, payload))
	if err != nil {
		t.Fatalf("parse apply: %v", err)
	}
	config, err := request.configuration()
	if err != nil {
		t.Fatalf("configuration: %v", err)
	}
	if config.Address != "10.22.4.1" || config.Peer != "10.22.4.2" || config.MTU != 1400 {
		t.Fatalf("unexpected configuration %+v", config)
	}
	if len(config.Prefixes) != 1 || config.Prefixes[0] != "10.50.0.0/16" {
		t.Fatalf("unexpected prefixes %v", config.Prefixes)
	}
	if len(config.Domains) != 1 || config.Domains[0] != "campus.edu" {
		t.Fatalf("unexpected domains %v", config.Domains)
	}
}

func TestParseRequestApplyRequiresDistinctPairMtuPrefix(t *testing.T) {
	cases := []map[string]any{
		{},
		func() map[string]any {
			p := envelope(opApply)
			p["address"], p["peer"], p["mtu"], p["prefixes"] = "10.0.0.1", "10.0.0.1", 1400, []string{"10.0.0.0/8"}
			return p
		}(),
		func() map[string]any {
			p := envelope(opApply)
			p["address"], p["peer"], p["mtu"], p["prefixes"] = "10.0.0.1", "10.0.0.2", 0, []string{"10.0.0.0/8"}
			return p
		}(),
		func() map[string]any {
			p := envelope(opApply)
			p["address"], p["peer"], p["mtu"], p["prefixes"] = "10.0.0.1", "10.0.0.2", 1400, []string{}
			return p
		}(),
	}
	for i, payload := range cases {
		if _, err := parseRequest(mustJSON(t, payload)); err == nil {
			t.Fatalf("case %d accepted an invalid apply", i)
		}
	}
}

func TestParseRequestRejectsProtocolDrift(t *testing.T) {
	reject := func(name string, payload map[string]any) {
		t.Helper()
		if _, err := parseRequest(mustJSON(t, payload)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	wrongVersion := envelope(opProbe)
	wrongVersion["version"] = helperProtocol + 1
	reject("wrong version", wrongVersion)
	reject("unknown operation", envelope("unite"))
	reject("malformed owner", map[string]any{
		"version": helperProtocol, "operation": opProbe,
		"owner": "not-a-uuid", "request_id": testRequest,
	})
	extra := envelope(opProbe)
	extra["surprise"] = true
	reject("unexpected field", extra)
	applyExtra := envelope(opApply)
	applyExtra["address"], applyExtra["peer"], applyExtra["mtu"], applyExtra["prefixes"] =
		"10.0.0.1", "10.0.0.2", 1400, []string{"10.0.0.0/8"}
	applyExtra["addresses"] = []string{"10.0.0.9"}
	reject("apply with extend field", applyExtra)
	emptyExtend := envelope(opExtend)
	emptyExtend["addresses"] = []string{}
	reject("extend without addresses", emptyExtend)
	emptyRoutes := envelope(opRoutes)
	emptyRoutes["prefixes"] = []string{}
	reject("routes without prefixes", emptyRoutes)
	if _, err := parseRequest(nil); err == nil {
		t.Fatal("empty payload was accepted")
	}
	if _, err := parseRequest([]byte(strings.Repeat("x", maxRequestBytes+1))); err == nil {
		t.Fatal("oversized payload was accepted")
	}
}

func TestMalformedReplyKeepsAttribution(t *testing.T) {
	payload := mustJSON(t, envelope(opProbe))
	reply := malformedReply(payload, errMalformed)
	if reply.Status != statusFailed || reply.Operation != opProbe {
		t.Fatalf("unexpected reply %+v", reply)
	}
	if reply.Owner != testOwner || reply.RequestID != testRequest {
		t.Fatalf("reply lost the envelope: %+v", reply)
	}
	unknown := malformedReply([]byte("{garbage"), errMalformed)
	if unknown.Owner != "" || unknown.Operation != "" {
		t.Fatalf("lenient parse invented fields: %+v", unknown)
	}
}
