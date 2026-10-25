package networkstate

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

func rulePayload() []byte {
	payload := make([]byte, unix.SizeofRtMsg)
	payload[0], payload[1], payload[2], payload[3] = unix.AF_INET, 24, 16, 4
	payload[4], payload[7] = 254, 1
	binary.NativeEndian.PutUint32(payload[8:12], 2)
	for _, attribute := range []struct {
		kind  int
		value []byte
	}{
		{nl.FRA_TABLE, nl.Uint32Attr(12345)}, {nl.FRA_PRIORITY, nl.Uint32Attr(52)},
		{nl.FRA_SRC, []byte{100, 64, 1, 0}}, {nl.FRA_DST, []byte{192, 0, 2, 0}},
		{nl.FRA_IP_PROTO, []byte{6}}, {nl.FRA_FWMARK, nl.Uint32Attr(0)},
		{nl.FRA_FWMASK, nl.Uint32Attr(0xffffffff)}, {999, []byte{1, 2, 3}},
	} {
		payload = append(payload, nl.NewRtAttr(attribute.kind, attribute.value).Serialize()...)
	}
	return payload
}

func ruleMessage(kind uint16, flags uint16, data []byte) []byte {
	length := unix.NLMSG_HDRLEN + len(data)
	message := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint32(message[:4], uint32(length))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], 1)
	binary.NativeEndian.PutUint32(message[12:16], 42)
	copy(message[unix.NLMSG_HDRLEN:], data)
	return message
}

func TestPolicyRulePreservesHeaderAndOpaqueSelectors(t *testing.T) {
	payload := rulePayload()
	rule, supported, err := parsePolicyRule(payload)
	if err != nil || !supported {
		t.Fatalf("parse: %v", err)
	}
	if rule.Table != 12345 || rule.Priority != 52 || rule.Action != 1 || rule.Flags != 2 || rule.TOS != 4 || rule.Source != "100.64.0.0/16" || rule.Destination != "192.0.2.0/24" {
		t.Fatalf("native routing rule header or scope lost: %+v", rule)
	}
	for _, expected := range []RuleAttribute{{nl.FRA_IP_PROTO, "06"}, {nl.FRA_FWMARK, "00000000"},
		{nl.FRA_FWMASK, hex.EncodeToString(nl.Uint32Attr(0xffffffff))}, {999, "010203"}} {
		if !slices.Contains(rule.Attributes, expected) {
			t.Fatalf("selector lost: %+v", expected)
		}
	}
	payload = make([]byte, unix.SizeofRtMsg)
	payload[0], payload[2], payload[4], payload[7] = unix.AF_INET6, 120, 255, 1
	address := netip.MustParseAddr("::ffff:192.0.2.9").As16()
	payload = append(payload, nl.NewRtAttr(nl.FRA_SRC, address[:]).Serialize()...)
	rule, supported, err = parsePolicyRule(payload)
	if err != nil || !supported || rule.Source != "::ffff:192.0.2.0/120" || rule.Table != 255 {
		t.Fatalf("native mapped IPv6 rule family broadened or header table lost: %+v %v", rule, err)
	}
}

func TestRuleDumpRejectsInterruptedMalformedAndForeignResults(t *testing.T) {
	message := ruleMessage(unix.RTM_NEWRULE, unix.NLM_F_MULTI, rulePayload())
	done := ruleMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, nil)
	rules, complete, err := parseRuleMessages(append(slices.Clone(message), done...), 42)
	if err != nil || !complete || len(rules) != 1 {
		t.Fatalf("complete dump: %v", err)
	}
	_, complete, err = parseRuleMessages(message, 42)
	if err != nil || complete {
		t.Fatal("unterminated batch marked complete")
	}
	interrupted := ruleMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, nil)
	foreign := slices.Clone(message)
	binary.NativeEndian.PutUint32(foreign[12:16], 43)
	badSequence := slices.Clone(message)
	binary.NativeEndian.PutUint32(badSequence[8:12], 2)
	for _, data := range [][]byte{append(slices.Clone(message), interrupted...), foreign, badSequence,
		append(slices.Clone(message), 1), append(slices.Clone(done), message...),
		ruleMessage(unix.NLMSG_ERROR, 0, nl.Uint32Attr(uint32(0xffffffff))),
		ruleMessage(unix.RTM_NEWRULE, unix.NLM_F_MULTI, rulePayload()[:13])} {
		rules, complete, err := parseRuleMessages(data, 42)
		if err == nil || complete || rules != nil {
			t.Fatal("invalid dump published partial rules")
		}
	}
}

func TestReadIncludesActualIPv4LocalPolicyTable(t *testing.T) {
	snapshot, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(snapshot.PolicyRules, func(rule PolicyRule) bool {
		return rule.Family == unix.AF_INET && rule.Table == unix.RT_TABLE_LOCAL && rule.Action == 1
	}) {
		t.Fatal("native IPv4 local-table routing rule omitted")
	}
}

func FuzzPolicyRuleWireBoundaries(f *testing.F) {
	f.Add(rulePayload())
	f.Add([]byte{2})
	f.Add(ruleMessage(unix.RTM_NEWRULE, unix.NLM_F_MULTI, rulePayload()))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parsePolicyRule(data)
		_, _, _ = parseRuleMessages(data, 42)
	})
}
