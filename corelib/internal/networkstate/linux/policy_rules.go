//go:build linux

package networkstate

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net/netip"
	"time"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

var errRuleSnapshot = errors.New("invalid or incomplete routing policy snapshot")

func parsePolicyRule(payload []byte) (model.PolicyRule, bool, error) {
	if len(payload) < unix.SizeofRtMsg {
		return model.PolicyRule{}, false, errRuleSnapshot
	}
	family, destinationBits, sourceBits := int(payload[0]), int(payload[1]), int(payload[2])
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return model.PolicyRule{}, false, nil
	}
	size := 4
	if family == unix.AF_INET6 {
		size = 16
	}
	if sourceBits > size*8 || destinationBits > size*8 {
		return model.PolicyRule{}, false, errRuleSnapshot
	}
	rule := model.PolicyRule{Family: family, Table: uint32(payload[4]), Action: payload[7],
		Flags: binary.NativeEndian.Uint32(payload[8:12]), TOS: payload[3], Attributes: []model.RuleAttribute{}}
	if payload[5] != 0 || payload[6] != 0 {
		return model.PolicyRule{}, false, errRuleSnapshot
	}
	attributes := payload[unix.SizeofRtMsg:]
	for len(attributes) > 0 {
		if len(attributes) < 4 {
			return model.PolicyRule{}, false, errRuleSnapshot
		}
		length := int(binary.NativeEndian.Uint16(attributes[:2]))
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(attributes) {
			return model.PolicyRule{}, false, errRuleSnapshot
		}
		kind, value := binary.NativeEndian.Uint16(attributes[2:4]), attributes[4:length]
		rule.Attributes = append(rule.Attributes, model.RuleAttribute{Type: kind, Value: hex.EncodeToString(value)})
		switch kind {
		case nl.FRA_TABLE, nl.FRA_PRIORITY:
			if len(value) != 4 {
				return model.PolicyRule{}, false, errRuleSnapshot
			}
			number := binary.NativeEndian.Uint32(value)
			if kind == nl.FRA_TABLE {
				rule.Table = number
			} else {
				rule.Priority = number
			}
		case nl.FRA_SRC, nl.FRA_DST:
			if len(value) != size {
				return model.PolicyRule{}, false, errRuleSnapshot
			}
			address, _ := netip.AddrFromSlice(value)
			bits := sourceBits
			if kind == nl.FRA_DST {
				bits = destinationBits
			}
			prefix := netip.PrefixFrom(address, bits).Masked().String()
			if kind == nl.FRA_SRC {
				rule.Source = prefix
			} else {
				rule.Destination = prefix
			}
		}
		attributes = attributes[aligned:]
	}
	if (sourceBits > 0 && rule.Source == "") || (destinationBits > 0 && rule.Destination == "") {
		return model.PolicyRule{}, false, errRuleSnapshot
	}
	return rule, true, nil
}

func parseRuleMessages(data []byte, port uint32) ([]model.PolicyRule, bool, error) {
	if len(data) == 0 {
		return nil, false, errRuleSnapshot
	}
	rules := []model.PolicyRule{}
	for len(data) > 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return nil, false, errRuleSnapshot
		}
		length := int(binary.NativeEndian.Uint32(data[:4]))
		if length < unix.NLMSG_HDRLEN || length > len(data) {
			return nil, false, errRuleSnapshot
		}
		aligned := (length + 3) &^ 3
		if aligned > len(data) {
			return nil, false, errRuleSnapshot
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		flags := binary.NativeEndian.Uint16(data[6:8])
		sequence, owner := binary.NativeEndian.Uint32(data[8:12]), binary.NativeEndian.Uint32(data[12:16])
		payload := data[unix.NLMSG_HDRLEN:length]
		data = data[aligned:]
		if sequence != 1 || owner != port || flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, false, errRuleSnapshot
		}
		switch kind {
		case unix.NLMSG_DONE, unix.NLMSG_ERROR:
			if len(payload) != 0 {
				if len(payload) < 4 {
					return nil, false, errRuleSnapshot
				}
				code := int32(binary.NativeEndian.Uint32(payload[:4]))
				if code < 0 {
					return nil, false, unix.Errno(-code)
				}
				if code > 0 {
					return nil, false, errRuleSnapshot
				}
			} else if kind == unix.NLMSG_ERROR {
				return nil, false, errRuleSnapshot
			}
			if kind == unix.NLMSG_DONE {
				if len(data) != 0 {
					return nil, false, errRuleSnapshot
				}
				return rules, true, nil
			}
		case unix.RTM_NEWRULE:
			rule, supported, err := parsePolicyRule(payload)
			if err != nil {
				return nil, false, err
			}
			if supported {
				rules = append(rules, rule)
			}
		default:
			return nil, false, errRuleSnapshot
		}
	}
	return rules, false, nil
}

func ReadPolicyRules() ([]model.PolicyRule, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	port := address.(*unix.SockaddrNetlink).Pid
	request := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofRtMsg)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_GETRULE)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	binary.NativeEndian.PutUint32(request[12:16], port)
	deadline := time.Now().Add(time.Second)
	timeout := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	rules := []model.PolicyRule{}
	buffer := make([]byte, 65536)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errRuleSnapshot
		}
		timeout = unix.NsecToTimeval(remaining.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return nil, err
		}
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			return nil, err
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if !ok || from.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return nil, errRuleSnapshot
		}
		batch, done, err := parseRuleMessages(buffer[:n], port)
		if err != nil {
			return nil, err
		}
		rules = append(rules, batch...)
		if len(rules) > 4096 {
			return nil, errRuleSnapshot
		}
		if done {
			return rules, nil
		}
	}
}
