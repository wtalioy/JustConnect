package main

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"net/netip"
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/bridge"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/networkstate"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/packetpipe"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/tundevice"
	"github.com/wtalioy/JustConnect/corelib/stack/gvisor"
)

var revision string
var sourceState string

func buildInfo() []byte {
	rev, state := revision, sourceState
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if rev == "" && setting.Key == "vcs.revision" {
				rev = setting.Value
			}
			if state == "" && setting.Key == "vcs.modified" {
				state = "clean"
				if setting.Value == "true" {
					state = "dirty"
				}
			}
		}
	}
	if rev == "" {
		rev = "unversioned"
	}
	if state == "" {
		state = "unknown"
	}
	var tunnelMTU uint32
	if !testDriver {
		tunnelMTU = gvisor.MTU
	}
	data, _ := json.Marshal(map[string]any{
		"schema_version": bridge.ABIVersion, "abi_version": bridge.ABIVersion,
		"test_driver": testDriver,
		"build": map[string]any{"revision": rev, "source_state": state,
			"upstream_commit": bridge.UpstreamCommit, "local_version": rev + "+" + state,
			"go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH},
		"capabilities": map[string]any{"embedded_vpn": !testDriver, "auth_method_query": !testDriver, "authentication_cache": !testDriver, "policy_update": true,
			"initial_protection":       true,
			"name_protection":          true,
			"network_snapshot":         networkstate.Supported(),
			"resource_snapshot":        !testDriver,
			"tun_dns_routes":           !testDriver && (tundevice.Supported || packetpipe.Supported),
			"raw_ipv4_tun_fd":          !testDriver && tundevice.Supported,
			"windows_ipv4_packet_pipe": !testDriver && packetpipe.Supported,
			"tunnel_mtu":               tunnelMTU,
			"async_start":              true, "authentication_response": true, "bounded_events": true,
			"max_sessions": 1, "max_handles": bridge.MaxHandles, "max_input_bytes": bridge.MaxInput,
			"max_output_bytes": bridge.MaxOutput, "max_wait_ms": bridge.MaxWaitMS, "max_auth_wait_ms": bridge.MaxAuthWaitMS,
			"max_diagnostics": bridge.MaxDiagnostics},
	})
	return data
}

func inputBytes(input *C.uint8_t, length C.uint32_t) ([]byte, bool) {
	if input == nil || length == 0 || length > bridge.MaxInput {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(input), C.int(length)), true
}

func outputValid(output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) bool {
	if length == nil {
		return false
	}
	*length = 0
	return capacity <= bridge.MaxOutput && (capacity == 0 || output != nil)
}

func writeOutput(data []byte, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	*length = C.uint32_t(len(data))
	if capacity < *length {
		return C.int32_t(bridge.BufferTooSmall)
	}
	if len(data) != 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), data)
	}
	return C.int32_t(bridge.OK)
}

//export jc_go_abi_version
func jc_go_abi_version() C.uint32_t { return bridge.ABIVersion }

//export jc_go_build_info
func jc_go_build_info(abi C.uint32_t, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	if !outputValid(output, capacity, length) {
		return C.int32_t(bridge.InvalidArgument)
	}
	if abi != bridge.ABIVersion {
		return C.int32_t(bridge.ABIMismatch)
	}
	return writeOutput(buildInfo(), output, capacity, length)
}

//export jc_go_network_snapshot
func jc_go_network_snapshot(abi C.uint32_t, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	if !outputValid(output, capacity, length) {
		return C.int32_t(bridge.InvalidArgument)
	}
	if abi != bridge.ABIVersion {
		return C.int32_t(bridge.ABIMismatch)
	}
	snapshot, err := networkstate.Read()
	if errors.Is(err, networkstate.ErrUnsupported) {
		return C.int32_t(bridge.Unsupported)
	}
	if err != nil {
		return C.int32_t(bridge.Internal)
	}
	data, err := json.Marshal(map[string]any{"schema_version": bridge.ABIVersion, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "network": snapshot})
	if err != nil {
		return C.int32_t(bridge.Internal)
	}
	if len(data) > bridge.MaxOutput {
		return C.int32_t(bridge.Limit)
	}
	return writeOutput(data, output, capacity, length)
}

//export jc_go_config_validate
func jc_go_config_validate(abi C.uint32_t, input *C.uint8_t, length C.uint32_t) C.int32_t {
	if abi != bridge.ABIVersion {
		return C.int32_t(bridge.ABIMismatch)
	}
	data, ok := inputBytes(input, length)
	if !ok {
		return C.int32_t(bridge.InvalidArgument)
	}
	_, status := bridge.ParseConfig(data)
	clear(data)
	return C.int32_t(status)
}

//export jc_go_session_attach_tun
func jc_go_session_attach_tun(handle C.uint64_t, generation C.uint64_t, fd C.int32_t, mtu C.uint32_t) C.int32_t {
	return attachTUN(handle, generation, fd, mtu, false)
}

//export jc_go_session_attach_tun_dns
func jc_go_session_attach_tun_dns(handle C.uint64_t, generation C.uint64_t, fd C.int32_t, mtu C.uint32_t) C.int32_t {
	return attachTUN(handle, generation, fd, mtu, true)
}

//export jc_go_session_attach_windows_pipe
func jc_go_session_attach_windows_pipe(handle C.uint64_t, generation C.uint64_t, pipe C.uint64_t, helperPID C.uint32_t, mtu C.uint32_t, source C.uint32_t, peer C.uint32_t, publishDNS C.uint32_t) C.int32_t {
	if testDriver || !packetpipe.Supported {
		return C.int32_t(bridge.Unsupported)
	}
	if publishDNS > 1 {
		return C.int32_t(bridge.InvalidArgument)
	}
	address := func(value uint32) netip.Addr {
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	device, err := packetpipe.Duplicate(uint64(pipe), uint32(helperPID), uint32(mtu), address(uint32(source)), address(uint32(peer)))
	if err != nil {
		return C.int32_t(bridge.InvalidArgument)
	}
	status := engine.AttachTUN(uint64(handle), uint64(generation), device, uint32(mtu), publishDNS == 1)
	if status != bridge.OK {
		_ = device.Close()
	}
	return C.int32_t(status)
}

//export jc_go_session_ack_dns_routes
func jc_go_session_ack_dns_routes(handle C.uint64_t, generation C.uint64_t, request C.uint64_t, applied C.uint32_t) C.int32_t {
	if testDriver || (!tundevice.Supported && !packetpipe.Supported) {
		return C.int32_t(bridge.Unsupported)
	}
	if applied > 1 {
		return C.int32_t(bridge.InvalidArgument)
	}
	return C.int32_t(engine.AcknowledgeDNSRoutes(uint64(handle), uint64(generation), uint64(request), applied == 1))
}

func attachTUN(handle C.uint64_t, generation C.uint64_t, fd C.int32_t, mtu C.uint32_t, publishDNS bool) C.int32_t {
	if testDriver || !tundevice.Supported {
		return C.int32_t(bridge.Unsupported)
	}
	device, err := tundevice.Duplicate(int(fd), uint32(mtu))
	if err != nil {
		return C.int32_t(bridge.InvalidArgument)
	}
	status := engine.AttachTUN(uint64(handle), uint64(generation), device, uint32(mtu), publishDNS)
	if status != bridge.OK {
		_ = device.Close()
	}
	return C.int32_t(status)
}

//export jc_go_session_create
func jc_go_session_create(abi C.uint32_t, handle *C.uint64_t) C.int32_t {
	if handle == nil {
		return C.int32_t(bridge.InvalidArgument)
	}
	*handle = 0
	value, status := engine.Create(uint32(abi))
	*handle = C.uint64_t(value)
	return C.int32_t(status)
}

//export jc_go_session_start
func jc_go_session_start(handle C.uint64_t, input *C.uint8_t, length C.uint32_t, generation *C.uint64_t) C.int32_t {
	if generation == nil {
		return C.int32_t(bridge.InvalidArgument)
	}
	*generation = 0
	data, ok := inputBytes(input, length)
	if !ok {
		return C.int32_t(bridge.InvalidArgument)
	}
	value, status := engine.Start(uint64(handle), data)
	*generation = C.uint64_t(value)
	return C.int32_t(status)
}

//export jc_go_session_read
func jc_go_session_read(handle C.uint64_t, wait C.uint32_t, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	if !outputValid(output, capacity, length) {
		return C.int32_t(bridge.InvalidArgument)
	}
	data, required, status := engine.Read(uint64(handle), uint32(capacity), uint32(wait))
	*length = C.uint32_t(required)
	if status != bridge.OK {
		return C.int32_t(status)
	}
	return writeOutput(data, output, capacity, length)
}

//export jc_go_session_respond
func jc_go_session_respond(handle C.uint64_t, input *C.uint8_t, length C.uint32_t) C.int32_t {
	data, ok := inputBytes(input, length)
	if !ok {
		return C.int32_t(bridge.InvalidArgument)
	}
	return C.int32_t(engine.Respond(uint64(handle), data))
}

//export jc_go_session_update_policy
func jc_go_session_update_policy(handle C.uint64_t, input *C.uint8_t, length C.uint32_t, generation *C.uint64_t) C.int32_t {
	if generation == nil {
		return C.int32_t(bridge.InvalidArgument)
	}
	*generation = 0
	data, ok := inputBytes(input, length)
	if !ok {
		return C.int32_t(bridge.InvalidArgument)
	}
	value, status := engine.UpdatePolicy(uint64(handle), data)
	*generation = C.uint64_t(value)
	return C.int32_t(status)
}

//export jc_go_session_resources
func jc_go_session_resources(handle C.uint64_t, generation C.uint64_t, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	if !outputValid(output, capacity, length) {
		return C.int32_t(bridge.InvalidArgument)
	}
	data, status := engine.Resources(uint64(handle), uint64(generation))
	if status != bridge.OK {
		return C.int32_t(status)
	}
	return writeOutput(data, output, capacity, length)
}

//export jc_go_session_stop
func jc_go_session_stop(handle C.uint64_t, wait C.uint32_t) C.int32_t {
	return C.int32_t(engine.Stop(uint64(handle), uint32(wait)))
}

//export jc_go_session_destroy
func jc_go_session_destroy(handle C.uint64_t, wait C.uint32_t) C.int32_t {
	return C.int32_t(engine.Destroy(uint64(handle), uint32(wait)))
}

func main() {}
