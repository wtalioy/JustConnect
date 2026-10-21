//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDeviceIdentityTracksAnActualPresentPnPNode(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
			t.Fatal(err)
		}
		identity, err := deviceInstanceID(row.InterfaceLuid)
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if present, err := devicePresent(identity); err != nil || !present {
			t.Fatal("native identity lookup missed its original PnP device", err)
		}
		if present, err := devicePresent(`SWD\WINTUN\{00000000-0000-0000-0000-000000000000}`); err != nil || present {
			t.Fatal("missing PnP node selected another device", err)
		}
		return
	}
	t.Fatal("no present PnP network device for identity verification")
}

func TestDeviceReadbackUsesNativeInterfaceAndRouteTables(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		if present, err := adapterPresent(iface.Name); err != nil || !present {
			t.Fatal("native interface lookup missed loopback", err)
		}
		row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
			t.Fatal(err)
		}
		if present, err := ownedInterfacePresent(row.InterfaceLuid); err != nil || !present {
			t.Fatal("LUID lookup missed the original loopback interface", err)
		}
		if _, err := ownedInterfacePresent(0); err == nil {
			t.Fatal("zero LUID could select another interface")
		}
		if routes, err := interfaceHasRoutes(uint32(iface.Index)); err != nil || !routes {
			t.Fatal("native route lookup missed loopback routes", err)
		}
		if routes, err := interfaceHasRoutes(^uint32(0)); err != nil || routes {
			t.Fatal("native route lookup returned an unrelated interface", err)
		}
		return
	}
	t.Fatal("no loopback interface for native readback")
}

func TestDeviceClientTokenKeepsIdentityWithoutElevation(t *testing.T) {
	token, err := restrictedToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	original, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(user.User.Sid, original.User.Sid) || token.IsElevated() {
		t.Fatalf("client identity/elevation: same user=%t elevated=%t", windows.EqualSid(user.User.Sid, original.User.Sid), token.IsElevated())
	}
	var size uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size < uint32(unsafe.Sizeof(windows.Tokenmandatorylabel{})) {
		t.Fatal("missing client integrity label")
	}
	label := make([]byte, size)
	if err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &label[0], size, &size); err != nil {
		t.Fatal(err)
	}
	if (*windows.Tokenmandatorylabel)(unsafe.Pointer(&label[0])).Label.Sid.String() != "S-1-16-8192" {
		t.Fatal("client was not limited to medium integrity")
	}
}

func TestDeviceFramesRejectOversizeAndTruncation(t *testing.T) {
	for _, size := range []uint32{0, 19, 65536, ^uint32(0)} {
		var input bytes.Buffer
		binary.Write(&input, binary.BigEndian, size)
		if _, err := readFrame(&input); !errors.Is(err, errRejectedFrame) {
			t.Fatalf("unsafe allocation boundary %d: %v", size, err)
		}
	}
	var short bytes.Buffer
	binary.Write(&short, binary.BigEndian, uint32(32))
	short.Write([]byte{0x45})
	if _, err := readFrame(&short); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated device input accepted", err)
	}
}

func TestDeviceProbeCannotInjectUnrelatedTraffic(t *testing.T) {
	packet := make([]byte, 32)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], 32)
	binary.BigEndian.PutUint16(packet[22:24], probePort)
	binary.BigEndian.PutUint16(packet[24:26], 12)
	copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	if !validPacket(packet, false) {
		t.Fatal("test subnet packet rejected")
	}
	for _, offset := range []int{0, 2, 6, 7, 9, 12, 16, 22, 24} {
		changed := bytes.Clone(packet)
		changed[offset] ^= 1
		if validPacket(changed, false) {
			t.Fatalf("unrelated protocol, address, port or fragmented packet accepted at %d", offset)
		}
	}
}
