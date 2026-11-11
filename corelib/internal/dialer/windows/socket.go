//go:build windows

package dialer

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func BindInterface(dialer *net.Dialer, interfaceName string) error {
	index, err := interfaceIndex(interfaceName)
	if err != nil {
		return err
	}
	dialer.ControlContext = func(_ context.Context, network, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			if strings.HasSuffix(network, "6") {
				bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, ipv6UnicastIf, int(index))
				return
			}
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], index)
			index := *(*uint32)(unsafe.Pointer(&bytes[0]))
			bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIf, int(index))
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var aliasToLuid = ipHelper.NewProc("ConvertInterfaceAliasToLuid")
var luidToIndex = ipHelper.NewProc("ConvertInterfaceLuidToIndex")

func interfaceIndex(name string) (uint32, error) {
	if name == "" {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	alias, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var luid uint64
	if status, _, _ := aliasToLuid.Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid))); status != 0 {
		return 0, syscall.Errno(status)
	}
	var index uint32
	if status, _, _ := luidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index))); status != 0 {
		return 0, syscall.Errno(status)
	}
	if index == 0 {
		return 0, windows.ERROR_INVALID_DATA
	}
	return index, nil
}
