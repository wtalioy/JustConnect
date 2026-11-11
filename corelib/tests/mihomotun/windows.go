//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	windowsfixture "github.com/wtalioy/JustConnect/corelib/tests/windows"
	"golang.org/x/sys/windows"
)

func ensureOrdinary() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	if os.Getenv("JC_TUN_ORDINARY") != "" {
		return fmt.Errorf("control consumer retained elevation")
	}
	token, err := windowsfixture.OrdinaryToken()
	if err != nil {
		return err
	}
	defer token.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, os.Args[1:]...)
	child.Env = append(os.Environ(), "JC_TUN_ORDINARY=1")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	if err := child.Run(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

var bestRoute = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

func routeInterface(ctx context.Context, ip netip.Addr) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var destination, source windows.RawSockaddrInet6 // SOCKADDR_INET unions.
	address := (*windows.RawSockaddrInet4)(unsafe.Pointer(&destination))
	address.Family, address.Addr = windows.AF_INET, ip.As4()
	var route windows.MibIpForwardRow2
	status, _, _ := bestRoute.Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&route)), uintptr(unsafe.Pointer(&source)))
	if status != 0 {
		return "", syscall.Errno(status)
	}
	iface, err := net.InterfaceByIndex(int(route.InterfaceIndex))
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}
