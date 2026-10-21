//go:build windows

// This disposable-runner probe owns a fresh adapter; it never loads the VPN core.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const probePort = 43877

type brokerDevice struct {
	Name  string
	Index uint32
	LUID  uint64
}

var errRejectedFrame = errors.New("rejected device frame")

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errRejectedFrame) {
			os.Exit(23)
		}
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return errors.New("device probe requires a disposable GitHub runner")
	}
	if len(os.Args) == 3 && os.Args[1] == "--client" {
		return client(os.Args[2])
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("device broker requires an elevated disposable runner")
	}
	if len(os.Args) == 5 && os.Args[1] == "--broker" {
		name := os.Args[3]
		if !strings.HasPrefix(name, "JCProbe") || len(name) != 23 {
			return errors.New("invalid test adapter name")
		}
		if _, err := hex.DecodeString(name[7:]); err != nil {
			return err
		}
		switch os.Args[4] {
		case "roundtrip", "oversized", "crash":
		default:
			return errors.New("invalid probe mode")
		}
		return broker(os.Args[2], name, os.Args[4])
	}
	if len(os.Args) != 2 {
		return errors.New("expected verified Wintun DLL path")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			_, network, err := net.ParseCIDR(address.String())
			if err == nil && network.Contains(net.ParseIP("192.0.2.1")) {
				return errors.New("test subnet already belongs to another adapter")
			}
		}
	}
	for _, mode := range []string{"roundtrip", "oversized", "crash"} {
		if err := runBroker(os.Args[1], mode); err != nil {
			return fmt.Errorf("%s: %w", mode, err)
		}
	}
	return nil
}

func executable() string {
	path, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return path
}

func powershell(script string) ([]byte, error) {
	operation, _, _ := strings.Cut(script, " ")
	fmt.Fprintln(os.Stderr, "START: adapter operation", operation)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", "-")
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader("$ErrorActionPreference='Stop';" + script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Join(ctx.Err(), fmt.Errorf("test adapter operation: %w: %s", err, output))
	}
	return bytes.TrimSpace(output), nil
}

func adapterPresent(name string) (bool, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		return false, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if windows.UTF16ToString(row.Alias[:]) == name {
			return true, nil
		}
	}
	return false, nil
}

func interfaceHasRoutes(index uint32) (bool, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return false, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range table.Rows() {
		if row.InterfaceIndex == index {
			return true, nil
		}
	}
	return false, nil
}

func ownedInterfacePresent(luid uint64) (bool, error) {
	if luid == 0 {
		return false, errors.New("invalid test interface LUID")
	}
	row := windows.MibIfRow2{InterfaceLuid: luid}
	err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.OperStatus != windows.IfOperStatusNotPresent, nil
}

func runBroker(dll, mode string) (result error) {
	fmt.Fprintln(os.Stderr, "START: device case", mode)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "JCProbe" + hex.EncodeToString(nonce[:])
	present, err := adapterPresent(name)
	if err != nil {
		return err
	}
	if present {
		return errors.New("test adapter already exists")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	setLimits := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetInformationJobObject")
	if ok, _, err := setLimits.Call(uintptr(job), windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable(), "--broker", dll, name, mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	var ready brokerDevice
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		// Independent safety cleanup is limited to this nonce's newly created device.
		var remaining bool
		var lookupErr error
		if ready.LUID != 0 {
			remaining, lookupErr = ownedInterfacePresent(ready.LUID)
		} else {
			remaining, lookupErr = adapterPresent(name)
		}
		if lookupErr != nil {
			result = errors.Join(result, lookupErr)
			return
		}
		if !remaining {
			return
		}
		result = errors.Join(result, errors.New("adapter survived its owner; independent cleanup required"))
		output, lookupErr := powershell("Get-NetAdapter -IncludeHidden | Where-Object {$_.Name -eq '" + name + "'} | Select-Object -ExpandProperty PnPDeviceID")
		if lookupErr != nil {
			result = errors.Join(result, lookupErr)
			return
		}
		deviceID := strings.TrimSpace(string(output))
		if !strings.HasPrefix(strings.ToUpper(deviceID), "SWD\\WINTUN\\") {
			result = errors.Join(result, fmt.Errorf("unexpected device identity %q; refusing removal", deviceID))
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
		defer stop()
		path := filepath.Join(os.Getenv("SystemRoot"), "System32", "pnputil.exe")
		cmd := exec.CommandContext(cleanup, path, "/remove-device", deviceID)
		cmd.WaitDelay = time.Second
		if output, err := cmd.CombinedOutput(); err != nil {
			result = errors.Join(result, fmt.Errorf("owned device cleanup: %w: %s", err, output))
		}
	}()
	if err = assignAndResume(job, uint32(cmd.Process.Pid)); err != nil {
		return err
	}
	if err = json.NewDecoder(bufio.NewReader(io.LimitReader(output, 4096))).Decode(&ready); err != nil {
		return fmt.Errorf("broker did not confirm its device: %w", err)
	}
	if ready.Name != name || ready.Index == 0 || ready.LUID == 0 {
		return errors.New("broker confirmed another device")
	}
	if mode == "crash" {
		if err = cmd.Process.Kill(); err != nil {
			return err
		}
	}
	err = cmd.Wait()
	if mode == "oversized" {
		var failure *exec.ExitError
		if !errors.As(err, &failure) || failure.ExitCode() != 23 {
			return fmt.Errorf("invalid frame was not rejected: %w", err)
		}
	} else if mode != "crash" && err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		present, err = ownedInterfacePresent(ready.LUID)
		if err != nil {
			return err
		}
		if !present {
			routes, err := interfaceHasRoutes(ready.Index)
			if err != nil {
				return err
			}
			if !routes {
				fmt.Printf("PASS: %s, owned adapter and routes removed (%s)\n", mode, name)
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	row := windows.MibIfRow2{InterfaceLuid: ready.LUID}
	readErr := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row)
	routes, routeErr := interfaceHasRoutes(ready.Index)
	return fmt.Errorf("owned adapter did not disappear after broker exit: state=%d admin=%d lookup=%v routes=%t route_error=%v", row.OperStatus, row.AdminStatus, readErr, routes, routeErr)
}

func assignAndResume(job windows.Handle, processID uint32) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, processID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if err = windows.AssignProcessToJobObject(job, process); err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != processID {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		previous, err := windows.ResumeThread(thread)
		windows.CloseHandle(thread)
		if err != nil {
			return err
		}
		if previous != 1 {
			return errors.New("device broker ran before its lifetime guard was installed")
		}
		return nil
	}
	return errors.New("suspended broker thread not found")
}

func restrictedToken() (windows.Token, error) {
	var original, restricted windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &original); err != nil {
		return 0, fmt.Errorf("open caller token: %w", err)
	}
	defer original.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	denied := windows.SIDAndAttributes{Sid: admin}
	create := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	const disableMaxPrivilege, luaToken = 0x1, 0x4
	ok, _, err := create.Call(uintptr(original), disableMaxPrivilege|luaToken, 1, uintptr(unsafe.Pointer(&denied)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if ok == 0 {
		return 0, fmt.Errorf("restrict caller token: %w", err)
	}
	medium, err := windows.StringToSid("S-1-16-8192")
	if err == nil {
		label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
		err = windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size())
	}
	if err != nil {
		restricted.Close()
		return 0, fmt.Errorf("limit client integrity: %w", err)
	}
	return restricted, nil
}

func broker(path, name, mode string) error {
	module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return err
	}
	defer windows.FreeLibrary(module)
	library := &windows.DLL{Name: path, Handle: module}
	procedures := make(map[string]*windows.Proc)
	for _, name := range []string{"WintunCreateAdapter", "WintunCloseAdapter", "WintunStartSession", "WintunEndSession", "WintunGetAdapterLUID", "WintunGetReadWaitEvent", "WintunReceivePacket", "WintunReleaseReceivePacket", "WintunAllocateSendPacket", "WintunSendPacket"} {
		procedures[name], err = library.FindProc(name)
		if err != nil {
			return err
		}
	}
	adapter, _, err := procedures["WintunCreateAdapter"].Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("JustConnectProbe"))), 0)
	if adapter == 0 {
		return fmt.Errorf("create test adapter: %w", err)
	}
	defer procedures["WintunCloseAdapter"].Call(adapter)
	session, _, err := procedures["WintunStartSession"].Call(adapter, 0x20000)
	if session == 0 {
		return fmt.Errorf("register device rings: %w", err)
	}
	defer procedures["WintunEndSession"].Call(session)
	var luid uint64
	_, _, _ = procedures["WintunGetAdapterLUID"].Call(adapter, uintptr(unsafe.Pointer(&luid)))
	if luid == 0 {
		return errors.New("adapter has no LUID")
	}
	var index uint32
	convert := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceLuidToIndex")
	if status, _, _ := convert.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index))); status != 0 || index == 0 {
		return fmt.Errorf("adapter index status %d", status)
	}
	idx := strconv.FormatUint(uint64(index), 10)
	script := "Set-NetIPInterface -InterfaceIndex " + idx + " -AddressFamily IPv4 -DadTransmits 0;" +
		"New-NetIPAddress -InterfaceIndex " + idx + " -IPAddress 192.0.2.1 -PrefixLength 30 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null;" +
		"New-NetRoute -InterfaceIndex " + idx + " -DestinationPrefix 192.0.2.2/32 -NextHop 0.0.0.0 -PolicyStore ActiveStore | Out-Null;" +
		"$r=@(Get-NetRoute -InterfaceIndex " + idx + " -DestinationPrefix 192.0.2.2/32 -PolicyStore ActiveStore);" +
		"if($r.Count -ne 1 -or $r[0].NextHop -ne '0.0.0.0'){throw 'owned host route was not applied'}"
	if _, err = powershell(script); err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(brokerDevice{name, index, luid}); err != nil {
		return err
	}
	if mode == "crash" {
		for {
			time.Sleep(time.Hour)
		}
	}
	token, err := restrictedToken()
	if err != nil {
		return err
	}
	defer token.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable(), "--client", mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	cmd.Env = os.Environ()
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	event, _, _ := procedures["WintunGetReadWaitEvent"].Call(session)
	var packet []byte
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var size uint32
		pointer, _, receiveErr := procedures["WintunReceivePacket"].Call(session, uintptr(unsafe.Pointer(&size)))
		if pointer == 0 {
			if receiveErr != windows.ERROR_NO_MORE_ITEMS {
				return fmt.Errorf("read test adapter: %w", receiveErr)
			}
			_, _ = windows.WaitForSingleObject(windows.Handle(event), 100)
			continue
		}
		if size < 20 || size > 65535 {
			_, _, _ = procedures["WintunReleaseReceivePacket"].Call(session, pointer)
			return errRejectedFrame
		}
		packet = make([]byte, size)
		var copied uintptr
		err = windows.ReadProcessMemory(windows.CurrentProcess(), pointer, &packet[0], uintptr(size), &copied)
		_, _, _ = procedures["WintunReleaseReceivePacket"].Call(session, pointer)
		if err != nil || copied != uintptr(size) {
			return errors.New("incomplete native packet copy")
		}
		if validPacket(packet, false) {
			break
		}
		packet = nil
	}
	if packet == nil {
		return errors.New("ordinary client packet never reached device broker")
	}
	if err = writeFrame(input, packet); err != nil {
		return err
	}
	input.Close()
	response, err := readFrame(output)
	if err != nil {
		return err
	}
	if !validPacket(response, true) || !bytes.Equal(response[28:], []byte("pong")) || !bytes.Equal(response[22:24], packet[20:22]) {
		return errRejectedFrame
	}
	pointer, _, err := procedures["WintunAllocateSendPacket"].Call(session, uintptr(len(response)))
	if pointer == 0 {
		return err
	}
	var copied uintptr
	if err = windows.WriteProcessMemory(windows.CurrentProcess(), pointer, &response[0], uintptr(len(response)), &copied); err != nil || copied != uintptr(len(response)) {
		return errors.New("incomplete native packet write")
	}
	_, _, _ = procedures["WintunSendPacket"].Call(session, pointer)
	return cmd.Wait()
}

func readFrame(input io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(input, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size < 20 || size > 65535 {
		return nil, errRejectedFrame
	}
	packet := make([]byte, size)
	_, err := io.ReadFull(input, packet)
	return packet, err
}

func writeFrame(output io.Writer, packet []byte) error {
	if err := binary.Write(output, binary.BigEndian, uint32(len(packet))); err != nil {
		return err
	}
	_, err := io.Copy(output, bytes.NewReader(packet))
	return err
}

func validPacket(packet []byte, reply bool) bool {
	if len(packet) != 32 || packet[0] != 0x45 || packet[9] != 17 || binary.BigEndian.Uint16(packet[2:4]) != 32 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || binary.BigEndian.Uint16(packet[24:26]) != 12 {
		return false
	}
	source, destination, port := []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, packet[22:24]
	if reply {
		source, destination, port = destination, source, packet[20:22]
	}
	return bytes.Equal(packet[12:16], source) && bytes.Equal(packet[16:20], destination) && binary.BigEndian.Uint16(port) == probePort
}

func client(mode string) error {
	if mode != "roundtrip" && mode != "oversized" {
		return errors.New("invalid client mode")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("packet consumer must not have an elevated token")
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: probePort})
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		return err
	}
	packet, err := readFrame(os.Stdin)
	if err != nil {
		return err
	}
	if !validPacket(packet, false) || !bytes.Equal(packet[28:], []byte("ping")) {
		return errRejectedFrame
	}
	if mode == "oversized" {
		return binary.Write(os.Stdout, binary.BigEndian, uint32(65536))
	}
	copy(packet[12:20], []byte{192, 0, 2, 2, 192, 0, 2, 1})
	packet[20], packet[22] = packet[22], packet[20]
	packet[21], packet[23] = packet[23], packet[21]
	packet[26], packet[27] = 0, 0 // IPv4 UDP permits an omitted checksum.
	copy(packet[28:], "pong")
	packet[10], packet[11] = 0, 0
	var sum uint32
	for offset := 0; offset < 20; offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[offset:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	if err = writeFrame(os.Stdout, packet); err != nil {
		return err
	}
	response := make([]byte, 32)
	size, err := conn.Read(response)
	if err != nil {
		return err
	}
	if string(response[:size]) != "pong" {
		return errors.New("device reply did not reach the original UDP socket")
	}
	fmt.Fprintln(os.Stderr, "PASS: non-elevated process consumed and returned an actual device packet")
	return nil
}
