//go:build windows && jc_wintun_probe

// This disposable-runner probe owns a fresh adapter; it never loads the VPN core.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const probePort = 43877

type brokerDevice struct {
	Name       string
	Index      uint32
	LUID       uint64
	InstanceID string
}

type brokerNotice struct {
	Stage  string
	Device brokerDevice
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
	benchmark := len(os.Args) == 3 && os.Args[1] == "--benchmark"
	if len(os.Args) != 2 && !benchmark {
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
	if benchmark {
		return runBroker(os.Args[2], "benchmark")
	}
	for _, mode := range []string{"connected", "roundtrip", "oversized", "crash", "setup-failure"} {
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

func adapterLUID(name string) (uint64, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		return 0, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if windows.UTF16ToString(row.Alias[:]) == name {
			return row.InterfaceLuid, nil
		}
	}
	return 0, windows.ERROR_NOT_FOUND
}

func adapterPresent(name string) (bool, error) {
	_, err := adapterLUID(name)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	return err == nil, err
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

func deviceInstanceID(luid uint64) (string, error) {
	row := windows.MibIfRow2{InterfaceLuid: luid}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return "", err
	}
	class, err := windows.GUIDFromString("{4d36e972-e325-11ce-bfc1-08002be10318}")
	if err != nil {
		return "", err
	}
	devices, err := windows.SetupDiGetClassDevsEx(&class, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return "", err
	}
	defer devices.Close()
	for i := 0; ; i++ {
		device, err := devices.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return "", windows.ERROR_NOT_FOUND
		}
		if err != nil {
			return "", err
		}
		handle, err := devices.OpenDevRegKey(device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err != nil {
			continue
		}
		key := registry.Key(handle)
		value, _, readErr := key.GetStringValue("NetCfgInstanceId")
		key.Close()
		if readErr != nil {
			continue
		}
		guid, err := windows.GUIDFromString(value)
		if err == nil && guid == row.InterfaceGuid {
			return devices.DeviceInstanceID(device)
		}
	}
}

func devicePresent(instanceID string) (bool, error) {
	id, err := windows.UTF16PtrFromString(instanceID)
	if err != nil || instanceID == "" {
		return false, errors.New("invalid test device identity")
	}
	var node windows.DEVINST
	locate := windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Locate_DevNodeW")
	status, _, _ := locate.Call(uintptr(unsafe.Pointer(&node)), uintptr(unsafe.Pointer(id)), 0)
	if windows.CONFIGRET(status) == windows.CR_NO_SUCH_DEVNODE {
		return false, nil
	}
	if windows.CONFIGRET(status) != windows.CR_SUCCESS {
		return false, fmt.Errorf("locate original test device: status %d", status)
	}
	return true, nil
}

func confirmDevice(input io.Reader, name string, owned *brokerDevice) error {
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(input, 4096)))
	var allocated brokerNotice
	if err := decoder.Decode(&allocated); err != nil {
		return err
	}
	device := allocated.Device
	if allocated.Stage != "allocated" || device.Name != name || device.Index == 0 || device.LUID == 0 ||
		!strings.HasPrefix(strings.ToUpper(device.InstanceID), "SWD\\WINTUN\\") {
		return errors.New("broker did not confirm its newly allocated device")
	}
	*owned = device
	var configured brokerNotice
	if err := decoder.Decode(&configured); err != nil {
		return err
	}
	if configured.Stage != "configured" || configured.Device != device {
		return errors.New("broker configuration changed device ownership")
	}
	return nil
}

func runBroker(dll, mode string) (result error) {
	fmt.Fprintln(os.Stderr, "START: device case", mode)
	owner, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	name := "JustConnect " + owner.String()
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
	native := os.Getenv("JC_TEST_CPP_WINTUN_BROKER")
	if native == "" {
		return errors.New("native C++ device broker is required by the device validation producer")
	}
	cmd := exec.CommandContext(ctx, native, "--broker", dll, name, mode, executable())
	cmd.Env = append(os.Environ(), "JC_TEST_WINTUN_BENCHMARK_BACKEND=cpp")
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
		if ready.InstanceID != "" {
			remaining, lookupErr = devicePresent(ready.InstanceID)
		} else if ready.LUID != 0 {
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
		deviceID := ready.InstanceID
		if deviceID == "" {
			luid, lookupErr := adapterLUID(name)
			if lookupErr != nil {
				result = errors.Join(result, lookupErr)
				return
			}
			deviceID, lookupErr = deviceInstanceID(luid)
			if lookupErr != nil {
				result = errors.Join(result, lookupErr)
				return
			}
		}
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
	confirmation := confirmDevice(output, name, &ready)
	if mode == "setup-failure" {
		if confirmation == nil || ready.InstanceID == "" {
			return errors.New("controlled setup failure did not retain original ownership")
		}
	} else if confirmation != nil {
		return fmt.Errorf("broker did not confirm its configuration: %w", confirmation)
	}
	if mode == "crash" {
		if err = cmd.Process.Kill(); err != nil {
			return err
		}
	}
	err = cmd.Wait()
	if mode == "setup-failure" {
		var failure *exec.ExitError
		if !errors.As(err, &failure) || failure.ExitCode() != 24 {
			return fmt.Errorf("unexpected device setup failure: %w", err)
		}
	} else if mode == "oversized" {
		var failure *exec.ExitError
		if !errors.As(err, &failure) || failure.ExitCode() != 23 {
			return fmt.Errorf("invalid frame was not rejected: %w", err)
		}
	} else if mode != "crash" && err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		present, err = devicePresent(ready.InstanceID)
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
	if mode != "roundtrip" && mode != "oversized" && mode != "benchmark" {
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
	budget, err := packetBudget(mode)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(budget))
	count, err := benchmarkCount(mode)
	if err != nil {
		return err
	}
	latencies := make([]float64, 0, count)
	frequency := int64(0)
	if mode == "benchmark" {
		if ok, _, callErr := queryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&frequency))); ok == 0 || frequency <= 0 {
			return fmt.Errorf("read performance counter frequency: %w", callErr)
		}
	}
	for iteration := range count {
		var started int64
		if mode == "benchmark" {
			if ok, _, callErr := queryPerformanceCounter.Call(uintptr(unsafe.Pointer(&started))); ok == 0 {
				return callErr
			}
		}
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
			return fmt.Errorf("ordinary UDP reply %d/%d: %w", iteration+1, count, err)
		}
		if string(response[:size]) != "pong" {
			return errors.New("device reply did not reach the original UDP socket")
		}
		if mode == "benchmark" {
			var finished int64
			if ok, _, callErr := queryPerformanceCounter.Call(uintptr(unsafe.Pointer(&finished))); ok == 0 {
				return callErr
			}
			latencies = append(latencies, float64(finished-started)*1e6/float64(frequency))
		}
	}
	if mode == "benchmark" {
		sort.Float64s(latencies)
		if err := json.NewEncoder(os.Stderr).Encode(map[string]any{"benchmark": "client", "backend": os.Getenv("JC_TEST_WINTUN_BENCHMARK_BACKEND"), "round_trips": count,
			"p50_us": latencies[count/2], "p95_us": latencies[(count-1)*95/100], "p99_us": latencies[(count-1)*99/100]}); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "PASS: non-elevated process consumed and returned an actual device packet")
	return nil
}

var queryPerformanceCounter = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
var queryPerformanceFrequency = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")

func benchmarkCount(mode string) (int, error) {
	if mode != "benchmark" {
		return 1, nil
	}
	count, err := strconv.Atoi(os.Getenv("JC_TEST_WINTUN_BENCHMARK_PACKETS"))
	if err != nil || count < 1 || count > 65536 {
		return 0, errors.New("invalid native benchmark packet count")
	}
	return count, nil
}

func packetBudget(mode string) (time.Duration, error) {
	if mode != "benchmark" {
		return 8 * time.Second, nil
	}
	milliseconds, err := strconv.Atoi(os.Getenv("JC_TEST_WINTUN_BENCHMARK_TIMEOUT_MS"))
	if err != nil || milliseconds < 1 || milliseconds > 30000 {
		return 0, errors.New("invalid native benchmark timeout")
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}
