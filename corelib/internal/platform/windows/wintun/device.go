//go:build windows

// Package wintun keeps native adapter and ring ownership inside the permission helper.
package wintun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/platform/ipconfig"
	"golang.org/x/sys/windows"
)

type Identity struct {
	Name  string
	GUID  windows.GUID
	LUID  uint64
	Index uint32
}

type Device struct {
	Identity
	module           windows.Handle
	adapter, session uintptr
	procedures       map[string]*windows.Proc
	ready, stop      windows.Handle
	mtu              uint32
	mu               sync.Mutex
	active           sync.WaitGroup
	read, write      sync.Mutex
	closed           bool
	once             sync.Once
}

// Create requires a verified DLL in the protected installation directory. Persist
// allocated's identity before any address or route is configured on the new adapter.
func Create(dllPath string, owner windows.GUID, source, peer netip.Addr, mtu uint32, targets []netip.Prefix, allocated func(Identity) error) (_ *Device, result error) {
	if !filepath.IsAbs(dllPath) || owner == (windows.GUID{}) || allocated == nil ||
		!ipconfig.ValidIPv4Pair(source, peer) || mtu < 68 || mtu > 65535 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	for _, target := range targets {
		if !target.IsValid() || !target.Addr().Is4() || target.Bits() < 2 || target != target.Masked() || target.Contains(source) {
			return nil, windows.ERROR_INVALID_PARAMETER
		}
	}
	module, err := windows.LoadLibraryEx(dllPath, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	d := &Device{module: module, mtu: mtu, procedures: make(map[string]*windows.Proc)}
	defer func() {
		if result != nil {
			_ = d.Close()
		}
	}()
	library := windows.DLL{Name: dllPath, Handle: module}
	for _, name := range []string{"WintunCreateAdapter", "WintunCloseAdapter", "WintunStartSession", "WintunEndSession", "WintunGetAdapterLUID", "WintunGetReadWaitEvent", "WintunReceivePacket", "WintunReleaseReceivePacket", "WintunAllocateSendPacket", "WintunSendPacket"} {
		d.procedures[name], err = library.FindProc(name)
		if err != nil {
			return nil, err
		}
	}
	d.Identity = Identity{Name: "JustConnect " + owner.String(), GUID: owner}
	var table *windows.MibIfTable2
	if err = windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		return nil, err
	}
	exists := false
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if row.InterfaceGuid == owner || windows.UTF16ToString(row.Alias[:]) == d.Name {
			exists = true
			break
		}
	}
	windows.FreeMibTable(unsafe.Pointer(table))
	if exists {
		return nil, windows.ERROR_ALREADY_EXISTS
	}
	d.adapter, _, err = d.procedures["WintunCreateAdapter"].Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(d.Name))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("JustConnect"))), uintptr(unsafe.Pointer(&owner)))
	if d.adapter == 0 {
		return nil, fmt.Errorf("create owned Wintun adapter: %w", err)
	}
	d.procedures["WintunGetAdapterLUID"].Call(d.adapter, uintptr(unsafe.Pointer(&d.LUID)))
	row := windows.MibIfRow2{InterfaceLuid: d.LUID}
	if err = windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return nil, err
	}
	if row.InterfaceGuid != owner || windows.UTF16ToString(row.Alias[:]) != d.Name {
		return nil, errors.New("new Wintun adapter identity differs")
	}
	d.Index = row.InterfaceIndex
	if err = allocated(d.Identity); err != nil {
		return nil, err
	}
	d.session, _, err = d.procedures["WintunStartSession"].Call(d.adapter, 0x20000) // Wintun's minimum ring capacity: 128 KiB.
	if d.session == 0 {
		return nil, fmt.Errorf("start owned Wintun rings: %w", err)
	}
	event, _, _ := d.procedures["WintunGetReadWaitEvent"].Call(d.session)
	d.ready = windows.Handle(event)
	d.stop, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	// Starting the rings brings the link up before address readiness is confirmed.
	if err = d.configure(source, peer, targets); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Device) begin() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	d.active.Add(1)
	return nil
}

func (d *Device) Read(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, io.ErrShortBuffer
	}
	d.read.Lock()
	defer d.read.Unlock()
	if err := d.begin(); err != nil {
		return 0, err
	}
	defer d.active.Done()
	for {
		if state, err := windows.WaitForSingleObject(d.stop, 0); err != nil || state == windows.WAIT_OBJECT_0 {
			return 0, io.ErrClosedPipe
		}
		var size uint32
		pointer, _, err := d.procedures["WintunReceivePacket"].Call(d.session, uintptr(unsafe.Pointer(&size)))
		if pointer == 0 {
			if err != windows.ERROR_NO_MORE_ITEMS {
				return 0, err
			}
			state, err := windows.WaitForMultipleObjects([]windows.Handle{d.stop, d.ready}, false, windows.INFINITE)
			if err != nil {
				return 0, err
			}
			if state == windows.WAIT_OBJECT_0 {
				return 0, io.ErrClosedPipe
			}
			continue
		}
		if size == 0 || size > 65535 {
			d.procedures["WintunReleaseReceivePacket"].Call(d.session, pointer)
			return 0, windows.ERROR_INVALID_DATA
		}
		buffer := packet[:min(int(size), len(packet))]
		var copied uintptr
		err = windows.ReadProcessMemory(windows.CurrentProcess(), pointer, &buffer[0], uintptr(len(buffer)), &copied)
		d.procedures["WintunReleaseReceivePacket"].Call(d.session, pointer)
		if err != nil {
			return 0, err
		}
		if copied != uintptr(len(buffer)) {
			return 0, io.ErrUnexpectedEOF
		}
		// The owned adapter may still emit IPv6 discovery; V1 captures IPv4 only.
		if packet[0]>>4 == 6 {
			continue
		}
		if size < 20 || size > d.mtu || uint64(size) > uint64(len(packet)) || packet[0]>>4 != 4 {
			return 0, windows.ERROR_INVALID_DATA
		}
		return int(size), nil
	}
}

func (d *Device) Write(packet []byte) (int, error) {
	if len(packet) < 20 || uint64(len(packet)) > uint64(d.mtu) || packet[0]>>4 != 4 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return 0, windows.ERROR_INVALID_DATA
	}
	d.write.Lock()
	defer d.write.Unlock()
	if err := d.begin(); err != nil {
		return 0, err
	}
	defer d.active.Done()
	var pointer uintptr
	var err error
	for {
		pointer, _, err = d.procedures["WintunAllocateSendPacket"].Call(d.session, uintptr(len(packet)))
		if pointer != 0 {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return 0, err
		}
		// Wintun exposes no write-ready event; wait briefly without blocking close.
		state, waitErr := windows.WaitForSingleObject(d.stop, 1)
		if waitErr != nil {
			return 0, waitErr
		}
		if state == windows.WAIT_OBJECT_0 {
			return 0, io.ErrClosedPipe
		}
	}
	// An allocated ring packet must always be released with SendPacket, including a failed copy.
	var copied uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), pointer, &packet[0], uintptr(len(packet)), &copied)
	d.procedures["WintunSendPacket"].Call(d.session, pointer)
	if err != nil {
		return 0, err
	}
	if copied != uintptr(len(packet)) {
		return 0, io.ErrShortWrite
	}
	return len(packet), nil
}

func (d *Device) Close() error {
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		if d.stop != 0 {
			_ = windows.SetEvent(d.stop)
		}
		d.mu.Unlock()
		d.active.Wait()
		if d.session != 0 {
			d.procedures["WintunEndSession"].Call(d.session)
		}
		if d.adapter != 0 {
			d.procedures["WintunCloseAdapter"].Call(d.adapter)
		}
		if d.stop != 0 {
			_ = windows.CloseHandle(d.stop)
		}
		if d.module != 0 {
			_ = windows.FreeLibrary(d.module)
		}
	})
	return nil
}
