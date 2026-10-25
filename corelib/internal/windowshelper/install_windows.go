package windowshelper

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Set only by the signed helper build, never by request parameters or environment.
var publisherSHA256, driverSHA256, licenseSHA256 string

const fileDeleteChild = 0x0040 // SDK FILE_DELETE_CHILD; x/sys does not export it.

func installationAttributes() (windows.SecurityAttributes, error) {
	security, err := windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if err != nil {
		return windows.SecurityAttributes{}, err
	}
	return windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}, nil
}

type Installation struct {
	Image, Driver string
	directories   []windows.Handle
}

func (i *Installation) Close() {
	for index := len(i.directories) - 1; index >= 0; index-- {
		_ = windows.CloseHandle(i.directories[index])
	}
	i.directories = nil
}

func decodedHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != len(result) {
		return result, windows.ERROR_NOT_SUPPORTED
	}
	copy(result[:], data)
	return result, nil
}

func trustedOwner(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	return err == nil && windows.EqualSid(sid, installer)
}

func immutableObject(handle windows.Handle, allowNewChildren bool) error {
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := security.Owner()
	if err != nil || !trustedOwner(owner) {
		return windows.ERROR_ACCESS_DENIED
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil {
		return windows.ERROR_ACCESS_DENIED
	}
	forbidden := uint32(windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | fileDeleteChild | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.GENERIC_ALL | windows.GENERIC_WRITE)
	if !allowNewChildren {
		forbidden |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if ok, _, err := getACE.Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&ace))); ok == 0 {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return windows.ERROR_ACCESS_DENIED
		}
		if uint32(ace.Mask)&forbidden != 0 && !trustedOwner((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return windows.ERROR_ACCESS_DENIED
		}
	}
	return nil
}

func (i *Installation) pinDirectory(path string, create, allowNewChildren bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if create {
		attributes, err := installationAttributes()
		if err != nil {
			return err
		}
		if err = windows.CreateDirectory(name, &attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return err
		}
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	var information windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &information); err == nil && (information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) {
		err = windows.ERROR_ACCESS_DENIED
	}
	if err == nil {
		err = immutableObject(handle, allowNewChildren)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return err
	}
	i.directories = append(i.directories, handle)
	return nil
}

func pinnedSource(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, err
	}
	var information windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &information); err == nil && (information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || information.FileSizeHigh != 0 || information.FileSizeLow == 0 || information.FileSizeLow > 64<<20) {
		err = windows.ERROR_INVALID_DATA
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func imageHash(file *os.File) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func installFile(source *os.File, path string, expected [sha256.Size]byte) error {
	if existing, err := pinnedSource(path); err == nil {
		defer existing.Close()
		if err := immutableObject(windows.Handle(existing.Fd()), false); err != nil {
			return err
		}
		actual, err := imageHash(existing)
		if err != nil {
			return err
		}
		if actual != expected {
			return windows.ERROR_INVALID_DATA
		}
		return nil
	} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	owner, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	temporary := path + "." + owner.String() + ".tmp"
	name := windows.StringToUTF16Ptr(temporary)
	attributes, err := installationAttributes()
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(handle), temporary)
	defer func() { _ = output.Close(); _ = windows.DeleteFile(name) }()
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(output, source); err != nil {
		return err
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := windows.MoveFileEx(name, windows.StringToUTF16Ptr(path), windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return err
		}
		return installFile(source, path, expected)
	}
	return nil
}

// PrepareInstallation copies only the signed build's own verified payloads into immutable versioned storage.
func PrepareInstallation() (_ *Installation, result error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	publisher, err := decodedHash(publisherSHA256)
	if err != nil {
		return nil, err
	}
	driverHash, err := decodedHash(driverSHA256)
	if err != nil {
		return nil, err
	}
	licenseHash, err := decodedHash(licenseSHA256)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	image, err := pinnedSource(self)
	if err != nil {
		return nil, err
	}
	defer image.Close()
	if err := verifyPublisher(self, windows.Handle(image.Fd()), publisher); err != nil {
		return nil, err
	}
	running, ok := debug.ReadBuildInfo()
	stored, err := buildinfo.Read(image)
	if !ok || err != nil || running.String() != stored.String() {
		return nil, windows.ERROR_INVALID_DATA
	}
	identity, err := imageHash(image)
	if err != nil {
		return nil, err
	}
	driver, err := pinnedSource(filepath.Join(filepath.Dir(self), contract.DriverLibrary))
	if err != nil {
		return nil, err
	}
	defer driver.Close()
	actual, err := imageHash(driver)
	if err != nil {
		return nil, err
	}
	if actual != driverHash {
		return nil, windows.ERROR_INVALID_DATA
	}
	license, err := pinnedSource(filepath.Join(filepath.Dir(self), contract.DriverLicense))
	if err != nil {
		return nil, err
	}
	defer license.Close()
	actual, err = imageHash(license)
	if err != nil {
		return nil, err
	}
	if actual != licenseHash {
		return nil, windows.ERROR_INVALID_DATA
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return nil, err
	}
	base = filepath.Clean(base)
	if !filepath.IsAbs(base) || strings.HasPrefix(base, `\\`) {
		return nil, windows.ERROR_NOT_SUPPORTED
	}
	installation := &Installation{}
	defer func() {
		if result != nil {
			installation.Close()
		}
	}()
	path := filepath.VolumeName(base) + string(os.PathSeparator)
	if err := installation.pinDirectory(path, false, true); err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(base, path), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		path = filepath.Join(path, part)
		if err := installation.pinDirectory(path, false, true); err != nil {
			return nil, err
		}
	}
	path = filepath.Join(base, contract.InstallDirectory)
	if err := installation.pinDirectory(path, true, false); err != nil {
		return nil, err
	}
	path = filepath.Join(path, hex.EncodeToString(identity[:]))
	if err := installation.pinDirectory(path, true, false); err != nil {
		return nil, err
	}
	installation.Image, installation.Driver = filepath.Join(path, contract.Executable), filepath.Join(path, contract.DriverLibrary)
	if err := installFile(image, installation.Image, identity); err != nil {
		return nil, err
	}
	if err := installFile(driver, installation.Driver, driverHash); err != nil {
		return nil, err
	}
	if err := installFile(license, filepath.Join(path, contract.DriverLicense), licenseHash); err != nil {
		return nil, err
	}
	return installation, nil
}
