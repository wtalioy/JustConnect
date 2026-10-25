package windowshelper

import (
	"crypto/sha256"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wintrust = windows.NewLazySystemDLL("wintrust.dll")
var providerFromState = wintrust.NewProc("WTHelperProvDataFromStateData")
var signerFromProvider = wintrust.NewProc("WTHelperGetProvSignerFromChain")
var certificateFromSigner = wintrust.NewProc("WTHelperGetProvCertFromChain")

// Only the documented prefix is read; the provider owns the full CRYPT_PROVIDER_CERT.
type providerCertificate struct {
	Size        uint32
	Certificate *windows.CertContext
}

func verifyPublisher(path string, handle windows.Handle, expected [sha256.Size]byte) error {
	if expected == ([sha256.Size]byte{}) {
		return windows.ERROR_NOT_SUPPORTED
	}
	if handle == 0 || handle == windows.InvalidHandle {
		return windows.ERROR_INVALID_HANDLE
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name, File: handle}
	data := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
	}
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	}()
	if err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data); err != nil {
		return err
	}
	provider, _, _ := providerFromState.Call(uintptr(data.StateData))
	if provider == 0 {
		return windows.ERROR_INVALID_DATA
	}
	signer, _, _ := signerFromProvider.Call(provider, 0, 0, 0)
	if signer == 0 {
		return windows.ERROR_INVALID_DATA
	}
	certificate, _, _ := certificateFromSigner.Call(signer, 0)
	if certificate == 0 {
		return windows.ERROR_INVALID_DATA
	}
	// Copy the provider prefix through the native API, avoiding unchecked uintptr dereferences.
	var value providerCertificate
	var copied uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), certificate, (*byte)(unsafe.Pointer(&value)), unsafe.Sizeof(value), &copied); err != nil {
		return err
	}
	if copied != unsafe.Sizeof(value) || uintptr(value.Size) < unsafe.Sizeof(value) || value.Certificate == nil {
		return windows.ERROR_INVALID_DATA
	}
	context := value.Certificate
	if context.Length == 0 || context.Length > 65536 || context.EncodedCert == nil {
		return windows.ERROR_INVALID_DATA
	}
	actual := sha256.Sum256(unsafe.Slice(context.EncodedCert, int(context.Length)))
	if actual != expected {
		return windows.ERROR_ACCESS_DENIED
	}
	return nil
}
