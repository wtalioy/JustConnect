package windowshelper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPublisherRefusesUnconfiguredAndUnsigned(t *testing.T) {
	if err := verifyPublisher("", 0, [sha256.Size]byte{}); !errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		t.Fatal("missing publisher identity was accepted", err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(file)
	expected := sha256.Sum256([]byte("unrelated test publisher"))
	if err := verifyPublisher(path, file, expected); err == nil {
		t.Fatal("unsigned test host passed the publisher boundary")
	}
}

func TestPublisherMatchesVerifiedLeaf(t *testing.T) {
	path := os.Getenv("JC_TEST_SIGNED_FIXTURE")
	if path == "" {
		t.Skip("signed fixture and independently verified certificate are provided by native validation")
	}
	encoded, err := hex.DecodeString(os.Getenv("JC_TEST_PUBLISHER_SHA256"))
	if err != nil || len(encoded) != sha256.Size {
		t.Fatal("signed fixture has no verified certificate fingerprint")
	}
	var expected [sha256.Size]byte
	copy(expected[:], encoded)
	file, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(file)
	if err = verifyPublisher(path, file, expected); err != nil {
		t.Fatal("verified signer refused", err)
	}
	expected[0] ^= 1
	if err = verifyPublisher(path, file, expected); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("different signer was not refused", err)
	}
}
