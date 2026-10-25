//go:build windows

package wintun

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestIPHelperLayoutMatchesNativeSDK(t *testing.T) {
	path := os.Getenv("JC_TEST_IPHELPER_LAYOUT")
	if path == "" {
		t.Skip("native SDK layout is provided by the Windows device workflow")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]map[string]uintptr
	if err = json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	var iface ipInterfaceRow
	var address windows.MibUnicastIpAddressRow
	var route windows.MibIpForwardRow2
	actual := map[string]map[string]uintptr{
		"interface": {"size": unsafe.Sizeof(iface), "TransmitOffload": unsafe.Offsetof(iface.TransmitOffload), "ReceiveOffload": unsafe.Offsetof(iface.ReceiveOffload), "DisableDefaultRoutes": unsafe.Offsetof(iface.DisableDefaultRoutes)},
		"address":   {"size": unsafe.Sizeof(address), "DadState": unsafe.Offsetof(address.DadState), "CreationTimeStamp": unsafe.Offsetof(address.CreationTimeStamp)},
		"route":     {"size": unsafe.Sizeof(route), "NextHop": unsafe.Offsetof(route.NextHop), "Metric": unsafe.Offsetof(route.Metric), "Protocol": unsafe.Offsetof(route.Protocol)},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Go IP Helper layout differs from native SDK: Go=%v SDK=%v", actual, expected)
	}
}
