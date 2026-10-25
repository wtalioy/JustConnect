package windowshelper

import (
	_ "embed"
	"encoding/json"
)

//go:embed contract.json
var contractJSON []byte

type helperContract struct {
	Protocol         uint32 `json:"protocol"`
	StorageVersion   uint32 `json:"storage_version"`
	Executable       string `json:"executable"`
	Service          string `json:"service"`
	InstallDirectory string `json:"install_directory"`
	StateRegistry    string `json:"state_registry"`
	MaxMessageBytes  int    `json:"max_message_bytes"`
	MaxRecordBytes   int    `json:"max_record_bytes"`
	DriverLibrary    string `json:"driver_library"`
	DriverLicense    string `json:"driver_license"`
	SDK              struct {
		Version       string `json:"version"`
		URL           string `json:"url"`
		ArchiveSHA256 string `json:"archive_sha256"`
	} `json:"sdk"`
}

var contract = func() helperContract {
	var value helperContract
	if err := json.Unmarshal(contractJSON, &value); err != nil {
		panic("invalid embedded Windows helper contract")
	}
	if value.Protocol == 0 || value.StorageVersion == 0 || value.Executable == "" || value.Service == "" || value.StateRegistry == "" || value.InstallDirectory == "" || value.MaxMessageBytes <= 0 || value.MaxRecordBytes < value.MaxMessageBytes || value.DriverLibrary == "" {
		panic("incomplete embedded Windows helper contract")
	}
	return value
}()
