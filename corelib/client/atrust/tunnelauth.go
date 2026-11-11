package atrust

import (
	"crypto/sha256"
	"fmt"
)

type trustProcess struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

type trustEnv struct {
	Application struct {
		Runtime struct {
			Process        trustProcess `json:"process"`
			ProcessTrusted string       `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

func newTrustEnv(name, path, platform string) trustEnv {
	const closed = "TrustAppClosed"
	var env trustEnv
	env.Application.Runtime.Process = trustProcess{
		Name:             name,
		DigitalSignature: closed,
		Platform:         platform,
		Fingerprint:      fmt.Sprintf("%X", sha256.Sum256([]byte(path))),
		Description:      closed,
		Path:             path,
		Version:          closed,
		SecurityEnv:      "normal",
	}
	env.Application.Runtime.ProcessTrusted = "TRUSTED"
	return env
}
