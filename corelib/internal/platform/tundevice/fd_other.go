//go:build !linux && !darwin

package tundevice

import (
	"errors"
	"os"
)

const Supported = false

func Duplicate(int, uint32) (*os.File, error) {
	return nil, errors.New("raw TUN fd attachment is unsupported on this platform")
}
