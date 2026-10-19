package keylog

import (
	"io"

	"github.com/wtalioy/JustConnect/corelib/internal/privatefile"
)

func Open(path string) (io.WriteCloser, error) {
	if path == "" {
		return nil, nil
	}
	return privatefile.Open(path)
}
