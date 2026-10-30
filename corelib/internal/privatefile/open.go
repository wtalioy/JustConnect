// Package privatefile creates files accessible only to the current user; native SSH fixtures use it for disposable keys.
package privatefile

import "os"

func Open(path string) (*os.File, error) {
	file, err := open(path)
	if err != nil {
		return nil, &os.PathError{Op: "open private file", Path: path, Err: err}
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
