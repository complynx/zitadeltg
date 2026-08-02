//go:build !linux && !windows

package app

import (
	"errors"
	"fmt"
	"os"
)

func openPrivateKeyNoFollow(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("RSA private key must not be a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	after, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(after, opened) {
		_ = file.Close()
		return nil, errors.New("RSA private key changed while it was opened")
	}
	return file, nil
}

func publishPrivateKeyNoReplace(temporaryPath string, path string) error {
	if err := os.Link(temporaryPath, path); err != nil {
		if os.IsExist(err) {
			return errPrivateKeyExists
		}
		return fmt.Errorf("atomic hard-link private key: %w", err)
	}
	return nil
}
