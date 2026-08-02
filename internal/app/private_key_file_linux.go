//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openPrivateKeyNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, errors.New("RSA private key must not be a symlink")
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func publishPrivateKeyNoReplace(temporaryPath string, path string) error {
	err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		return errPrivateKeyExists
	}

	// Mounted filesystems that do not implement renameat2 flags may still
	// support hard links, which are also atomic and cannot replace a file.
	if linkErr := os.Link(temporaryPath, path); linkErr == nil {
		return nil
	} else if os.IsExist(linkErr) {
		return errPrivateKeyExists
	} else {
		return errors.Join(
			fmt.Errorf("atomic no-replace rename private key: %w", err),
			fmt.Errorf("atomic hard-link private key: %w", linkErr),
		)
	}
}
