//go:build windows

package app

import (
	"errors"
	"os"
)

var errWindowsKeyPersistenceUnsupported = errors.New("Windows key persistence is not supported; run zitadeltg on Linux")

func openPrivateKeyNoFollow(string) (*os.File, error) {
	return nil, errWindowsKeyPersistenceUnsupported
}

func publishPrivateKeyNoReplace(string, string) error {
	return errWindowsKeyPersistenceUnsupported
}
