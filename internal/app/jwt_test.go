package app

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignerCreatesPersistentPrivateKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "zitadeltg-rsa.pem")

	first, err := NewSigner(JWTConfig{
		KeyID:          "test-key",
		PrivateKeyFile: keyPath,
	})
	require.NoError(t, err)
	require.False(t, first.Ephemeral())

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	second, err := NewSigner(JWTConfig{
		KeyID:          "test-key",
		PrivateKeyFile: keyPath,
	})
	require.NoError(t, err)
	assert.Equal(t, first.JWKS(), second.JWKS())
}

func TestSignerJWKSReturnsCopy(t *testing.T) {
	signer, err := NewSigner(JWTConfig{KeyID: "test-key"})
	require.NoError(t, err)
	first := signer.JWKS()
	require.NotEmpty(t, first)
	first[0] = 'x'
	assert.NotEqual(t, first, signer.JWKS())
}

func TestNewSignerRejectsBroadPrivateKeyPermissions(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "zitadeltg-rsa.pem")
	_, err := NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: keyPath})
	require.NoError(t, err)
	require.NoError(t, os.Chmod(keyPath, 0o644))

	_, err = NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: keyPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permissions")
}

func TestNewSignerRejectsOversizedPrivateKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oversized.pem")
	require.NoError(t, os.WriteFile(keyPath, make([]byte, maxPrivateKeyPEMBytes+1), 0o600))
	_, err := NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: keyPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestNewSignerRejectsSymlinkedPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	_, err := NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: keyPath})
	require.NoError(t, err)
	linkPath := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(keyPath, linkPath))

	_, err = NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: linkPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
}

func TestNewSignerConcurrentCreationUsesOneCompleteKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "zitadeltg-rsa.pem")
	start := make(chan struct{})
	signers := make([]*Signer, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			signers[i], errs[i] = NewSigner(JWTConfig{KeyID: "test-key", PrivateKeyFile: keyPath})
		}()
	}
	close(start)
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.Equal(t, signers[0].JWKS(), signers[1].JWKS())
}

func TestPrivateKeyPublicationNeverReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	temporaryPath := filepath.Join(dir, "temporary-key")
	targetPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(temporaryPath, []byte("new key"), 0o600))
	require.NoError(t, os.WriteFile(targetPath, []byte("existing key"), 0o600))

	err := publishPrivateKeyNoReplace(temporaryPath, targetPath)
	require.ErrorIs(t, err, errPrivateKeyExists)
	data, readErr := os.ReadFile(targetPath)
	require.NoError(t, readErr)
	assert.Equal(t, "existing key", string(data))
}
