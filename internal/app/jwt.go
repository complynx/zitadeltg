package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	keyID     string
	private   *rsa.PrivateKey
	jwks      json.RawMessage
	ephemeral bool
}

var errPrivateKeyExists = errors.New("private key file already exists")

const maxPrivateKeyPEMBytes = 1 << 20

func NewSigner(cfg JWTConfig) (*Signer, error) {
	var key *rsa.PrivateKey
	var err error
	switch {
	case cfg.PrivateKeyPEM != "":
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.PrivateKeyPEM))
	case cfg.PrivateKeyFile != "":
		key, err = loadOrCreateRSAPrivateKey(cfg.PrivateKeyFile)
	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA private key is %d bits; use at least 2048 bits", key.N.BitLen())
	}

	jwk, err := jwkset.NewJWKFromKey(&key.PublicKey, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			ALG: jwkset.AlgRS256,
			KID: cfg.KeyID,
			USE: jwkset.UseSig,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}
	store := jwkset.NewMemoryStorage()
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		return nil, fmt.Errorf("store JWK: %w", err)
	}
	jwks, err := store.JSONPublic(context.Background())
	if err != nil {
		return nil, fmt.Errorf("render JWKS: %w", err)
	}

	return &Signer{
		keyID:     cfg.KeyID,
		private:   key,
		jwks:      jwks,
		ephemeral: cfg.PrivateKeyPEM == "" && cfg.PrivateKeyFile == "",
	}, nil
}

func (s *Signer) Ephemeral() bool {
	return s.ephemeral
}

func (s *Signer) Sign(claims map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header[jwkset.HeaderKID] = s.keyID
	return token.SignedString(s.private)
}

func (s *Signer) JWKS() json.RawMessage {
	return append(json.RawMessage(nil), s.jwks...)
}

func loadOrCreateRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	key, err := readRSAPrivateKey(path)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA private key: %w", err)
	}
	if err := writeRSAPrivateKey(path, key); errors.Is(err, errPrivateKeyExists) {
		return waitForRSAPrivateKey(path, 2*time.Second)
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

func waitForRSAPrivateKey(path string, timeout time.Duration) (*rsa.PrivateKey, error) {
	deadline := time.Now().Add(timeout)
	for {
		key, err := readRSAPrivateKey(path)
		if err == nil {
			return key, nil
		}
		if !os.IsNotExist(err) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	file, err := openPrivateKeyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("RSA private key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("RSA private key permissions %o are too broad; use 0600", info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPrivateKeyPEMBytes {
		return nil, errors.New("RSA private key file is too large")
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

func writeRSAPrivateKey(path string, key *rsa.PrivateKey) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create private key directory: %w", err)
		}
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	file, err := os.CreateTemp(dir, ".zitadeltg-rsa-*")
	if err != nil {
		return fmt.Errorf("create temporary private key file: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary private key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary private key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary private key file: %w", err)
	}
	// Publish the completely written temporary file atomically without ever
	// replacing a key created concurrently by this service or an operator.
	if err := publishPrivateKeyNoReplace(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open private key directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync private key directory: %w", err)
	}
	return nil
}
