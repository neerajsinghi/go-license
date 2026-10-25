package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	pemPrivateType = "PRIVATE KEY"
	pemPublicType  = "PUBLIC KEY"
)

// GenerateKey creates a new Ed25519 key pair. If r is nil, crypto/rand is
// used.
func GenerateKey(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("license: generate key: %w", err)
	}
	return pub, priv, nil
}

// MarshalPrivateKey encodes priv as a PKCS#8 PEM block.
func MarshalPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key is %d bytes", ErrInvalidKey, len(priv))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateType, Bytes: der}), nil
}

// MarshalPublicKey encodes pub as a PKIX ("SubjectPublicKeyInfo") PEM block.
func MarshalPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes", ErrInvalidKey, len(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublicType, Bytes: der}), nil
}

// ParsePrivateKey decodes a PKCS#8 PEM-encoded Ed25519 private key.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPrivateType {
		return nil, fmt.Errorf("%w: no %q PEM block found", ErrInvalidKey, pemPrivateType)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an Ed25519 key (%T)", ErrInvalidKey, k)
	}
	return priv, nil
}

// ParsePublicKey decodes a PKIX PEM-encoded Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPublicType {
		return nil, fmt.Errorf("%w: no %q PEM block found", ErrInvalidKey, pemPublicType)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an Ed25519 key (%T)", ErrInvalidKey, k)
	}
	return pub, nil
}
