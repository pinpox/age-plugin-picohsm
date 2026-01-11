// Package plugin implements age plugin recipient and identity types for Pico HSM.
package plugin

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// rand returns the crypto/rand.Reader for generating random bytes.
func randReader() io.Reader {
	return rand.Reader
}

const (
	// p256Label is the HKDF info label for P-256 ECDH.
	p256Label = "age-encryption.org/v1/picohsm-p256"

	// fileKeySize is the size of an age file key.
	fileKeySize = 16
)

// Recipient implements age.Recipient for Pico HSM P-256 keys.
// Encryption does not require the hardware - only the public key.
type Recipient struct {
	PublicKey []byte // 65-byte uncompressed P-256 public key (04 || X || Y)
}

// NewRecipient creates a new Recipient from a 65-byte uncompressed P-256 public key.
func NewRecipient(publicKey []byte) (*Recipient, error) {
	if len(publicKey) != 65 {
		return nil, fmt.Errorf("invalid public key length: %d (expected 65)", len(publicKey))
	}
	if publicKey[0] != 0x04 {
		return nil, errors.New("public key must be uncompressed (start with 0x04)")
	}
	return &Recipient{PublicKey: publicKey}, nil
}

// Wrap implements age.Recipient. It wraps a file key for this recipient.
// This operation does not require the HSM - it only uses the public key.
func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if len(fileKey) != fileKeySize {
		return nil, fmt.Errorf("invalid file key size: %d", len(fileKey))
	}

	// Parse recipient's P-256 public key
	p256 := ecdh.P256()
	recipientPub, err := p256.NewPublicKey(r.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipient public key: %w", err)
	}

	// Generate ephemeral P-256 keypair
	ephemeralPriv, err := p256.GenerateKey(randReader())
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	// Compute shared secret: ECDH(ephemeral_secret, recipient_public)
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive wrap key using HKDF
	// Salt = ephemeral_public || recipient_public
	salt := make([]byte, 130)
	copy(salt[:65], ephemeralPub)
	copy(salt[65:], r.PublicKey)

	wrapKey, err := hkdfSHA256(sharedSecret, salt, []byte(p256Label), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrap key: %w", err)
	}

	// Wrap file key with ChaCha20-Poly1305
	wrappedKey, err := aeadEncrypt(wrapKey, fileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap file key: %w", err)
	}

	// Compute recipient fingerprint (first 8 bytes of SHA-256 of public key)
	recipientFP := sha256.Sum256(r.PublicKey)

	// Create stanza with ephemeral public key and recipient fingerprint as arguments
	stanza := &age.Stanza{
		Type: "picohsm",
		Args: []string{
			base64.RawStdEncoding.EncodeToString(ephemeralPub),
			base64.RawStdEncoding.EncodeToString(recipientFP[:8]),
		},
		Body: wrappedKey,
	}

	return []*age.Stanza{stanza}, nil
}

// hkdfSHA256 derives a key using HKDF-SHA256.
func hkdfSHA256(secret, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// aeadEncrypt encrypts plaintext with ChaCha20-Poly1305 using a zero nonce.
// This is safe because each key is only used once (derived from fresh randomness).
func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// aeadDecrypt decrypts ciphertext with ChaCha20-Poly1305 using a zero nonce.
func aeadDecrypt(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	expectedSize := fileKeySize + aead.Overhead()
	if len(ciphertext) != expectedSize {
		return nil, errors.New("invalid ciphertext size")
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}
