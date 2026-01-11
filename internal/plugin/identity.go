package plugin

import (
	"encoding/base64"
	"errors"
	"fmt"

	"filippo.io/age"
	"github.com/pinpox/age-plugin-picohsm/internal/hsm"
)

// Identity implements age.Identity for Pico HSM P-256 keys.
// Decryption requires the HSM to perform the ECDH operation.
type Identity struct {
	HSM       *hsm.HSM
	Key       *hsm.Key
	PublicKey []byte // 65-byte uncompressed P-256 public key (for matching stanzas)
}

// NewIdentity creates a new Identity from an HSM key.
func NewIdentity(h *hsm.HSM, key *hsm.Key) (*Identity, error) {
	if len(key.PublicKey) != 65 {
		return nil, fmt.Errorf("invalid public key length: %d (expected 65)", len(key.PublicKey))
	}
	return &Identity{
		HSM:       h,
		Key:       key,
		PublicKey: key.PublicKey,
	}, nil
}

// Unwrap implements age.Identity. It unwraps file keys from matching stanzas.
func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, stanza := range stanzas {
		if stanza.Type != "picohsm" {
			continue
		}

		fileKey, err := i.unwrapStanza(stanza)
		if err != nil {
			// Try next stanza
			continue
		}
		return fileKey, nil
	}

	return nil, age.ErrIncorrectIdentity
}

// unwrapStanza attempts to unwrap a single stanza.
func (i *Identity) unwrapStanza(stanza *age.Stanza) ([]byte, error) {
	if len(stanza.Args) != 1 {
		return nil, errors.New("invalid stanza: expected 1 argument")
	}

	// Decode ephemeral public key from stanza args
	ephemeralPublic, err := base64.RawStdEncoding.DecodeString(stanza.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	if len(ephemeralPublic) != 65 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPublic))
	}

	// Use HSM to derive shared secret: ECDH(hsm_private, ephemeral_public)
	sharedSecret, err := i.HSM.DeriveSharedSecret(i.Key.Handle, ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive unwrap key using HKDF
	// Salt = ephemeral_public || recipient_public (our public key)
	salt := make([]byte, 130)
	copy(salt[:65], ephemeralPublic)
	copy(salt[65:], i.PublicKey)

	unwrapKey, err := hkdfSHA256(sharedSecret, salt, []byte(p256Label), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive unwrap key: %w", err)
	}

	// Unwrap file key with ChaCha20-Poly1305
	fileKey, err := aeadDecrypt(unwrapKey, stanza.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap file key: %w", err)
	}

	return fileKey, nil
}
