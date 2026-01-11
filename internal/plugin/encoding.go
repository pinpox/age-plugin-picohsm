package plugin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/plugin"
)

const (
	// PluginName is the name of this plugin.
	PluginName = "picohsm"
)

// EncodeRecipient encodes a public key as a recipient string.
func EncodeRecipient(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", errors.New("public key must be 32 bytes")
	}
	s := plugin.EncodeRecipient(PluginName, publicKey)
	if s == "" {
		return "", errors.New("failed to encode recipient")
	}
	return s, nil
}

// DecodeRecipient decodes a recipient string to a public key.
func DecodeRecipient(s string) ([]byte, error) {
	name, data, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(name, PluginName) {
		return nil, fmt.Errorf("invalid recipient plugin name: %s", name)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid recipient data length: %d", len(data))
	}
	return data, nil
}

// IdentityData holds the data encoded in an identity string.
type IdentityData struct {
	Slot     uint32
	KeyID    []byte
	KeyLabel string
}

// EncodeIdentity encodes identity data as an identity string.
func EncodeIdentity(data *IdentityData) (string, error) {
	// Format: [4 bytes slot] [1 byte keyID len] [keyID] [label]
	buf := make([]byte, 4+1+len(data.KeyID)+len(data.KeyLabel))
	binary.BigEndian.PutUint32(buf[0:4], data.Slot)
	buf[4] = byte(len(data.KeyID))
	copy(buf[5:5+len(data.KeyID)], data.KeyID)
	copy(buf[5+len(data.KeyID):], data.KeyLabel)

	s := plugin.EncodeIdentity(PluginName, buf)
	if s == "" {
		return "", errors.New("failed to encode identity")
	}
	return s, nil
}

// DecodeIdentity decodes an identity string to identity data.
func DecodeIdentity(s string) (*IdentityData, error) {
	name, data, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(name, PluginName) {
		return nil, fmt.Errorf("invalid identity plugin name: %s", name)
	}

	if len(data) < 5 {
		return nil, errors.New("identity data too short")
	}

	slot := binary.BigEndian.Uint32(data[0:4])
	keyIDLen := int(data[4])

	if len(data) < 5+keyIDLen {
		return nil, errors.New("identity data too short for key ID")
	}

	keyID := data[5 : 5+keyIDLen]
	keyLabel := string(data[5+keyIDLen:])

	return &IdentityData{
		Slot:     slot,
		KeyID:    keyID,
		KeyLabel: keyLabel,
	}, nil
}
