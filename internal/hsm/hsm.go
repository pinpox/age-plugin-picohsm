// Package hsm provides communication with Pico HSM via PKCS#11.
package hsm

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// X25519 curve OID per RFC 8410
var oidX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}

// PKCS#11 constants not defined in miekg/pkcs11
const (
	CKK_EC_MONTGOMERY             = 0x00000041
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN = 0x00001055
)

// HSM represents a connection to a Pico HSM device.
type HSM struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	slot    uint
	module  string
}

// Key represents an X25519 key on the HSM.
type Key struct {
	Handle    pkcs11.ObjectHandle
	Label     string
	ID        []byte
	PublicKey []byte // 32-byte X25519 public key
}

// DefaultModulePaths contains common paths for the OpenSC PKCS#11 module.
var DefaultModulePaths = []string{
	"/usr/lib/opensc-pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/opt/homebrew/lib/opensc-pkcs11.so",
	"/usr/local/opt/opensc/lib/opensc-pkcs11.so",
}

// New creates a new HSM instance.
func New() *HSM {
	return &HSM{}
}

// Open connects to the HSM using the specified PKCS#11 module path.
// If modulePath is empty, it tries the default paths.
func (h *HSM) Open(modulePath string) error {
	paths := []string{modulePath}
	if modulePath == "" {
		paths = DefaultModulePaths
	}

	var lastErr error
	for _, path := range paths {
		if path == "" {
			continue
		}
		ctx := pkcs11.New(path)
		if ctx == nil {
			lastErr = fmt.Errorf("failed to load PKCS#11 module: %s", path)
			continue
		}

		if err := ctx.Initialize(); err != nil {
			ctx.Destroy()
			lastErr = fmt.Errorf("failed to initialize PKCS#11: %w", err)
			continue
		}

		// Find a slot with a token present
		slots, err := ctx.GetSlotList(true)
		if err != nil {
			ctx.Finalize()
			ctx.Destroy()
			lastErr = fmt.Errorf("failed to get slot list: %w", err)
			continue
		}

		if len(slots) == 0 {
			ctx.Finalize()
			ctx.Destroy()
			lastErr = errors.New("no tokens found")
			continue
		}

		// Use the first slot with a token
		slot := slots[0]

		// Open a session
		session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			ctx.Finalize()
			ctx.Destroy()
			lastErr = fmt.Errorf("failed to open session: %w", err)
			continue
		}

		h.ctx = ctx
		h.session = session
		h.slot = slot
		h.module = path
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("no PKCS#11 module found")
}

// Login authenticates to the HSM with the given PIN.
func (h *HSM) Login(pin string) error {
	if h.ctx == nil {
		return errors.New("HSM not opened")
	}
	return h.ctx.Login(h.session, pkcs11.CKU_USER, pin)
}

// Logout logs out from the HSM.
func (h *HSM) Logout() error {
	if h.ctx == nil {
		return nil
	}
	return h.ctx.Logout(h.session)
}

// Close closes the HSM connection.
func (h *HSM) Close() error {
	if h.ctx == nil {
		return nil
	}

	h.ctx.CloseSession(h.session)
	h.ctx.Finalize()
	h.ctx.Destroy()
	h.ctx = nil
	return nil
}

// ListX25519Keys returns all X25519 private keys on the HSM.
func (h *HSM) ListX25519Keys() ([]Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	// Encode the X25519 OID for searching
	ecParams, err := asn1.Marshal(oidX25519)
	if err != nil {
		return nil, fmt.Errorf("failed to encode OID: %w", err)
	}

	// Search for private keys with X25519 curve
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_MONTGOMERY),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("failed to init find: %w", err)
	}
	defer h.ctx.FindObjectsFinal(h.session)

	handles, _, err := h.ctx.FindObjects(h.session, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	var keys []Key
	for _, handle := range handles {
		key, err := h.getKeyInfo(handle)
		if err != nil {
			continue // Skip keys we can't read
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// FindX25519Key finds an X25519 key by label or ID.
func (h *HSM) FindX25519Key(labelOrID string) (*Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	// Encode the X25519 OID
	ecParams, err := asn1.Marshal(oidX25519)
	if err != nil {
		return nil, fmt.Errorf("failed to encode OID: %w", err)
	}

	// Try finding by label first
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_MONTGOMERY),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelOrID),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("failed to init find: %w", err)
	}

	handles, _, err := h.ctx.FindObjects(h.session, 1)
	h.ctx.FindObjectsFinal(h.session)

	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(handles) > 0 {
		key, err := h.getKeyInfo(handles[0])
		if err != nil {
			return nil, err
		}
		return &key, nil
	}

	// Try finding by ID
	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_MONTGOMERY),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(labelOrID)),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("failed to init find: %w", err)
	}

	handles, _, err = h.ctx.FindObjects(h.session, 1)
	h.ctx.FindObjectsFinal(h.session)

	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(handles) == 0 {
		return nil, fmt.Errorf("key not found: %s", labelOrID)
	}

	key, err := h.getKeyInfo(handles[0])
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// getKeyInfo retrieves key information including the public key.
func (h *HSM) getKeyInfo(privHandle pkcs11.ObjectHandle) (Key, error) {
	// Get private key attributes
	attrs, err := h.ctx.GetAttributeValue(h.session, privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return Key{}, fmt.Errorf("failed to get private key attributes: %w", err)
	}

	key := Key{Handle: privHandle}
	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_LABEL:
			key.Label = string(attr.Value)
		case pkcs11.CKA_ID:
			key.ID = attr.Value
		}
	}

	// Find corresponding public key
	pubKey, err := h.getPublicKey(key.ID, key.Label)
	if err != nil {
		return Key{}, err
	}
	key.PublicKey = pubKey

	return key, nil
}

// getPublicKey finds and returns the raw X25519 public key bytes.
func (h *HSM) getPublicKey(id []byte, label string) ([]byte, error) {
	ecParams, _ := asn1.Marshal(oidX25519)

	// Try to find by ID first
	var template []*pkcs11.Attribute
	if len(id) > 0 {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_MONTGOMERY),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
	} else {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_MONTGOMERY),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("failed to init find public key: %w", err)
	}

	handles, _, err := h.ctx.FindObjects(h.session, 1)
	h.ctx.FindObjectsFinal(h.session)

	if err != nil {
		return nil, fmt.Errorf("failed to find public key: %w", err)
	}

	if len(handles) == 0 {
		return nil, errors.New("public key not found")
	}

	// Get the EC_POINT attribute which contains the public key
	attrs, err := h.ctx.GetAttributeValue(h.session, handles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key value: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, errors.New("empty public key")
	}

	// EC_POINT is DER-encoded OCTET STRING containing the raw point
	// For X25519, this is typically 04 20 <32 bytes> (OCTET STRING of length 32)
	ecPoint := attrs[0].Value
	return parseECPoint(ecPoint)
}

// parseECPoint extracts the raw 32-byte X25519 public key from EC_POINT.
func parseECPoint(ecPoint []byte) ([]byte, error) {
	// The EC_POINT for X25519 is an OCTET STRING containing the 32-byte u-coordinate
	// It may be wrapped in ASN.1 OCTET STRING encoding: 04 20 <32 bytes>
	if len(ecPoint) == 32 {
		return ecPoint, nil
	}

	if len(ecPoint) == 34 && ecPoint[0] == 0x04 && ecPoint[1] == 0x20 {
		return ecPoint[2:], nil
	}

	// Try ASN.1 decoding
	var rawPoint []byte
	if _, err := asn1.Unmarshal(ecPoint, &rawPoint); err == nil && len(rawPoint) == 32 {
		return rawPoint, nil
	}

	return nil, fmt.Errorf("unexpected EC_POINT format: length %d", len(ecPoint))
}

// GenerateX25519Key generates a new X25519 key pair on the HSM.
func (h *HSM) GenerateX25519Key(label string, id []byte) (*Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	ecParams, err := asn1.Marshal(oidX25519)
	if err != nil {
		return nil, fmt.Errorf("failed to encode OID: %w", err)
	}

	// Public key template
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	// Private key template
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, nil),
	}

	pubHandle, privHandle, err := h.ctx.GenerateKeyPair(h.session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	_ = pubHandle // We'll fetch the public key via getKeyInfo

	key, err := h.getKeyInfo(privHandle)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

// DeriveSharedSecret performs X25519 ECDH with the HSM's private key and the given public key.
func (h *HSM) DeriveSharedSecret(privHandle pkcs11.ObjectHandle, peerPublicKey []byte) ([]byte, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	if len(peerPublicKey) != 32 {
		return nil, fmt.Errorf("invalid peer public key length: %d (expected 32)", len(peerPublicKey))
	}

	// The peer public key needs to be in the format expected by CKM_ECDH1_DERIVE
	// For X25519, this is just the raw 32-byte u-coordinate
	params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPublicKey)

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params),
	}

	// Template for the derived secret key
	// We derive a generic secret that we can extract
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}

	secretHandle, err := h.ctx.DeriveKey(h.session, mech, privHandle, template)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer h.ctx.DestroyObject(h.session, secretHandle)

	// Extract the derived secret
	attrs, err := h.ctx.GetAttributeValue(h.session, secretHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get derived secret: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, errors.New("empty derived secret")
	}

	return attrs[0].Value, nil
}

// SlotInfo returns information about the current slot.
func (h *HSM) SlotInfo() (pkcs11.TokenInfo, error) {
	if h.ctx == nil {
		return pkcs11.TokenInfo{}, errors.New("HSM not opened")
	}
	return h.ctx.GetTokenInfo(h.slot)
}
