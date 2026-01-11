// Package hsm provides communication with Pico HSM via PKCS#11.
package hsm

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/miekg/pkcs11"
)

// P-256 (secp256r1) curve OID
var oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}

// HSM represents a connection to a Pico HSM device.
type HSM struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	slot    uint
	module  string
}

// Key represents an EC P-256 key on the HSM.
type Key struct {
	Handle    pkcs11.ObjectHandle
	Label     string
	ID        []byte
	PublicKey []byte // 65-byte uncompressed P-256 public key (04 || X || Y)
}

// DefaultModulePaths contains common paths for the OpenSC PKCS#11 module.
var DefaultModulePaths = []string{
	"/usr/lib/opensc-pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/opt/homebrew/lib/opensc-pkcs11.so",
	"/usr/local/opt/opensc/lib/opensc-pkcs11.so",
	"/run/current-system/sw/lib/opensc-pkcs11.so", // NixOS system path
}

// findModulePath attempts to find the OpenSC PKCS#11 module.
func findModulePath() string {
	// Check environment variable first
	if path := os.Getenv("PICOHSM_PKCS11_MODULE"); path != "" {
		return path
	}

	// Try default paths
	for _, path := range DefaultModulePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try to find via pkcs11-tool (works on NixOS with nix-shell)
	if pkcs11Tool, err := exec.LookPath("pkcs11-tool"); err == nil {
		// pkcs11-tool is typically in .../bin/, opensc-pkcs11.so in .../lib/
		binDir := filepath.Dir(pkcs11Tool)
		libPath := filepath.Join(filepath.Dir(binDir), "lib", "opensc-pkcs11.so")
		if _, err := os.Stat(libPath); err == nil {
			return libPath
		}
	}

	// Try to find via pkg-config
	if out, err := exec.Command("pkg-config", "--variable=libdir", "opensc-pkcs11").Output(); err == nil {
		libDir := strings.TrimSpace(string(out))
		if libDir != "" {
			path := filepath.Join(libDir, "opensc-pkcs11.so")
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	return ""
}

// New creates a new HSM instance.
func New() *HSM {
	return &HSM{}
}

// Open connects to the HSM using the specified PKCS#11 module path.
// If modulePath is empty, it auto-detects the path.
func (h *HSM) Open(modulePath string) error {
	if modulePath == "" {
		modulePath = findModulePath()
	}
	if modulePath == "" {
		return errors.New("could not find OpenSC PKCS#11 module; set PICOHSM_PKCS11_MODULE environment variable")
	}
	paths := []string{modulePath}

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

// ListP256Keys returns all P-256 private keys on the HSM.
func (h *HSM) ListP256Keys() ([]Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	// Search for EC private keys (don't filter by EC_PARAMS as some tokens don't support it)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("failed to init find: %w", err)
	}

	handles, _, err := h.ctx.FindObjects(h.session, 100)
	h.ctx.FindObjectsFinal(h.session) // Must finalize before calling getKeyInfo which does its own find

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

// FindP256Key finds a P-256 key by label or ID.
func (h *HSM) FindP256Key(labelOrID string) (*Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	// Try finding by label first (don't filter by EC_PARAMS as some tokens don't support it)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
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
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
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

// getPublicKey finds and returns the P-256 public key bytes.
func (h *HSM) getPublicKey(id []byte, label string) ([]byte, error) {
	// Try to find by ID first (don't filter by EC_PARAMS as some tokens don't support it)
	var template []*pkcs11.Attribute
	if len(id) > 0 {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
	} else {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
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

// parseECPoint extracts the 65-byte uncompressed P-256 public key from EC_POINT.
func parseECPoint(ecPoint []byte) ([]byte, error) {
	// P-256 uncompressed point is 65 bytes: 04 || X (32 bytes) || Y (32 bytes)
	// It may be wrapped in ASN.1 OCTET STRING encoding
	if len(ecPoint) == 65 && ecPoint[0] == 0x04 {
		return ecPoint, nil
	}

	// Try ASN.1 decoding (OCTET STRING wrapping)
	var rawPoint []byte
	if _, err := asn1.Unmarshal(ecPoint, &rawPoint); err == nil {
		if len(rawPoint) == 65 && rawPoint[0] == 0x04 {
			return rawPoint, nil
		}
	}

	// Some implementations return just the ASN.1 wrapped point
	if len(ecPoint) == 67 && ecPoint[0] == 0x04 && ecPoint[1] == 0x41 {
		return ecPoint[2:], nil
	}

	return nil, fmt.Errorf("unexpected EC_POINT format: length %d", len(ecPoint))
}

// GenerateP256Key generates a new P-256 EC key pair on the HSM.
func (h *HSM) GenerateP256Key(label string, id []byte) (*Key, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	ecParams, err := asn1.Marshal(oidP256)
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
		pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
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

// DeriveSharedSecret performs P-256 ECDH with the HSM's private key and the given public key.
func (h *HSM) DeriveSharedSecret(privHandle pkcs11.ObjectHandle, peerPublicKey []byte) ([]byte, error) {
	if h.ctx == nil {
		return nil, errors.New("HSM not opened")
	}

	if len(peerPublicKey) != 65 {
		return nil, fmt.Errorf("invalid peer public key length: %d (expected 65)", len(peerPublicKey))
	}

	// The peer public key needs to be in the format expected by CKM_ECDH1_DERIVE
	// For P-256, this is the 65-byte uncompressed point (04 || X || Y)
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
