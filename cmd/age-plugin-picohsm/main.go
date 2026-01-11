// age-plugin-picohsm is an age plugin for Pico HSM hardware security modules.
//
// It uses X25519 keys stored on the HSM for encryption and decryption.
// Encryption can be done without the hardware (using only the public key).
// Decryption requires the HSM to perform the ECDH operation.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/pinpox/age-plugin-picohsm/internal/hsm"
	ageplugin "github.com/pinpox/age-plugin-picohsm/internal/plugin"
	"golang.org/x/term"
)

const version = "0.1.0"

// readPIN reads a PIN from the terminal without echoing it.
func readPIN(prompt string) (string, error) {
	// Open /dev/tty directly to ensure we read from the terminal
	// even if stdin is redirected
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("failed to open terminal: %w", err)
	}
	defer tty.Close()

	fmt.Print(prompt)
	pinBytes, err := term.ReadPassword(int(tty.Fd()))
	fmt.Println() // newline after hidden input
	if err != nil {
		return "", err
	}
	return string(pinBytes), nil
}

func main() {
	// Check if we're being invoked as an age plugin
	var pluginMode string
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--age-plugin=") {
			pluginMode = strings.TrimPrefix(arg, "--age-plugin=")
			break
		}
	}

	if pluginMode != "" {
		runPlugin(pluginMode)
		return
	}

	// CLI flags
	generateFlag := flag.Bool("generate", false, "Generate a new X25519 key on the HSM")
	labelFlag := flag.String("label", "", "Label for the key (used with --generate)")
	listFlag := flag.Bool("list", false, "List X25519 keys on the HSM")
	pinFlag := flag.String("pin", "", "HSM PIN (will prompt if not provided)")
	moduleFlag := flag.String("module", "", "Path to PKCS#11 module (auto-detected if not specified)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	convertFlag := flag.String("convert", "", "Convert identity to recipient (provide identity string)")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("age-plugin-picohsm %s\n", version)
		os.Exit(0)
	}

	if *convertFlag != "" {
		if err := convertIdentityToRecipient(*convertFlag, *moduleFlag, *pinFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *listFlag {
		if err := listKeys(*moduleFlag, *pinFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *generateFlag {
		if *labelFlag == "" {
			fmt.Fprintf(os.Stderr, "Error: --label is required with --generate")
			os.Exit(1)
		}
		if err := generateKey(*moduleFlag, *pinFlag, *labelFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// No command specified, print usage
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:")
	fmt.Fprintf(os.Stderr, "  %s --generate --label my-key    Generate a new key\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s --list                       List keys on HSM\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nThis binary is also invoked by age as a plugin.")
}

// runPlugin runs the age plugin protocol.
func runPlugin(mode string) {
	proto := ageplugin.NewProtocol(os.Stdin, os.Stdout)

	switch mode {
	case "recipient-v1":
		if err := runRecipientV1(proto); err != nil {
			proto.WriteInternalError(err.Error())
			proto.WriteDone()
			os.Exit(1)
		}
	case "identity-v1":
		if err := runIdentityV1(proto); err != nil {
			proto.WriteInternalError(err.Error())
			proto.WriteDone()
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin mode: %s\n", mode)
		os.Exit(1)
	}
}

// runRecipientV1 handles the recipient-v1 state machine (encryption).
func runRecipientV1(proto *ageplugin.Protocol) error {
	var recipients [][]byte // public keys
	var fileKeys [][]byte

	// Phase 1: Read commands from client
	for {
		stanza, err := proto.ReadStanza()
		if err != nil {
			return fmt.Errorf("failed to read stanza: %w", err)
		}

		switch stanza.Type {
		case "add-recipient":
			if len(stanza.Args) != 1 {
				continue
			}
			// Decode the recipient
			pubKey, err := ageplugin.DecodeRecipient(stanza.Args[0])
			if err != nil {
				// Not our recipient type, ignore
				continue
			}
			recipients = append(recipients, pubKey)

		case "add-identity":
			// We could convert identity to recipient here, but that requires HSM access
			// For now, skip identities in recipient mode
			continue

		case "wrap-file-key":
			fileKeys = append(fileKeys, stanza.Body)

		case "done":
			goto phase2

		default:
			// Ignore unknown commands
			continue
		}
	}

phase2:
	// Phase 2: Wrap file keys and respond
	for fileIdx, fileKey := range fileKeys {
		for recipIdx, pubKey := range recipients {
			recipient, err := ageplugin.NewRecipient(pubKey)
			if err != nil {
				proto.WriteError("recipient", recipIdx, err.Error())
				continue
			}

			stanzas, err := recipient.Wrap(fileKey)
			if err != nil {
				proto.WriteError("recipient", recipIdx, err.Error())
				continue
			}

			for _, s := range stanzas {
				if err := proto.WriteRecipientStanza(fileIdx, s); err != nil {
					return err
				}
				// Read ok response
				resp, err := proto.ReadStanza()
				if err != nil {
					return err
				}
				if resp.Type != "ok" {
					return fmt.Errorf("unexpected response to recipient-stanza: %s", resp.Type)
				}
			}
		}
	}

	return proto.WriteDone()
}

// runIdentityV1 handles the identity-v1 state machine (decryption).
func runIdentityV1(proto *ageplugin.Protocol) error {
	var identities []*ageplugin.IdentityData
	fileStanzas := make(map[int][]*age.Stanza) // file index -> stanzas
	var requiredFingerprints []string          // fingerprints we need keys for

	// Phase 1: Read commands from client
	for {
		stanza, err := proto.ReadStanza()
		if err != nil {
			return fmt.Errorf("failed to read stanza: %w", err)
		}

		switch stanza.Type {
		case "add-identity":
			if len(stanza.Args) != 1 {
				continue
			}
			idData, err := ageplugin.DecodeIdentity(stanza.Args[0])
			if err != nil {
				// Not our identity type, ignore
				continue
			}
			identities = append(identities, idData)

		case "recipient-stanza":
			if len(stanza.Args) < 2 {
				continue
			}
			fileIdx, err := strconv.Atoi(stanza.Args[0])
			if err != nil {
				continue
			}
			// Check if this is our stanza type
			if stanza.Args[1] != "picohsm" {
				continue
			}
			// Convert to age.Stanza
			ageStanza := &age.Stanza{
				Type: stanza.Args[1],
				Args: stanza.Args[2:],
				Body: stanza.Body,
			}
			fileStanzas[fileIdx] = append(fileStanzas[fileIdx], ageStanza)

			// Extract fingerprint for error messages
			if fp := ageplugin.ExtractFingerprintFromStanza(ageStanza); fp != nil {
				fpStr := ageplugin.FormatFingerprint(fp)
				// Deduplicate
				found := false
				for _, existing := range requiredFingerprints {
					if existing == fpStr {
						found = true
						break
					}
				}
				if !found {
					requiredFingerprints = append(requiredFingerprints, fpStr)
				}
			}

		case "done":
			goto phase2

		default:
			// Ignore unknown commands
			continue
		}
	}

phase2:
	if len(identities) == 0 {
		return proto.WriteDone()
	}

	// Build description of required keys for error messages
	var keyHint string
	if len(requiredFingerprints) > 0 {
		keyHint = fmt.Sprintf("key with fingerprint %s", strings.Join(requiredFingerprints, " or "))
	} else {
		keyHint = "the required key"
	}

	// Initialize HSM
	h := hsm.New()
	if err := h.Open(""); err != nil {
		proto.WriteInternalError(fmt.Sprintf("Please plug in HSM with %s (failed to open HSM: %v)", keyHint, err))
		return proto.WriteDone()
	}
	defer h.Close()

	// Get PIN from environment or prompt
	pin := os.Getenv("PICOHSM_PIN")
	if pin == "" {
		var err error
		pin, err = proto.RequestSecret("Enter HSM PIN:")
		if err != nil {
			proto.WriteInternalError(fmt.Sprintf("failed to get PIN: %v", err))
			return proto.WriteDone()
		}
	}

	if err := h.Login(pin); err != nil {
		proto.WriteInternalError(fmt.Sprintf("failed to login: %v", err))
		return proto.WriteDone()
	}
	defer h.Logout()

	// Try to unwrap each file's stanzas
	for fileIdx, stanzas := range fileStanzas {
		var unwrapped bool

		for idIdx, idData := range identities {
			// Find the key on HSM
			var key *hsm.Key
			var findErr error
			if idData.KeyLabel != "" {
				key, findErr = h.FindP256Key(idData.KeyLabel)
			} else if len(idData.KeyID) > 0 {
				key, findErr = h.FindP256Key(string(idData.KeyID))
			}

			if findErr != nil {
				proto.WriteError("identity", idIdx, findErr.Error())
				continue
			}

			// Create identity
			identity, err := ageplugin.NewIdentity(h, key)
			if err != nil {
				proto.WriteError("identity", idIdx, err.Error())
				continue
			}

			// Try to unwrap
			fileKey, err := identity.Unwrap(stanzas)
			if err != nil {
				continue // Try next identity
			}

			// Success!
			if err := proto.WriteFileKey(fileIdx, fileKey); err != nil {
				return err
			}
			// Read ok response
			resp, err := proto.ReadStanza()
			if err != nil {
				return err
			}
			if resp.Type != "ok" {
				return fmt.Errorf("unexpected response to file-key: %s", resp.Type)
			}
			unwrapped = true
			break
		}

		if !unwrapped {
			// No identity could unwrap - this is normal, age will try other identities
			// The fingerprint info is already in the stanza for matching
			continue
		}
	}

	return proto.WriteDone()
}

// generateKey generates a new X25519 key on the HSM.
func generateKey(modulePath, pin, label string) error {
	h := hsm.New()
	if err := h.Open(modulePath); err != nil {
		return fmt.Errorf("failed to open HSM: %w", err)
	}
	defer h.Close()

	// Get PIN if not provided
	if pin == "" {
		var err error
		pin, err = readPIN("Enter HSM PIN: ")
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
	}

	if err := h.Login(pin); err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	defer h.Logout()

	// Generate random key ID
	keyID := make([]byte, 4)
	if _, err := rand.Read(keyID); err != nil {
		return fmt.Errorf("failed to generate key ID: %w", err)
	}

	fmt.Printf("Generating P-256 key with label %q...\n", label)

	key, err := h.GenerateP256Key(label, keyID)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode recipient
	recipient, err := ageplugin.EncodeRecipient(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode recipient: %w", err)
	}

	// Encode identity
	identity, err := ageplugin.EncodeIdentity(&ageplugin.IdentityData{
		Slot:     0, // TODO: get actual slot
		KeyID:    key.ID,
		KeyLabel: key.Label,
	})
	if err != nil {
		return fmt.Errorf("failed to encode identity: %w", err)
	}

	fingerprint := ageplugin.Fingerprint(key.PublicKey)

	fmt.Println()
	fmt.Println("Public key (recipient):")
	fmt.Printf("  %s\n", recipient)
	fmt.Println()
	fmt.Println("Secret key (identity):")
	fmt.Printf("  %s\n", identity)
	fmt.Println()
	fmt.Printf("Fingerprint: %s\n", ageplugin.FormatFingerprint(fingerprint))
	fmt.Println()
	fmt.Println("Save the identity to a file and use it with age -d -i <file>")

	return nil
}

// listKeys lists X25519 keys on the HSM.
func listKeys(modulePath, pin string) error {
	h := hsm.New()
	if err := h.Open(modulePath); err != nil {
		return fmt.Errorf("failed to open HSM: %w", err)
	}
	defer h.Close()

	// Get PIN if not provided
	if pin == "" {
		var err error
		pin, err = readPIN("Enter HSM PIN: ")
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
	}

	if err := h.Login(pin); err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	defer h.Logout()

	// Get token info
	info, err := h.SlotInfo()
	if err == nil {
		fmt.Printf("Token: %s\n", strings.TrimSpace(string(info.Label[:])))
		fmt.Printf("Manufacturer: %s\n", strings.TrimSpace(string(info.ManufacturerID[:])))
		fmt.Println()
	}

	keys, err := h.ListP256Keys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No P-256 keys found on HSM.")
		fmt.Println("Use --generate --label <name> to create one.")
		return nil
	}

	fmt.Printf("Found %d P-256 key(s):\n\n", len(keys))

	for i, key := range keys {
		recipient, err := ageplugin.EncodeRecipient(key.PublicKey)
		if err != nil {
			fmt.Printf("%d. %s (ID: %x) - failed to encode: %v\n", i+1, key.Label, key.ID, err)
			continue
		}

		identity, err := ageplugin.EncodeIdentity(&ageplugin.IdentityData{
			Slot:     0,
			KeyID:    key.ID,
			KeyLabel: key.Label,
		})
		if err != nil {
			fmt.Printf("%d. %s (ID: %x) - failed to encode identity: %v\n", i+1, key.Label, key.ID, err)
			continue
		}

		fingerprint := ageplugin.Fingerprint(key.PublicKey)
		fmt.Printf("%d. Label: %s\n", i+1, key.Label)
		fmt.Printf("   ID: %x\n", key.ID)
		fmt.Printf("   Fingerprint: %s\n", ageplugin.FormatFingerprint(fingerprint))
		fmt.Printf("   Recipient: %s\n", recipient)
		fmt.Printf("   Identity: %s\n", identity)
		fmt.Println()
	}

	return nil
}

// convertIdentityToRecipient converts an identity string to a recipient string.
func convertIdentityToRecipient(identityStr, modulePath, pin string) error {
	h := hsm.New()
	if err := h.Open(modulePath); err != nil {
		return fmt.Errorf("failed to open HSM: %w", err)
	}
	defer h.Close()

	// Get PIN if not provided
	if pin == "" {
		var err error
		pin, err = readPIN("Enter HSM PIN: ")
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
	}

	if err := h.Login(pin); err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	defer h.Logout()

	// Parse identity
	idData, err := ageplugin.DecodeIdentity(identityStr)
	if err != nil {
		return fmt.Errorf("failed to parse identity: %w", err)
	}

	// Find the key
	var key *hsm.Key
	if idData.KeyLabel != "" {
		key, err = h.FindP256Key(idData.KeyLabel)
	} else if len(idData.KeyID) > 0 {
		key, err = h.FindP256Key(string(idData.KeyID))
	} else {
		return fmt.Errorf("identity has no key label or ID")
	}

	if err != nil {
		return fmt.Errorf("failed to find key: %w", err)
	}

	// Encode recipient
	recipient, err := ageplugin.EncodeRecipient(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode recipient: %w", err)
	}

	fmt.Println(recipient)
	return nil
}
