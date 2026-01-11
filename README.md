# age-plugin-picohsm

An [age](https://age-encryption.org) plugin for [Pico HSM](https://github.com/polhenarejos/pico-hsm) hardware security modules.

## Features

- **X25519 encryption**: Native age-compatible encryption using X25519 keys
- **Hardware-backed keys**: Private keys never leave the HSM
- **Asymmetric encryption**: Encrypt without the hardware (public key only), decrypt with hardware
- **Session PIN caching**: Enter PIN once per session, not per operation
- **Key backup**: Use DKEK to clone keys across multiple HSMs

## Installation

```bash
go install github.com/pinpox/age-plugin-picohsm/cmd/age-plugin-picohsm@latest
```

Or build from source:

```bash
git clone https://github.com/pinpox/age-plugin-picohsm
cd age-plugin-picohsm
go build -o age-plugin-picohsm ./cmd/age-plugin-picohsm
```

Ensure the binary is in your `$PATH`.

## Prerequisites

- Pico HSM flashed with [pico-hsm firmware](https://github.com/polhenarejos/pico-hsm)
- OpenSC installed (`opensc-pkcs11.so` module)
- `pcscd` service running

## Usage

### Generate a new key on HSM

```bash
age-plugin-picohsm --generate --label my-age-key
```

This outputs:
- **Recipient**: `age1picohsm1...` - share this for encryption
- **Identity**: `AGE-PLUGIN-PICOHSM-1...` - save this for decryption

### List keys on HSM

```bash
age-plugin-picohsm --list
```

### Encrypt a file

```bash
# Using the recipient (no HSM needed)
age -r age1picohsm1... -o secret.age secret.txt
```

### Decrypt a file

```bash
# Save identity to a file
echo "AGE-PLUGIN-PICOHSM-1..." > identity.txt

# Decrypt (requires HSM + PIN)
age -d -i identity.txt -o secret.txt secret.age
```

### Multiple recipients

```bash
# Encrypt to both HSM key and a regular age key
age -r age1picohsm1... -r age1regular... -o secret.age secret.txt
```

## Key Backup with DKEK

To use the same key on multiple Pico HSMs:

1. Initialize both HSMs with the same DKEK
2. Generate key on first HSM
3. Export with `sc-hsm-tool --wrap-key`
4. Import on second HSM with `sc-hsm-tool --unwrap-key`

See [Pico HSM backup documentation](https://github.com/polhenarejos/pico-hsm/blob/master/doc/backup-and-restore.md).

## How it works

### Encryption (recipient-v1)
1. Plugin receives public key from recipient string
2. Generates ephemeral X25519 keypair
3. Computes shared secret via ECDH (software)
4. Derives wrap key via HKDF-SHA256
5. Wraps file key with ChaCha20-Poly1305

### Decryption (identity-v1)
1. Plugin connects to HSM via PKCS#11
2. Prompts for PIN
3. Sends ephemeral public key to HSM
4. HSM performs ECDH internally, returns shared secret
5. Plugin derives unwrap key and decrypts file key

## Comparison with other plugins

| Plugin | Key Type | Hardware | Touch per op | PIN caching |
|--------|----------|----------|--------------|-------------|
| **age-plugin-picohsm** | X25519 | Pico HSM | No | Yes (session) |
| age-plugin-yubikey | P-256 (PIV) | YubiKey | Optional | 15s window |
| age-plugin-fido2-hmac | Symmetric | FIDO2 | Yes | No |

## License

MIT
