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

## PIN Entry

By default, the plugin prompts for the PIN in the terminal. For graphical
prompts (useful when running in the background or from scripts), set
`PICOHSM_ASKPASS` to an askpass-compatible program:

```bash
export PICOHSM_ASKPASS=ksshaskpass
age-plugin-picohsm --list
```

The plugin also respects `SSH_ASKPASS` as a fallback when no terminal is
available.

### PIN Caching with picohsm-askpass

The included `picohsm-askpass` script wraps any askpass program and caches the
PIN in the Linux kernel keyring, so you only get prompted once per session:

```bash
export PICOHSM_ASKPASS=./picohsm-askpass
export PICOHSM_ASKPASS_BACKEND=ksshaskpass  # or any askpass program
age-plugin-picohsm --list
```

The cache expires after 5 minutes by default. Configure via `PICOHSM_PIN_TIMEOUT`
(in seconds, 0 to disable caching):

```bash
export PICOHSM_PIN_TIMEOUT=600  # 10 minutes
```

Requires `keyutils` for the kernel keyring.

You can also skip all prompting by setting `PICOHSM_PIN` directly (not
recommended for interactive use):

```bash
PICOHSM_PIN=123456 age -d -i identity.txt secret.age
```

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
