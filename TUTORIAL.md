# Pico HSM Tutorial: age Encryption and SSH Authentication

1. [Introduction & Prerequisites](#1-introduction--prerequisites)
2. [DKEK Setup (Do This First!)](#2-dkek-setup-do-this-first)
3. [First Pico HSM Initialization](#3-first-pico-hsm-initialization)
4. [Generate Keys on HSM](#4-generate-keys-on-hsm)
5. [Backup Keys (Critical Step!)](#5-backup-keys-critical-step)
6. [Using age-plugin-picohsm](#6-using-age-plugin-picohsm)
7. [SSH with PKCS#11](#7-ssh-with-pkcs11)
8. [Cloning to Additional HSMs](#8-cloning-to-additional-hsms)
9. [Recovery to New HSM](#9-recovery-to-new-hsm-all-hsms-lost)
10. [Bootstrapping a New Computer](#10-bootstrapping-a-new-computer)
11. [Backup Strategy Summary](#11-backup-strategy-summary)

---

## 1. Introduction & Prerequisites

### What This Tutorial Covers

You will set up a Pico HSM to securely store cryptographic keys that:
- Never leave the HSM in plaintext
- Can be backed up and transferred to other HSMs via encrypted export
- Work with age encryption and SSH authentication

This tutorial covers setting up Pico HSM for:
- **age encryption** via age-plugin-picohsm
- **SSH authentication** via PKCS#11
- **Multi-device redundancy** via DKEK key transfer
- **Backup and recovery** to new HSMs

### Security Model

Keys are generated directly on the HSM and cannot be extracted as plaintext.
Backup and transfer between HSMs is possible through DKEK (Device Key Encryption
Key) - a master key that encrypts key exports. With your DKEK share and wrapped
key files, you can restore keys to any compatible HSM.

### Hardware Required

- One or more Raspberry Pi Pico devices flashed with [pico-hsm
  firmware](https://github.com/polhenarejos/pico-hsm). You will need to set the
  VID:PID to a know value as shown in the pico-hsm docs.

### Software Required

Install the following packages:

```bash
# Debian/Ubuntu
sudo apt install opensc pcscd age

# Fedora
sudo dnf install opensc pcsc-lite age

# NixOS (add to configuration or use nix-shell)
nix-shell -p opensc pcsclite age
```

Additionally, you need:
- **age-plugin-picohsm** (this plugin) - install from releases or build from source
- **sc-hsm-tool** - included with OpenSC (handles initialization, DKEK, key backup)

### Environment Variables

Throughout this tutorial, set your PIN as an environment variable:

```bash
export YOUR_PIN="your-chosen-pin"
```

Find your PKCS#11 module path:

```bash
# Common locations:
# - /usr/lib/opensc-pkcs11.so
# - /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
# - /usr/lib/pkcs11/opensc-pkcs11.so

export PICOHSM_PKCS11_MODULE="/usr/lib/opensc-pkcs11.so"
```

---

## 2. DKEK Setup

**CRITICAL**: Create your DKEK share BEFORE initializing your first HSM. Without
DKEK, keys cannot be backed up or transferred to other devices.

DKEK (Device Key Encryption Key) is a master key used to encrypt key exports.
When you export a key from an HSM, it's wrapped (encrypted) with the DKEK. Only
HSMs that have imported the same DKEK share can unwrap and use these keys.

### Create DKEK Share

- **Store `dkek.pbe` securely** - this file plus its password can decrypt your key backups
- **The password is essential** - without it, the DKEK share is useless

```bash
sc-hsm-tool --create-dkek-share dkek.pbe
```

You will be prompted to enter a password. Choose a strong password and remember
it - you'll need it whenever you import this DKEK share into an HSM.

---

## 3. First Pico HSM Initialization

Plug in your flashed Pico HSM. Verify it's detected:

```bash
# List smart card readers
pcsc_scan

# Or check with OpenSC
pkcs11-tool --module $PICOHSM_PKCS11_MODULE --list-slots
```

Initialize the Device: 

```bash
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin $YOUR_PIN
```

Options:
- `--so-pin` - Security Officer PIN (hex string, used for administrative tasks like PIN reset)
- `--pin` - Your user PIN for daily use
- `--dkek-shares 1` - Optional: specify number of DKEK shares (default: 1)

**Note**: The SO-PIN shown (`3537363231383830`) is a common default and only meant as example.

Immediately after initialization, import your DKEK share:

```bash
sc-hsm-tool --import-dkek-share dkek.pbe
```

Enter the password you chose when creating the DKEK share, then verify DKEK
import:

```bash
sc-hsm-tool --print-dkek-share
```

This confirms the DKEK was imported successfully.

---

## 4. Generate Keys on HSM

We'll create two separate keys:
1. **age-key** - for age encryption/decryption
2. **ssh-key** - for SSH authentication

### Generate age Encryption Key

```bash
age-plugin-picohsm --generate --label age-key --pin $YOUR_PIN
```

Output will show:
- **Recipient** (public key) - share this with others so they can encrypt to you
- **Identity** - reference string for decryption (save this!)

Example output:
```
Generating P-256 key with label "age-key"...

Public key (recipient):
  age1picohsm1qv5te...

Secret key (identity):
  AGE-PLUGIN-PICOHSM-1Q9GFU...

Save the identity to a file and use it with age -d -i <file>
```

Save the identity string to a file:

```bash
echo "AGE-PLUGIN-PICOHSM-1Q9GFU..." > ~/.age-identity.txt
chmod 600 ~/.age-identity.txt
```

### Generate SSH Key

```bash
pkcs11-tool --module $PICOHSM_PKCS11_MODULE --login --pin $YOUR_PIN \
  --keypairgen --key-type EC:prime256v1 --label ssh-key --id 02
```

### Verify Keys

List all keys on the HSM:

```bash
# Using age-plugin-picohsm
age-plugin-picohsm --list --pin $YOUR_PIN

# Using pkcs15-tool (shows more detail)
pkcs15-tool -D
```

---

## 5. Backup Keys

### Find Key References

First, identify the key references needed for backup:

```bash
pkcs15-tool -D
```

Look for output like:
```
Private EC Key [age-key]
    ...
    Key ref        : 1

Private EC Key [ssh-key]
    ...
    Key ref        : 2
```

### Export Keys (Encrypted with DKEK)

```bash
# Export age key
sc-hsm-tool --wrap-key age-key-backup.bin --key-reference 1 --pin $YOUR_PIN

# Export SSH key
sc-hsm-tool --wrap-key ssh-key-backup.bin --key-reference 2 --pin $YOUR_PIN
```

These `.bin` files contain your keys encrypted with the DKEK. They are useless
without the DKEK share.

### Files to Back Up

| File                  | Purpose                   | Security                           |
|-----------------------|---------------------------|------------------------------------|
| `dkek.pbe`            | DKEK share (master key)   | Store securely + remember password |
| `age-key-backup.bin`  | Encrypted age key         | Safe to store alongside DKEK       |
| `ssh-key-backup.bin`  | Encrypted SSH key         | Safe to store alongside DKEK       |
| `~/.age-identity.txt` | Identity reference string | Not secret, but convenient to keep |

**Remember**: Without BOTH `dkek.pbe` (+ password) AND the wrapped key files,
recovery is impossible.

---

## 6. Using age-plugin-picohsm

### Environment Setup

```bash
export PICOHSM_PKCS11_MODULE="/usr/lib/opensc-pkcs11.so"
export PICOHSM_PIN=$YOUR_PIN
```

### List Keys

```bash
age-plugin-picohsm --list
```

### Encrypt a File

Use the recipient string from `--list` or `--generate`:

```bash
# Encrypt to HSM recipient
echo "secret message" | age -r age1picohsm1qv5te... -o secret.age

# Encrypt a file
age -r age1picohsm1qv5te... -o document.age document.txt
```

**Note**: Encryption doesn't require the HSM - only the public key (recipient string).

### Decrypt a File

Decryption requires the HSM to be connected:

```bash
# Using identity file
age -d -i ~/.age-identity.txt secret.age

# Output to file
age -d -i ~/.age-identity.txt -o document.txt document.age
```

If `PICOHSM_PIN` is not set, you'll be prompted for the PIN.

### Multiple Recipients

You can encrypt to multiple recipients (including non-HSM age keys):

```bash
age -r age1picohsm1qv5te... -r age1abc123... -o secret.age plaintext.txt
```

---

## 7. SSH with PKCS#11

### Add HSM to ssh-agent

```bash
# Start ssh-agent if not running
eval $(ssh-agent)

# Add HSM keys to agent
ssh-add -s $PICOHSM_PKCS11_MODULE
```

Enter your PIN when prompted.

### Get SSH Public Key

Extract the public key for `~/.ssh/authorized_keys` or GitHub/GitLab:

```bash
ssh-add -L
```

Output will be something like:
```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK... ssh-key
```

Add this to `~/.ssh/authorized_keys` on servers you want to access.

### Configure SSH Client

Option 1: Use ssh-agent (recommended):

```bash
# Add to ~/.bashrc or ~/.zshrc
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
ssh-add -s $PICOHSM_PKCS11_MODULE
```

Option 2: Configure per-host in `~/.ssh/config`:

```
Host myserver
    HostName server.example.com
    User myuser
    PKCS11Provider /usr/lib/opensc-pkcs11.so
```

Option 3: Command line:

```bash
ssh -I $PICOHSM_PKCS11_MODULE user@server
```

### Remove HSM from Agent

```bash
ssh-add -e $PICOHSM_PKCS11_MODULE
```

---

## 8. Cloning to Additional HSMs

Having multiple HSMs with identical keys provides redundancy - if one fails, you can immediately switch to another.

### Initialize Second HSM

Connect the new HSM (disconnect the first one to avoid confusion):

```bash
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin $YOUR_PIN
```

### Import Same DKEK Share

```bash
sc-hsm-tool --import-dkek-share dkek.pbe
```

Use the same password as before.

### Import Keys from Backup

```bash
# Import age key
sc-hsm-tool --unwrap-key age-key-backup.bin --key-reference 1 --pin $YOUR_PIN

# Import SSH key
sc-hsm-tool --unwrap-key ssh-key-backup.bin --key-reference 2 --pin $YOUR_PIN
```

### Verify

```bash
age-plugin-picohsm --list --pin $YOUR_PIN
```

Both HSMs now have identical keys. You can use either one interchangeably.

---

## 9. Recovery to New HSM (All HSMs Lost)

If all your HSMs are lost, stolen, or destroyed, you can recover to a brand new
device.

### Requirements

You need:
- `dkek.pbe` file + password
- `age-key-backup.bin` and/or `ssh-key-backup.bin`
- A new Pico HSM (or freshly flashed Pico)

### Recovery Steps

```bash
# 1. Flash Pico with pico-hsm firmware (if not already a Pico HSM)
# See: https://github.com/polhenarejos/pico-hsm

# 2. Initialize the new HSM
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin $YOUR_PIN

# 3. Import your DKEK share
sc-hsm-tool --import-dkek-share dkek.pbe

# 4. Import your keys
sc-hsm-tool --unwrap-key age-key-backup.bin --key-reference 1 --pin $YOUR_PIN
sc-hsm-tool --unwrap-key ssh-key-backup.bin --key-reference 2 --pin $YOUR_PIN

# 5. Verify
age-plugin-picohsm --list --pin $YOUR_PIN
```

Your new HSM now has the same keys as your old ones. All your encrypted files
can be decrypted, and SSH servers will accept your key.

---

## 10. Bootstrapping a New Computer

When setting up a new computer, you just need your Pico HSM - no key files to
transfer.

### Configure Environment

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export PICOHSM_PKCS11_MODULE="/usr/lib/opensc-pkcs11.so"
export PICOHSM_PIN="$YOUR_PIN"  # Or omit to be prompted
```

### Connect HSM and Verify

```bash
# Plug in your Pico HSM

# Verify detection
pkcs11-tool --module $PICOHSM_PKCS11_MODULE --list-slots

# List keys
age-plugin-picohsm --list --pin $YOUR_PIN
```

### Set Up age Identity

Create your identity file:

```bash
# Get your identity string
age-plugin-picohsm --list --pin $YOUR_PIN

# Save to file
echo "AGE-PLUGIN-PICOHSM-1..." > ~/.age-identity.txt
chmod 600 ~/.age-identity.txt
```

### Set Up SSH

```bash
# Add HSM to ssh-agent
ssh-add -s $PICOHSM_PKCS11_MODULE

# Verify
ssh-add -L
```

---

## 11. Backup Strategy Summary

### What to Back Up

| Item                  | Purpose                   | Required For          |
|-----------------------|---------------------------|-----------------------|
| `dkek.pbe` + password | Master encryption key     | Any recovery          |
| `age-key-backup.bin`  | Your age key (encrypted)  | age recovery          |
| `ssh-key-backup.bin`  | Your SSH key (encrypted)  | SSH recovery          |
| Recipient strings     | Let others encrypt to you | Sharing with contacts |
| Identity strings      | Reference for decryption  | Convenience           |


### Security Principles

1. **Keys never exist as plaintext** outside the HSM
2. **DKEK + wrapped files** together enable recovery
3. **Either alone is useless** - defense in depth
4. **Multiple HSMs** provide operational redundancy
5. **Geographic distribution** of backups protects against disasters

---

## Troubleshooting

### HSM Not Detected

```bash
# Check if pcscd is running
sudo systemctl status pcscd

# Restart pcscd
sudo systemctl restart pcscd

# Check USB device
lsusb | grep -i pico
```

### Wrong PIN

After too many wrong PIN attempts, the HSM may lock. Use the SO-PIN to reset:

```bash
pkcs11-tool --module $PICOHSM_PKCS11_MODULE --login --login-type so \
  --init-pin --new-pin $YOUR_PIN
```

### Key Reference Numbers

If `--key-reference` numbers don't match, use `pkcs15-tool -D` to find the correct references for your keys.

### Permission Errors

Your user might need to be member of the `plugdev` group

---

## References

- [Pico HSM GitHub](https://github.com/polhenarejos/pico-hsm)
- [Pico HSM Backup Documentation](https://github.com/polhenarejos/pico-hsm/blob/master/doc/backup-and-restore.md)
- [SmartCard-HSM Documentation](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM)
- [age encryption](https://github.com/FiloSottile/age)
- [OpenSC](https://github.com/OpenSC/OpenSC)
- [age plugin specification](https://github.com/C2SP/C2SP/blob/main/age-plugin.md)
