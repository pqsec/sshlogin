# sshlogin

A challenge-response authentication system for Linux using provisioned SSH public keys.

`sshlogin` enables secure authentication over low-bandwidth, text-only channels (such as serial consoles, BMC/IPMI SOL, or emergency KVMs) by proving possession of an SSH private key **without** transmitting the private key over the wire.

It consists of two components:
1. **`pam_sshlogin.so`**: A Linux PAM module that checks the user's `~/.ssh/authorized_keys`, generates ephemeral ECDH public-key challenges for all eligible keys, and verifies the one-time password (OTP) response.
2. **`sshlogin-response`**: A standalone client CLI tool that parses the challenge token from the console, computes the ECDH shared secret using the local SSH private key, and outputs the OTP.

---

## How It Works

```text
  [ Serial Console / PAM ]                        [ Client Machine ]
             │                                             │
      User attempts login                                  │
             │                                             │
  Read ~/.ssh/authorized_keys                              │
  Generate ephemeral ECDH key pairs                        │
             │                                             │
      Display challenges ──────── (Copy token) ───────────>│
             │                                    sshlogin-response
             │                                    -c <token> -i ~/.ssh/id_ed25519
             │                                    Compute ECDH shared secret
             │                                             │
      Prompt for OTP     <─────── (Type OTP) ──────────────┘
             │
  Verify OTP against all
  keys in constant-time
             │
  [ PAM_SUCCESS or PAM_AUTH_ERR ]
```

### Cryptographic Details

- **ECDSA Keys (NIST P-256, P-384, P-521)**: The PAM module generates an ephemeral key pair on the matching NIST curve and computes the ECDH shared secret via `crypto/ecdh`.
- **Ed25519 Keys**: Ed25519 signing keys are mapped to Montgomery Curve25519 (X25519) points using the canonical birational map $u = (1 + y) / (1 - y) \pmod{2^{255}-19}$ via `filippo.io/edwards25519`. The client derives the X25519 private scalar from the Ed25519 seed via SHA-512 with RFC 7748 clamping.
- **OTP Derivation & Encoding**: The raw ECDH shared secret is expanded using HKDF-SHA256 (RFC 5869) with domain separation (`sshlogin-otp-v1`), encoded with unpadded Base64URL (`-` and `_`, no padding), and truncated to the desired character length (default: 10 characters $\approx 60$ bits of entropy). This ensures uniform bit distribution and eliminates bias from curve coordinate representations (such as leading-zero padding in P-521).
- **Multiple Keys**: Challenges are generated and presented for all eligible keys in `authorized_keys`. The user responds with whichever key they have; the PAM module tests the response across all keys in constant-time.
- **Fall-Through**: If no eligible ECDSA/Ed25519 keys are provisioned for the user, the module returns `PAM_IGNORE`, allowing standard password authentication (e.g. `pam_unix.so`) to proceed seamlessly.

---

## Requirements

- **Go**: 1.22 or higher
- **Build-time**: `pam-devel` (RPM / Fedora / RHEL) or `libpam0g-dev` (Debian / Ubuntu)
- **Runtime**: Linux with PAM support

---

## Building

```bash
# Build both the PAM module and response utility
make build

# Or build individually:
make build-pam       # produces pam_sshlogin.so
make build-response  # produces sshlogin-response
```

Run tests:
```bash
make test
```

### Interactive PAM Testing (Throwaway Container)

To test against a real Linux PAM stack with `pamtester` in an isolated container (using Podman or Docker):

```bash
# Build and launch the interactive test container
make container-shell
```

Inside the container:
- Test user `alice` has both Ed25519 (`~/.ssh/id_ed25519`) and ECDSA P-256 (`~/.ssh/id_ecdsa`) keys provisioned in `~/.ssh/authorized_keys`.
- Run `test-auth ed25519` or `test-auth ecdsa` for an automated verification loop.
- Or test manually:
  ```bash
  pamtester -v sshlogin alice authenticate
  sshlogin-response -c <token> -i /home/alice/.ssh/id_ed25519
  ```

---

## Installation

```bash
sudo make install
```

By default, this installs:
- `pam_sshlogin.so` to `/usr/lib64/security/` (configurable with `PAM_LIBDIR`)
- `sshlogin-response` to `/usr/local/bin/` (configurable with `BIN_DIR`)

---

## Configuration

Add `pam_sshlogin.so` to your PAM service file (for example, `/etc/pam.d/login`, `/etc/pam.d/remote`, or `/etc/pam.d/sshd`).

Example configuration with password fallback:

```pam
#%PAM-1.0
auth    sufficient    pam_sshlogin.so  otp_len=10
auth    substack      password-auth
```

### Module Options

| Option | Default | Description |
|---|---|---|
| `otp_len=N` | `10` | Number of Base64URL characters required for the OTP (minimum: `6`). |
| `keys_file=PATH` | `~/.ssh/authorized_keys` | Custom path to the authorized keys file. |

---

## Usage Example

### 1. Serial Console Login Prompt

When logging in on a serial console:

```
login: alice
sshlogin: use 'sshlogin-response -c <token>' to compute your OTP

  [1] SHA256:vj47eJ34bK8Z4B51h8Z9f4W3eY6w8b2A1bC3dE4fG5h (x25519)
      x25519:vE8x1H4sL2W9k7Z3b5Q8c6V1m0P4y2T5r7X8u9J2a3b

Enter OTP (10 chars): 
```

### 2. Computing the Response

On your workstation where your SSH key is located:

```bash
sshlogin-response -c "x25519:vE8x1H4sL2W9k7Z3b5Q8c6V1m0P4y2T5r7X8u9J2a3b" -i ~/.ssh/id_ed25519
```

Output:
```
k9X_2aL1mP
```

(If `-i` is omitted, `sshlogin-response` automatically checks `~/.ssh/id_ecdsa` and `~/.ssh/id_ed25519`. Passphrase-protected keys will securely prompt for passphrase.)

### 3. Authenticate

Copy or type `k9X_2aL1mP` into the console prompt and press Enter.

---

## License

Apache-2.0 / MIT
