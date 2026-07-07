# PKI Setup with SoftHSM2 and OpenSSL

A complete guide to building a local Public Key Infrastructure (PKI) using SoftHSM2 as a PKCS#11 software HSM, OpenSSL for certificate management, and system-level trust installation for local TLS testing.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [SoftHSM2 Installation and Token Initialization](#2-softhsm2-installation-and-token-initialization)
3. [RSA 4096 Keypair Generation via PKCS#11](#3-rsa-4096-keypair-generation-via-pkcs11)
4. [Root CA Creation](#4-root-ca-creation)
5. [Wildcard Certificate Issuance](#5-wildcard-certificate-issuance)
6. [System Trust Installation](#6-system-trust-installation)
7. [Local TLS Testing](#7-local-tls-testing)
8. [File Reference](#8-file-reference)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

Install the required packages before beginning. These commands assume a Debian/Ubuntu-based system.

```bash
sudo apt-get update
sudo apt-get install -y \
    softhsm2 \
    openssl \
    libengine-pkcs11-openssl \
    gnutls-bin \
    ca-certificates
```

Verify the installations:

```bash
softhsm2-util --version
openssl version
pkcs11-tool --version
```

### Directory Layout

Establish a working directory to keep all PKI artifacts organized:

```bash
mkdir -p ~/pki/{certs,keys,csr,db}
cd ~/pki
```

---

## 2. SoftHSM2 Installation and Token Initialization

SoftHSM2 is a software-based PKCS#11 HSM. It stores cryptographic objects (keys, certificates) in a local token database, making it suitable for development and testing environments where a physical HSM is unavailable.

### Configure SoftHSM2

Locate or create the SoftHSM2 configuration file. By default it lives at `/etc/softhsm/softhsm2.conf` (system-wide) or `~/.config/softhsm2/softhsm2.conf` (per-user).

```bash
# Check the default config location
softhsm2-util --show-slots

# Ensure the token directory exists
mkdir -p /var/lib/softhsm/tokens
```

If creating a per-user config:

```bash
mkdir -p ~/.config/softhsm2
cat > ~/.config/softhsm2/softhsm2.conf <<EOF
directories.tokendir = $HOME/.local/share/softhsm2/tokens
objectstore.backend = file
log.level = INFO
EOF
mkdir -p ~/.local/share/softhsm2/tokens
```

### Initialize the Token

Initialize a new PKCS#11 token in slot 0. You will be prompted to set a **Security Officer (SO) PIN** (admin PIN) and a **User PIN** (operational PIN).

```bash
softhsm2-util --init-token --slot 0 --label "AcquireRootCA"
```

**Example output:**

```
The token has been initialized and is reassigned to slot 0x7ac75460
```

> **Note:** SoftHSM2 reassigns the logical slot number after initialization. The hex value (e.g., `0x7ac75460`) is the actual slot handle — record it for subsequent commands.

Confirm the token is visible:

```bash
softhsm2-util --show-slots
```

Locate the PKCS#11 provider library:

```bash
find /usr -name "libsofthsm2.so" 2>/dev/null
# Typically: /usr/lib/softhsm/libsofthsm2.so
```

---

## 3. RSA 4096 Keypair Generation via PKCS#11

Generate an RSA 4096-bit key pair directly inside the SoftHSM2 token. The private key never leaves the HSM boundary — only the public key is exported for use in certificate operations.

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --keypairgen \
    --key-type RSA:4096 \
    --label "AcquireRootCA" \
    --id 01
```

You will be prompted for the **User PIN** set during token initialization.

**Flags explained:**

| Flag | Purpose |
|------|--------|
| `--module` | Path to the SoftHSM2 PKCS#11 shared library |
| `--slot` | Target token slot (hex value from initialization) |
| `--login` | Authenticate with the User PIN |
| `--keypairgen` | Generate a public/private key pair |
| `--key-type RSA:4096` | RSA algorithm, 4096-bit modulus |
| `--label` | Human-readable name stored in the token |
| `--id 01` | Hex object ID for referencing the key |

Verify the key objects are present in the token:

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --list-objects
```

You should see both a **Private Key Object** and a **Public Key Object** labeled `AcquireRootCA`.

---

## 3.1 Ethereum Signing Key (secp256k1) — Required for the Relayer

The RSA 4096 key above is used exclusively for TLS certificates. Ethereum transaction signing requires a separate **ECDSA secp256k1** key. Generate it in the same token with a distinct ID and label:

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --keypairgen \
    --key-type EC:secp256k1 \
    --label "AcquireRelayer" \
    --id 02
```

Verify both objects are stored:

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --list-objects
# Expected: Private Key + Public Key objects for both AcquireRootCA (id=01) and AcquireRelayer (id=02)
```

### Derive the Ethereum Address from the HSM Public Key

The relayer prints this automatically on startup. To get it beforehand:

```bash
# Export the secp256k1 public key
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --read-object \
    --type pubkey \
    --label "AcquireRelayer" \
    --output-file ~/pki/keys/relayer_pub.der
```

The Ethereum address is `keccak256(x || y)[12:]` where `x || y` are the 64-byte uncompressed EC coordinates. The relayer derives and logs this automatically — use that address as `authorizedRelayer` when deploying `BridgeMainnet.sol`:

```js
// Hardhat / Remix deployment
const bridge = await BridgeMainnet.deploy("0xHSM_DERIVED_ADDRESS");
```

### Environment Variables for the Relayer

```bash
export HSM_USER_PIN="your-user-pin"          # PIN set during softhsm2-util --init-token
export TX_PRIVATE_KEY="hex-private-key"      # Funded Ethereum account that pays mainnet gas
```

---

## 4. Root CA Creation

With the key pair stored in the HSM, create the Root CA certificate using OpenSSL's PKCS#11 engine to sign with the HSM-resident private key.

### 4.1 Create the OpenSSL CA Configuration

```bash
cat > ~/pki/root_ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /root/pki
certs             = $dir/certs
new_certs_dir     = $dir/db
database          = $dir/db/index.txt
serial            = $dir/db/serial
private_key       = $dir/keys/acquire_root_ca.key
certificate       = $dir/certs/acquire_root_ca.pem
default_md        = sha256
default_days      = 3650
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
default_md          = sha256
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
C  = US
ST = California
L  = Visalia
O  = Acquire
OU = Infrastructure
CN = Acquire Root CA

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints       = CA:FALSE
nsCertType             = server
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
EOF
```

Initialize the CA database:

```bash
touch ~/pki/db/index.txt
echo 1000 > ~/pki/db/serial
```

### 4.2 Export the HSM Public Key

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0x7ac75460 \
    --login \
    --read-object \
    --type pubkey \
    --label "AcquireRootCA" \
    --output-file ~/pki/keys/acquire_root_ca_pub.der

# Convert DER to PEM
openssl rsa \
    -pubin \
    -inform DER \
    -in ~/pki/keys/acquire_root_ca_pub.der \
    -out ~/pki/keys/acquire_root_ca_pub.pem
```

### 4.3 Generate the Self-Signed Root CA Certificate

```bash
openssl req \
    -new \
    -x509 \
    -days 3650 \
    -sha256 \
    -engine pkcs11 \
    -keyform engine \
    -key "pkcs11:token=AcquireRootCA;object=AcquireRootCA;type=private" \
    -out ~/pki/certs/acquire_root_ca.pem \
    -config ~/pki/root_ca.cnf \
    -extensions v3_ca
```

> **Note:** The `-engine pkcs11` flag instructs OpenSSL to delegate private key operations to the SoftHSM2 token via the `libp11` engine. You will be prompted for the User PIN.

Verify the Root CA certificate:

```bash
openssl x509 \
    -in ~/pki/certs/acquire_root_ca.pem \
    -noout \
    -text
```

Confirm the output shows `CA:TRUE`, `Certificate Sign, CRL Sign` key usage, and a 10-year validity window.

---

## 5. Wildcard Certificate Issuance

Issue a wildcard TLS certificate (e.g., `*.acquire.local`) signed by the Root CA.

### 5.1 Create the Wildcard Certificate Configuration

```bash
cat > ~/pki/wildcard.cnf <<'EOF'
[ req ]
default_bits        = 4096
default_md          = sha256
distinguished_name  = req_distinguished_name
req_extensions      = v3_req
prompt              = no

[ req_distinguished_name ]
C  = US
ST = California
L  = Visalia
O  = Acquire
OU = Infrastructure
CN = *.acquire.local

[ v3_req ]
basicConstraints     = CA:FALSE
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = @alt_names

[ alt_names ]
DNS.1 = *.acquire.local
DNS.2 = acquire.local
EOF
```

### 5.2 Generate the Wildcard Private Key

```bash
openssl genrsa \
    -out ~/pki/keys/wildcard.key \
    4096

chmod 600 ~/pki/keys/wildcard.key
```

### 5.3 Generate the CSR

```bash
openssl req \
    -new \
    -sha256 \
    -key ~/pki/keys/wildcard.key \
    -out ~/pki/csr/wildcard.csr \
    -config ~/pki/wildcard.cnf
```

Verify the CSR:

```bash
openssl req -in ~/pki/csr/wildcard.csr -noout -text
```

Confirm the SANs include `*.acquire.local` and `acquire.local`.

### 5.4 Sign the CSR with the Root CA

```bash
openssl x509 \
    -req \
    -days 825 \
    -sha256 \
    -in ~/pki/csr/wildcard.csr \
    -CA ~/pki/certs/acquire_root_ca.pem \
    -CAkey "pkcs11:token=AcquireRootCA;object=AcquireRootCA;type=private" \
    -CAkeyform engine \
    -engine pkcs11 \
    -CAcreateserial \
    -out ~/pki/certs/wildcard.crt \
    -extfile ~/pki/wildcard.cnf \
    -extensions v3_req
```

Verify the certificate chain:

```bash
openssl verify \
    -CAfile ~/pki/certs/acquire_root_ca.pem \
    ~/pki/certs/wildcard.crt
# Expected: wildcard.crt: OK
```

---

## 6. System Trust Installation

### Linux (Debian/Ubuntu)

```bash
sudo cp ~/pki/certs/acquire_root_ca.pem \
    /usr/local/share/ca-certificates/acquire_root_ca.crt

sudo update-ca-certificates
```

**Expected output:**

```
1 added, 0 removed; done.
```

### Linux (RHEL/CentOS/Fedora)

```bash
sudo cp ~/pki/certs/acquire_root_ca.pem \
    /etc/pki/ca-trust/source/anchors/acquire_root_ca.crt

sudo update-ca-trust extract
```

### macOS

```bash
sudo security add-trusted-cert \
    -d \
    -r trustRoot \
    -k /Library/Keychains/System.keychain \
    ~/pki/certs/acquire_root_ca.pem
```

### Verify System Trust

```bash
openssl verify \
    -CAfile /etc/ssl/certs/ca-certificates.crt \
    ~/pki/certs/wildcard.crt
```

---

## 7. Local TLS Testing

### 7.1 Add a Local DNS Entry

```bash
echo "127.0.0.1  test.acquire.local" | sudo tee -a /etc/hosts
```

### 7.2 Start the TLS Test Server

```bash
openssl s_server \
    -accept 8443 \
    -cert ~/pki/certs/wildcard.crt \
    -key ~/pki/keys/wildcard.key \
    -CAfile ~/pki/certs/acquire_root_ca.pem \
    -WWW \
    -verify 1
```

**Expected output:** `ACCEPT`

### 7.3 Connect with the TLS Test Client

In a second terminal:

```bash
openssl s_client \
    -connect test.acquire.local:8443 \
    -CAfile ~/pki/certs/acquire_root_ca.pem \
    -servername test.acquire.local
```

**Successful handshake output:**

```
depth=1 CN=Acquire Root CA
verify return:1
depth=0 CN=*.acquire.local
verify return:1
...
Verify return code: 0 (ok)
```

`Verify return code: 0 (ok)` confirms the full chain is trusted and the handshake succeeded.

### 7.4 Test with curl

```bash
# Using system trust store
curl -v https://test.acquire.local:8443/

# Explicit CA fallback
curl -v \
    --cacert ~/pki/certs/acquire_root_ca.pem \
    https://test.acquire.local:8443/
```

---

## 8. File Reference

| File | Location | Purpose |
|------|----------|--------|
| `acquire_root_ca.pem` | `~/pki/certs/` | Root CA certificate (PEM) |
| `acquire_root_ca.key` | `~/pki/keys/` | PKCS#11 URI / key reference for Root CA |
| `wildcard.key` | `~/pki/keys/` | Wildcard server private key |
| `wildcard.csr` | `~/pki/csr/` | Wildcard certificate signing request |
| `wildcard.crt` | `~/pki/certs/` | Signed wildcard TLS certificate |
| `root_ca.cnf` | `~/pki/` | OpenSSL configuration for Root CA |
| `wildcard.cnf` | `~/pki/` | OpenSSL configuration for wildcard cert |
| `softhsm2.conf` | `~/.config/softhsm2/` | SoftHSM2 configuration |
| Token DB | `~/.local/share/softhsm2/tokens/` | SoftHSM2 token storage (HSM key objects) |

---

## 9. Troubleshooting

### `pkcs11-tool` cannot find the module

```
error: PKCS11 module "..." not found
```

Locate the library:

```bash
find /usr -name "libsofthsm2.so" 2>/dev/null
```

---

### OpenSSL cannot load the PKCS#11 engine

Install the `libp11` engine bridge:

```bash
sudo apt-get install -y libengine-pkcs11-openssl
openssl engine pkcs11 -t
# Expected: (pkcs11) pkcs11 engine ... [ available ]
```

---

### Token slot ID changed after reboot

SoftHSM2 slot IDs may shift between sessions. Always query first:

```bash
softhsm2-util --show-slots | grep -A5 "AcquireRootCA"
```

---

### `verify return code: 21` (unable to verify first certificate)

The CA is missing from the presented trust bundle. Pass it explicitly:

```bash
openssl s_client \
    -connect test.acquire.local:8443 \
    -CAfile ~/pki/certs/acquire_root_ca.pem
```

---

### Certificate SAN mismatch

Confirm the wildcard cert covers the test hostname:

```bash
openssl x509 \
    -in ~/pki/certs/wildcard.crt \
    -noout \
    -ext subjectAltName
# Must include: DNS:*.acquire.local
```

---

*PKI stack: SoftHSM2 · OpenSSL · libp11*
