# EC Certificate Curve Extractor (PA2)

This repository contains a program that connects to a **TLS-enabled website** (or reads a local **X.509 certificate file**) and extracts:

- The **server (leaf) certificate**
- The **named elliptic curve** used by the certificate’s EC public key (if it is an EC key)
- The **finite-field characteristic** \(p\) (for GF(p))
- The **elliptic-curve equation parameters** \(a\) and \(b\)

It prints the curve in **short Weierstrass form**:

\[
y^2 \equiv x^3 + a x + b \pmod p
\]

---

## Key features

- **Website → certificate extraction**
  - Performs a TLS handshake and grabs the **leaf certificate** presented by the server.
- **Offline certificate analysis**
  - Accepts a local certificate file (`--cert`) in **PEM or DER**.
- **EC key detection**
  - Automatically checks whether the certificate public key is **Elliptic Curve**; if it’s RSA/other, it reports that cleanly.
- **Curve parameters output**
  - For common WebPKI curves, prints \(p, a, b\) and the curve equation.
  - Uses the optional `ecdsa` package when available, otherwise falls back to built-in constants.

---

## What the program prints

1. Basic certificate metadata (subject, issuer, serial, signature info)
2. Public-key type (EC vs non-EC)
3. If EC:
   - Named curve (e.g., `secp256r1`)
   - Curve equation format and values:
     - `p` (field characteristic)
     - `a`, `b`

---

## Supported curves (built-in)

The script includes built-in domain parameters for these curves:

- `secp256r1` / `prime256v1` (NIST P-256)
- `secp384r1` (NIST P-384)
- `secp521r1` (NIST P-521)
- `secp256k1`

If your curve name is not covered, installing `ecdsa` may add support:
```bash
pip install ecdsa
```

---

## Function-by-function explanation (viva-friendly)

### Input parsing
- **`_parse_host(input_str)`**
  - Extracts a clean hostname from inputs like:
    - `https://example.com/path`
    - `example.com`
    - `example.com:8443`
- **`_maybe_parse_port(input_str, default_port)`**
  - Determines the port from either the URL/`host:port` input, or uses the default.

### Certificate extraction/loading
- **`fetch_leaf_certificate_der(host, port, timeout, insecure, sni)`**
  - Opens a TCP socket, wraps it in TLS, and retrieves the **leaf certificate** bytes (DER) from the handshake.
  - Supports:
    - `--insecure` (disable validation, still extracts cert)
    - `--sni` (override SNI name if needed)
- **`der_to_pem(der)`**
  - Converts DER certificate bytes to PEM format.
- **`load_certificate_any(path)`**
  - Loads a local certificate file, trying PEM first then DER.

### Curve parameter extraction
- **`get_curve_params(curve_name)`**
  - Main “parameter resolver” for named curves.
  - Combines:
    - `_curve_params_via_ecdsa(curve_name)` (if `ecdsa` is installed)
    - `_curve_params_builtin(curve_name)` (fallback constants)
- **`_curve_params_via_ecdsa(curve_name)`**
  - Uses the `ecdsa` library’s known curves to obtain \(p, a, b\).
- **`_curve_params_builtin(curve_name)`**
  - Provides hardcoded \(p, a, b\) for common TLS/Web curves.

### Output formatting
- **`describe_certificate(cert)`**
  - Prints certificate identity (subject, issuer) and signature metadata.
- **`curve_equation_text(params)`**
  - Prints the standard curve equation and the extracted values.
- **`format_hex(n)`**
  - Converts integers to readable hex (0x…).

### Program entrypoint
- **`main()`**
  - Orchestrates the entire flow:
    1. Decide input mode (website vs `--cert`)
    2. Fetch/load certificate
    3. Extract public key and check if it is EC
    4. Print curve equation parameters when applicable

---

## Usage

### From a website
```bash
pip install cryptography
python pa2_ec_cert_curve_params.py https://example.com
```

### Specify port / host:port
```bash
python pa2_ec_cert_curve_params.py example.com --port 8443
python pa2_ec_cert_curve_params.py example.com:8443
```

### Save the fetched leaf certificate
```bash
python pa2_ec_cert_curve_params.py example.com --save-cert leaf.pem
```

### From a local certificate file
```bash
python pa2_ec_cert_curve_params.py --cert leaf.pem
```

---

## Exit codes (useful for grading/scripts)

- `0` — success (EC params printed)
- `2` — EC key detected, but curve parameters could not be derived
- `3` — certificate public key is not EC (e.g., RSA)

---

## Notes

- This program extracts **domain parameters** \(p, a, b\) of the **named curve** used by the certificate public key.
- It does not attempt to derive parameters from arbitrary encodings beyond the known named-curve mappings (unless `ecdsa` supports it).
