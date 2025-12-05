# EC Certificate Curve Extractor

This repository contains a program that connects to a **TLS-enabled website** and extracts:

- The **server (leaf) certificate**
- The **named elliptic curve** used by the certificate’s EC public key (if it is an EC key)
- The **finite-field characteristic** \(p\) 
- The **elliptic-curve equation parameters** \(a\) and \(b\)

It prints the curve in **short Weierstrass form**

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



## Supported curves (built-in)

The script includes built-in domain parameters for these curves:

- `secp256r1` / `prime256v1` (NIST P-256)
- `secp384r1` (NIST P-384)
- `secp521r1` (NIST P-521)
- `secp256k1`


---

## Function Explanations

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


---

## Notes

- This program extracts **domain parameters** \(p, a, b\) of the **named curve** used by the certificate public key.
- It does not attempt to derive parameters from arbitrary encodings beyond the known named-curve mappings (unless `ecdsa` supports it).
