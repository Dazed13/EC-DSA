from __future__ import annotations

import argparse
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class CurveParams:
    name: str
    field_characteristic: int  # p for prime fields, 2 for binary fields (rare in TLS cert keys)
    a: int
    b: int
    form: str = "short-weierstrass"  # y^2 = x^3 + ax + b (mod p)


def _parse_host(input_str: str) -> str:
    """
    Accepts:
      - 'example.com'
      - 'https://example.com/path'
      - 'example.com:8443' (host:port)
    Returns hostname only (no port).
    """
    if "://" in input_str:
        parsed = urlparse(input_str)
        host = parsed.hostname
        if not host:
            raise ValueError(f"Could not parse hostname from URL: {input_str}")
        return host
    # no scheme: could be host or host:port
    # urlparse treats 'example.com:443' as scheme if no //, so do manual split:
    if input_str.count(":") == 1 and "/" not in input_str:
        return input_str.split(":", 1)[0]
    return input_str.split("/", 1)[0]


def _maybe_parse_port(input_str: str, default_port: int) -> int:
    if "://" in input_str:
        parsed = urlparse(input_str)
        return parsed.port or default_port
    # plain host:port
    if input_str.count(":") == 1 and "/" not in input_str:
        try:
            return int(input_str.split(":", 1)[1])
        except ValueError:
            return default_port
    return default_port


def fetch_leaf_certificate_der(
    host: str,
    port: int = 443,
    *,
    timeout: float = 8.0,
    insecure: bool = False,
    sni: Optional[str] = None,
) -> bytes:
    """
    Connect to host:port using TLS and return the *leaf* certificate in DER form.
    """
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    server_hostname = sni or host

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("No certificate received from the peer.")
            return der


def der_to_pem(der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate_any(path: str) -> x509.Certificate:
    data = open(path, "rb").read()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _curve_params_via_ecdsa(curve_name: str) -> Optional[CurveParams]:
    """
    If the `ecdsa` package is available, use it to obtain (p,a,b) for several curves.
    """
    try:
        import ecdsa  # type: ignore
        from ecdsa import curves  # type: ignore
    except Exception:
        return None

    # Map cryptography curve names to ecdsa curve objects
    name_map = {
        "secp256r1": curves.NIST256p,
        "prime256v1": curves.NIST256p,  # alias seen in some contexts
        "secp384r1": curves.NIST384p,
        "secp521r1": curves.NIST521p,
        "secp256k1": curves.SECP256k1,
    }

    c = name_map.get(curve_name)
    if c is None:
        return None

    # ecdsa curve exposes the underlying finite field prime p and curve a,b
    p = int(c.curve.p())
    a = int(c.curve.a())
    b = int(c.curve.b())
    return CurveParams(name=curve_name, field_characteristic=p, a=a, b=b)


def _curve_params_builtin(curve_name: str) -> Optional[CurveParams]:
    """
    Built-in parameters for common short-Weierstrass prime-field curves used on the Web.
    (All values are integers.)
    """
    # secp256r1 / prime256v1 (NIST P-256)
    if curve_name in {"secp256r1", "prime256v1"}:
        p = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        a = (p - 3) % p
        b = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        return CurveParams(name="secp256r1", field_characteristic=p, a=a, b=b)

    # secp384r1 (NIST P-384)
    if curve_name == "secp384r1":
        p = int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFF0000000000000000FFFFFFFF",
            16,
        )
        a = (p - 3) % p
        b = int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        )
        return CurveParams(name="secp384r1", field_characteristic=p, a=a, b=b)

    # secp521r1 (NIST P-521)
    if curve_name == "secp521r1":
        p = (1 << 521) - 1
        a = (p - 3) % p
        b = int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
            "3F00",
            16,
        )
        return CurveParams(name="secp521r1", field_characteristic=p, a=a, b=b)

    # secp256k1
    if curve_name == "secp256k1":
        p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
        a = 0
        b = 7
        return CurveParams(name="secp256k1", field_characteristic=p, a=a, b=b)

    return None


def get_curve_params(curve_name: str) -> Optional[CurveParams]:
    # Prefer ecdsa (more general), fallback to built-in.
    return _curve_params_via_ecdsa(curve_name) or _curve_params_builtin(curve_name)


def describe_certificate(cert: x509.Certificate) -> str:
    subj = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    return (
        f"Subject: {subj}\n"
        f"Issuer:  {issuer}\n"
        f"Serial:  {hex(cert.serial_number)}\n"
        f"SigAlg:  {cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string} / {sig_algo}\n"
    )


def format_hex(n: int) -> str:
    # Compact but readable hex with 0x prefix
    return "0x" + format(n, "x")


def curve_equation_text(params: CurveParams) -> str:
    if params.form != "short-weierstrass":
        return f"(unsupported curve form: {params.form})"
    p = params.field_characteristic
    return (
        "Curve form: short Weierstrass over GF(p)\n"
        f"Equation: y^2 ≡ x^3 + a·x + b (mod p)\n"
        f"p (field characteristic) = {format_hex(p)}\n"
        f"a = {format_hex(params.a)}\n"
        f"b = {format_hex(params.b)}\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch a TLS certificate and extract EC curve equation + field characteristic.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("website", nargs="?", help="Website hostname or URL (e.g., https://bits-pilani.ac.in)")
    src.add_argument("--cert", help="Path to a local certificate file (PEM or DER).")

    ap.add_argument("--port", type=int, default=443, help="TLS port (default: 443). If website includes :port, it wins.")
    ap.add_argument("--timeout", type=float, default=8.0, help="Socket timeout seconds (default: 8).")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation (still extracts the cert).")
    ap.add_argument("--sni", help="Override SNI server name (default: hostname).")
    ap.add_argument("--save-cert", help="Save fetched leaf certificate (PEM) to this path.")

    args = ap.parse_args(argv)

    if args.cert:
        cert = load_certificate_any(args.cert)
        pem_out = cert.public_bytes(serialization.Encoding.PEM)
    else:
        host = _parse_host(args.website)
        port = _maybe_parse_port(args.website, args.port)
        der = fetch_leaf_certificate_der(host, port, timeout=args.timeout, insecure=args.insecure, sni=args.sni)
        pem_out = der_to_pem(der)
        cert = x509.load_pem_x509_certificate(pem_out)

        if args.save_cert:
            with open(args.save_cert, "wb") as f:
                f.write(pem_out)

        print(f"Fetched leaf certificate from {host}:{port}\n")

    print(describe_certificate(cert))

    pub = cert.public_key()

    # EC public key (the classic ECDSA / EC key case)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = getattr(pub.curve, "name", "unknown")
        print(f"Public key type: EC ({pub.key_size} bits)")
        print(f"Named curve: {curve_name}\n")

        params = get_curve_params(curve_name)
        if not params:
            print("Could not derive (p, a, b) for this curve name with current mappings.")
            print("Tip: `pip install ecdsa` may add support for more named curves.\n")
            return 2

        print(curve_equation_text(params))
        return 0

    # Non-EC key: still show what it is so the user knows why params aren't available.
    print(f"Public key type: {type(pub).__name__}")
    print("This certificate's public key is not an EC key, so there is no EC curve equation to extract.\n")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
