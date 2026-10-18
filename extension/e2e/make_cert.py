"""Throwaway self-signed TLS certificate for the end-to-end test's local copies
of the AI sites. Written to the directory given as argv[1] (a temp dir); never
committed. Run with the backend's Python (it has `cryptography`)."""

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOSTS = ["chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com", "copilot.com"]

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "guardrail-e2e")])
now = datetime.datetime.now(datetime.UTC)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False)
    .sign(key, hashes.SHA256())
)
(out / "e2e-key.pem").write_bytes(
    key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
)
(out / "e2e-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print(out)
