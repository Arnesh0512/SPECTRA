from pathlib import Path
import tempfile
import sys
from spectra.scanners.source.python_scanner import PythonASTScanner
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXPANDED_SNIPPET = """
import hashlib
import hmac
import ssl
import secrets
import random

# 1. cryptography hazmat - Asymmetric & Curves
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography import x509

key_rsa_weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
key_rsa_ok = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_p256 = ec.generate_private_key(ec.SECP256R1())
key_p384 = ec.generate_private_key(ec.SECP384R1())
key_k1 = ec.generate_private_key(ec.SECP256K1())
key_dsa = dsa.generate_private_key(key_size=1024)
key_ed = ed25519.Ed25519PrivateKey.generate()
key_x = x25519.X25519PrivateKey.generate()

# 2. cryptography hazmat - Symmetric Ciphers & Modes
c_ecb = Cipher(algorithms.AES(b"0123456789abcdef"), modes.ECB())
c_gcm = Cipher(algorithms.AES(b"0123456789abcdef"), modes.GCM(b"123456789012"))

# 3. Serialization & Certificate Loaders (CodeQL Targets)
loaded_priv = serialization.load_pem_private_key(b"dummy_pem", password=None)
loaded_pub = serialization.load_pem_public_key(b"dummy_pem")
cert = x509.load_pem_x509_certificate(b"dummy_cert")

# 4. PyCryptodome / PyCrypto - Legacy Ciphers & Insecure Modes
from Crypto.Cipher import AES as PyCryptoAES, DES, DES3, ARC4, Blowfish, ChaCha20_Poly1305
from Crypto.PublicKey import RSA as PyCryptoRSA, ECC as PyCryptoECC

pc_aes_ecb = PyCryptoAES.new(b"0123456789abcdef", PyCryptoAES.MODE_ECB)
pc_des = DES.new(b"12345678", DES.MODE_ECB)
pc_des3 = DES3.new(b"1234567812345678", DES3.MODE_ECB)
pc_rc4 = ARC4.new(b"secretkey")
pc_bf = Blowfish.new(b"secretkey")
pc_chacha = ChaCha20_Poly1305.new(key=b"0123456789abcdef0123456789abcdef")
pc_rsa_weak = PyCryptoRSA.generate(1024)
pc_ecc = PyCryptoECC.generate(curve="P-256")

# 5. Pure Python ECC Libraries (python-ecdsa, coincurve, fastecdsa)
import ecdsa
from coincurve import PrivateKey as CoincurvePrivateKey
from fastecdsa import keys as fastecdsa_keys

ecdsa_weak = ecdsa.SigningKey.generate(curve=ecdsa.curves.NIST192p)
ecdsa_secp = ecdsa.SigningKey.generate(curve=ecdsa.curves.SECP256k1)
cc_key = CoincurvePrivateKey()
fast_key = fastecdsa_keys.gen_keypair(curve=ecdsa.curves.NIST256p)

# 6. PyNaCl (libsodium bindings)
import nacl.public
import nacl.signing
import nacl.secret

nacl_box_key = nacl.public.PrivateKey.generate()
nacl_sign_key = nacl.signing.SigningKey.generate()
nacl_secret_box = nacl.secret.SecretBox(b"0123456789abcdef0123456789abcdef")

# 7. Hash Functions & HMACs
md5_hash = hashlib.md5(b"test")
sha1_hash = hashlib.sha1(b"test")
sha256_hash = hashlib.sha256(b"test")
sha3_hash = hashlib.sha3_256(b"test")
blake_hash = hashlib.blake2b(b"test")
hmac_bad = hmac.new(b"secret", digestmod=hashlib.md5)
hmac_ok = hmac.new(b"secret", digestmod=hashlib.sha256)

# 8. Python-RSA & M2Crypto
import rsa as py_rsa
rsa_keys = py_rsa.newkeys(1024)

# 9. SSL & Secrets / PRNG
ctx_bad = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
csprng = secrets.token_bytes(32)
insecure_rand = random.random()
insecure_randint = random.randint(1, 100)
"""

with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
    f.write(EXPANDED_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = PythonASTScanner(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print(f"\n======================================================================")
    print(f"  AST EXHAUSTIVE CRYPTO RECON SCAN: {len(findings)} TOTAL FINDINGS DETECTED")
    print(f"======================================================================\n")

    # Metrics aggregation
    critical_issues = 0
    high_issues = 0
    curve_extracted_count = 0
    quantum_safe_count = 0

    for idx, raw in enumerate(findings, 1):
        asset = normalizer.normalize(raw.to_dict())
        issues = [iss["issue"] for iss in asset.security_findings]
        
        for iss in asset.security_findings:
            sev = iss.get("severity", "").upper()
            if sev == "CRITICAL":
                critical_issues += 1
            elif sev == "HIGH":
                high_issues += 1

        if asset.curve:
            curve_extracted_count += 1
        if asset.quantum_safe:
            quantum_safe_count += 1

        # Format console log
        print(f"[{idx:02d}] {asset.algorithm:<15} | Name: {asset.name:<25} | Primitive: {asset.primitive:<22}")
        if asset.curve:
            print(f"     └─ Curve:     {asset.curve}")
        if asset.key_size:
            print(f"     └─ Key Size:  {asset.key_size} bits")
        if asset.mode:
            print(f"     └─ Mode:      {asset.mode}")
        if raw.operation:
            print(f"     └─ Operation: {raw.operation}")
        if issues:
            print(f"     └─ Issues ({len(issues)}): {issues}")

    print(f"\n======================================================================")
    print(f"  SCAN SUMMARY STATISTICS")
    print(f"======================================================================")
    print(f"  Total Assets Normalized: {len(findings)}")
    print(f"  Curves Extracted:        {curve_extracted_count}")
    print(f"  Critical Issues Flagged: {critical_issues}")
    print(f"  High Severity Issues:    {high_issues}")
    print(f"  Quantum-Safe Assets:     {quantum_safe_count}")
    print(f"======================================================================\n")

finally:
    temp_path.unlink(missing_ok=True)