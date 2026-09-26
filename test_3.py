from pathlib import Path
import tempfile
from spectra.scanners.source.js_ts_scanner import JSTSSParser
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXHAUSTIVE_JSTS_SNIPPET = """
import crypto from 'node:crypto';
import CryptoJS from 'crypto-js';
import forge from 'node-forge';
import * as secp from '@noble/curves/secp256k1';
import * as ed from '@noble/curves/ed25519';
import nacl from 'tweetnacl';

// 1. Node.js Symmetric Ciphers & Modes
const cEcb = crypto.createCipheriv('aes-128-ecb', key, null);
const cGcm = crypto.createCipheriv('aes-256-gcm', key, iv);
const cDes = crypto.createCipheriv('des-cbc', key, iv);
const c3Des = crypto.createCipheriv('des-ede3-cbc', key, iv);
const cRc4 = crypto.createCipheriv('rc4', key, null);

// 2. Node.js Asymmetric Key Pairs & Key Size
crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
crypto.generateKeyPairSync('dsa', { modulusLength: 1024 });
crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
crypto.generateKeyPairSync('ed25519');

// 3. Node.js Diffie-Hellman & ECDH Curves
const ecdh1 = crypto.createECDH('secp256k1');
const ecdh2 = crypto.createECDH('secp384r1');

// 4. Node.js Signatures, Hashes & MACs
const sig1 = crypto.createSign('SHA1');
const sig2 = crypto.createSign('SHA256');
const hash1 = crypto.createHash('md5');
const hash2 = crypto.createHash('sha256');
const hash3 = crypto.createHash('sha512');
const hmac1 = crypto.createHmac('sha1', 'secret');
const hmac2 = crypto.createHmac('sha256', 'secret');

// 5. Browser WebCrypto Subtle (RSA, AES, ECDSA, SHA-256)
window.crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024 }, true, ['encrypt']);
window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
window.crypto.subtle.digest('SHA-256', data);
window.crypto.subtle.digest('SHA-1', data);

// 6. CryptoJS Operations & Insecure ECB Mode
const cjsAesEcb = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB });
const cjsDes = CryptoJS.DES.encrypt(msg, key);
const cjs3Des = CryptoJS.TripleDES.encrypt(msg, key);
const cjsMd5 = CryptoJS.MD5(msg);
const cjsSha1 = CryptoJS.SHA1(msg);
const cjsSha256 = CryptoJS.SHA256(msg);
const cjsHmac = CryptoJS.HmacSHA256(msg, 'secret');

// 7. Node Forge RSA & Hashes
forge.rsa.generateKeyPair({ bits: 1024 });
forge.md.md5.create();
forge.md.sha256.create();

// 8. Modern Noble Curves & TweetNaCl
secp.secp256k1.getPublicKey(privKey);
ed.ed25519.getPublicKey(privKey);
nacl.sign.keyPair();
nacl.box.keyPair();
nacl.secretbox(msg, nonce, key);

// 9. Randomness: CSPRNG vs Insecure Math.random
const randomBytes = crypto.randomBytes(32);
const csprngWeb = window.crypto.getRandomValues(new Uint8Array(16));
const insecureRand = Math.random();
"""

with tempfile.NamedTemporaryFile("w", suffix=".ts", delete=False, encoding="utf-8") as f:
    f.write(EXHAUSTIVE_JSTS_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = JSTSSParser(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print("\n" + "=" * 70)
    print(f"  JS/TS EXHAUSTIVE CRYPTO RECON: {len(findings)} FINDINGS DETECTED")
    print("=" * 70 + "\n")

    critical_count = 0
    high_count = 0
    curve_count = 0
    quantum_safe_count = 0

    for idx, raw in enumerate(findings, 1):
        asset = normalizer.normalize(raw.to_dict())
        issues = [iss["issue"] for iss in asset.security_findings]

        for iss in asset.security_findings:
            sev = iss.get("severity", "").upper()
            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1

        if asset.curve:
            curve_count += 1
        if asset.quantum_safe:
            quantum_safe_count += 1

        print(f"[{idx:02d}] {asset.algorithm:<18} | Name: {asset.name:<26} | Primitive: {asset.primitive:<22}")
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

    print("\n" + "=" * 70)
    print("  SCAN SUMMARY STATISTICS")
    print("=" * 70)
    print(f"  Total Assets Normalized: {len(findings)}")
    print(f"  Curves Extracted:        {curve_count}")
    print(f"  Critical Issues Flagged: {critical_count}")
    print(f"  High Severity Issues:    {high_count}")
    print(f"  Quantum-Safe Assets:     {quantum_safe_count}")
    print("=" * 70 + "\n")

finally:
    temp_path.unlink(missing_ok=True)