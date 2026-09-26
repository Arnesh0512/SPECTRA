from pathlib import Path
import tempfile
from spectra.scanners.source.go_scanner import GoScanner
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXHAUSTIVE_GO_SNIPPET = """
package main

import (
    "crypto/aes"
    "crypto/des"
    "crypto/rc4"
    "crypto/cipher"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/ecdh"
    "crypto/elliptic"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/sha1"
    "crypto/md5"
    "crypto/hmac"
    "crypto/tls"
    cryptoRand "crypto/rand"
    mathRand "math/rand"

    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/nacl/secretbox"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/argon2"

    "github.com/cloudflare/circl/kem/kyber/kyber768"
    "github.com/cloudflare/circl/sign/dilithium"
    "github.com/cloudflare/circl/sign/sphincs"
)

func executeComprehensiveCrypto() {
    // -------------------------------------------------------------
    // 1. Symmetric Ciphers & Modes
    // -------------------------------------------------------------
    blockAes, _ := aes.NewCipher(key)
    blockDes, _ := des.NewCipher(key)
    block3Des, _ := des.NewTripleDESCipher(key)
    streamRc4, _ := rc4.NewCipher(key)

    gcm, _ := cipher.NewGCM(blockAes)
    cbcEnc := cipher.NewCBCEncrypter(blockAes, iv)
    cbcDec := cipher.NewCBCDecrypter(blockAes, iv)
    ctr := cipher.NewCTR(blockAes, iv)

    // -------------------------------------------------------------
    // 2. RSA Key Generation & Modulus Sizes
    // -------------------------------------------------------------
    privWeakRsa, _ := rsa.GenerateKey(cryptoRand.Reader, 1024)
    privOkRsa, _ := rsa.GenerateKey(cryptoRand.Reader, 2048)

    // -------------------------------------------------------------
    // 3. Elliptic Curves & Asymmetric Keygens
    // -------------------------------------------------------------
    curveP256 := elliptic.P256()
    curveP384 := elliptic.P384()
    curveP521 := elliptic.P521()

    privEcdsa, _ := ecdsa.GenerateKey(curveP256, cryptoRand.Reader)
    pubEd, privEd, _ := ed25519.GenerateKey(cryptoRand.Reader)

    ecdhP256 := ecdh.P256()
    ecdhP384 := ecdh.P384()
    ecdhX25519 := ecdh.X25519()

    // -------------------------------------------------------------
    // 4. Hash Functions & HMAC
    // -------------------------------------------------------------
    hSha256 := sha256.New()
    hSha512 := sha512.New()
    hSha1 := sha1.New()
    hMd5 := md5.New()
    hMac := hmac.New(sha256.New, key)

    // -------------------------------------------------------------
    // 5. TLS Configurations & Protocol Versions
    // -------------------------------------------------------------
    badTlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS10,
    }
    goodTlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS13,
    }

    // -------------------------------------------------------------
    // 6. Extended x/crypto Packages
    // -------------------------------------------------------------
    aeadChaCha, _ := chacha20poly1305.New(key)
    var sealedBox [64]byte
    secretbox.Seal(sealedBox[:0], message, &nonce, &secretKey)
    var sharedSecret [32]byte
    curve25519.X25519(sharedSecret[:], privKey[:], pubKey[:])
    hSha3 := sha3.New256()
    kdfArgon := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

    // -------------------------------------------------------------
    // 7. Post-Quantum Cryptography (CIRCL)
    // -------------------------------------------------------------
    pubKyber, privKyber, _ := kyber768.GenerateKeyPair()
    pubDilithium, privDilithium, _ := dilithium.GenerateKey()
    pubSphincs, privSphincs, _ := sphincs.GenerateKey()

    // -------------------------------------------------------------
    // 8. Randomness: Secure CSPRNG vs Weak PRNG
    // -------------------------------------------------------------
    buf := make([]byte, 32)
    cryptoRand.Read(buf)
    mathRand.Read(buf)
}
"""

with tempfile.NamedTemporaryFile("w", suffix=".go", delete=False, encoding="utf-8") as f:
    f.write(EXHAUSTIVE_GO_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = GoScanner(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print("\n" + "=" * 70)
    print(f"  GO EXHAUSTIVE CRYPTO RECON: {len(findings)} FINDINGS DETECTED")
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

        print(f"[{idx:02d}] {asset.algorithm:<20} | Name: {asset.name:<28} | Primitive: {asset.primitive:<22}")
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