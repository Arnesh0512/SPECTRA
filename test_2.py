from pathlib import Path
import tempfile
from spectra.scanners.source.jvm_scanner import JVMScanner
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXHAUSTIVE_JVM_SNIPPET = """
package com.enterprise.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

// Bouncy Castle PQC generators
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;

public class CompleteCryptoAudit {
    public void executeComprehensiveSuite() throws Exception {
        // -------------------------------------------------------------
        // 1. Symmetric Ciphers & Mode Vulnerabilities
        // -------------------------------------------------------------
        Cipher cEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cEcb.doFinal(new byte[]{1, 2, 3});

        Cipher cGcm = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher cDes = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher c3Des = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher cRc4 = Cipher.getInstance("RC4");
        Cipher cBf = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        Cipher cChaCha = Cipher.getInstance("ChaCha20");

        // -------------------------------------------------------------
        // 2. Asymmetric Key Pair Generators & Key Size Flags
        // -------------------------------------------------------------
        KeyPairGenerator kpgRsaWeak = KeyPairGenerator.getInstance("RSA");
        kpgRsaWeak.initialize(1024);

        KeyPairGenerator kpgRsaOk = KeyPairGenerator.getInstance("RSA");
        kpgRsaOk.initialize(2048);

        KeyPairGenerator kpgDsaWeak = KeyPairGenerator.getInstance("DSA");
        kpgDsaWeak.initialize(1024);

        // -------------------------------------------------------------
        // 3. Elliptic Curve Parameter Specs (Standard & Insecure)
        // -------------------------------------------------------------
        KeyPairGenerator kpgEc = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecP256 = new ECGenParameterSpec("secp256r1");
        ECGenParameterSpec ecP384 = new ECGenParameterSpec("secp384r1");
        ECGenParameterSpec ecP521 = new ECGenParameterSpec("secp521r1");
        ECGenParameterSpec ecK1 = new ECGenParameterSpec("secp256k1");
        ECGenParameterSpec ecX25519 = new ECGenParameterSpec("X25519");
        ECGenParameterSpec ecEd25519 = new ECGenParameterSpec("Ed25519");
        ECGenParameterSpec ecWeak = new ECGenParameterSpec("secp192r1");

        // -------------------------------------------------------------
        // 4. Digital Signatures & Insecure Digest Combinations
        // -------------------------------------------------------------
        Signature sigMd5Rsa = Signature.getInstance("MD5withRSA");
        Signature sigSha1Rsa = Signature.getInstance("SHA1withRSA");
        sigSha1Rsa.sign();

        Signature sigSha256Ec = Signature.getInstance("SHA256withECDSA");
        sigSha256Ec.verify(new byte[]{});

        Signature sigSha384Rsa = Signature.getInstance("SHA384withRSA");

        // -------------------------------------------------------------
        // 5. Message Authentication Codes (MAC)
        // -------------------------------------------------------------
        Mac macMd5 = Mac.getInstance("HmacMD5");
        Mac macSha1 = Mac.getInstance("HmacSHA1");
        Mac macSha256 = Mac.getInstance("HmacSHA256");
        macSha256.doFinal(new byte[]{});

        // -------------------------------------------------------------
        // 6. Cryptographic Hash Functions
        // -------------------------------------------------------------
        MessageDigest mdMd5 = MessageDigest.getInstance("MD5");
        MessageDigest mdSha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest mdSha256 = MessageDigest.getInstance("SHA-256");
        mdSha256.digest(new byte[]{});
        MessageDigest mdSha512 = MessageDigest.getInstance("SHA-512");

        // -------------------------------------------------------------
        // 7. Key Agreement & Key Derivation
        // -------------------------------------------------------------
        KeyAgreement kaDiffieHellman = KeyAgreement.getInstance("DH");
        SecretKeyFactory skfPbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        // -------------------------------------------------------------
        // 8. KeyStore & Certificate Parsing
        // -------------------------------------------------------------
        KeyStore ksJks = KeyStore.getInstance("JKS");
        ksJks.load(null, null);

        KeyStore ksPkcs12 = KeyStore.getInstance("PKCS12");
        CertificateFactory cfX509 = CertificateFactory.getInstance("X.509");

        // -------------------------------------------------------------
        // 9. TLS / SSL Transport Contexts
        // -------------------------------------------------------------
        SSLContext sslV3 = SSLContext.getInstance("SSLv3");
        SSLContext tls10 = SSLContext.getInstance("TLSv1");
        SSLContext tls13 = SSLContext.getInstance("TLSv1.3");

        // -------------------------------------------------------------
        // 10. Randomness: CSPRNG vs Weak PRNG
        // -------------------------------------------------------------
        SecureRandom csprng1 = new SecureRandom();
        SecureRandom csprng2 = SecureRandom.getInstance("SHA1PRNG");

        // -------------------------------------------------------------
        // 11. Bouncy Castle Post-Quantum Cryptography (NIST PQC)
        // -------------------------------------------------------------
        KyberKeyPairGenerator bcKyber = new KyberKeyPairGenerator();
        DilithiumKeyPairGenerator bcDilithium = new DilithiumKeyPairGenerator();
        SPHINCSPlusKeyPairGenerator bcSphincs = new SPHINCSPlusKeyPairGenerator();
        FalconKeyPairGenerator bcFalcon = new FalconKeyPairGenerator();
        BIKEKeyPairGenerator bcBike = new BIKEKeyPairGenerator();
        HQCKeyPairGenerator bcHqc = new HQCKeyPairGenerator();
    }
}
"""

with tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8") as f:
    f.write(EXHAUSTIVE_JVM_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = JVMScanner(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print("\n" + "=" * 70)
    print(f"  JVM EXHAUSTIVE CRYPTO RECON: {len(findings)} FINDINGS DETECTED")
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