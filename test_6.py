from pathlib import Path
import tempfile
from spectra.scanners.source.rust_scanner import RustScanner
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXHAUSTIVE_RUST_SNIPPET = """
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use ring::agreement::{X25519, ECDH_P256, ECDH_P384};
use ring::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256};
use ring::digest::{SHA256, SHA512};
use aes_gcm::Aes256Gcm;
use rsa::RsaPrivateKey;
use p256::SecretKey as P256Key;
use p384::SecretKey as P384Key;
use k256::SecretKey as Secp256k1Key;
use ed25519_dalek::SigningKey;
use sha2::Sha256;
use md5::Md5;
use sha1::Sha1;
use rand::rngs::OsRng;
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincsplus;

fn execute_rust_crypto() {
    // 1. RustCrypto Symmetric Ciphers & Modes
    let cipher = Aes256Gcm::new(&key);
    let broken_des = Des::new(&key);
    let broken_rc4 = Rc4::new(&key);

    // 2. Ring AEAD, Agreement, Signatures, Digests
    let _aead1 = AES_256_GCM;
    let _aead2 = CHACHA20_POLY1305;
    let _kx1 = X25519;
    let _kx2 = ECDH_P256;
    let _kx3 = ECDH_P384;
    let _sig1 = ED25519;
    let _sig2 = RSA_PKCS1_2048_8192_SHA256;
    let _h1 = SHA256;
    let _h2 = SHA512;

    // 3. RSA Key Generation & Modulus Audits
    let mut rng = OsRng;
    let rsa_weak = RsaPrivateKey::new(&mut rng, 1024).expect("keysize");
    let rsa_ok = RsaPrivateKey::new(&mut rng, 2048).expect("keysize");

    // 4. CodeQL Targets: PKCS#8 Deserialization
    let priv_pem = RsaPrivateKey::from_pkcs8_pem(pem_str).unwrap();
    let priv_der = SigningKey::from_pkcs8_der(der_bytes).unwrap();

    // 5. RustCrypto Curves
    let ec1 = P256Key::random(&mut OsRng);
    let ec2 = P384Key::random(&mut OsRng);
    let ec3 = Secp256k1Key::random(&mut OsRng);
    let ed = SigningKey::generate(&mut OsRng);

    // 6. Hashes
    let _h_sha = Sha256::new();
    let _h_md5 = Md5::new();
    let _h_sha1 = Sha1::new();

    // 7. CodeQL Targets: Rustls Configuration & Server Bind
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults();
    let listener = TcpListener::bind("127.0.0.1:443").await.unwrap();

    // 8. CodeQL Targets: Direct Operational Calls
    cipher.encrypt(nonce, plaintext);
    cipher.decrypt(nonce, ciphertext);
    signer.sign(data);
    verifier.verify(data, signature);

    // 9. Post-Quantum Cryptography (PQC)
    let (pk_k, sk_k) = kyber768::keypair();
    let (pk_d, sk_d) = dilithium3::keypair();
    let (pk_s, sk_s) = sphincsplus::keypair();

    // 10. Randomness
    let secure_rng = OsRng;
    let standard_rng = thread_rng();
}
"""

with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False, encoding="utf-8") as f:
    f.write(EXHAUSTIVE_RUST_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = RustScanner(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print("\n" + "=" * 70)
    print(f"  RUST EXHAUSTIVE CRYPTO RECON: {len(findings)} FINDINGS DETECTED")
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