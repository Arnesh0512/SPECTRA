from pathlib import Path
import tempfile
from spectra.scanners.source.cpp_scanner import CPPScanner
from spectra.engine.normalizer import AssetNormalizer
from spectra.scanners.source.rules import DEFAULT_RULE_ENGINE

EXHAUSTIVE_CPP_SNIPPET = """
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <oqs/oqs.h>
#include <stdlib.h>

void execute_crypto_suite() {
    // -------------------------------------------------------------
    // 1. OpenSSL Symmetric Ciphers & Modes
    // -------------------------------------------------------------
    const EVP_CIPHER* aes_ecb = EVP_aes_128_ecb();
    const EVP_CIPHER* aes_gcm = EVP_aes_256_gcm();
    const EVP_CIPHER* aes_cbc = EVP_aes_128_cbc();
    const EVP_CIPHER* des_ede = EVP_des_ede3_cbc();
    const EVP_CIPHER* des_cbc = EVP_des_cbc();
    const EVP_CIPHER* rc4 = EVP_rc4();
    const EVP_CIPHER* chacha = EVP_chacha20_poly1305();

    // -------------------------------------------------------------
    // 2. OpenSSL 3.0 Fetch API
    // -------------------------------------------------------------
    EVP_CIPHER* fetch_aes = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_CIPHER* fetch_ecb = EVP_CIPHER_fetch(NULL, "AES-128-ECB", NULL);
    EVP_MD* fetch_sha3 = EVP_MD_fetch(NULL, "SHA3-256", NULL);

    // -------------------------------------------------------------
    // 3. OpenSSL Hash & Digest Functions
    // -------------------------------------------------------------
    const EVP_MD* md5 = EVP_md5();
    const EVP_MD* sha1 = EVP_sha1();
    const EVP_MD* sha256 = EVP_sha256();
    const EVP_MD* sha512 = EVP_sha512();

    // -------------------------------------------------------------
    // 4. OpenSSL RSA Key Generation & Key Size Audits
    // -------------------------------------------------------------
    RSA* rsa_weak = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa_weak, 1024, e, NULL);

    EVP_PKEY_CTX* ctx_rsa_ok = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx_rsa_ok, 2048);

    // -------------------------------------------------------------
    // 5. OpenSSL Elliptic Curves (NIST & Insecure)
    // -------------------------------------------------------------
    EC_KEY* ec_p256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY* ec_p384 = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY* ec_k1 = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY* ec_x25519 = EC_KEY_new_by_curve_name(NID_X25519);
    EC_KEY* ec_weak = EC_KEY_new_by_curve_name(NID_secp192r1);

    // -------------------------------------------------------------
    // 6. Operational Lifecycles
    // -------------------------------------------------------------
    EVP_CIPHER_CTX* enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc_ctx, aes_gcm, NULL, key, iv);
    EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(sign_ctx, NULL, sha256, NULL, pkey);
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, "secret", 6, sha256, NULL);

    // -------------------------------------------------------------
    // 7. Libsodium Operations
    // -------------------------------------------------------------
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
    crypto_sign_keypair(pk, sk);
    crypto_secretbox_easy(cipher, msg, msg_len, nonce, key);

    // -------------------------------------------------------------
    // 8. Open Quantum Safe (liboqs PQC)
    // -------------------------------------------------------------
    OQS_KEM* kem_kyber = OQS_KEM_new("Kyber768");
    OQS_SIG* sig_dilithium = OQS_SIG_new("Dilithium3");
    OQS_SIG* sig_falcon = OQS_SIG_new("Falcon-512");
    OQS_SIG* sig_sphincs = OQS_SIG_new("SPHINCS+-SHA2-128s");

    // -------------------------------------------------------------
    // 9. Randomness: CSPRNG vs Insecure rand()
    // -------------------------------------------------------------
    unsigned char rand_buf[32];
    RAND_bytes(rand_buf, sizeof(rand_buf));
    randombytes_buf(rand_buf, sizeof(rand_buf));
    int insecure_number = rand();
}
"""

with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as f:
    f.write(EXHAUSTIVE_CPP_SNIPPET)
    temp_path = Path(f.name)

try:
    scanner = CPPScanner(rule_engine=DEFAULT_RULE_ENGINE)
    findings = scanner.parse_file(temp_path)
    normalizer = AssetNormalizer()

    print("\n" + "=" * 70)
    print(f"  C/C++ EXHAUSTIVE CRYPTO RECON: {len(findings)} FINDINGS DETECTED")
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

        print(f"[{idx:02d}] {asset.algorithm:<20} | Name: {asset.name:<26} | Primitive: {asset.primitive:<22}")
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