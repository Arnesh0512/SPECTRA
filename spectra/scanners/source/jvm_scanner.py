"""
spectra.scanners.source.jvm_scanner
========================================
Java and Kotlin source code cryptographic scanner.
Extracts JCA/JCE transformations, KeyPairGenerators, KeyStores, EC curves,
SSLContext configurations, and Bouncy Castle PQC implementations.
"""

from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# Match factory patterns: Class.getInstance("ALGORITHM", ...)
JCA_FACTORY_REGEX = re.compile(
    r'\b(?P<class>Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Signature|Mac|KeyStore|CertificateFactory|SSLContext|SecretKeyFactory|KeyAgreement|SecureRandom)'
    r'\s*\.\s*getInstance\s*\(\s*["\'](?P<spec>[^"\']+)["\']',
    re.IGNORECASE
)

# Match KeyPairGenerator / KeyGenerator initializations: .initialize(2048), .init(1024)
KEY_INIT_REGEX = re.compile(
    r'\b(?P<caller>[a-zA-Z0-9_]+)\s*\.\s*(?:initialize|init)\s*\(\s*(?P<size>\d+)\s*\)',
    re.IGNORECASE
)

# Match Elliptic Curve parameter spec: new ECGenParameterSpec("secp256r1")
EC_SPEC_REGEX = re.compile(
    r'new\s+ECGenParameterSpec\s*\(\s*["\'](?P<curve>[^"\']+)["\']\s*\)',
    re.IGNORECASE
)

# Match CodeQL operational method calls: obj.sign(), obj.verify(), obj.doFinal(), obj.load()
METHOD_CALL_REGEX = re.compile(
    r'\b(?P<var>[a-zA-Z0-9_]+)\s*\.\s*(?P<method>doFinal|sign|verify|digest|update|load|generateCertificate)\s*\(',
    re.IGNORECASE
)

# Match direct Bouncy Castle or standard PQC instantiations
BC_PQC_REGEX = re.compile(
    r'new\s+(?P<class>(MLKEM|Kyber|MLDSA|Dilithium|SLHDSA|SPHINCSPlus|Falcon|BIKE|HQC)KeyPairGenerator)\s*\(',
    re.IGNORECASE
)


class JVMScanner(BaseSourceScanner):
    """Scanner for Java (.java) and Kotlin (.kt) source files."""

    def supported_extensions(self) -> List[str]:
        return [".java", ".kt"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        # Local state to correlate variables with algorithms
        var_to_algo: Dict[str, str] = {}

        for line_idx, line in enumerate(lines, start=1):
            clean_line = line.strip()
            if clean_line.startswith("//") or clean_line.startswith("/*") or clean_line.startswith("*"):
                continue

            # 1. JCA Factory calls: Class.getInstance("...")
            for match in JCA_FACTORY_REGEX.finditer(line):
                class_name = match.group("class")
                spec_str = match.group("spec").strip()
                col = match.start()

                finding = self._process_jca_factory_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    class_name=class_name,
                    spec=spec_str
                )
                if finding:
                    findings.append(finding)

                    # Extract variable assignment: Cipher c = Cipher.getInstance(...)
                    assign_match = re.search(rf'([a-zA-Z0-9_]+)\s*=\s*{class_name}\.getInstance', line)
                    if assign_match:
                        var_to_algo[assign_match.group(1)] = finding.algorithm

            # 2. Key Size Initializations: .initialize(2048), .init(1024)
            for match in KEY_INIT_REGEX.finditer(line):
                var_name = match.group("caller")
                key_size = int(match.group("size"))
                col = match.start()

                associated_algo = var_to_algo.get(var_name, "ASYMMETRIC-KEY")
                sec_findings = []
                if key_size < 2048 and any(x in associated_algo.upper() for x in ["RSA", "DSA", "ASYMMETRIC"]):
                    sec_findings.append({
                        "issue": f"Key size ({key_size} bits) is below the minimum recommended threshold (2048 bits)",
                        "severity": "HIGH"
                    })

                snippet = self.extract_snippet(file_path, line_idx)
                findings.append(
                    SourceFinding(
                        source_domain="source_code",
                        language="jvm",
                        file_path=str(file_path.resolve()),
                        line_number=line_idx,
                        column_number=col,
                        code_snippet=snippet,
                        primitive="public_key",
                        algorithm=associated_algo,
                        key_size=key_size,
                        quantum_safe=False,
                        nist_status="deprecated_pqc" if "RSA" in associated_algo else "unknown",
                        security_findings=sec_findings,
                        raw_metadata={"caller": var_name, "key_size": key_size}
                    )
                )

            # 3. Elliptic Curve Parameter Specs: new ECGenParameterSpec("secp256r1")
            for match in EC_SPEC_REGEX.finditer(line):
                raw_curve = match.group("curve").strip()
                col = match.start()
                canonical_curve = self._resolve_curve_name(raw_curve)

                sec_findings = []
                if "192" in raw_curve.lower() or "160" in raw_curve.lower():
                    sec_findings.append({
                        "issue": f"Insecure or deprecated elliptic curve specified: {raw_curve}",
                        "severity": "HIGH"
                    })

                snippet = self.extract_snippet(file_path, line_idx)
                findings.append(
                    SourceFinding(
                        source_domain="source_code",
                        language="jvm",
                        file_path=str(file_path.resolve()),
                        line_number=line_idx,
                        column_number=col,
                        code_snippet=snippet,
                        primitive="public_key",
                        algorithm="ECC",
                        curve=canonical_curve,
                        quantum_safe=False,
                        nist_status="deprecated_pqc",
                        security_findings=sec_findings,
                        raw_metadata={"raw_curve": raw_curve}
                    )
                )

            # 4. CodeQL Operations: obj.sign(), obj.verify(), obj.doFinal()
            for match in METHOD_CALL_REGEX.finditer(line):
                var_name = match.group("var")
                method_name = match.group("method")
                col = match.start()

                # If variable was tracked from a previous factory call
                if var_name in var_to_algo:
                    associated_algo = var_to_algo[var_name]
                    op_name = self._map_method_to_operation(method_name)
                    snippet = self.extract_snippet(file_path, line_idx)

                    findings.append(
                        SourceFinding(
                            source_domain="source_code",
                            language="jvm",
                            file_path=str(file_path.resolve()),
                            line_number=line_idx,
                            column_number=col,
                            code_snippet=snippet,
                            primitive="cryptographic_operation",
                            algorithm=associated_algo,
                            operation=op_name,
                            quantum_safe=False,
                            nist_status="operational",
                            security_findings=[],
                            raw_metadata={"method_call": method_name, "receiver": var_name}
                        )
                    )

            # 5. Direct Bouncy Castle PQC Instantiations
            for match in BC_PQC_REGEX.finditer(line):
                class_name = match.group("class")
                col = match.start()
                finding = self._process_bc_pqc_finding(file_path, line_idx, col, class_name)
                if finding:
                    findings.append(finding)

        return findings

    def _process_jca_factory_finding(
        self,
        file_path: Path,
        line_idx: int,
        col: int,
        class_name: str,
        spec: str
    ) -> Optional[SourceFinding]:
        algo_name, mode, padding = self._parse_transformation(spec)
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(algo_name)

        # Lookup rule metadata
        rule_algo_name = algo_rule.name if algo_rule else algo_name
        primitive = algo_rule.primitive if algo_rule else self._map_class_to_primitive(class_name)
        quantum_safe = algo_rule.quantum_safe if algo_rule else False
        nist_status = algo_rule.nist_status if algo_rule else "unknown"


        sec_findings = []

        # Flag insecure cipher modes
        if mode and mode.upper() in ["ECB", "NONE"]:
            sec_findings.append({
                "issue": f"Insecure block cipher mode '{mode}' detected in transformation '{spec}'",
                "severity": "CRITICAL"
            })

        # Flag deprecated algorithms & signature digests
        spec_upper = spec.upper()
        if any(weak in spec_upper for weak in ["MD5", "SHA1", "DES", "3DES", "DESEDE", "RC4"]):
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic primitive or digest configured: {spec}",
                "severity": "HIGH"
            })

        # Flag weak TLS protocols in SSLContext.getInstance(...)
        if class_name == "SSLContext" and any(proto in spec_upper for proto in ["SSL", "TLSV1.0", "TLSV1.1"]):
            sec_findings.append({
                "issue": f"Deprecated and insecure TLS/SSL protocol version requested: {spec}",
                "severity": "CRITICAL"
            })

        # Flag insecure JKS KeyStores
        if class_name == "KeyStore" and spec_upper == "JKS":
            sec_findings.append({
                "issue": "Insecure legacy JKS KeyStore format used; migrate to PKCS12",
                "severity": "MEDIUM"
            })

        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="jvm",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=primitive,
            algorithm=rule_algo_name,
            mode=mode,
            padding=padding,
            operation=self._map_class_to_operation(class_name),
            quantum_safe=quantum_safe,
            nist_status=nist_status,
            security_findings=sec_findings,
            raw_metadata={"jca_class": class_name, "raw_spec": spec}
        )

    def _process_bc_pqc_finding(
        self,
        file_path: Path,
        line_idx: int,
        col: int,
        class_name: str
    ) -> SourceFinding:
        name_clean = class_name.replace("KeyPairGenerator", "")
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(name_clean)

        canonical_name = algo_rule.name if algo_rule else name_clean
        primitive = algo_rule.primitive if algo_rule else (
            "signature" if any(sig in canonical_name.upper() for sig in ["DSA", "DILITHIUM", "SPHINCS", "FALCON"]) 
            else "key_encapsulation"
        )
        nist_status = algo_rule.nist_status if algo_rule else "fips_pqc_standard"

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="jvm",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=primitive,
            algorithm=canonical_name,
            operation="keypair_generation",
            quantum_safe=True,
            nist_status=nist_status,
            security_findings=[],
            raw_metadata={"bouncy_castle_class": class_name}
        )

    def _parse_transformation(self, spec: str) -> Tuple[str, Optional[str], Optional[str]]:
        parts = spec.split("/")
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], None
        return spec, None, None

    def _resolve_curve_name(self, raw_curve: str) -> str:
        mapping = {
            "secp256r1": "NIST-P256",
            "prime256v1": "NIST-P256",
            "secp384r1": "NIST-P384",
            "secp521r1": "NIST-P521",
            "secp256k1": "secp256k1",
            "x25519": "X25519",
            "ed25519": "Ed25519",
        }
        return mapping.get(raw_curve.lower(), raw_curve)

    def _map_class_to_primitive(self, class_name: str) -> str:
        mapping = {
            "Cipher": "symmetric_cipher",
            "KeyGenerator": "symmetric_key_gen",
            "KeyPairGenerator": "public_key",
            "MessageDigest": "hash",
            "Signature": "signature",
            "Mac": "mac",
            "KeyStore": "key_management",
            "CertificateFactory": "certificate",
            "SSLContext": "secure_transport",
            "SecretKeyFactory": "key_derivation",
            "KeyAgreement": "key_exchange",
            "SecureRandom": "prng"
        }
        return mapping.get(class_name, "cryptographic_operation")

    def _map_class_to_operation(self, class_name: str) -> str:
        mapping = {
            "Cipher": "cipher_instantiation",
            "KeyGenerator": "key_generator_instantiation",
            "KeyPairGenerator": "keypair_generator_instantiation",
            "MessageDigest": "digest_instantiation",
            "Signature": "signature_instantiation",
            "Mac": "mac_instantiation",
            "KeyStore": "keystore_access",
            "CertificateFactory": "certificate_parsing",
            "SSLContext": "tls_session_init",
            "SecretKeyFactory": "key_derivation_init",
            "KeyAgreement": "key_agreement_init",
            "SecureRandom": "prng_instantiation"
        }
        return mapping.get(class_name, "instantiation")

    def _map_method_to_operation(self, method_name: str) -> str:
        mapping = {
            "doFinal": "encryption_or_decryption",
            "sign": "digital_signature_generation",
            "verify": "signature_verification",
            "digest": "digest_computation",
            "update": "stream_update",
            "load": "keystore_load",
            "generateCertificate": "certificate_generation"
        }
        return mapping.get(method_name, "cryptographic_execution")