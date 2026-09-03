"""Mobile Security Agent — OWASP MASVS L1/L2 compliance scanning.

Scans mobile app source code and configuration files for:
- MASVS-STORAGE: Insecure data storage (NSUserDefaults, SharedPreferences, SQLite plaintext)
- MASVS-CRYPTO: Weak cryptography, hardcoded keys in mobile code
- MASVS-AUTH: Biometric bypass, missing device binding, weak session handling
- MASVS-NETWORK: Cleartext traffic, certificate pinning missing, insecure WebView
- MASVS-PLATFORM: WebView JS enabled, file:// access, intent schemes
- MASVS-CODE: Debuggable, backup enabled, code obfuscation missing

Supports: Flutter (Dart), React Native (JS/TS), Android (Kotlin/Java), iOS (Swift)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.security.mobile_security_agent")


@register
class MobileSecurityAgent(BaseAgent):
    """Check mobile app code for OWASP MASVS compliance violations."""

    group = AgentGroup.SECURITY
    name = "MobileSecurityAgent"
    description = "OWASP MASVS L1/L2 compliance scanning"

    # ── MASVS-STORAGE: Positive patterns (found = issue) ──
    STORAGE_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "nsuserdefaults_sensitive",
            r"UserDefaults\.standard",
            "iOS UserDefaults used for sensitive data (MASVS-STORAGE-1)",
            Severity.HIGH,
        ),
        (
            "sharedprefs_sensitive",
            r"SharedPreferences",
            "Android SharedPreferences stores data in plaintext (MASVS-STORAGE-1)",
            Severity.HIGH,
        ),
        (
            "sqlite_plaintext",
            r"(RawQuery|rawQuery|database\.execSQL)\s*\([^)]*?(password|secret|token|ssn|cvv)",
            "SQLite plaintext query with sensitive data (MASVS-STORAGE-2)",
            Severity.HIGH,
        ),
        (
            "nsdata_plaintext",
            r"writeToFile.*atomically",
            "NSData writeToFile stores unencrypted data (MASVS-STORAGE-3)",
            Severity.MEDIUM,
        ),
        (
            "firestore_sensitive",
            r"\.setData\s*\([^)]*?(password|secret|token|ssn|cvv)",
            "Sensitive data in Firestore without encryption (MASVS-STORAGE-4)",
            Severity.MEDIUM,
        ),
        (
            "flutter_local_storage",
            r"SharedPreferences\.getInstance.*(password|token|secret|key)",
            "Flutter local storage with sensitive data (MASVS-STORAGE-1)",
            Severity.HIGH,
        ),
        (
            "react_native_async",
            r"AsyncStorage\.setItem.*(password|token|secret|key)",
            "React Native AsyncStorage with sensitive data (MASVS-STORAGE-1)",
            Severity.HIGH,
        ),
    ]

    # ── MASVS-CRYPTO: Positive patterns (found = issue) ──
    CRYPTO_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "md5_in_mobile",
            r"MessageDigest\.getInstance\(\"MD5\"\)",
            "MD5 hash used in mobile app (MASVS-CRYPTO-1)",
            Severity.MEDIUM,
        ),
        (
            "aes_ecb",
            r"AES/(ECB|CBC)/PKCS5Padding",
            "AES-ECB mode used (MASVS-CRYPTO-1)",
            Severity.HIGH,
        ),
        (
            "hardcoded_key_mobile",
            r"(secretKey|SecretKeySpec|keyBytes)\s*=\s*['\"][a-zA-Z0-9+/=]{16,}['\"]",
            "Hardcoded cryptographic key (MASVS-CRYPTO-2)",
            Severity.CRITICAL,
        ),
        (
            "base64_encoding",
            r"Base64\.encodeToString.*(password|secret|token)",
            "Base64 encoding used instead of encryption (MASVS-CRYPTO-1)",
            Severity.HIGH,
        ),
        (
            "obfuscated_secret",
            r"String\.format.*%s.*(password|secret).*reverse",
            "Obvious obfuscation of secrets (MASVS-CRYPTO-3)",
            Severity.MEDIUM,
        ),
        (
            "flutter_insecure_random",
            r"\bRandom\(\)",
            "Insecure Random() without cryptographically secure source (MASVS-CRYPTO-4)",
            Severity.MEDIUM,
        ),
    ]

    # ── MASVS-NETWORK: Positive patterns (found = issue) ──
    NETWORK_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "cleartext_traffic",
            r"android:usesCleartextTraffic=\"true\"",
            "Cleartext HTTP traffic allowed (MASVS-NETWORK-1)",
            Severity.HIGH,
        ),
        (
            "nsc_cleartext",
            r"NSAppTransportSecurity.*NSAllowsArbitraryLoads\s*=\s*true",
            "ATS allows arbitrary loads — cleartext traffic (MASVS-NETWORK-1)",
            Severity.HIGH,
        ),
        (
            "flutter_http",
            r"http://[^s]",
            "Unencrypted HTTP connection in Flutter (MASVS-NETWORK-1)",
            Severity.HIGH,
        ),
        (
            "react_native_http",
            r"fetch\(['\"]http://",
            "Unencrypted HTTP fetch in React Native (MASVS-NETWORK-1)",
            Severity.HIGH,
        ),
        (
            "websocket_unencrypted",
            r"WebSocket\(['\"]ws://",
            "Unencrypted WebSocket connection (MASVS-NETWORK-1)",
            Severity.HIGH,
        ),
    ]

    # ── MASVS-PLATFORM: Positive patterns (found = issue) ──
    PLATFORM_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "webview_js_enabled",
            r"webView\.settings\.javaScriptEnabled\s*=\s*true",
            "WebView JavaScript enabled (MASVS-PLATFORM-1)",
            Severity.HIGH,
        ),
        (
            "webview_file_access",
            r"webView\.settings\.allowFileAccess\s*=\s*true",
            "WebView file access enabled (MASVS-PLATFORM-1)",
            Severity.HIGH,
        ),
        (
            "intent_scheme",
            r"intent://[^?]*?",
            "Intent scheme URL handler — verify input validation (MASVS-PLATFORM-2)",
            Severity.MEDIUM,
        ),
        (
            "exposed_activity",
            r"android:exported=\"true\"",
            "Exported Android activity (MASVS-PLATFORM-3)",
            Severity.MEDIUM,
        ),
        (
            "flutter_javascript_channel",
            r"JavascriptChannel|javascriptMode:",
            "Flutter JavaScript channel enabled (MASVS-PLATFORM-1)",
            Severity.HIGH,
        ),
        (
            "deep_link_validation",
            r"autoVerify\s*=\s*true|intent-filter.*android:autoVerify",
            "Deep link auto-verify — validate URL handling (MASVS-PLATFORM-2)",
            Severity.MEDIUM,
        ),
        (
            "react_native_webview_js",
            r"source=\{\{uri|injectedJavaScript",
            "React Native WebView with JS execution (MASVS-PLATFORM-1)",
            Severity.HIGH,
        ),
    ]

    # ── MASVS-CODE: Positive patterns (found = issue) ──
    CODE_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "debuggable",
            r"android:debuggable=\"true\"",
            "App is debuggable in manifest (MASVS-CODE-1)",
            Severity.HIGH,
        ),
        (
            "backup_enabled",
            r"android:allowBackup=\"true\"",
            "App backup allowed — data extraction risk (MASVS-CODE-1)",
            Severity.MEDIUM,
        ),
        (
            "log_sensitive",
            r"(Log\.d|Log\.i|Log\.v|console\.log|print)\s*\([^)]*?(password|token|secret|key|cvv|ssn)",
            "Sensitive data logged (MASVS-CODE-2)",
            Severity.HIGH,
        ),
        (
            "flutter_debug_mode",
            r"kReleaseMode\s*==\s*false|assert\(debug",
            "Flutter debug mode check — may indicate debug build (MASVS-CODE-1)",
            Severity.MEDIUM,
        ),
        (
            "react_native_dev",
            r"__DEV__\s*===\s*true",
            "React Native dev mode check (MASVS-CODE-1)",
            Severity.MEDIUM,
        ),
        (
            "proguard_missing",
            r"-dontobfuscate|-dontoptimize",
            "ProGuard obfuscation or optimization disabled (MASVS-CODE-3)",
            Severity.MEDIUM,
        ),
        (
            "sourcemap_enabled",
            r"inlineSourceMap|sourceMap\s*:\s*true",
            "Source maps enabled in production (MASVS-CODE-3)",
            Severity.MEDIUM,
        ),
    ]

    # ── MASVS-AUTH: Positive patterns (found = issue) ──
    AUTH_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "biometric_fallback",
            r"setDeviceCredentialAllowed\s*=\s*true|setAllowedAuthenticators.*DEVICE_CREDENTIAL",
            "Biometric auth allows device credential fallback (MASVS-AUTH-1)",
            Severity.MEDIUM,
        ),
        (
            "no_device_binding",
            r"refreshToken|sessionToken",
            "Session token without device binding check (MASVS-AUTH-2)",
            Severity.MEDIUM,
        ),
        (
            "local_authentication",
            r"LocalAuthentication|DeviceCredentialHandler",
            "Local auth without strong biometric (MASVS-AUTH-1)",
            Severity.MEDIUM,
        ),
        (
            "token_in_url",
            r"Authorization.*Bearer.*\{.*url|token.*query.*param",
            "Auth token passed in URL query string (MASVS-AUTH-3)",
            Severity.CRITICAL,
        ),
    ]

    # ── Missing defensive controls (NOT found = issue) ──
    DEFENSIVE_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "missing_certificate_pinning",
            r"certificatePinner|TrustManager|sslPinning|nspinnedDomains|certificate_pinning",
            "No certificate pinning detected in network calls (MASVS-NETWORK-2)",
            Severity.MEDIUM,
        ),
        (
            "missing_secure_storage",
            r"SecureStore|keychain|keystore|EncryptedSharedPreferences|NSFileProtectionComplete|flutter_secure_storage|react-native-encrypted-storage",
            "No secure key storage used (MASVS-CRYPTO-2)",
            Severity.MEDIUM,
        ),
        (
            "missing_biometric",
            r"BiometricPrompt|biometric\.authenticate|authenticateWithBiometrics|LocalAuthentication\.default",
            "No strong biometric authentication (MASVS-AUTH-1)",
            Severity.MEDIUM,
        ),
        (
            "missing_session_timeout",
            r"sessionTimeout|session_expiry|tokenExpiry|expirationDuration|tokenLifetime",
            "No session timeout configuration found (MASVS-AUTH-4)",
            Severity.MEDIUM,
        ),
        (
            "missing_proguard",
            r"-obfuscate|-repackageclasses",
            "Code obfuscation not configured (MASVS-CODE-3)",
            Severity.MEDIUM,
        ),
        (
            "missing_deep_link_verify",
            r"verifyHost|hostVerification|checkUrl|validateLink",
            "No deep link URL verification (MASVS-PLATFORM-2)",
            Severity.MEDIUM,
        ),
    ]

    # Files to exclude from scanning (node_modules, vendor, etc.)
    NON_MOBILE_EXTS = frozenset(
        {".md", ".txt", ".csv", ".json", ".yaml", ".yml", ".xml", ".html", ".css"}
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings: list[Finding] = []

        all_files: list[Path] = []
        for ext in (
            ".dart",
            ".kt",
            ".java",
            ".swift",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".plist",
            ".pro",
            ".gradle",
        ):
            all_files.extend(safe_rglob(root, f"*{ext}"))

        is_mobile_project = False
        seen_defensive: set[str] = set()

        for fp in all_files:
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("MobileSecurityAgent._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))
            fname = fp.name

            if fname in {
                "AndroidManifest.xml",
                "Info.plist",
                "pubspec.yaml",
                "build.gradle",
                "Podfile",
                "app.json",
            }:
                is_mobile_project = True

            # Positive-match patterns
            for pname, pattern, msg, severity in self.STORAGE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-312",
                        )
                    )

            for pname, pattern, msg, severity in self.CRYPTO_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-327",
                        )
                    )

            for pname, pattern, msg, severity in self.NETWORK_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-319",
                        )
                    )

            for pname, pattern, msg, severity in self.PLATFORM_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-749",
                        )
                    )

            for pname, pattern, msg, severity in self.CODE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-489",
                        )
                    )

            for pname, pattern, msg, severity in self.AUTH_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-287",
                        )
                    )

            # Negative-match patterns: scan all text once, track which seen
            if is_mobile_project:
                for pname, pattern, _msg, _severity in self.DEFENSIVE_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        seen_defensive.add(pname)

        # Report missing defensive controls
        if is_mobile_project:
            for pname, _pattern, msg, severity in self.DEFENSIVE_PATTERNS:
                if pname not in seen_defensive:
                    findings.append(
                        Finding(
                            agent=self.name,
                            type=pname,
                            severity=severity,
                            file="",
                            message=msg,
                            cwe="CWE-1104",
                        )
                    )

        result.findings = findings
        result.status = AgentStatus.DONE
        result.files_scanned = len(all_files)
