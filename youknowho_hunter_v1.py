#!/usr/bin/env python3
"""
InnovateIT BugHunter v1.0.0 "Quantum"
=======================================================================
Full-stack, offline-first security analysis with CVSS 3.1 scoring,
AST-level backend auditing, semantic JS taint tracking, attack-path
correlation (Quantum Risk Index), SARIF 2.1.0 and a hardened workbench.

Design goals
------------
* Zero third-party dependencies (Python 3.9+ standard library only).
* Non-destructive: source, configs, HAR captures and JS are never executed.
  The only network activity is the explicit, scope-gated `recon` command,
  which requires --i-have-authorization and never follows redirects.
* Every finding carries a stable fingerprint, CVSS 3.1 base vector/score,
  a calibrated exploitability probability and OWASP ASVS v5.0.0 / CWE /
  Bugcrowd VRT mappings.
* Correlated findings are fused into attack paths. A chain's probability is
  the product of every link's calibrated exploitability (all steps must
  hold); the portfolio-level "Quantum Risk Index" (QRI) blends the strongest
  finding or chain with a breadth multiplier for critical/high findings.

Exit codes
----------
0  clean / below gate      2  CI gate triggered      3  usage or input error
4  internal error          130 interrupted
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import concurrent.futures
import dataclasses
import datetime as _dt
import fnmatch
import hashlib
import html
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

VERSION = "1.0.0"
CODENAME = "Quantum"
TOOL_NAME = "InnovateIT BugHunter"
REPORT_SCHEMA_VERSION = "1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
LOG = logging.getLogger("bughunter")


# ===========================================================================
# 1. Severity, confidence and rule registry
# ===========================================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_WEIGHT = {"CRITICAL": 1.00, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25, "INFO": 0.10}
CONFIDENCE_WEIGHT = {"HIGH": 1.00, "MEDIUM": 0.70, "LOW": 0.40}


def roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


_CVSS_METRICS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def cvss_base_score(vector: str) -> float:
    """Compute a CVSS 3.1 base score from a vector string.

    Raises ValueError for malformed vectors so the registry can be validated
    at import time (see `validate_rule_registry`).
    """
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        raise ValueError(f"Unsupported CVSS vector prefix: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Malformed CVSS metric {part!r} in {vector!r}")
        key, val = part.split(":", 1)
        metrics[key] = val

    for required in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if required not in metrics:
            raise ValueError(f"CVSS vector missing {required}: {vector!r}")
    scope_changed = metrics["S"] == "C"
    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"Bad CVSS scope: {vector!r}")

    av = _CVSS_METRICS["AV"].get(metrics["AV"])
    ac = _CVSS_METRICS["AC"].get(metrics["AC"])
    ui = _CVSS_METRICS["UI"].get(metrics["UI"])
    pr = (_CVSS_PR_CHANGED if scope_changed else _CVSS_METRICS["PR"]).get(metrics["PR"])
    c = _CVSS_METRICS["CIA"].get(metrics["C"])
    i = _CVSS_METRICS["CIA"].get(metrics["I"])
    a = _CVSS_METRICS["CIA"].get(metrics["A"])
    if None in (av, ac, ui, pr, c, i, a):
        raise ValueError(f"Bad CVSS metric value: {vector!r}")

    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))  # type: ignore[operator]
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    exploitability = 8.22 * av * ac * pr * ui  # type: ignore[operator]
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


@dataclass(frozen=True)
class AuditRule:
    rule_id: str
    title: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str          # HIGH, MEDIUM, LOW
    cwe: str
    vrt: str
    asvs: str                # OWASP ASVS v5.0.0 requirement tag
    cvss: str                # CVSS 3.1 base vector
    description: str
    remediation: str
    verification_hint: str
    tags: tuple[str, ...] = ()

    @property
    def cvss_score(self) -> float:
        return cvss_base_score(self.cvss)

    @property
    def tags_text(self) -> str:
        return ", ".join(self.tags)


def _r(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    cwe: str,
    vrt: str,
    asvs: str,
    cvss: str,
    description: str,
    remediation: str,
    verification_hint: str,
    tags: Sequence[str] = (),
) -> AuditRule:
    return AuditRule(
        rule_id, title, severity, confidence, cwe, vrt, asvs, cvss,
        description, remediation, verification_hint, tuple(tags),
    )


_CVSS_WEB_CORS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_CVSS_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_CVSS_MED_CONF = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
_CVSS_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_CVSS_SQLI = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_CVSS_SSRF = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
_CVSS_DESER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_CVSS_AUTHZ = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
_CVSS_CRYPTO = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
_CVSS_DISCLOSE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_CVSS_IAC = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"

RULES: dict[str, AuditRule] = {r.rule_id: r for r in [
    _r("BH-001", "Permissive CORS Policy with Credentials Enabled", "HIGH", "HIGH", "CWE-942",
       "server_security_misconfiguration.cors.wildcard_or_reflected_with_credentials", "v5.0.0-3.4.2",
       _CVSS_WEB_CORS,
       "Response reflects Origin or uses '*' alongside Access-Control-Allow-Credentials: true.",
       "Restrict Access-Control-Allow-Origin to a strict allowlist of trusted origins.",
       "Inspect CORS headers in captured HAR responses across distinct Origin headers.",
       ("cors", "web", "session")),
    _r("BH-002", "CORS Trusts 'null' Origin", "MEDIUM", "HIGH", "CWE-942",
       "server_security_misconfiguration.cors.null_origin", "v5.0.0-3.4.2",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "Access-Control-Allow-Origin permits 'null', which sandboxed iframes can generate.",
       "Remove 'null' from permitted CORS origins.",
       "Review CORS middleware configuration.", ("cors", "web")),
    _r("BH-003", "Missing Content-Security-Policy (CSP) Header", "LOW", "HIGH", "CWE-693",
       "server_security_misconfiguration.missing_security_headers.csp", "v5.0.0-3.4.3",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "HTML response omits Content-Security-Policy.",
       "Deploy a strict nonce/hash-based CSP with object-src 'none'.",
       "Check HTML document response headers.", ("headers", "web")),
    _r("BH-004", "Weak Content-Security-Policy Directives", "MEDIUM", "HIGH", "CWE-693",
       "server_security_misconfiguration.unsafe_csp", "v5.0.0-3.4.3",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "CSP permits 'unsafe-inline', 'unsafe-eval', or broad '*' script sources.",
       "Replace 'unsafe-inline' with cryptographic nonces/hashes and remove 'unsafe-eval'.",
       "Audit CSP directives in browser DevTools.", ("headers", "xss")),
    _r("BH-005", "Missing or Weak HSTS Header", "LOW", "HIGH", "CWE-319",
       "server_security_misconfiguration.missing_security_headers.hsts", "v5.0.0-12.2.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
       "HTTPS response omits Strict-Transport-Security or uses max-age < 15552000.",
       "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
       "Inspect HTTPS response headers.", ("headers", "tls")),
    _r("BH-006", "Missing Clickjacking Defense Headers", "LOW", "HIGH", "CWE-1021",
       "server_security_misconfiguration.clickjacking", "v5.0.0-3.4.4",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "HTML response lacks both CSP frame-ancestors and X-Frame-Options.",
       "Add frame-ancestors 'self' (or 'none') to CSP and X-Frame-Options: DENY.",
       "Verify framing headers on UI routes.", ("headers", "web")),
    _r("BH-007", "Session Cookie Missing HttpOnly or Secure Flag", "MEDIUM", "HIGH", "CWE-1004",
       "server_security_misconfiguration.cookie_flags", "v5.0.0-3.3.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
       "Session-like Set-Cookie header lacks HttpOnly and/or Secure.",
       "Set Secure, HttpOnly, and SameSite=Lax/Strict on all session cookies.",
       "Inspect Set-Cookie attributes in login responses.", ("cookies", "web")),
    _r("BH-008", "Cookie Uses SameSite=None Without Secure", "MEDIUM", "HIGH", "CWE-1275",
       "server_security_misconfiguration.cookie_samesite", "v5.0.0-3.3.2",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
       "Set-Cookie specifies SameSite=None without the Secure attribute.",
       "Always pair SameSite=None with Secure over HTTPS.",
       "Check Set-Cookie header flags.", ("cookies", "csrf")),
    _r("BH-009", "Authenticated JSON Response Missing Cache-Control: no-store", "LOW", "MEDIUM", "CWE-524",
       "server_security_misconfiguration.cache_control", "v5.0.0-14.2.1",
       "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "Authenticated API response omits Cache-Control: no-store.",
       "Set Cache-Control: no-store, max-age=0 on sensitive API endpoints.",
       "Review caching headers on authenticated endpoints.", ("headers", "privacy")),
    _r("BH-010", "Exposed JavaScript Source Map (.js.map)", "LOW", "HIGH", "CWE-540",
       "sensitive_data_exposure.source_map_exposure", "v5.0.0-14.1.2",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "Production bundle exposes sourceMappingURL or inline sourcesContent.",
       "Strip sourceMappingURL comments from production builds and restrict .map files.",
       "Verify production CDN asset policies.", ("client", "exposure")),
    _r("BH-011", "Multi-Hop Taint Flow into Dangerous DOM Sink", "MEDIUM", "HIGH", "CWE-79",
       "cross_site_scripting_xss.dom_based.taint_flow", "v5.0.0-1.2.1",
       _CVSS_XSS,
       "Static data-flow tracer linked a controllable source (URL/storage/postMessage) to a DOM execution sink.",
       "Sanitize untrusted input with DOMPurify or use safe textContent/createElement APIs.",
       "Trace the reported variable chain in DevTools Sources.", ("xss", "client", "taint")),
    _r("BH-012", "postMessage Listener Without Strict Origin Validation", "MEDIUM", "MEDIUM", "CWE-346",
       "client_side_enforcement.postmessage_origin_validation", "v5.0.0-3.6.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "window.addEventListener('message') reads event.data without checking event.origin.",
       "Validate event.origin against an exact allowlist before processing event.data.",
       "Inspect the message event handler in client JS.", ("client", "postmessage")),
    _r("BH-013", "High-Entropy Credential / Secret Exposed in Artifact", "HIGH", "HIGH", "CWE-798",
       "sensitive_data_exposure.hardcoded_credentials", "v5.0.0-13.3.1",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
       "Pattern + Shannon-entropy analysis matched a probable API key, token, or private key.",
       "Revoke and rotate the credential immediately; move secrets server-side.",
       "Verify key scope in provider IAM console and rotate.", ("secrets", "exposure")),
    _r("BH-014", "JWT Uses Unsecured 'none' Algorithm", "CRITICAL", "HIGH", "CWE-347",
       "broken_authentication.jwt.none_algorithm", "v5.0.0-9.1.2",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
       "JWT header specifies 'alg': 'none' or lacks a signature segment.",
       "Enforce explicit asymmetric/HMAC algorithm allowlists and reject 'none'.",
       "Inspect JWT header in captured traffic.", ("jwt", "auth")),
    _r("BH-015", "JWT Missing 'exp' or 'aud' Claims", "MEDIUM", "HIGH", "CWE-613",
       "broken_authentication.jwt.missing_claims", "v5.0.0-9.2.1",
       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
       "JWT payload lacks expiration ('exp') or audience ('aud') claims.",
       "Require short-lived 'exp' and validate 'aud' and 'iss' on resource servers.",
       "Decode JWT payload claims.", ("jwt", "auth")),
    _r("BH-016", "JWT Excessive Lifetime (> 24 Hours)", "LOW", "HIGH", "CWE-613",
       "broken_authentication.jwt.long_lived_token", "v5.0.0-9.2.1",
       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
       "JWT 'exp' minus 'iat' exceeds 24 hours.",
       "Reduce access token TTL to 15-60 minutes and use rotating refresh tokens.",
       "Compare 'iat' and 'exp' timestamps.", ("jwt", "auth")),
    _r("BH-017", "Sensitive PII / Secret Keys in Unencrypted JWT Payload", "LOW", "MEDIUM", "CWE-200",
       "sensitive_data_exposure.jwt_pii", "v5.0.0-9.1.3",
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
       "Decoded JWT payload contains sensitive attribute names.",
       "Store only opaque user IDs and scopes in signed JWTs.",
       "Inspect JWT payload fields.", ("jwt", "privacy")),
    _r("BH-018", "OAuth 2.0 Flow Missing 'state' or Using Implicit Grant", "MEDIUM", "HIGH", "CWE-352",
       "broken_authentication.oauth.missing_state_or_implicit", "v5.0.0-10.2.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "OAuth authorize request omits 'state' CSRF protection or uses response_type=token.",
       "Enforce Authorization Code + PKCE (S256) with a random 'state' parameter.",
       "Inspect /authorize parameters in HAR capture.", ("oauth", "auth", "csrf")),
    _r("BH-019", "Open-Redirect Parameter Surface Observed", "INFO", "LOW", "CWE-601",
       "unvalidated_redirects_and_forwards.parameter_surface", "v5.0.0-1.2.8",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
       "Request carries redirect-style parameters (next, redirect_uri, returnTo, url).",
       "Enforce relative-path or strict domain allowlist validation on redirect targets.",
       "Review server-side redirect validation logic.", ("redirect", "web")),
    _r("BH-020", "GraphQL Endpoint / Introspection Surface Detected", "INFO", "HIGH", "CWE-200",
       "server_security_misconfiguration.graphql_introspection", "v5.0.0-4.3.1",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "GraphQL endpoint or __schema metadata observed in traffic or client scripts.",
       "Disable introspection in production and enforce query depth/cost limits.",
       "Check production GraphQL configuration.", ("graphql", "surface")),
    _r("BH-021", "Exposed OpenAPI / Swagger Specification Surface", "INFO", "HIGH", "CWE-200",
       "sensitive_data_exposure.api_documentation_exposed", "v5.0.0-14.1.1",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "swagger.json or openapi.json path referenced or served.",
       "Restrict API docs to authenticated internal environments.",
       "Audit documented routes for proper authz.", ("surface", "api")),
    _r("BH-022", "Server Software Version Banner Disclosure", "INFO", "HIGH", "CWE-200",
       "server_security_misconfiguration.information_disclosure.server_banner", "v5.0.0-14.1.3",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "Response headers disclose specific web server or framework versions.",
       "Strip version details from Server and X-Powered-By headers.",
       "Check edge proxy header sanitization.", ("headers", "exposure")),
    _r("BH-023", "TLS Certificate Expiring Soon (< 30 Days)", "MEDIUM", "HIGH", "CWE-295",
       "cryptographic_issues.certificate_or_tls_posture", "v5.0.0-12.1.2",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
       "TLS certificate expires in under 30 days.",
       "Automate certificate renewal via ACME.",
       "Inspect certificate validity dates.", ("tls", "availability")),
    _r("BH-024", "Missing /.well-known/security.txt Policy", "INFO", "HIGH", "CWE-1059",
       "informational.missing_security_txt", "v5.0.0-13.1.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
       "Domain does not publish RFC 9116 /.well-known/security.txt.",
       "Publish /.well-known/security.txt with Contact and Expires fields.",
       "Check /.well-known/security.txt.", ("governance",)),
    _r("BH-025", "Client-Side Prototype Pollution Sink Pattern in JS", "MEDIUM", "MEDIUM", "CWE-1321",
       "client_side_enforcement.prototype_pollution", "v5.0.0-1.2.9",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
       "Recursive merge/extend helper writes dynamic bracket keys without blocking '__proto__', 'constructor', or 'prototype'.",
       "Reject '__proto__', 'constructor', and 'prototype' keys during object merges or use Object.create(null).",
       "Review the flagged merge/assignment helper in client JS.", ("client", "prototype")),
    _r("BH-026", "Unobserved ('Ghost') API Endpoint Referenced in Client JS", "INFO", "HIGH", "CWE-200",
       "attack_surface.unobserved_client_route", "v5.0.0-4.1.1",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "Frontend bundle references an API route that was never called during the captured HAR session.",
       "Verify all hidden/admin/legacy routes enforce strict server-side authentication and authorization.",
       "Review route handler and authorization middleware in backend codebase.",
       ("surface", "client")),
    _r("BH-027", "Cross-Role Authorization Parity Candidate (Role-Diff)", "MEDIUM", "MEDIUM", "CWE-284",
       "broken_access_control.authorization_review_candidate", "v5.0.0-8.2.1",
       _CVSS_AUTHZ,
       "Endpoint returned HTTP 200 with structured data for both higher-privilege and lower-privilege captures.",
       "Ensure object-level and function-level authorization checks reject unauthorized roles with 403/401.",
       "Compare response fields and authorization rules for this endpoint across user roles.",
       ("authz", "api")),
    _r("BH-028", "OpenAPI Operation Explicitly Declares Empty Security ('security: []')", "MEDIUM", "HIGH", "CWE-306",
       "broken_access_control.unauthenticated_api_operation", "v5.0.0-4.1.2",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
       "OpenAPI/Swagger specification marks a state-changing path with 'security: []'.",
       "Attach appropriate OAuth2/Bearer/APIKey security schemes to sensitive operations.",
       "Review OpenAPI security requirements and gateway auth enforcement.", ("api", "authz")),
    _r("BH-029", "OpenAPI Schema Exposes Sensitive Field Names in Responses", "LOW", "HIGH", "CWE-200",
       "sensitive_data_exposure.excessive_data_exposure", "v5.0.0-4.2.1",
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
       "OpenAPI response schema defines sensitive properties (e.g., passwordHash, secret, ssn).",
       "Filter internal/sensitive model attributes using dedicated response DTOs.",
       "Inspect response DTO serialization.", ("api", "privacy")),
    _r("BH-030", "High-Sensitivity IDOR / Object-Reference Parameter Surface", "INFO", "MEDIUM", "CWE-639",
       "broken_access_control.idor.parameter_surface", "v5.0.0-8.2.2",
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
       "State-changing or sensitive API endpoint accepts numeric IDs or UUIDs in path/query parameters.",
       "Enforce ownership/tenant checks on every object lookup rather than trusting client-supplied IDs.",
       "Verify object-level ownership enforcement on this endpoint.", ("authz", "surface")),
    _r("BH-031", "Dynamic String Concatenation / Interpolation in SQL Query", "HIGH", "HIGH", "CWE-89",
       "sql_injection.dynamic_query_construction", "v5.0.0-1.2.4",
       _CVSS_SQLI,
       "Backend source constructs SQL statements via string formatting/interpolation instead of parameterized placeholders.",
       "Use parameterized queries / prepared statements or ORM bind parameters.",
       "Inspect the flagged query builder line in source control.", ("sqli", "backend", "taint")),
    _r("BH-032", "OS Command Execution with Shell Evaluation Enabled", "HIGH", "HIGH", "CWE-78",
       "os_command_injection.shell_execution", "v5.0.0-1.2.5",
       _CVSS_RCE,
       "Backend code invokes subprocess(..., shell=True), os.system(), or child_process.exec().",
       "Use argument arrays with shell=False (execFile/spawn) and strictly validate inputs.",
       "Verify whether user-influenced values reach the command invocation.",
       ("cmdi", "backend", "taint")),
    _r("BH-033", "Server-Side Outbound Request with Dynamic URL Variable (SSRF Sink)", "MEDIUM", "MEDIUM", "CWE-918",
       "server_side_request_forgery.dynamic_url_sink", "v5.0.0-1.2.6",
       _CVSS_SSRF,
       "Outbound HTTP client (requests/fetch/urllib/axios) receives a dynamic variable URL without obvious allowlist validation.",
       "Validate destination hostnames against an allowlist and block private/link-local IP ranges post-DNS resolution.",
       "Trace the URL variable back to request parameters or webhook configurations.",
       ("ssrf", "backend", "taint")),
    _r("BH-034", "Unsafe Deserialization Call (pickle.loads / yaml.load)", "HIGH", "HIGH", "CWE-502",
       "insecure_deserialization.unsafe_loader", "v5.0.0-1.5.2",
       _CVSS_DESER,
       "Code deserializes data using pickle.loads() or yaml.load() without SafeLoader.",
       "Use JSON or yaml.safe_load() for untrusted serialized payloads.",
       "Review data origin passed to the deserializer.", ("deserialization", "backend")),
    _r("BH-035", "Weak Cryptographic Hash (MD5/SHA1) or Disabled TLS Verification", "MEDIUM", "HIGH", "CWE-327",
       "cryptographic_issues.weak_hash_or_disabled_tls", "v5.0.0-11.3.1",
       _CVSS_CRYPTO,
       "Code uses MD5/SHA1 or explicitly disables TLS certificate validation (verify=False / rejectUnauthorized: false).",
       "Use SHA-256+/Argon2id and keep TLS certificate verification enabled.",
       "Audit cryptographic helper and HTTP client options.", ("crypto", "backend")),
    _r("BH-036", "Container / IaC Privileged Execution or Root User Configuration", "MEDIUM", "HIGH", "CWE-250",
       "infrastructure_misconfiguration.privileged_container_or_root", "v5.0.0-13.2.1",
       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
       "Dockerfile or Kubernetes manifest runs as root ('USER root') or sets 'privileged: true'.",
       "Specify a non-root USER in Dockerfiles and set allowPrivilegeEscalation: false in Kubernetes.",
       "Review deployment manifest securityContext.", ("iac", "container")),
    _r("BH-037", "CI/CD Workflow Command Injection or Untrusted Checkout", "HIGH", "MEDIUM", "CWE-94",
       "cicd.workflow_command_injection", "v5.0.0-1.2.7",
       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
       "GitHub Actions workflow interpolates attacker-controlled event fields into `run:` or checks out untrusted PR code via pull_request_target.",
       "Pass event data through env: variables instead of ${{ }} interpolation, pin actions by SHA, and never run untrusted code in pull_request_target.",
       "Inspect the workflow trigger, interpolation sites and checkout ref.", ("cicd", "ci", "supplychain")),
    _r("BH-038", "JWT Signature Verification Disabled or Algorithm Not Pinned", "HIGH", "HIGH", "CWE-347",
       "broken_authentication.jwt.verification_disabled", "v5.0.0-9.1.2",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
       "Backend calls jwt.decode(..., verify=False) / options={'verify_signature': False} or does not pin the accepted algorithm allowlist.",
       "Always verify signatures with an explicit algorithms allowlist; never trust the token's own 'alg' header.",
       "Inspect the token verification call and its options.", ("jwt", "auth", "backend")),
    _r("BH-039", "Sensitive Parameter Carried in URL Query String", "MEDIUM", "MEDIUM", "CWE-598",
       "sensitive_data_exposure.query_string_secret", "v5.0.0-3.5.3",
       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
       "Access token, API key, password or session identifier appears in a URL query string (logs, Referer, browser history).",
       "Move credentials into Authorization headers or POST bodies and scrub Referer for outbound links.",
       "Check proxy/access logs and third-party Referer leakage for this endpoint.", ("exposure", "secrets", "web")),
    _r("BH-040", "Sensitive Configuration or Backup File Reachable", "LOW", "MEDIUM", "CWE-538",
       "sensitive_data_exposure.file_exposure", "v5.0.0-14.1.4",
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
       "A well-known sensitive path (/.env, /.git/HEAD, backup, server-status) responded with content.",
       "Block dotfiles and backup extensions at the edge, and remove VCS metadata from deploy artifacts.",
       "Confirm the response body contains real configuration rather than a soft-404 page.",
       ("exposure", "recon")),
    _r("BH-041", "Kubernetes Workload Uses Host Namespace or Host Path", "MEDIUM", "HIGH", "CWE-250",
       "infrastructure_misconfiguration.kubernetes_host_namespace", "v5.0.0-13.2.2",
       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
       "Manifest sets hostNetwork/hostPID/hostIPC or mounts a hostPath volume, weakening container isolation.",
       "Drop host namespaces and hostPath mounts; use dedicated CSI volumes and NetworkPolicies.",
       "Review pod spec securityContext and volume definitions.", ("iac", "k8s", "container")),
    _r("BH-042", "Deprecated TLS Protocol Version or Weak Cipher Negotiated", "MEDIUM", "HIGH", "CWE-326",
       "cryptographic_issues.weak_tls_protocol", "v5.0.0-12.1.1",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
       "Endpoint negotiated TLS 1.0/1.1 or a legacy cipher suite such as RC4/3DES/CBC-SHA1.",
       "Require TLS 1.2+ (prefer 1.3) with AEAD cipher suites and disable legacy protocols at the edge.",
       "Re-test with `openssl s_client -tls1_1` and review the edge TLS policy.",
       ("tls", "crypto")),
    _r("BH-043", "Unpinned Container Base Image or Third-Party CI Action", "MEDIUM", "HIGH", "CWE-1104",
       "supplychain.unpinned_dependency", "v5.0.0-13.2.3",
       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N",
       "Dockerfile FROM uses ':latest' or no digest, or a workflow `uses:` reference is not pinned to a commit SHA.",
       "Pin images by sha256 digest and actions by full commit SHA; enable Dependabot for routine bumps.",
       "Verify the resolved digest/SHA matches the reviewed artifact.", ("supplychain", "iac", "ci")),
    _r("BH-044", "Dynamic Code Evaluation in Backend (eval / exec)", "HIGH", "HIGH", "CWE-95",
       "code_injection.dynamic_evaluation", "v5.0.0-1.2.10",
       _CVSS_RCE,
       "Backend code evaluates a dynamically constructed expression with eval(), exec(), or compile().",
       "Remove dynamic evaluation; use explicit dispatch tables or parsed allowlisted expressions.",
       "Trace whether request-controlled data reaches the evaluated expression.",
       ("codeinj", "backend")),
    _r("BH-045", "Server-Side Template Injection Sink", "HIGH", "MEDIUM", "CWE-1336",
       "server_side_template_injection.dynamic_template", "v5.0.0-1.2.11",
       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N",
       "Backend renders an attacker-influenced string as a template (render_template_string, Template(...).render, Handlebars.compile).",
       "Use static templates with parameter binding; never compile user input as a template.",
       "Confirm the template string origin and test with a benign arithmetic probe.",
       ("ssti", "backend", "taint")),
]}


def validate_rule_registry() -> None:
    """Fail fast on inconsistent rule metadata (also exercised by self-test)."""
    seen_titles: set[str] = set()
    for rid, rule in RULES.items():
        if not re.fullmatch(r"BH-\d{3}", rid):
            raise ValueError(f"Bad rule id: {rid}")
        if rule.severity not in SEVERITY_ORDER:
            raise ValueError(f"{rid}: bad severity {rule.severity}")
        if rule.confidence not in CONFIDENCE_WEIGHT:
            raise ValueError(f"{rid}: bad confidence {rule.confidence}")
        if not rule.cwe.startswith("CWE-"):
            raise ValueError(f"{rid}: bad CWE {rule.cwe}")
        if rule.title in seen_titles:
            raise ValueError(f"{rid}: duplicate title {rule.title!r}")
        seen_titles.add(rule.title)
        score = rule.cvss_score  # raises on malformed vector
        if not 0.0 <= score <= 10.0:
            raise ValueError(f"{rid}: CVSS out of range ({score})")


validate_rule_registry()


# ===========================================================================
# 2. Core models: findings, attack paths, scan results
# ===========================================================================

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    vrt: str
    asvs: str
    asset: str
    location: str
    evidence: str
    remediation: str
    verification_hint: str
    start_line: int = 0
    end_line: int = 0
    column: int = 0
    snippet: str = ""
    fingerprint: str = ""
    stable_id: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    exploitability: float = 0.0
    risk_score: float = 0.0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    attack_path_ids: list[str] = field(default_factory=list)
    baseline_state: str = ""        # "new" | "unchanged" | "updated"
    suppressed: bool = False
    suppression_reason: str = ""

    def __post_init__(self) -> None:
        if not self.cvss_vector:
            self.cvss_vector = RULES[self.rule_id].cvss
        if not self.cvss_score:
            self.cvss_score = cvss_base_score(self.cvss_vector)
        base = self.cvss_score / 10.0
        conf = CONFIDENCE_WEIGHT.get(self.confidence, 0.4)
        # Exploitability blends CVSS base with analyzer confidence, capped at 0.95.
        self.exploitability = round(min(0.95, base * (0.55 + 0.45 * conf)), 4)
        self.risk_score = round(
            min(100.0, self.cvss_score * 6.0 + SEVERITY_WEIGHT.get(self.severity, 0.1) * 25.0
                + conf * 15.0), 1,
        )
        if not self.fingerprint:
            raw = f"{self.rule_id}|{self.asset}|{self.location}|{self.evidence[:160]}"
            self.fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]
        if not self.stable_id:
            # Content-anchored id: survives line drift, changes when the code changes.
            anchor = re.sub(r"\s+", " ", self.snippet or self.evidence)[:200]
            self.stable_id = hashlib.sha256(
                f"{self.rule_id}|{self.asset}|{anchor}".encode("utf-8", "replace")
            ).hexdigest()[:20]
        if not self.tags:
            self.tags = list(RULES[self.rule_id].tags)

    @classmethod
    def from_rule(
        cls,
        rule_id: str,
        asset: str,
        location: str,
        evidence: str,
        *,
        start_line: int = 0,
        end_line: int = 0,
        column: int = 0,
        snippet: str = "",
        confidence: str | None = None,
        metadata: dict[str, Any] | None = None,
        severity: str | None = None,
    ) -> "Finding":
        r = RULES[rule_id]
        return cls(
            rule_id=r.rule_id,
            title=r.title,
            severity=severity or r.severity,
            confidence=confidence or r.confidence,
            cwe=r.cwe,
            vrt=r.vrt,
            asvs=r.asvs,
            asset=asset,
            location=location,
            evidence=evidence[:500],
            remediation=r.remediation,
            verification_hint=r.verification_hint,
            start_line=start_line,
            end_line=end_line or start_line,
            column=column,
            snippet=snippet[:400],
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        allowed = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class AttackPath:
    path_id: str
    title: str
    severity: str
    narrative: str
    rule_ids: list[str]
    finding_fingerprints: list[str]
    combined_probability: float
    qri: float                      # Quantum Risk Index, 0-100
    assets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    by_language: dict[str, int] = field(default_factory=dict)
    suppressed_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    endpoints: list[str] = field(default_factory=list)
    ranked_endpoints: list[dict[str, Any]] = field(default_factory=list)
    ghost_routes: list[str] = field(default_factory=list)
    backend_routes: list[str] = field(default_factory=list)
    correlated_routes: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    asvs_matrix: list[dict[str, Any]] = field(default_factory=list)
    cwe_coverage: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ===========================================================================
# 3. Text utilities: line index, entropy, redaction, escaping
# ===========================================================================

class LineIndex:
    """Maps character offsets to 1-based line/column in O(log n)."""

    __slots__ = ("_starts",)

    def __init__(self, text: str) -> None:
        self._starts = [0]
        self._starts.extend(m.end() for m in re.finditer(r"\n", text))

    def line_col(self, offset: int) -> tuple[int, int]:
        import bisect

        idx = bisect.bisect_right(self._starts, offset) - 1
        return idx + 1, offset - self._starts[idx] + 1

    def line_count(self) -> int:
        return len(self._starts)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def redact_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    keep = 4 if len(secret) >= 24 else 2
    return f"{secret[:keep]}****{secret[-keep:]}"


def safe_snippet(text: str, limit: int = 240) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed[:limit]


def escape_html(value: Any) -> str:
    return html.escape(str(value), quote=True)


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def json_dumps(payload: Any, indent: int | None = 2) -> str:
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=_json_default)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def read_text_file(path: Path, max_bytes: int) -> str | None:
    """Read UTF-8-ish text, returning None for binary/oversized files."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    # utf-8-sig first: a BOM left in place is fatal to ast.parse() on Windows files.
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


# ===========================================================================
# 4. Scope enforcement, SSRF guard, rate limiting and pinned HTTP client
# ===========================================================================

class ScopeViolationError(Exception):
    """Raised when a target is outside authorized scope or resolves to a restricted IP."""


class ScopeGuard:
    """Domain allowlist plus DNS-pinned SSRF guard.

    The guard resolves once, validates *every* returned address, and hands the
    validated IP to `PinnedHttpClient`, so a later DNS answer cannot redirect
    the connection into a private range (DNS-rebinding defence).
    """

    def __init__(self, allowed_domains: Sequence[str], allow_subdomains: bool = True) -> None:
        cleaned = []
        for raw in allowed_domains:
            domain = raw.strip().lower().lstrip(".")
            if not domain:
                continue
            if domain.startswith("*."):
                domain = domain[2:]
            cleaned.append(domain)
        self.allowed_domains = cleaned
        self.allow_subdomains = allow_subdomains
        if not self.allowed_domains:
            raise ValueError("At least one authorized scope domain must be specified.")

    def is_domain_in_scope(self, host: str) -> bool:
        h = (host or "").strip().lower().rstrip(".").split(":")[0]
        if not h:
            return False
        try:
            ipaddress.ip_address(h)
            return False  # bare IP literals are never in scope
        except ValueError:
            pass
        for allowed in self.allowed_domains:
            if h == allowed:
                return True
            if self.allow_subdomains and h.endswith("." + allowed):
                return True
        return False

    @staticmethod
    def is_restricted_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return not ip.is_global or ip.is_multicast

    def resolve(self, host: str, port: int) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ScopeViolationError(f"DNS resolution failed for '{host}': {exc}") from exc
        addresses: list[str] = []
        for info in infos:
            addr = info[4][0]
            if self.is_restricted_ip(addr):
                raise ScopeViolationError(
                    f"SSRF Guard blocked '{host}' resolving to restricted IP {addr}."
                )
            if addr not in addresses:
                addresses.append(addr)
        if not addresses:
            raise ScopeViolationError(f"'{host}' resolved to no usable address.")
        return addresses

    def validate_url(self, url: str, resolve_dns: bool = True) -> tuple[str, list[str]]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(f"Unsupported scheme '{parsed.scheme}'.")
        host = parsed.hostname
        if not host:
            raise ScopeViolationError(f"Missing hostname in URL: {url}")
        if not self.is_domain_in_scope(host):
            raise ScopeViolationError(f"Host '{host}' is OUTSIDE authorized scope {self.allowed_domains}.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return url, (self.resolve(host, port) if resolve_dns else [])


class TokenBucket:
    """Thread-safe token bucket: sustained rps with a configurable burst."""

    def __init__(self, requests_per_second: float = 2.0, burst: float | None = None) -> None:
        self.rate = max(0.05, float(requests_per_second))
        self.capacity = max(1.0, float(burst) if burst is not None else max(1.0, self.rate))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            if time.monotonic() + wait > deadline:
                raise TimeoutError("Rate limiter wait exceeded timeout.")
            time.sleep(min(wait, 1.0))

    # Backwards-compatible alias
    def wait(self) -> None:
        self.acquire()


@dataclass
class PinnedResponse:
    url: str
    status: int
    headers: dict[str, list[str]]
    body: str
    ip: str


class PinnedHttpClient:
    """Minimal HTTP client that connects to a pre-validated IP.

    * No automatic redirects: each hop is re-validated against the scope.
    * Certificate verification and SNI use the original hostname.
    * Response bodies are capped to avoid memory abuse.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        limiter: TokenBucket | None = None,
        timeout: float = 8.0,
        user_agent: str = "",
        max_bytes: int = 512_000,
        verify_tls: bool = True,
    ) -> None:
        self.guard = guard
        self.limiter = limiter or TokenBucket(2.0)
        self.timeout = timeout
        self.user_agent = user_agent or f"{TOOL_NAME}/{VERSION} (authorized-passive-audit)"
        self.max_bytes = max_bytes
        self._ssl_context = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-in only
        )
        if verify_tls:
            self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # type: ignore[attr-defined]

    def fetch(self, url: str, max_redirects: int = 0) -> PinnedResponse:
        current = url
        for hop in range(max_redirects + 1):
            validated, ips = self.guard.validate_url(current)
            parsed = urllib.parse.urlparse(validated)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ip = ips[0]
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            self.limiter.acquire()
            sock: socket.socket | None = None
            try:
                raw = socket.create_connection((ip, port), timeout=self.timeout)
                if parsed.scheme == "https":
                    sock = self._ssl_context.wrap_socket(raw, server_hostname=host)
                else:
                    sock = raw
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
                conn.sock = sock
                conn.request(
                    "GET",
                    path,
                    headers={
                        "Host": host if port in (80, 443) else f"{host}:{port}",
                        "User-Agent": self.user_agent,
                        "Accept": "*/*",
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                    },
                )
                response = conn.getresponse()
                headers: dict[str, list[str]] = {}
                for key, value in response.getheaders():
                    headers.setdefault(key.lower(), []).append(value)
                body = response.read(self.max_bytes).decode("utf-8", errors="replace")
                status = response.status
                location = response.getheader("Location") or ""
                response.close()
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

            if status in (301, 302, 303, 307, 308) and location and hop < max_redirects:
                current = urllib.parse.urljoin(current, location)
                LOG.debug("Following in-scope redirect to %s", current)
                continue
            return PinnedResponse(validated, status, headers, body, ip)
        raise ScopeViolationError(f"Too many redirects for {url}")


# ===========================================================================
# 5. Suppressions (file-based + inline comments)
# ===========================================================================

@dataclass
class Suppression:
    reason: str
    rule_id: str = ""
    path_glob: str = ""
    fingerprint: str = ""
    stable_id: str = ""
    expires: str = ""

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if not self.expires:
            return False
        try:
            exp = _dt.date.fromisoformat(self.expires)
        except ValueError:
            return False
        return exp < (today or _dt.date.today())

    def matches(self, finding: Finding) -> bool:
        if self.is_expired():
            return False
        if self.fingerprint and finding.fingerprint != self.fingerprint:
            return False
        if self.stable_id and finding.stable_id != self.stable_id:
            return False
        if self.rule_id and finding.rule_id != self.rule_id:
            return False
        if self.path_glob and not (
            fnmatch.fnmatch(finding.asset, self.path_glob)
            or fnmatch.fnmatch(finding.asset.replace("\\", "/"), self.path_glob)
        ):
            return False
        return bool(self.fingerprint or self.stable_id or self.rule_id or self.path_glob)


class SuppressionSet:
    """Loads `.bughunterignore` / `--suppress` JSON files.

    Accepted shapes:
      {"suppressions": [ {...}, ... ]}
      [ {...}, ... ]
    Each entry: rule_id, path, fingerprint, stable_id, reason, expires (YYYY-MM-DD).
    """

    def __init__(self, entries: Sequence[Suppression] = ()) -> None:
        self.entries = list(entries)

    @classmethod
    def load(cls, paths: Sequence[Path]) -> "SuppressionSet":
        entries: list[Suppression] = []
        for path in paths:
            if not path.is_file():
                raise FileNotFoundError(f"Suppression file not found: {path}")
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            raw_entries = data.get("suppressions", []) if isinstance(data, dict) else data
            if not isinstance(raw_entries, list):
                raise ValueError(f"Invalid suppression file structure: {path}")
            for raw in raw_entries:
                if not isinstance(raw, dict):
                    continue
                entries.append(
                    Suppression(
                        reason=str(raw.get("reason", "suppressed")),
                        rule_id=str(raw.get("rule_id", "")),
                        path_glob=str(raw.get("path", "")),
                        fingerprint=str(raw.get("fingerprint", "")),
                        stable_id=str(raw.get("stable_id", "")),
                        expires=str(raw.get("expires", "")),
                    )
                )
        return cls(entries)

    def reason_for(self, finding: Finding) -> str | None:
        for entry in self.entries:
            if entry.matches(finding):
                return entry.reason
        return None

    def apply(self, findings: Sequence[Finding]) -> list[Finding]:
        for finding in findings:
            reason = self.reason_for(finding)
            if reason:
                finding.suppressed = True
                finding.suppression_reason = reason
        return list(findings)


_INLINE_IGNORE = re.compile(
    r"bughunter:\s*ignore(?:-file|-next-line)?\s+((?:BH-\d{3}[,\s]*)+)(?:\s*[-:]\s*(.*))?",
    re.IGNORECASE,
)


def inline_suppressions(text: str) -> tuple[dict[int, set[str]], set[str], bool]:
    """Parse inline suppressions.

    Returns (line -> rules, rules for whole file, ignore_whole_file).
    `bughunter:ignore-file BH-013` disables the rule for the file;
    `bughunter:ignore-next-line BH-013` targets the following line.
    """
    per_line: dict[int, set[str]] = {}
    file_rules: set[str] = set()
    ignore_file = False
    index = LineIndex(text)
    for match in _INLINE_IGNORE.finditer(text):
        line_no, _ = index.line_col(match.start())
        rules = {r.strip().upper() for r in re.split(r"[,\s]+", match.group(1)) if r.strip()}
        directive = match.group(0).lower()
        if "ignore-file" in directive:
            file_rules.update(rules)
            ignore_file = True
        elif "ignore-next-line" in directive:
            per_line.setdefault(line_no + 1, set()).update(rules)
        else:
            per_line.setdefault(line_no, set()).update(rules)
    return per_line, file_rules, ignore_file


def apply_inline_suppressions(text: str, findings: list[Finding]) -> list[Finding]:
    per_line, file_rules, _ = inline_suppressions(text)
    for finding in findings:
        if finding.rule_id in file_rules:
            finding.suppressed = True
            finding.suppression_reason = "inline ignore-file"
            continue
        for line, rules in per_line.items():
            if finding.rule_id in rules and line in (finding.start_line, finding.start_line - 0):
                finding.suppressed = True
                finding.suppression_reason = f"inline ignore (line {line})"
                break
    return findings


# ===========================================================================
# 6. Secret detection engine
# ===========================================================================

@dataclass(frozen=True)
class SecretPattern:
    label: str
    regex: re.Pattern[str]
    min_entropy: float = 0.0
    group: int = 1


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 3.2),
    SecretPattern("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), 3.8),
    SecretPattern("Stripe Live Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"), 3.8),
    SecretPattern("GitHub Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"), 3.8),
    SecretPattern("Slack Token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,60})\b"), 3.5),
    SecretPattern("Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"), 3.5),
    SecretPattern("SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,30}\.[A-Za-z0-9_\-]{40,50})\b"), 3.6),
    SecretPattern("npm Token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 3.8),
    SecretPattern("OpenAI API Key", re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,})\b"), 3.8),
    SecretPattern("Anthropic API Key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), 3.8),
    SecretPattern("Private Key PEM Block", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"), 2.5),
    SecretPattern(
        "Database Connection URI",
        re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]{6,}@[^\s'\"]+)"),
        3.0,
    ),
    SecretPattern(
        "Generic High-Entropy Secret",
        re.compile(
            r"""(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|private[_-]?key)"""
            r"""\s*[:=]\s*['"]([A-Za-z0-9_\-\.=+/]{24,100})['"]""",
            re.IGNORECASE,
        ),
        3.6,
    ),
    SecretPattern(
        "Bearer Token Literal",
        re.compile(r"""(?:Authorization|authorization)\s*[:=]\s*['"]Bearer\s+([A-Za-z0-9\-_\.]{24,})['"]"""),
        3.4,
    ),
)

_PLACEHOLDER_TOKENS = (
    "example", "sample", "dummy", "placeholder", "changeme", "replaceme", "redacted",
    "your_", "your-", "xxxx", "0000", "1234567890", "abcdefgh", "test_only", "test-only",
    "akiaiosfodnn7example", "not_a_real", "fake", "todo", "insert_", "yourtoken",
)


def is_probable_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(token in lowered for token in _PLACEHOLDER_TOKENS):
        return True
    if re.fullmatch(r"(.)\1{7,}", lowered):
        return True
    return value.startswith("<") or value.endswith(">")


def scan_text_for_secrets(
    text: str,
    asset: str,
    location_prefix: str,
    *,
    line_index: LineIndex | None = None,
    min_entropy_override: float | None = None,
) -> list[Finding]:
    """Pattern + entropy secret scan with redaction and placeholder filtering."""
    findings: list[Finding] = []
    index = line_index or LineIndex(text)
    seen: set[str] = set()
    for spec in SECRET_PATTERNS:
        for match in spec.regex.finditer(text):
            value = match.group(spec.group)
            if not value or value in seen:
                continue
            if is_probable_placeholder(value):
                continue
            threshold = spec.min_entropy if min_entropy_override is None else min_entropy_override
            entropy = shannon_entropy(value)
            if entropy < threshold:
                continue
            seen.add(value)
            line_no, col = index.line_col(match.start(spec.group))
            findings.append(
                Finding.from_rule(
                    "BH-013",
                    asset=asset,
                    location=f"{location_prefix}:{line_no}:{col}",
                    evidence=f"{spec.label} matched: {redact_secret(value)} (entropy={entropy:.2f})",
                    start_line=line_no,
                    column=col,
                    snippet=redact_secret(value),
                    metadata={"secret_type": spec.label, "entropy": round(entropy, 2)},
                )
            )
    return findings


# ===========================================================================
# 7. JWT inspector
# ===========================================================================

JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*(?![\w-])")
SENSITIVE_JWT_KEYS = {
    "password", "passwd", "secret", "ssn", "credit_card", "creditcard", "private_key",
    "pin", "mfa_secret", "totp", "api_key", "apikey", "refresh_token",
}


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def inspect_jwt_token(
    token: str, asset: str, location: str, *, start_line: int = 0
) -> list[Finding]:
    findings: list[Finding] = []
    parts = token.strip().split(".")
    if len(parts) != 3:
        return findings
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return findings
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return findings

    alg = str(header.get("alg", "")).lower()
    if alg == "none" or not parts[2]:
        findings.append(
            Finding.from_rule(
                "BH-014", asset=asset, location=location,
                evidence=f"JWT alg={header.get('alg')!r}, signature_present={bool(parts[2])}",
                start_line=start_line,
            )
        )

    missing = [c for c in ("exp", "aud") if c not in payload]
    if missing:
        findings.append(
            Finding.from_rule(
                "BH-015", asset=asset, location=location,
                evidence=f"Missing JWT claims: {', '.join(missing)}",
                start_line=start_line,
            )
        )

    exp, iat = payload.get("exp"), payload.get("iat")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        ttl_hours = (exp - iat) / 3600.0
        if ttl_hours > 24:
            findings.append(
                Finding.from_rule(
                    "BH-016", asset=asset, location=location,
                    evidence=f"JWT TTL is {ttl_hours:.1f}h (> 24h).",
                    start_line=start_line,
                )
            )
    if isinstance(exp, (int, float)) and exp < time.time():
        findings.append(
            Finding.from_rule(
                "BH-015", asset=asset, location=location,
                evidence="JWT is already expired (stale credential in artifact).",
                start_line=start_line,
            )
        )

    pii_keys = [k for k in payload if str(k).lower() in SENSITIVE_JWT_KEYS]
    if pii_keys:
        findings.append(
            Finding.from_rule(
                "BH-017", asset=asset, location=location,
                evidence=f"JWT exposes keys: {', '.join(pii_keys)}",
                start_line=start_line,
            )
        )

    if any(k in header for k in ("jku", "x5u", "jwk")):
        findings.append(
            Finding.from_rule(
                "BH-038", asset=asset, location=location,
                evidence=f"JWT header embeds remote key reference(s): {', '.join(k for k in ('jku','x5u','jwk') if k in header)}",
                start_line=start_line,
                confidence="MEDIUM",
            )
        )
    return findings


# ===========================================================================
# 8. JavaScript / TypeScript auditor (masking + taint + sinks)
# ===========================================================================

TAINT_SOURCE_EXPR = re.compile(
    r"(?:"
    r"location\.(?:search|hash|href|pathname|toString)"
    r"|document\.(?:URL|documentURI|referrer|cookie|baseURI)"
    r"|(?:window|self|top)\.name"
    r"|history\.state"
    r"|new\s+URLSearchParams"
    r"|(?:local|session)Storage\.getItem"
    r"|event\.data"
    r"|(?:request|req)\.(?:query|params|body|url)"
    r"|URLSearchParams\([^)]*\)\.get"
    r")"
)

VAR_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
)
PLAIN_ASSIGN_RE = re.compile(r"(?:^|[;{}]\s*)([A-Za-z_$][\w$]*)\s*=\s*([^=;\n][^;\n]*)")

SINK_CALL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML/outerHTML assignment", re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*([^;\n]+)")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,]{0,80},\s*([^)]{1,400})\)")),
    ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*([^)]{1,400})\)")),
    ("eval/Function", re.compile(r"\b(?:eval|Function)\s*\(\s*([^)]{1,400})\)")),
    ("string timer", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*([^,)]{1,400})")),
    ("location assignment", re.compile(r"\b(?:window\.|document\.)?location(?:\.href|\.assign|\.replace)?\s*=\s*([^;\n]+)")),
    ("jQuery .html/.append", re.compile(r"\.(?:html|append|prepend|after|before)\s*\(\s*([^)]{1,400})\)")),
    ("React dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML\s*:\s*\{[^}]*__html\s*:\s*([^,}]+)")),
    ("iframe srcdoc", re.compile(r"\.srcdoc\s*=\s*([^;\n]+)")),
)

SANITIZER_HINTS = re.compile(
    r"(?:DOMPurify\.(?:sanitize|clean)|sanitizeHtml|escapeHtml|encodeURIComponent|textContent\s*=|createTextNode|validator\.escape|he\.encode)"
)

POSTMESSAGE_LISTENER = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]\s*,\s*"""
    r"""(?:function\s*\w*\s*\(([^)]*)\)|\(?([^)=]*)\)?\s*=>)\s*\{([\s\S]{0,900})""",
    re.MULTILINE,
)

PROTO_POLLUTION_RE = re.compile(
    r"(?:for\s*\(\s*(?:const|let|var)\s+(\w+)\s+in\s+[\w$.]+\s*\)|Object\.keys\([^)]*\)\.forEach)"
    r"[\s\S]{0,400}\[\s*(?:\1|key|k|prop|property)\s*\]\s*=",
)

ROUTE_EXTRACTOR = re.compile(
    r"""['"`](/(?:api|rest|graphql|v\d+|internal|admin|auth|oauth|swagger|openapi)[A-Za-z0-9_\-./{}:${}]*)['"`]""",
    re.IGNORECASE,
)

_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte"}


def mask_js(source: str) -> str:
    """Blank strings and comments while preserving offsets and newlines."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if ch in ("'", '"', "`"):
            quote = ch
            out[i] = " "
            i += 1
            while i < n:
                c = source[i]
                if c == "\\":
                    out[i] = " "
                    if i + 1 < n:
                        out[i + 1] = " " if source[i + 1] != "\n" else "\n"
                    i += 2
                    continue
                if c == quote:
                    out[i] = " "
                    i += 1
                    break
                if c == "\n":
                    if quote != "`":
                        break
                    out[i] = "\n"
                    i += 1
                    continue
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n - 1 and not (source[i] == "*" and source[i + 1] == "/"):
                out[i] = "\n" if source[i] == "\n" else " "
                i += 1
            if i < n - 1:
                out[i] = out[i + 1] = " "
                i += 2
            continue
        i += 1
    return "".join(out)


def trace_js_taint_vars(content: str, masked: str | None = None) -> dict[str, str]:
    """Fixed-point taint propagation across variable assignments."""
    masked = masked if masked is not None else mask_js(content)
    assignments: list[tuple[str, str]] = []
    for match in VAR_ASSIGN_RE.finditer(masked):
        rhs_start, rhs_end = match.span(2)
        assignments.append((match.group(1), content[rhs_start:rhs_end]))
    for match in PLAIN_ASSIGN_RE.finditer(masked):
        if match.group(1) in ("if", "while", "for", "return", "function"):
            continue
        rhs_start, rhs_end = match.span(2)
        assignments.append((match.group(1), content[rhs_start:rhs_end]))

    tainted: dict[str, str] = {}
    for var_name, expr in assignments:
        source = TAINT_SOURCE_EXPR.search(expr)
        if source:
            tainted[var_name] = source.group(0)[:60]

    for _ in range(4):
        changed = False
        for var_name, expr in assignments:
            if var_name in tainted:
                continue
            for source_var, root in tainted.items():
                if re.search(rf"\b{re.escape(source_var)}\b", expr):
                    tainted[var_name] = f"{root} -> {source_var}"
                    changed = True
                    break
        if not changed:
            break
    return tainted


def audit_js_content(
    content: str,
    asset: str,
    location: str,
    *,
    line_index: LineIndex | None = None,
) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    discovered_routes: set[str] = set()
    index = line_index or LineIndex(content)
    masked = mask_js(content)

    if "//# sourceMappingURL=" in content or "//@ sourceMappingURL=" in content:
        line_no = content[: content.find("sourceMappingURL")].count("\n") + 1
        findings.append(
            Finding.from_rule(
                "BH-010", asset=asset, location=f"{location}:{line_no}",
                evidence="Bundle exposes sourceMappingURL comment.",
                start_line=line_no,
            )
        )

    tainted_vars = trace_js_taint_vars(content, masked)
    for sink_name, pattern in SINK_CALL_PATTERNS:
        for match in pattern.finditer(masked):
            start, end = match.span(1)
            arg = content[start:end].strip()
            line_no, col = index.line_col(match.start())
            if not arg:
                continue
            direct = TAINT_SOURCE_EXPR.search(arg)
            flow_var = next(
                (var for var in tainted_vars if re.search(rf"\b{re.escape(var)}\b", arg)),
                None,
            )
            if not direct and not flow_var:
                continue
            if SANITIZER_HINTS.search(arg):
                continue
            if sink_name == "string timer" and re.match(r"(?:function|\(|async\b|[\w$.]+\s*=>)", arg):
                continue
            chain = f"{tainted_vars[flow_var]} -> {flow_var}" if flow_var else direct.group(0) if direct else ""
            findings.append(
                Finding.from_rule(
                    "BH-011",
                    asset=asset,
                    location=f"{location}:{line_no}:{col}",
                    evidence=f"{sink_name} receives untrusted data [{chain}]: {safe_snippet(arg, 120)}",
                    start_line=line_no,
                    column=col,
                    snippet=safe_snippet(match.group(0), 200),
                )
            )

    for match in PROTO_POLLUTION_RE.finditer(masked):
        block_start = match.start()
        block_end = min(len(content), match.end() + 120)
        block = content[block_start:block_end]
        if "__proto__" in block or "constructor" in block:
            continue
        if re.search(r"(?:hasOwnProperty|Object\.create\(null\)|__proto__)", masked[block_start:block_end]):
            continue
        line_no, col = index.line_col(block_start)
        findings.append(
            Finding.from_rule(
                "BH-025",
                asset=asset,
                location=f"{location}:{line_no}:{col}",
                evidence="Dynamic bracket property assignment loop lacks '__proto__' / 'constructor' guard.",
                start_line=line_no,
                column=col,
                snippet=safe_snippet(match.group(0), 180),
            )
        )

    for match in POSTMESSAGE_LISTENER.finditer(content):
        body = match.group(3) or ""
        if re.search(r"(?:event|evt|e|msg|message)\.origin\b", body) or "origin ===" in body:
            continue
        line_no, col = index.line_col(match.start())
        findings.append(
            Finding.from_rule(
                "BH-012",
                asset=asset,
                location=f"{location}:{line_no}:{col}",
                evidence="postMessage handler reads event.data without an event.origin check in the first 900 chars.",
                start_line=line_no,
                column=col,
                snippet=safe_snippet(match.group(0), 160),
            )
        )

    findings.extend(scan_text_for_secrets(content, asset, f"{location}", line_index=index))
    for jwt_match in set(JWT_REGEX.findall(content)):
        line_no = content[: content.find(jwt_match)].count("\n") + 1
        findings.extend(inspect_jwt_token(jwt_match, asset, f"{location}:embedded_jwt", start_line=line_no))

    for route_match in ROUTE_EXTRACTOR.finditer(content):
        route = route_match.group(1).split("?")[0].rstrip("/") or "/"
        discovered_routes.add(route)
        if "graphql" in route.lower():
            findings.append(
                Finding.from_rule("BH-020", asset=asset, location=location, evidence=f"GraphQL route in JS: {route}")
            )
        if "swagger" in route.lower() or "openapi" in route.lower():
            findings.append(
                Finding.from_rule("BH-021", asset=asset, location=location, evidence=f"OpenAPI route in JS: {route}")
            )

    return findings, discovered_routes


def audit_javascript_file(path: Path, text: str) -> tuple[list[Finding], set[str], set[str]]:
    """Audit a single JS/TS/HTML file or source map. Returns findings, routes, tech."""
    findings: list[Finding] = []
    routes: set[str] = set()
    technologies: set[str] = set()
    asset = str(path)
    if path.suffix == ".map":
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            return findings, routes, technologies
        sources = raw.get("sources", []) if isinstance(raw, dict) else []
        contents = raw.get("sourcesContent", []) if isinstance(raw, dict) else []
        findings.append(
            Finding.from_rule(
                "BH-010", asset=asset, location=path.name,
                evidence=f"Source map exposes {len(sources)} original source files.",
            )
        )
        for src_name, src_code in zip(sources, contents):
            if isinstance(src_code, str):
                sub, sub_routes = audit_js_content(src_code, asset, f"{path.name}->{src_name}")
                findings.extend(sub)
                routes.update(sub_routes)
        return findings, routes, technologies

    sub, routes = audit_js_content(text, asset, path.name)
    findings.extend(sub)
    if path.suffix in (".html", ".htm"):
        if re.search(r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js", text, re.IGNORECASE):
            technologies.add("react")
        if "ng-version" in text or "angular" in text.lower():
            technologies.add("angular")
        if "__NEXT_DATA__" in text:
            technologies.add("next.js")
    return findings, routes, technologies


# ===========================================================================
# 9. Python AST auditor (intra-procedural taint -> sink)
# ===========================================================================

REQUEST_SOURCE_PREFIXES = (
    "request.args", "request.form", "request.json", "request.data", "request.files",
    "request.headers", "request.cookies", "request.values", "request.get_json",
    "request.GET", "request.POST", "request.body", "request.query", "request.params",
    "request.FILES", "req.query", "req.body", "req.params", "req.headers",
    "event.get", "sys.argv", "input(",
)

JWT_DECODE_SINKS = {"jwt.decode", "jose.jwt.decode", "jwt.verify", "jws.verify"}


def dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _call_name(node: ast.Call) -> str:
    return dotted_name(node.func)


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _has_truthy_kw(call: ast.Call, name: str) -> bool:
    value = _kwarg(call, name)
    if value is None:
        return False
    if isinstance(value, ast.Constant):
        return bool(value.value)
    return False


def _is_false_kw(call: ast.Call, name: str) -> bool:
    value = _kwarg(call, name)
    return isinstance(value, ast.Constant) and value.value is False


def _source_of(expr: ast.AST) -> str:
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute):
            name = dotted_name(node)
            if name.startswith(REQUEST_SOURCE_PREFIXES):
                return name
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("input", "raw_input") or name.startswith(REQUEST_SOURCE_PREFIXES):
                return name
        elif isinstance(node, ast.Subscript):
            name = dotted_name(node.value)
            if name.startswith(REQUEST_SOURCE_PREFIXES):
                return name
    return ""


def _expr_is_tainted(expr: ast.AST, tainted: dict[str, str]) -> bool:
    if not tainted:
        return False
    return any(isinstance(n, ast.Name) and n.id in tainted for n in ast.walk(expr))


def _is_dynamic_expr(expr: ast.AST) -> bool:
    if isinstance(expr, ast.Constant):
        return False
    if isinstance(expr, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(expr, ast.Call):
        name = _call_name(expr)
        if name.endswith((".format", ".join", ".replace", ".strip")):
            return True
    return True  # variables, calls and comprehensions are all "dynamic"


def _scope_nodes(body: Sequence[ast.stmt]) -> Iterator[ast.AST]:
    """Iterate a function/module body without descending into nested scopes."""
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            stack.append(child)


class PythonAuditor:
    """Intra-procedural taint analysis for Python backends using the stdlib AST."""

    ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "route", "websocket", "api_route"}

    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.text = text
        self.asset = str(path)
        self.index = LineIndex(text)
        self.findings: list[Finding] = []
        self.routes: set[str] = set()
        self.technologies: set[str] = set()

    def _snippet(self, node: ast.AST) -> str:
        try:
            return safe_snippet(ast.get_source_segment(self.text, node) or "", 200)
        except (ValueError, TypeError):
            return ""

    def _add(self, rule_id: str, node: ast.AST, evidence: str, confidence: str | None = None) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        end_line = getattr(node, "end_lineno", line_no) or line_no
        col = (getattr(node, "col_offset", 0) or 0) + 1
        self.findings.append(
            Finding.from_rule(
                rule_id, asset=self.asset, location=f"{self.path.name}:{line_no}:{col}",
                evidence=evidence, start_line=line_no, end_line=end_line, column=col,
                snippet=self._snippet(node), confidence=confidence,
            )
        )

    def audit(self) -> tuple[list[Finding], set[str], set[str]]:
        try:
            tree = ast.parse(self.text)
        except (SyntaxError, ValueError) as exc:
            LOG.debug("Python parse failed for %s: %s", self.path, exc)
            return self.findings, self.routes, self.technologies

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._note_import(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self._note_import(node.module)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._collect_routes(node)
                self._analyse_scope(node.body)
            elif isinstance(node, ast.Call) and dotted_name(node.func) in ("path", "re_path", "url"):
                self._collect_django_route(node)
        self._analyse_scope(tree.body)
        return self.findings, self.routes, self.technologies

    def _note_import(self, module: str) -> None:
        root = module.split(".")[0]
        if root in ("flask", "fastapi", "django", "aiohttp", "tornado", "starlette", "bottle"):
            self.technologies.add(f"python:{root}")

    def _collect_routes(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            name = _call_name(decorator).split(".")[-1].lower()
            if name in self.ROUTE_DECORATORS and decorator.args:
                first = decorator.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    self.routes.add(first.value)

    def _collect_django_route(self, node: ast.Call) -> None:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            value = node.args[0].value
            if value.startswith("/") or value == "":
                self.routes.add(value if value.startswith("/") else "/" + value)

    def _analyse_scope(self, body: Sequence[ast.stmt]) -> None:
        nodes = list(_scope_nodes(body))
        assignments: list[tuple[str, ast.AST]] = []
        for node in nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.append((target.id, node.value))
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                assignments.append((elt.id, node.value))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                assignments.append((node.target.id, node.value))
            elif isinstance(node, ast.NamedExpr):
                assignments.append((node.target.id, node.value))

        tainted: dict[str, str] = {}
        for name, value in assignments:
            source = _source_of(value)
            if source:
                tainted[name] = source
        for _ in range(4):
            changed = False
            for name, value in assignments:
                if name in tainted:
                    continue
                if _expr_is_tainted(value, tainted):
                    root = next(n.id for n in ast.walk(value) if isinstance(n, ast.Name) and n.id in tainted)
                    tainted[name] = f"{tainted[root]} -> {root}"
                    changed = True
            if not changed:
                break

        for node in nodes:
            if isinstance(node, ast.Call):
                self._check_call(node, tainted)

    def _check_call(self, call: ast.Call, tainted: dict[str, str]) -> None:
        name = _call_name(call)
        short = name.split(".")[-1]
        args = call.args
        tainted_arg = next((a for a in args if _expr_is_tainted(a, tainted)), None)
        source_arg = next((a for a in args if _source_of(a)), None)
        dynamic = bool(args) and _is_dynamic_expr(args[0])
        tainted_call = bool(tainted_arg or source_arg)

        # SQL injection -----------------------------------------------------
        if short in ("execute", "executemany", "executescript", "raw", "query") and name != "re.query":
            if args and dynamic:
                confidence = "HIGH" if tainted_call else "MEDIUM"
                self._add(
                    "BH-031", call,
                    f"SQL statement built dynamically via {name}(): {self._snippet(args[0])}",
                    confidence,
                )

        # Command injection -------------------------------------------------
        if name in ("os.system", "os.popen", "os.spawnl", "os.spawnv") or (
            name.startswith("subprocess.") and _has_truthy_kw(call, "shell")
        ):
            self._add("BH-032", call, f"Shell execution via {name}(): {self._snippet(call)}")

        # Dynamic code evaluation (builtins only; re.compile is not code eval) --
        if name in ("eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile") and args:
            self._add("BH-044", call, f"Dynamic code evaluation via {name}(): {self._snippet(args[0])}")

        # Unsafe deserialisation -------------------------------------------
        if name in ("pickle.load", "pickle.loads", "dill.load", "dill.loads", "marshal.loads", "_pickle.loads"):
            self._add("BH-034", call, f"Unsafe deserialisation via {name}().")
        elif name in ("yaml.load", "yaml.unsafe_load", "yaml.full_load"):
            loader = _kwarg(call, "Loader")
            safe = isinstance(loader, ast.Attribute) and "Safe" in loader.attr
            if not safe:
                self._add("BH-034", call, f"{name}() without SafeLoader.")

        # SSRF ---------------------------------------------------------------
        if (
            name.startswith(("requests.", "httpx.", "urllib.request.urlopen", "urllib.urlopen"))
            and short in ("get", "post", "put", "delete", "request", "head", "patch", "urlopen")
        ):
            if args and dynamic and not isinstance(args[0], ast.Constant):
                confidence = "HIGH" if tainted_call else "MEDIUM"
                self._add(
                    "BH-033", call,
                    f"Outbound request uses dynamic URL: {self._snippet(args[0])}",
                    confidence,
                )

        # Weak crypto / disabled TLS ---------------------------------------
        if name in ("hashlib.md5", "hashlib.sha1", "cryptography.hazmat.primitives.hashes.MD5"):
            self._add("BH-035", call, f"Weak digest {name}().")
        elif _is_false_kw(call, "verify") or _is_false_kw(call, "rejectUnauthorized"):
            self._add("BH-035", call, f"TLS verification disabled in {name}().")

        # JWT verification ---------------------------------------------------
        if name in JWT_DECODE_SINKS:
            options = _kwarg(call, "options")
            verify_off = _is_false_kw(call, "verify")
            if isinstance(options, ast.Dict):
                for key, value in zip(options.keys, options.values):
                    if isinstance(key, ast.Constant) and key.value == "verify_signature":
                        if isinstance(value, ast.Constant) and value.value is False:
                            verify_off = True
            if verify_off:
                self._add("BH-038", call, f"JWT signature verification disabled in {name}().")

        # Server-side template injection ------------------------------------
        if short in ("render_template_string", "from_string") or name in (
            "jinja2.Template", "Template", "handlebars.compile",
        ):
            if args and (tainted_call or not isinstance(args[0], ast.Constant)):
                self._add("BH-045", call, f"Template compiled from dynamic input via {name}().", "MEDIUM")


def audit_python_file(path: Path, text: str) -> tuple[list[Finding], set[str], set[str]]:
    auditor = PythonAuditor(path, text)
    findings, routes, technologies = auditor.audit()
    findings.extend(scan_text_for_secrets(text, str(path), path.name, line_index=auditor.index))
    return findings, routes, technologies


# ===========================================================================
# 10. Generic (non-Python) backend source auditor
# ===========================================================================

GENERIC_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "BH-031",
        re.compile(
            r"""(?:execute|query|raw)\s*\(\s*(?:`[^`]*\$\{|f['"]|['"][^'"]*['"]\s*(?:\+|%|\.format\())""",
            re.IGNORECASE,
        ),
        "Dynamic SQL string concatenation/formatting detected.",
        "MEDIUM",
    ),
    (
        "BH-032",
        re.compile(
            r"""(?:subprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|child_process\.exec(?:Sync)?\s*\(|execSync\s*\()"""
        ),
        "OS command execution with shell evaluation enabled.",
        "HIGH",
    ),
    (
        "BH-044",
        re.compile(r"""(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|new\s+Function\s*\("""),
        "Dynamic code evaluation sink.",
        "MEDIUM",
    ),
    (
        "BH-034",
        re.compile(r"""\bpickle\.loads?\s*\(|\byaml\.load\s*\([^)]*\)|\bunserialize\s*\(|\bmarshal\.loads\s*\("""),
        "Potentially unsafe deserialization call detected.",
        "HIGH",
    ),
    (
        "BH-035",
        re.compile(r"""\bhashlib\.(?:md5|sha1)\s*\(|\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0"""),
        "Weak cryptographic digest (MD5/SHA1) or disabled TLS certificate verification.",
        "HIGH",
    ),
    (
        "BH-038",
        re.compile(r"""jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|verify_signature['"]?\s*:\s*False)|jwt\.verify\s*\([^)]*ignoreExpiration"""),
        "JWT verification explicitly disabled.",
        "HIGH",
    ),
    (
        "BH-045",
        re.compile(r"""render_template_string\s*\(|\bTemplate\s*\([^)]*\)\.render\s*\(|handlebars\.compile\s*\("""),
        "Server-side template compiled from dynamic input.",
        "MEDIUM",
    ),
)

BACKEND_ROUTE_RE = re.compile(
    r"""(?:@(?:app|router|bp|api)\.(?:get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]"""
    r"""|(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"""
    r"""|HandleFunc\s*\(\s*['"]([^'"]+)['"]"""
    r"""|@(?:Get|Post|Put|Delete)Mapping\s*\(\s*['"]([^'"]+)['"])"""
)

_SOURCE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".py", ".go", ".php", ".java", ".rb", ".cs", ".kt", ".scala", ".rs",
    ".html", ".htm",
}


def audit_generic_source(path: Path, text: str) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    routes: set[str] = set()
    index = LineIndex(text)
    for rule_id, pattern, message, confidence in GENERIC_PATTERNS:
        if path.suffix in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs") and rule_id == "BH-044":
            # The JS auditor already covers eval/DOM; keep this pass for server-side sinks.
            continue
        for match in pattern.finditer(text):
            if rule_id == "BH-034" and "SafeLoader" in text[match.start(): match.end() + 40]:
                continue
            line_no, col = index.line_col(match.start())
            findings.append(
                Finding.from_rule(
                    rule_id, asset=str(path), location=f"{path.name}:{line_no}:{col}",
                    evidence=f"{message} Snippet: {safe_snippet(match.group(0), 100)}",
                    start_line=line_no, column=col, confidence=confidence,
                )
            )
    for match in BACKEND_ROUTE_RE.finditer(text):
        route = next((g for g in match.groups() if g), "")
        if route:
            routes.add(route if route.startswith("/") else "/" + route)
    return findings, routes


# ===========================================================================
# 11. Dockerfile, Kubernetes and CI/CD auditors
# ===========================================================================

def _line_of(text: str, needle: str) -> int:
    pos = text.find(needle)
    return text[:pos].count("\n") + 1 if pos >= 0 else 0


def audit_dockerfile(text: str, asset: str) -> list[Finding]:
    findings: list[Finding] = []
    index = LineIndex(text)
    user_seen = False
    for match in re.finditer(r"^[ \t]*FROM[ \t]+([^\s#]+)", text, re.IGNORECASE | re.MULTILINE):
        image = match.group(1)
        if image.lower() == "scratch":
            continue
        digest_pinned = "@sha256:" in image
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
        if not digest_pinned and (tag in ("", "latest")):
            line_no, col = index.line_col(match.start(1))
            findings.append(
                Finding.from_rule(
                    "BH-043", asset=asset, location=f"{asset}:{line_no}:{col}",
                    evidence=f"Base image '{image}' is not pinned by digest or version tag.",
                    start_line=line_no, column=col, confidence="HIGH",
                )
            )
    for match in re.finditer(r"^[ \t]*USER[ \t]+(\S+)", text, re.IGNORECASE | re.MULTILINE):
        user_seen = True
        user = match.group(1).strip().lower()
        if user in ("root", "0", "root:root", "0:0"):
            line_no, col = index.line_col(match.start())
            findings.append(
                Finding.from_rule(
                    "BH-036", asset=asset, location=f"{asset}:{line_no}:{col}",
                    evidence=f"Container explicitly runs as root: 'USER {match.group(1)}'.",
                    start_line=line_no, column=col,
                )
            )
    if not user_seen and re.search(r"^[ \t]*FROM", text, re.IGNORECASE | re.MULTILINE):
        line_no = _line_of(text, "FROM")
        findings.append(
            Finding.from_rule(
                "BH-036", asset=asset, location=f"{asset}:{line_no}",
                evidence="Dockerfile sets no USER instruction; the container inherits the base image user (often root).",
                start_line=line_no, confidence="LOW", severity="INFO",
            )
        )
    return findings


def _load_yaml_documents(text: str) -> list[Any] | None:
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except Exception:
        return None


def _iter_workload_specs(doc: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(doc, dict):
        return
    kind = str(doc.get("kind", ""))
    if kind not in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
        return
    spec = doc.get("spec", {})
    if not isinstance(spec, dict):
        return
    if kind == "Pod":
        yield spec
    elif kind == "CronJob":
        job = spec.get("jobTemplate", {}).get("spec", {})
        yield job.get("template", {}).get("spec", {}) if isinstance(job, dict) else {}
    else:
        yield spec.get("template", {}).get("spec", {})


def audit_kubernetes(text: str, asset: str) -> list[Finding]:
    findings: list[Finding] = []
    docs = _load_yaml_documents(text)
    images: list[tuple[str, str]] = []
    if docs is not None:
        for doc in docs:
            for pod_spec in _iter_workload_specs(doc):
                if not isinstance(pod_spec, dict):
                    continue
                for host_key in ("hostNetwork", "hostPID", "hostIPC"):
                    if pod_spec.get(host_key) is True:
                        line_no = _line_of(text, host_key)
                        findings.append(
                            Finding.from_rule(
                                "BH-041", asset=asset, location=f"{asset}:{line_no}",
                                evidence=f"Pod spec enables {host_key}: true.",
                                start_line=line_no,
                            )
                        )
                for volume in pod_spec.get("volumes", []) or []:
                    if isinstance(volume, dict) and "hostPath" in volume:
                        line_no = _line_of(text, "hostPath")
                        findings.append(
                            Finding.from_rule(
                                "BH-041", asset=asset, location=f"{asset}:{line_no}",
                                evidence=f"Volume '{volume.get('name', '?')}' mounts a hostPath directory.",
                                start_line=line_no,
                            )
                        )
                containers = list(pod_spec.get("containers", []) or []) + list(pod_spec.get("initContainers", []) or [])
                for container in containers:
                    if not isinstance(container, dict):
                        continue
                    image = str(container.get("image", ""))
                    if image:
                        images.append((str(container.get("name", "?")), image))
                    security = container.get("securityContext", {}) or {}
                    if security.get("privileged") is True:
                        line_no = _line_of(text, "privileged")
                        findings.append(
                            Finding.from_rule(
                                "BH-036", asset=asset, location=f"{asset}:{line_no}",
                                evidence=f"Container '{container.get('name', '?')}' runs privileged: true.",
                                start_line=line_no,
                            )
                        )
                    if security.get("allowPrivilegeEscalation") is True:
                        line_no = _line_of(text, "allowPrivilegeEscalation")
                        findings.append(
                            Finding.from_rule(
                                "BH-036", asset=asset, location=f"{asset}:{line_no}",
                                evidence=f"Container '{container.get('name', '?')}' allows privilege escalation.",
                                start_line=line_no, confidence="MEDIUM",
                            )
                        )
                    if security.get("runAsUser") == 0:
                        line_no = _line_of(text, "runAsUser")
                        findings.append(
                            Finding.from_rule(
                                "BH-036", asset=asset, location=f"{asset}:{line_no}",
                                evidence=f"Container '{container.get('name', '?')}' explicitly runs as UID 0.",
                                start_line=line_no,
                            )
                        )
    else:
        for key, rule_id in (("privileged", "BH-036"), ("hostNetwork", "BH-041"), ("hostPID", "BH-041"), ("hostPath", "BH-041")):
            for match in re.finditer(rf"^[ \t-]*{key}\s*:\s*(?:true|$)", text, re.MULTILINE | re.IGNORECASE):
                line_no, _ = LineIndex(text).line_col(match.start())
                findings.append(
                    Finding.from_rule(
                        rule_id, asset=asset, location=f"{asset}:{line_no}",
                        evidence=f"Manifest sets {key} (heuristic match).",
                        start_line=line_no, confidence="MEDIUM",
                    )
                )
        images = [(m.group(0), m.group(1)) for m in re.finditer(r"image:\s*(\S+)", text)]

    for name, image in images:
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
        if "@sha256:" not in image and tag in ("", "latest"):
            line_no = _line_of(text, image)
            findings.append(
                Finding.from_rule(
                    "BH-043", asset=asset, location=f"{asset}:{line_no}",
                    evidence=f"Container image '{image}' is not pinned by digest.",
                    start_line=line_no, confidence="HIGH",
                )
            )
    return findings


def audit_ci_workflow(text: str, asset: str) -> list[Finding]:
    findings: list[Finding] = []
    index = LineIndex(text)
    if re.search(r"pull_request_target", text) and re.search(
        r"ref:\s*\$\{\{\s*github\.event\.pull_request\.(?:head|merge)", text
    ):
        line_no, col = index.line_col(re.search(r"pull_request_target", text).start())  # type: ignore[union-attr]
        findings.append(
            Finding.from_rule(
                "BH-037", asset=asset, location=f"{asset}:{line_no}:{col}",
                evidence="pull_request_target workflow checks out untrusted PR head code (secret exfiltration risk).",
                start_line=line_no, column=col,
            )
        )

    tainted_expr = re.compile(
        r"\$\{\{\s*(?:github\.(?:event\.(?:issue|pull_request|comment|review|head_commit)|head_ref)"
        r"|env\.(?:TITLE|BODY|COMMENT|BRANCH))"
    )
    run_indent: int | None = None
    for line_no, line in enumerate(text.splitlines(), start=1):
        if re.search(r"^\s*#", line):
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        run_header = re.match(r"^(\s*)(?:-\s+)?run:\s*([|>])?\s*(.*)$", line)
        if run_header:
            run_indent = len(run_header.group(1))
            inline_command = run_header.group(3)
            if inline_command and tainted_expr.search(inline_command):
                findings.append(
                    Finding.from_rule(
                        "BH-037", asset=asset, location=f"{asset}:{line_no}",
                        evidence=f"Attacker-controlled expression in run step: {safe_snippet(inline_command, 120)}",
                        start_line=line_no,
                    )
                )
            continue
        if run_indent is not None:
            if stripped and indent <= run_indent:
                run_indent = None
            elif tainted_expr.search(line):
                findings.append(
                    Finding.from_rule(
                        "BH-037", asset=asset, location=f"{asset}:{line_no}",
                        evidence=f"Attacker-controlled expression interpolated in run block: {safe_snippet(line, 120)}",
                        start_line=line_no,
                    )
                )
        for match in re.finditer(r"uses:\s*([^\s#]+)", line):
            action = match.group(1)
            if action.startswith("./") or action.startswith("docker://"):
                continue
            if "@" not in action:
                findings.append(
                    Finding.from_rule(
                        "BH-043", asset=asset, location=f"{asset}:{line_no}",
                        evidence=f"Action '{action}' has no pinned ref.",
                        start_line=line_no, confidence="MEDIUM",
                    )
                )
                continue
            ref = action.rsplit("@", 1)[1]
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                findings.append(
                    Finding.from_rule(
                        "BH-043", asset=asset, location=f"{asset}:{line_no}",
                        evidence=f"Action '{action}' is pinned to a mutable tag, not a commit SHA.",
                        start_line=line_no, confidence="MEDIUM",
                    )
                )
    return findings


# ===========================================================================
# 12. OpenAPI / Swagger auditor
# ===========================================================================

SENSITIVE_SCHEMA_FIELDS = {
    "password", "passwordhash", "password_hash", "secret", "apikey", "api_key", "api-key",
    "ssn", "socialsecuritynumber", "creditcard", "credit_card", "privatekey", "private_key",
    "internalrole", "mfa_secret", "otp_secret", "refresh_token", "access_token",
}

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")


def _load_structured_spec(path: Path) -> Any:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        docs = _load_yaml_documents(text)
        if docs:
            return docs[0]
        raise ValueError(f"Spec is neither valid JSON nor YAML: {path}")


def _iter_schema_properties(schema: Any, seen: set[int] | None = None) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (property_name, schema_node) recursively through a JSON Schema."""
    seen = seen or set()
    if not isinstance(schema, dict) or id(schema) in seen:
        return
    seen.add(id(schema))
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for prop_name, prop_schema in properties.items():
            if isinstance(prop_schema, dict):
                yield str(prop_name), prop_schema
                yield from _iter_schema_properties(prop_schema, seen)
    for key in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(key, []) or []:
            yield from _iter_schema_properties(sub, seen)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _iter_schema_properties(items, seen)


def audit_openapi_spec(spec_path: Path) -> ScanResult:
    raw = _load_structured_spec(spec_path)
    if not isinstance(raw, dict) or not (raw.get("paths") or raw.get("swagger") or raw.get("openapi")):
        raise ValueError(f"Not an OpenAPI/Swagger document: {spec_path}")

    findings: list[Finding] = []
    routes: set[str] = set()
    paths = raw.get("paths", {}) or {}
    global_security = raw.get("security")
    asset = spec_path.name

    for route, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            http_method = method.upper()
            routes.add(f"{http_method} {route}")
            op_security = operation.get("security", global_security)
            if http_method in STATE_CHANGING:
                if op_security == []:
                    findings.append(
                        Finding.from_rule(
                            "BH-028", asset=asset, location=f"{http_method} {route}",
                            evidence="Operation explicitly sets 'security: []' (no authentication).",
                        )
                    )
                elif op_security is None:
                    findings.append(
                        Finding.from_rule(
                            "BH-028", asset=asset, location=f"{http_method} {route}",
                            evidence="State-changing operation inherits no global security scheme.",
                            confidence="MEDIUM",
                        )
                    )
            for response in (operation.get("responses") or {}).values():
                if not isinstance(response, dict):
                    continue
                for media in (response.get("content") or {}).values():
                    if not isinstance(media, dict):
                        continue
                    schema = media.get("schema")
                    exposed = {
                        name for name, _ in _iter_schema_properties(schema)
                        if name.lower() in SENSITIVE_SCHEMA_FIELDS
                    }
                    if exposed:
                        findings.append(
                            Finding.from_rule(
                                "BH-029", asset=asset, location=f"{http_method} {route} response",
                                evidence=f"Response schema exposes sensitive properties: {', '.join(sorted(exposed))}",
                            )
                        )

    schemas = (raw.get("components", {}) or {}).get("schemas", {}) or raw.get("definitions", {}) or {}
    for schema_name, schema_def in schemas.items():
        exposed = sorted({
            name for name, _ in _iter_schema_properties(schema_def)
            if name.lower() in SENSITIVE_SCHEMA_FIELDS
        })
        if exposed:
            findings.append(
                Finding.from_rule(
                    "BH-029", asset=asset, location=f"schema:{schema_name}",
                    evidence=f"Schema exposes sensitive property names: {', '.join(exposed)}",
                )
            )

    for server in raw.get("servers", []) or []:
        if not isinstance(server, dict):
            continue
        url = str(server.get("url", ""))
        parsed = urllib.parse.urlparse(url)
        if parsed.username or parsed.password:
            findings.append(
                Finding.from_rule(
                    "BH-013", asset=asset, location="servers",
                    evidence=f"Server URL embeds credentials: {redact_secret(parsed.username or '')}",
                    confidence="MEDIUM",
                )
            )

    result = ScanResult(findings=deduplicate_findings(findings), endpoints=sorted(routes))
    return result


# ===========================================================================
# 13. HAR auditor, APS ranking and role diffing
# ===========================================================================

REDIRECT_PARAM_NAMES = {
    "next", "url", "target", "rurl", "dest", "destination", "redir",
    "redirect_uri", "redirect_url", "return", "returnto", "continue",
}
SENSITIVE_QUERY_NAMES = {
    "token", "access_token", "id_token", "refresh_token", "api_key", "apikey",
    "api-key", "secret", "client_secret", "password", "passwd", "auth", "authorization",
    "session", "sessionid", "jwt", "key", "sig", "signature", "code",
}
SESSION_COOKIE_HINTS = ("sess", "sid", "token", "auth", "jwt", "csrf", "login")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
NUMERIC_SEG_RE = re.compile(r"(?<=/)\d+(?=/|$)")
HEX_ID_SEG_RE = re.compile(r"(?<=/)[0-9a-f]{16,}(?=/|$)", re.IGNORECASE)


def normalize_endpoint_template(method: str, path: str) -> str:
    norm = UUID_RE.sub("{uuid}", path)
    norm = NUMERIC_SEG_RE.sub("{id}", norm)
    norm = HEX_ID_SEG_RE.sub("{id}", norm)
    return f"{method.upper()} {norm}"


def _headers_to_map(headers_list: Any) -> dict[str, list[str]]:
    hmap: dict[str, list[str]] = {}
    if not isinstance(headers_list, list):
        return hmap
    for item in headers_list:
        if not isinstance(item, dict):
            continue
        key = str(item.get("name", "")).lower().strip()
        value = str(item.get("value", "")).strip()
        if key:
            hmap.setdefault(key, []).append(value)
    return hmap


def is_sensitive_query_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in SENSITIVE_QUERY_NAMES:
        return True
    return lowered.endswith(("_token", "_key", "_secret", "_password", "token"))


def compute_aps_score(
    method: str,
    norm_path: str,
    has_auth: bool,
    statuses: Iterable[int],
    query_keys: Sequence[str],
    finding_count: int,
    avg_response_bytes: int = 0,
    content_types: Sequence[str] = (),
) -> tuple[int, list[str]]:
    """Attack Priority Score with an explainable component breakdown."""
    status_set = set(statuses)
    score = 10
    reasons = ["base=10"]
    if method.upper() in STATE_CHANGING:
        score += 18
        reasons.append(f"state-changing method {method.upper()}=+18")
    if has_auth:
        score += 15
        reasons.append("authenticated session observed=+15")
    if "{id}" in norm_path or "{uuid}" in norm_path:
        score += 16
        reasons.append("object identifier in path=+16")
    if any(k.lower() in REDIRECT_PARAM_NAMES for k in query_keys):
        score += 10
        reasons.append("redirect-style parameter=+10")
    sensitive = [k for k in query_keys if is_sensitive_query_name(k)]
    if sensitive:
        score += 12
        reasons.append(f"sensitive query parameter(s) {', '.join(sensitive[:3])}=+12")
    if any(k.lower() in ("file", "path", "url", "uri", "template", "query", "role", "admin", "cmd", "exec") for k in query_keys):
        score += 12
        reasons.append("high-risk parameter name=+12")
    if 200 in status_set:
        score += 5
        reasons.append("HTTP 200=+5")
    if any("json" in ct for ct in content_types):
        score += 4
        reasons.append("structured JSON response=+4")
    if avg_response_bytes > 2048:
        score += 3
        reasons.append("large response body=+3")
    if finding_count:
        bonus = min(20, finding_count * 6)
        score += bonus
        reasons.append(f"{finding_count} correlated finding(s)=+{bonus}")
    return min(score, 100), reasons


def audit_har_file(har_path: Path, scope_guard: ScopeGuard | None = None) -> ScanResult:
    try:
        data = json.loads(har_path.read_text(encoding="utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid HAR JSON in {har_path}: {exc}") from exc
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    if not isinstance(entries, list):
        raise ValueError(f"HAR has no log.entries array: {har_path}")

    findings: list[Finding] = []
    endpoints: set[str] = set()
    observed_paths: set[str] = set()
    js_discovered_routes: set[str] = set()
    technologies: set[str] = set()
    endpoint_profiles: dict[str, dict[str, Any]] = {}
    skipped_out_of_scope = 0

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        findings_before = len(findings)
        request = entry.get("request", {}) or {}
        response = entry.get("response", {}) or {}
        url = str(request.get("url", ""))
        method = str(request.get("method", "GET")).upper()
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if not host:
            continue
        if scope_guard and not scope_guard.is_domain_in_scope(host):
            skipped_out_of_scope += 1
            continue

        clean_endpoint = f"{method} {parsed.scheme}://{parsed.netloc}{parsed.path}"
        norm_template = normalize_endpoint_template(method, parsed.path)
        endpoints.add(clean_endpoint)
        observed_paths.add(parsed.path.rstrip("/") or "/")

        req_headers = _headers_to_map(request.get("headers", []))
        resp_headers = _headers_to_map(response.get("headers", []))
        status = int(response.get("status", 0) or 0)
        content = response.get("content", {}) or {}
        mime = str(content.get("mimeType", "")).lower()
        body_text = content.get("text", "") or ""
        if content.get("encoding") == "base64" and body_text:
            try:
                body_text = base64.b64decode(body_text).decode("utf-8", errors="replace")
            except (ValueError, binascii.Error):
                body_text = ""

        query = urllib.parse.parse_qs(parsed.query)
        query_keys = sorted(query.keys())
        has_auth = "authorization" in req_headers or "cookie" in req_headers
        location = f"{clean_endpoint}"
        body_index = LineIndex(body_text) if body_text else None

        if ("{id}" in norm_template or "{uuid}" in norm_template) and (
            "/api" in parsed.path.lower() or "application/json" in mime
        ):
            findings.append(
                Finding.from_rule(
                    "BH-030", asset=host, location=norm_template,
                    evidence=f"Object identifier template observed on API route: {parsed.path}",
                )
            )

        redirect_keys = [k for k in query_keys if k.lower() in REDIRECT_PARAM_NAMES]
        if redirect_keys:
            findings.append(
                Finding.from_rule(
                    "BH-019", asset=host, location=location,
                    evidence=f"Redirect-style parameters: {', '.join(redirect_keys)}",
                )
            )

        sensitive_keys = [k for k in query_keys if is_sensitive_query_name(k)]
        if sensitive_keys:
            findings.append(
                Finding.from_rule(
                    "BH-039", asset=host, location=location,
                    evidence=f"Credential-like parameter(s) in URL query: {', '.join(sensitive_keys)}",
                )
            )
        for key in query_keys:
            for value in query.get(key, []):
                for jwt_token in set(JWT_REGEX.findall(value)):
                    findings.extend(inspect_jwt_token(jwt_token, host, f"{location} (query:{key})"))

        if "/authorize" in parsed.path.lower() or "client_id" in query:
            response_types = query.get("response_type", [])
            if "state" not in query or any("token" in rt for rt in response_types):
                findings.append(
                    Finding.from_rule(
                        "BH-018", asset=host, location=location,
                        evidence=f"OAuth authorize params: response_type={response_types}, has_state={'state' in query}",
                    )
                )

        acao_values = resp_headers.get("access-control-allow-origin", [])
        acac_values = [v.lower() for v in resp_headers.get("access-control-allow-credentials", [])]
        request_origins = req_headers.get("origin", [])
        if acao_values:
            acao = acao_values[0]
            credentials = "true" in acac_values
            if acao == "null":
                findings.append(
                    Finding.from_rule("BH-002", asset=host, location=location, evidence="ACAO=null")
                )
            elif (acao == "*" and credentials) or (
                request_origins and acao == request_origins[0] and credentials
            ):
                findings.append(
                    Finding.from_rule(
                        "BH-001", asset=host, location=location,
                        evidence=f"Origin={request_origins}, ACAO={acao}, ACAC={acac_values}",
                    )
                )

        if "text/html" in mime and 200 <= status < 400:
            csp_list = resp_headers.get("content-security-policy", [])
            if not csp_list:
                findings.append(Finding.from_rule("BH-003", asset=host, location=location, evidence="Missing CSP header."))
            elif any(tok in " ; ".join(csp_list) for tok in ("'unsafe-inline'", "'unsafe-eval'", "script-src *")):
                findings.append(
                    Finding.from_rule("BH-004", asset=host, location=location, evidence=f"CSP: {' ; '.join(csp_list)[:150]}")
                )
            if not resp_headers.get("x-frame-options") and not any("frame-ancestors" in c for c in csp_list):
                findings.append(
                    Finding.from_rule("BH-006", asset=host, location=location, evidence="Missing X-Frame-Options & frame-ancestors.")
                )

        if parsed.scheme == "https" and 200 <= status < 400:
            hsts = resp_headers.get("strict-transport-security", [])
            if not hsts:
                findings.append(Finding.from_rule("BH-005", asset=host, location=location, evidence="Missing HSTS header."))
            else:
                match_age = re.search(r"max-age=(\d+)", hsts[0])
                if match_age and int(match_age.group(1)) < 15552000:
                    findings.append(
                        Finding.from_rule("BH-005", asset=host, location=location, evidence=f"Weak HSTS max-age={match_age.group(1)}.")
                    )

        for cookie in resp_headers.get("set-cookie", []):
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=", 1)[0].strip()
            if "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                findings.append(
                    Finding.from_rule("BH-008", asset=host, location=location, evidence=f"Cookie '{cookie_name}' SameSite=None without Secure.")
                )
            if any(hint in cookie_name.lower() for hint in SESSION_COOKIE_HINTS):
                if "httponly" not in cookie_lower or "secure" not in cookie_lower:
                    findings.append(
                        Finding.from_rule("BH-007", asset=host, location=location, evidence=f"Cookie '{cookie_name}' missing HttpOnly/Secure.")
                    )

        if "authorization" in req_headers and "application/json" in mime and status == 200:
            cache_control = " ".join(resp_headers.get("cache-control", [])).lower()
            if "no-store" not in cache_control:
                findings.append(
                    Finding.from_rule("BH-009", asset=host, location=location, evidence=f"Cache-Control='{cache_control or 'MISSING'}'")
                )

        for banner_header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            for value in resp_headers.get(banner_header, []):
                technologies.add(f"{banner_header}: {value}")
                if re.search(r"\d+\.\d+", value):
                    findings.append(
                        Finding.from_rule("BH-022", asset=host, location=location, evidence=f"{banner_header}: {value}")
                    )

        for auth_value in req_headers.get("authorization", []):
            for jwt_token in JWT_REGEX.findall(auth_value):
                findings.extend(inspect_jwt_token(jwt_token, host, f"{location} (Authorization)"))

        if body_text:
            for jwt_token in set(JWT_REGEX.findall(body_text)):
                findings.extend(
                    inspect_jwt_token(jwt_token, host, f"{location} (Body)", start_line=1)
                )
            if "javascript" in mime or parsed.path.endswith(".js"):
                js_findings, js_routes = audit_js_content(body_text, host, location, line_index=body_index)
                findings.extend(js_findings)
                js_discovered_routes.update(js_routes)
            else:
                findings.extend(
                    scan_text_for_secrets(
                        body_text, host, f"har_entry_{idx}:{location}", line_index=body_index
                    )
                )

        if "/graphql" in parsed.path.lower() or ("__schema" in body_text and "queryType" in body_text):
            findings.append(Finding.from_rule("BH-020", asset=host, location=location, evidence="GraphQL surface detected."))
        if any(p in parsed.path.lower() for p in ("swagger.json", "openapi.json", "/api-docs")):
            findings.append(Finding.from_rule("BH-021", asset=host, location=location, evidence="OpenAPI/Swagger path detected."))

        profile = endpoint_profiles.setdefault(
            norm_template,
            {
                "template": norm_template,
                "host": host,
                "method": method,
                "sample_url": url,
                "statuses": set(),
                "authenticated_seen": False,
                "unauthenticated_seen": False,
                "query_keys": set(),
                "body_lengths": [],
                "content_types": set(),
                "auth_schemes": set(),
                "finding_count": 0,
            },
        )
        profile["finding_count"] += len(findings) - findings_before
        profile["statuses"].add(status)
        if has_auth:
            profile["authenticated_seen"] = True
            if "authorization" in req_headers:
                scheme = req_headers["authorization"][0].split(" ", 1)[0] if req_headers["authorization"] else "unknown"
                profile["auth_schemes"].add(scheme)
            if "cookie" in req_headers:
                profile["auth_schemes"].add("cookie")
        else:
            profile["unauthenticated_seen"] = True
        profile["query_keys"].update(query_keys)
        profile["body_lengths"].append(len(body_text))
        if mime:
            profile["content_types"].add(mime.split(";")[0])

    ranked_endpoints: list[dict[str, Any]] = []
    for template, profile in endpoint_profiles.items():
        related = profile["finding_count"]
        statuses = sorted(profile["statuses"])
        average_bytes = int(sum(profile["body_lengths"]) / max(len(profile["body_lengths"]), 1))
        aps, reasons = compute_aps_score(
            method=profile["method"],
            norm_path=template,
            has_auth=profile["authenticated_seen"],
            statuses=statuses,
            query_keys=sorted(profile["query_keys"]),
            finding_count=related,
            avg_response_bytes=average_bytes,
            content_types=sorted(profile["content_types"]),
        )
        ranked_endpoints.append({
            "template": template,
            "host": profile["host"],
            "aps_score": aps,
            "aps_reasons": reasons,
            "statuses": statuses,
            "authenticated_seen": profile["authenticated_seen"],
            "unauthenticated_seen": profile["unauthenticated_seen"],
            "auth_schemes": sorted(profile["auth_schemes"]),
            "query_keys": sorted(profile["query_keys"]),
            "content_types": sorted(profile["content_types"]),
            "avg_response_bytes": average_bytes,
        })
    ranked_endpoints.sort(key=lambda item: (-item["aps_score"], item["template"]))

    normalized_observed = {path.rstrip("/") or "/" for path in observed_paths}
    ghost_routes = sorted({
        route for route in js_discovered_routes
        if (route.rstrip("/") or "/").lower() not in {p.lower() for p in normalized_observed}
    })
    for route in ghost_routes:
        findings.append(
            Finding.from_rule(
                "BH-026", asset=har_path.name, location=route,
                evidence=f"Route '{route}' extracted from client JS was never requested in captured HAR traffic.",
            )
        )

    return ScanResult(
        findings=deduplicate_findings(findings),
        endpoints=sorted(endpoints),
        ranked_endpoints=ranked_endpoints,
        ghost_routes=ghost_routes,
        technologies=sorted(technologies),
        metadata={
            "entries_analyzed": len(entries),
            "skipped_out_of_scope": skipped_out_of_scope,
            "endpoint_profiles": len(endpoint_profiles),
        },
    )


def diff_roles_har(
    high_priv_har: Path,
    low_priv_har: Path,
    scope_guard: ScopeGuard | None = None,
) -> ScanResult:
    high = audit_har_file(high_priv_har, scope_guard=scope_guard)
    low = audit_har_file(low_priv_har, scope_guard=scope_guard)
    high_map = {endpoint["template"]: endpoint for endpoint in high.ranked_endpoints}
    low_map = {endpoint["template"]: endpoint for endpoint in low.ranked_endpoints}
    shared = sorted(set(high_map) & set(low_map))

    parity_candidates: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for template in shared:
        high_ep = high_map[template]
        low_ep = low_map[template]
        if 200 in high_ep["statuses"] and 200 in low_ep["statuses"] and low_ep["avg_response_bytes"] > 20:
            parity_candidates.append({
                "template": template,
                "host": low_ep["host"],
                "high_priv_bytes": high_ep["avg_response_bytes"],
                "low_priv_bytes": low_ep["avg_response_bytes"],
                "aps_score": max(high_ep["aps_score"], low_ep["aps_score"]),
                "rows_returned_low_priv": low_ep["avg_response_bytes"] // 128,
            })
            findings.append(
                Finding.from_rule(
                    "BH-027", asset=low_ep["host"], location=template,
                    evidence=(
                        f"Both high-priv ({high_ep['avg_response_bytes']}B) and low-priv "
                        f"({low_ep['avg_response_bytes']}B) sessions received HTTP 200 OK."
                    ),
                )
            )

    return ScanResult(
        findings=deduplicate_findings(findings),
        ranked_endpoints=sorted(parity_candidates, key=lambda item: -item["aps_score"]),
        endpoints=sorted(set(high.endpoints) | set(low.endpoints)),
        technologies=sorted(set(high.technologies) | set(low.technologies)),
        metadata={
            "high_priv_file": high_priv_har.name,
            "low_priv_file": low_priv_har.name,
            "shared_endpoints_checked": len(shared),
            "parity_candidates": len(parity_candidates),
        },
    )


# ===========================================================================
# 14. Scope-gated passive reconnaissance
# ===========================================================================

SENSITIVE_PROBES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=.{1,200}$"), "dotenv configuration file"),
    ("/.git/HEAD", re.compile(r"^(?:ref:\s+refs/|[0-9a-f]{40})"), "exposed git metadata"),
    ("/server-status", re.compile(r"(?i)apache server status|server status"), "server-status page"),
    ("/phpinfo.php", re.compile(r"(?i)phpinfo\(\)|PHP Version"), "phpinfo page"),
    ("/backup.zip", re.compile(r"^PK\x03\x04"), "archive backup file"),
)


def _parse_cert_date(value: str) -> _dt.datetime | None:
    try:
        return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def passive_recon(
    target_url: str,
    scope_guard: ScopeGuard,
    rate_limiter: TokenBucket,
    timeout: float = 8.0,
    probe_sensitive: bool = False,
    verify_tls: bool = True,
) -> ScanResult:
    target_url, resolved = scope_guard.validate_url(target_url)
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    findings: list[Finding] = []
    endpoints: set[str] = set()
    technologies: set[str] = set()
    tls_info: dict[str, Any] = {}
    probe_errors: list[dict[str, str]] = []
    successful_probes = 0
    client = PinnedHttpClient(scope_guard, rate_limiter, timeout=timeout, verify_tls=verify_tls)

    if parsed.scheme == "https":
        try:
            context = (
                ssl.create_default_context()
                if verify_tls
                else ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-in only
            )
            raw = socket.create_connection((resolved[0], port), timeout=timeout)
            with context.wrap_socket(raw, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert() or {}
                cipher = tls_socket.cipher()
                version = tls_socket.version() or ""
                tls_info = {
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "not_after": cert.get("notAfter", ""),
                    "issuer": dict(item[0] for item in cert.get("issuer", []) if item),
                    "subject_alt_names": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
                }
                expiry = _parse_cert_date(cert.get("notAfter", ""))
                if expiry:
                    days_left = (expiry - _dt.datetime.now(_dt.timezone.utc)).days
                    tls_info["days_until_expiry"] = days_left
                    if days_left < 30:
                        findings.append(
                            Finding.from_rule(
                                "BH-023", asset=host, location=f"{host}:{port}",
                                evidence=f"TLS certificate expires in {days_left} days.",
                            )
                        )
                weak_protocol = version in ("TLSv1", "TLSv1.1")
                weak_cipher = bool(cipher) and any(
                    token in cipher[0].lower() for token in ("rc4", "3des", "des-", "null", "md5")
                )
                if weak_protocol or weak_cipher:
                    findings.append(
                        Finding.from_rule(
                            "BH-042", asset=host, location=f"{host}:{port}",
                            evidence=f"Negotiated {version} with cipher {cipher[0] if cipher else 'unknown'}.",
                        )
                    )
        except (ssl.SSLError, OSError) as exc:
            tls_info["error"] = str(exc)
            tls_info["verified"] = False
            LOG.warning("TLS inspection failed for %s: %s", host, exc)

    base = f"{parsed.scheme}://{parsed.netloc}"
    probes = ["/", "/robots.txt", "/.well-known/security.txt"]
    if probe_sensitive:
        probes.extend(path for path, _, _ in SENSITIVE_PROBES)
    has_security_txt = False

    for path in probes:
        url = urllib.parse.urljoin(base, path)
        try:
            response = client.fetch(url, max_redirects=0)
        except (ScopeViolationError, OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
            probe_errors.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            LOG.warning("Probe failed for %s: %s", url, exc)
            continue
        successful_probes += 1
        endpoints.add(f"GET {url} [{response.status}]")
        headers = response.headers
        body = response.body

        if path == "/.well-known/security.txt" and response.status == 200 and "contact:" in body.lower():
            has_security_txt = True
        if path == "/robots.txt" and response.status == 200:
            for line in body.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(("disallow:", "allow:", "sitemap:", "crawl-delay:")):
                    endpoints.add(f"ROBOTS {stripped[:160]}")
        if path == "/":
            for banner in ("server", "x-powered-by", "x-aspnet-version"):
                for value in headers.get(banner, []):
                    technologies.add(f"{banner}: {value}")
                    if re.search(r"\d+\.\d+", value):
                        findings.append(
                            Finding.from_rule("BH-022", asset=host, location=url, evidence=f"{banner}: {value}")
                        )
            csp = " ; ".join(headers.get("content-security-policy", []))
            if not csp:
                findings.append(Finding.from_rule("BH-003", asset=host, location=url, evidence="Missing CSP header."))
            elif any(token in csp for token in ("'unsafe-inline'", "'unsafe-eval'", "script-src *")):
                findings.append(Finding.from_rule("BH-004", asset=host, location=url, evidence=f"CSP: {csp[:150]}"))
            if parsed.scheme == "https" and not headers.get("strict-transport-security"):
                findings.append(Finding.from_rule("BH-005", asset=host, location=url, evidence="Missing HSTS header."))
            if not headers.get("x-frame-options") and "frame-ancestors" not in csp:
                findings.append(Finding.from_rule("BH-006", asset=host, location=url, evidence="Missing clickjacking headers."))
            findings.extend(scan_text_for_secrets(body, host, url))
        else:
            findings.extend(scan_text_for_secrets(body, host, url))

        for probe_path, signature, label in SENSITIVE_PROBES:
            if path == probe_path and response.status == 200 and signature.search(body):
                findings.append(
                    Finding.from_rule(
                        "BH-040", asset=host, location=url,
                        evidence=f"Reachable {label} ({len(body)} bytes) — {label} exposure.",
                    )
                )

    # Only claim "missing security.txt" when at least one probe actually reached
    # the origin — otherwise a TLS/connectivity failure would become a false positive.
    if successful_probes and not has_security_txt:
        findings.append(
            Finding.from_rule(
                "BH-024", asset=host, location=urllib.parse.urljoin(base, "/.well-known/security.txt"),
                evidence="No RFC 9116 security.txt published.",
            )
        )

    return ScanResult(
        findings=deduplicate_findings(findings),
        endpoints=sorted(endpoints),
        technologies=sorted(technologies),
        tls=tls_info,
        metadata={
            "target": target_url,
            "resolved_ip": resolved[0] if resolved else "",
            "probes": len(probes),
            "successful_probes": successful_probes,
            "probe_errors": probe_errors,
            "tls_verified": verify_tls,
        },
    )


# ===========================================================================
# 15. Repository scanner: inventory, dispatch, parallel execution
# ===========================================================================

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", "target",
    "vendor", ".next", ".nuxt", "coverage", ".idea", ".gradle", "bower_components",
    "site-packages", ".terraform",
}
DEFAULT_EXCLUDED_FILE_GLOBS = (
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "*.pyc", "*.so", "*.dll", "*.exe", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp",
    "*.ico", "*.woff", "*.woff2", "*.ttf", "*.eot", "*.pdf", "*.zip", "*.gz", "*.tar",
)
TEXT_FILE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm",
    ".go", ".php", ".java", ".rb", ".cs", ".kt", ".scala", ".rs", ".swift", ".sh", ".bash",
    ".ps1", ".sql", ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".tfvars", ".gradle", ".md", ".txt", ".pem", ".key",
    ".dockerfile", ".map", ".har",
}


@dataclass
class ScannerConfig:
    excluded_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_DIRS))
    excluded_globs: tuple[str, ...] = DEFAULT_EXCLUDED_FILE_GLOBS
    excluded_paths: set[str] = field(default_factory=set)
    include_suffixes: set[str] | None = None
    max_file_bytes: int = 2_500_000
    jobs: int = 0
    follow_symlinks: bool = False

    def resolved_jobs(self) -> int:
        if self.jobs > 0:
            return self.jobs
        return max(4, min(32, (os.cpu_count() or 4) * 2))


def _is_previous_report_dir(dirpath: str, filenames: Sequence[str]) -> bool:
    """Detect a directory that holds one of our own generated reports.

    Re-scanning a previous HTML/JSON report would ingest its embedded finding
    text as if it were application code, so these directories are pruned.
    """
    for name in filenames:
        if not (name.endswith("_findings.json") or name.endswith("_dashboard.html")):
            continue
        try:
            with open(os.path.join(dirpath, name), "rb") as handle:
                head = handle.read(2048)
        except OSError:
            continue
        if b"InnovateIT BugHunter" in head:
            return True
    return False


def iter_scan_files(paths: Sequence[Path], config: ScannerConfig) -> Iterator[Path]:
    seen: set[str] = set()
    excluded_roots = {Path(item).resolve() for item in config.excluded_paths}
    for root in paths:
        explicit_file = root.is_file()
        if explicit_file:
            candidates = [root]
        elif root.is_dir():
            candidates = []
            for dirpath, dirnames, filenames in os.walk(root, followlinks=config.follow_symlinks):
                current = Path(dirpath).resolve()
                if any(current == excluded or excluded in current.parents for excluded in excluded_roots):
                    dirnames[:] = []
                    continue
                if _is_previous_report_dir(dirpath, filenames):
                    dirnames[:] = []
                    continue
                dirnames[:] = sorted(d for d in dirnames if d.lower() not in config.excluded_dirs)
                for name in sorted(filenames):
                    candidates.append(Path(dirpath) / name)
        else:
            LOG.warning("Skipping missing path: %s", root)
            continue
        for candidate in candidates:
            normalized = str(candidate.resolve()) if candidate.exists() else str(candidate)
            if normalized in seen:
                continue
            seen.add(normalized)
            if explicit_file:
                yield candidate
                continue
            lowered = candidate.name.lower()
            if any(fnmatch.fnmatch(lowered, pattern) for pattern in config.excluded_globs):
                continue
            if candidate.suffix.lower() not in TEXT_FILE_EXTENSIONS and not lowered.startswith("dockerfile"):
                if candidate.suffix.lower() not in (".map", ".har"):
                    continue
            if config.include_suffixes is not None and candidate.suffix.lower() not in config.include_suffixes:
                continue
            yield candidate


def _looks_like_openapi(name: str, text: str) -> bool:
    lowered = name.lower()
    if "openapi" not in lowered and "swagger" not in lowered:
        return False
    head = text[:20000]
    return '"paths"' in head or "\npaths:" in head or head.lstrip().startswith("paths:")


def scan_single_file(
    path: Path,
    config: ScannerConfig,
    inline_filter: bool = True,
    scope_guard: ScopeGuard | None = None,
) -> dict[str, Any]:
    """Scan one file and return an intermediate result dict (thread-safe)."""
    empty = {"findings": [], "routes": set(), "technologies": set(), "kind": "skip", "bytes": 0}
    text = read_text_file(path, config.max_file_bytes)
    if text is None:
        return empty
    findings: list[Finding] = []
    routes: set[str] = set()
    technologies: set[str] = set()
    name_lower = path.name.lower()
    suffix = path.suffix.lower()
    kind = "text"

    try:
        if suffix == ".har":
            kind = "har"
            har_result = audit_har_file(path, scope_guard=scope_guard)
            findings.extend(har_result.findings)
            routes.update(har_result.ghost_routes)
            return {
                "findings": findings,
                "routes": routes,
                "technologies": set(har_result.technologies),
                "kind": kind,
                "bytes": len(text),
                "_har": har_result,
            }
        if name_lower.startswith("dockerfile") or name_lower.endswith(".dockerfile"):
            kind = "dockerfile"
            findings.extend(audit_dockerfile(text, str(path)))
        elif suffix in (".yml", ".yaml"):
            spec_result: ScanResult | None = None
            if _looks_like_openapi(path.name, text):
                try:
                    spec_result = audit_openapi_spec(path)
                except (ValueError, json.JSONDecodeError) as exc:
                    LOG.debug("Skipping YAML OpenAPI candidate %s: %s", path, exc)
            if spec_result is not None:
                kind = "openapi"
                findings.extend(spec_result.findings)
                routes.update(spec_result.endpoints)
            elif ".github/workflows" in str(path).replace("\\", "/") or (
                re.search(r"(?m)^\s*jobs:\s*$", text) and "runs-on:" in text
            ):
                kind = "ci"
                findings.extend(audit_ci_workflow(text, str(path)))
            elif "apiVersion:" in text and re.search(r"(?m)^\s*kind:\s*\w+", text):
                kind = "kubernetes"
                findings.extend(audit_kubernetes(text, str(path)))
            else:
                kind = "config"
        elif suffix == ".py":
            kind = "python"
            py_findings, py_routes, py_tech = audit_python_file(path, text)
            findings.extend(py_findings)
            routes.update(py_routes)
            technologies.update(py_tech)
        elif suffix in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".map"):
            kind = "javascript"
            js_findings, js_routes, js_tech = audit_javascript_file(path, text)
            findings.extend(js_findings)
            routes.update(js_routes)
            technologies.update(js_tech)
        elif suffix == ".json" and _looks_like_openapi(path.name, text):
            kind = "openapi"
            spec_result = audit_openapi_spec(path)
            findings.extend(spec_result.findings)
            routes.update(spec_result.endpoints)
        else:
            kind = "source" if suffix in _SOURCE_EXTENSIONS else "text"
            if kind == "source":
                generic_findings, generic_routes = audit_generic_source(path, text)
                findings.extend(generic_findings)
                routes.update(generic_routes)

        # Secrets and bearer tokens are scanned for every text artifact (specific
        # scanners may re-find them; deduplication collapses identical evidence).
        if kind not in ("har", "openapi"):
            findings.extend(scan_text_for_secrets(text, str(path), path.name))
            if "eyJ" in text:
                token_index = LineIndex(text)
                for jwt_token in set(JWT_REGEX.findall(text)):
                    line_no, _ = token_index.line_col(text.find(jwt_token))
                    findings.extend(
                        inspect_jwt_token(jwt_token, str(path), path.name, start_line=line_no)
                    )
        if inline_filter:
            findings = apply_inline_suppressions(text, findings)
    except Exception as exc:  # keep the scan alive; surface the file as an error
        LOG.warning("Scanner error on %s: %s", path, exc)
        return {**empty, "kind": "error", "error": str(exc), "bytes": len(text)}

    return {
        "findings": findings,
        "routes": routes,
        "technologies": technologies,
        "kind": kind,
        "bytes": len(text),
    }


def scan_paths(
    paths: Sequence[Path],
    config: ScannerConfig | None = None,
    suppressions: SuppressionSet | None = None,
    baseline: Sequence[Finding] = (),
    jobs: int = 0,
    scope_guard: ScopeGuard | None = None,
) -> ScanResult:
    config = config or ScannerConfig()
    if jobs:
        config.jobs = jobs
    started = time.monotonic()
    stats = ScanStats(started_at=utc_now_iso())
    findings: list[Finding] = []
    routes: set[str] = set()
    technologies: set[str] = set()
    languages: Counter[str] = Counter()
    har_results: list[ScanResult] = []

    files = list(iter_scan_files(paths, config))
    if not files:
        raise ValueError(f"No scannable files found under: {', '.join(str(p) for p in paths)}")

    results: list[dict[str, Any]] = []
    if config.resolved_jobs() == 1:
        results = [scan_single_file(path, config, scope_guard=scope_guard) for path in files]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.resolved_jobs()) as pool:
            futures = [
                pool.submit(scan_single_file, path, config, True, scope_guard) for path in files
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    LOG.warning("Unhandled scanner failure: %s", exc)

    for result in results:
        stats.files_scanned += 1 if result["kind"] != "skip" else 0
        stats.files_skipped += 1 if result["kind"] == "skip" else 0
        stats.bytes_scanned += int(result.get("bytes", 0))
        languages[str(result["kind"])] += 1
        findings.extend(result["findings"])
        routes.update(result["routes"])
        technologies.update(result["technologies"])
        if "_har" in result and isinstance(result["_har"], ScanResult):
            har_results.append(result["_har"])

    for har_result in har_results:
        routes.update(har_result.ghost_routes)
        technologies.update(har_result.technologies)

    stats.by_language = dict(sorted(languages.items()))
    stats.duration_seconds = round(time.monotonic() - started, 3)
    stats.finished_at = utc_now_iso()
    stats.suppressed_count = 0

    suppressions = suppressions or SuppressionSet()
    suppressions.apply(findings)
    stats.suppressed_count = sum(1 for finding in findings if finding.suppressed)
    if baseline:
        apply_baseline(findings, baseline)

    endpoints: set[str] = set()
    ranked: list[dict[str, Any]] = []
    ghosts: set[str] = set()
    for har_result in har_results:
        endpoints.update(har_result.endpoints)
        ranked.extend(har_result.ranked_endpoints)
        ghosts.update(har_result.ghost_routes)

    backend_routes = sorted({route for route in routes if route.startswith("/")})
    ghost_sorted = sorted(ghosts)
    correlated = sorted(
        ghost for ghost in ghost_sorted
        if any(
            ghost.rstrip("/") == backend.rstrip("/") or backend.rstrip("/") in ghost
            for backend in backend_routes
        )
    )

    result = ScanResult(
        findings=deduplicate_findings(findings),
        endpoints=sorted(endpoints),
        ranked_endpoints=sorted(ranked, key=lambda item: -item.get("aps_score", 0)),
        ghost_routes=ghost_sorted,
        backend_routes=backend_routes,
        correlated_routes=correlated,
        technologies=sorted(technologies),
        stats=stats,
        metadata={"scanned_paths": [str(p) for p in paths]},
    )
    finalize_result(result)
    return result


def apply_baseline(findings: Sequence[Finding], baseline_findings: Sequence[Finding]) -> None:
    by_stable = {finding.stable_id: finding for finding in baseline_findings}
    by_fingerprint = {finding.fingerprint: finding for finding in baseline_findings}
    for finding in findings:
        if finding.stable_id in by_stable:
            prior = by_stable[finding.stable_id]
            finding.baseline_state = "unchanged" if prior.fingerprint == finding.fingerprint else "updated"
        elif finding.fingerprint in by_fingerprint:
            finding.baseline_state = "unchanged"
        else:
            finding.baseline_state = "new"


# ===========================================================================
# 16. Deduplication, ASVS/CWE coverage, attack-path correlation
# ===========================================================================

def deduplicate_findings(findings: Sequence[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    by_stable: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint in unique:
            continue
        twin = by_stable.get(finding.stable_id)
        if twin is not None:
            if len(finding.evidence) > len(twin.evidence):
                twin.evidence = finding.evidence
            twin.metadata.setdefault("also_reported", [])
            if finding.rule_id not in twin.metadata["also_reported"]:
                twin.metadata["also_reported"].append(finding.rule_id)
            continue
        unique[finding.fingerprint] = finding
        by_stable[finding.stable_id] = finding
    return sorted(
        unique.values(),
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), -item.risk_score, item.rule_id, item.asset),
    )


CWE_TOP25 = [
    "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", "CWE-416",
    "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287", "CWE-269", "CWE-502",
    "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476", "CWE-798", "CWE-190", "CWE-400", "CWE-306",
]


def build_asvs_matrix(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    by_requirement: dict[str, list[Finding]] = {}
    for finding in findings:
        if not finding.suppressed:
            by_requirement.setdefault(finding.asvs, []).append(finding)
    requirement_ids = sorted({rule.asvs for rule in RULES.values()})
    matrix: list[dict[str, Any]] = []
    violated = 0
    for requirement in requirement_ids:
        matched = by_requirement.get(requirement, [])
        if matched:
            violated += 1
        matrix.append({
            "asvs_requirement": requirement,
            "status": "FINDINGS_DETECTED" if matched else "NO_STATIC_VIOLATIONS",
            "finding_count": len(matched),
            "max_risk": round(max((f.risk_score for f in matched), default=0.0), 1),
            "mapped_rules": sorted({rule.rule_id for rule in RULES.values() if rule.asvs == requirement}),
        })
    coverage = round(100.0 * (len(requirement_ids) - violated) / max(len(requirement_ids), 1), 1)
    for row in matrix:
        row["coverage_pct"] = coverage
    return matrix


def build_cwe_coverage(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    counts = Counter(finding.cwe for finding in findings if not finding.suppressed)
    rows = [
        {"cwe": cwe, "in_top25": cwe in CWE_TOP25, "finding_count": counts.get(cwe, 0)}
        for cwe in sorted(set(CWE_TOP25) | set(counts))
    ]
    return sorted(rows, key=lambda row: (-row["finding_count"], row["cwe"]))


@dataclass(frozen=True)
class ChainDefinition:
    chain_id: str
    title: str
    severity: str
    rule_ids: tuple[str, ...]
    narrative: str
    same_asset: bool = False


CHAIN_DEFINITIONS: tuple[ChainDefinition, ...] = (
    ChainDefinition(
        "CHAIN-01", "Source map hands attackers the credential hidden in the bundle", "CRITICAL",
        ("BH-010", "BH-013"),
        "An exposed source map reconstructs readable client code, and a live credential is embedded "
        "in that same artifact. The map turns a redacted one-line finding into a usable key plus the "
        "exact call site, so rotation is urgent.",
        same_asset=True,
    ),
    ChainDefinition(
        "CHAIN-02", "Hidden client route is also unauthenticated server-side", "CRITICAL",
        ("BH-026", "BH-028"),
        "A route referenced by the frontend bundle never appears in captured traffic, and the API "
        "specification declares it without authentication. That combination is a prime unauthenticated "
        "hidden-endpoint candidate.",
        same_asset=False,
    ),
    ChainDefinition(
        "CHAIN-03", "Forged JWT accepted from any origin", "CRITICAL",
        ("BH-014", "BH-001"),
        "Unsigned ('none') tokens are accepted while CORS reflects arbitrary origins with credentials. "
        "An attacker page can mint its own token and read authenticated responses cross-origin.",
        same_asset=False,
    ),
    ChainDefinition(
        "CHAIN-04", "Open redirect launders server-side request forgery", "HIGH",
        ("BH-019", "BH-033"),
        "A redirect parameter is exposed and a backend HTTP client takes a dynamic URL. Chaining an "
        "in-scope redirect with the SSRF sink can reach internal services while keeping the allowlist happy.",
        same_asset=False,
    ),
    ChainDefinition(
        "CHAIN-05", "Prototype pollution feeds a DOM execution sink", "HIGH",
        ("BH-025", "BH-011"),
        "An unguarded deep-merge enables __proto__ injection, and tainted data reaches an HTML/eval sink. "
        "Pollution can supply the payload that the sink later executes.",
        same_asset=True,
    ),
    ChainDefinition(
        "CHAIN-06", "Weak hash plus long-lived token enables offline forgery", "HIGH",
        ("BH-035", "BH-016"),
        "A weak digest and an excessively long token lifetime give an attacker a large offline window "
        "to recover or reuse material.",
        same_asset=False,
    ),
    ChainDefinition(
        "CHAIN-07", "Root container with host mounts breaks tenant isolation", "CRITICAL",
        ("BH-036", "BH-041"),
        "The workload runs as root and mounts host namespaces/paths, so any container compromise "
        "escalates directly to the node.",
        same_asset=True,
    ),
    ChainDefinition(
        "CHAIN-08", "Unauthenticated state-changing API with object IDs", "HIGH",
        ("BH-028", "BH-030"),
        "A state-changing operation declares no authentication and the surface accepts object "
        "identifiers, making cross-tenant object manipulation plausible.",
        same_asset=False,
    ),
)


def _chain_probability(probabilities: Sequence[float]) -> float:
    """Probability that every link of an attack chain holds.

    A chain is only exploitable when all of its preconditions are real, so the
    per-link probabilities multiply (with a small feasibility factor for the
    correlation step itself) instead of being combined as an independent union.
    """
    combined = 1.0
    for probability in probabilities:
        combined *= max(0.01, min(0.95, probability))
    return round(combined * 0.9, 4)


def build_attack_paths(findings: Sequence[Finding]) -> list[AttackPath]:
    active = [finding for finding in findings if not finding.suppressed]
    paths: list[AttackPath] = []
    seen_members: set[tuple[str, ...]] = set()

    for definition in CHAIN_DEFINITIONS:
        by_rule: dict[str, list[Finding]] = {rule_id: [] for rule_id in definition.rule_ids}
        for finding in active:
            if finding.rule_id in by_rule:
                by_rule[finding.rule_id].append(finding)
        if not all(by_rule.values()):
            continue

        if definition.same_asset:
            assets = sorted({finding.asset for group in by_rule.values() for finding in group})
            groups: list[list[Finding]] = []
            for asset in assets:
                group = [findings_for_rule[0] for findings_for_rule in
                         ([f for f in by_rule[rule_id] if f.asset == asset] for rule_id in definition.rule_ids)
                         if findings_for_rule]
                if len(group) == len(definition.rule_ids):
                    groups.append(group)
        else:
            groups = [[group[0] for group in by_rule.values()]]

        for group in groups:
            member_key = tuple(sorted(finding.fingerprint for finding in group))
            if member_key in seen_members:
                continue
            seen_members.add(member_key)
            probability = _chain_probability([finding.exploitability for finding in group])
            qri = round(probability * 100, 1)
            path = AttackPath(
                path_id=f"{definition.chain_id}-{hashlib.sha256('|'.join(member_key).encode()).hexdigest()[:6]}",
                title=definition.title,
                severity=definition.severity,
                narrative=definition.narrative,
                rule_ids=list(definition.rule_ids),
                finding_fingerprints=[finding.fingerprint for finding in group],
                combined_probability=probability,
                qri=qri,
                assets=sorted({finding.asset for finding in group}),
            )
            paths.append(path)
            for finding in group:
                if path.path_id not in finding.attack_path_ids:
                    finding.attack_path_ids.append(path.path_id)

    paths.sort(key=lambda item: (-item.qri, item.path_id))
    return paths


def compute_quantum_index(findings: Sequence[Finding], paths: Sequence[AttackPath]) -> float:
    """Portfolio exposure: strongest finding or chain, scaled by finding breadth.

    The index answers "how exposed is this artifact set right now?", not "how
    many issues exist": one fully-chained critical path outweighs dozens of
    informational findings, while a broad set of critical/high findings acts as
    a capped independent exposure signal (noisy-OR), never dominating the
    strongest single finding or chain.
    """
    active = [finding for finding in findings if not finding.suppressed]
    if not active:
        return 0.0
    strongest = max(finding.exploitability for finding in active)
    if paths:
        strongest = max(strongest, max(path.combined_probability for path in paths))
    breadth = min(
        0.25,
        0.02 * sum(1 for finding in active if finding.severity in ("CRITICAL", "HIGH")),
    )
    # Noisy-OR: a broad set of severe findings is an independent exposure signal,
    # but it can never dominate the strongest single finding or chain.
    return round(min(99.0, 100.0 * (1.0 - (1.0 - strongest) * (1.0 - breadth))), 1)


def finalize_result(result: ScanResult) -> ScanResult:
    result.attack_paths = build_attack_paths(result.findings)
    result.asvs_matrix = build_asvs_matrix(result.findings)
    result.cwe_coverage = build_cwe_coverage(result.findings)
    result.metadata["quantum_risk_index"] = compute_quantum_index(result.findings, result.attack_paths)
    result.metadata["finding_counts"] = {
        severity: sum(1 for f in result.findings if f.severity == severity and not f.suppressed)
        for severity in SEVERITY_ORDER
    }
    return result


# ===========================================================================
# 17. Fusion and differential analysis
# ===========================================================================

def result_to_payload(result: ScanResult, generated_at: str | None = None) -> dict[str, Any]:
    counts = {
        severity: sum(1 for f in result.findings if f.severity == severity and not f.suppressed)
        for severity in SEVERITY_ORDER
    }
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "codename": CODENAME,
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at or utc_now_iso(),
        "summary": {
            "total_findings": sum(counts.values()),
            "suppressed_findings": sum(1 for f in result.findings if f.suppressed),
            "severity_counts": counts,
            "quantum_risk_index": result.metadata.get(
                "quantum_risk_index",
                compute_quantum_index(result.findings, result.attack_paths),
            ),
            "attack_paths": len(result.attack_paths),
            "new_findings": sum(1 for f in result.findings if f.baseline_state == "new"),
            "files_scanned": result.stats.files_scanned,
        },
        "stats": result.stats.to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "attack_paths": [path.to_dict() for path in result.attack_paths],
        "asvs_matrix": result.asvs_matrix,
        "cwe_coverage": result.cwe_coverage,
        "endpoints": result.endpoints,
        "ranked_endpoints": result.ranked_endpoints,
        "ghost_routes": result.ghost_routes,
        "backend_routes": result.backend_routes,
        "correlated_frontend_backend_routes": result.correlated_routes,
        "technologies": result.technologies,
        "tls": result.tls,
        "metadata": result.metadata,
    }


def fuse_artifact_runs(json_paths: Sequence[Path], baseline: Sequence[Finding] = ()) -> ScanResult:
    findings: list[Finding] = []
    endpoints: set[str] = set()
    ranked: list[dict[str, Any]] = []
    ghosts: set[str] = set()
    backend_routes: set[str] = set()
    technologies: set[str] = set()
    tls: dict[str, Any] = {}
    stats = ScanStats()
    sources: list[str] = []
    for path in json_paths:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError(f"Not a BugHunter JSON artifact: {path}")
        sources.append(str(path))
        for raw in data.get("findings", []) or []:
            if isinstance(raw, dict):
                findings.append(Finding.from_dict(raw))
        endpoints.update(data.get("endpoints", []) or [])
        ranked.extend(data.get("ranked_endpoints", []) or [])
        ghosts.update(data.get("ghost_routes", []) or [])
        backend_routes.update(data.get("backend_routes", []) or [])
        technologies.update(data.get("technologies", []) or [])
        if isinstance(data.get("tls"), dict) and data["tls"]:
            tls = data["tls"]
        raw_stats = data.get("stats") or {}
        stats.files_scanned += int(raw_stats.get("files_scanned", 0) or 0)
        stats.bytes_scanned += int(raw_stats.get("bytes_scanned", 0) or 0)

    if baseline:
        apply_baseline(findings, baseline)
    result = ScanResult(
        findings=deduplicate_findings(findings),
        endpoints=sorted(endpoints),
        ranked_endpoints=sorted(ranked, key=lambda item: -item.get("aps_score", 0)),
        ghost_routes=sorted(ghosts),
        backend_routes=sorted(backend_routes),
        correlated_routes=sorted(
            ghost for ghost in ghosts
            if any(ghost.rstrip("/") == backend.rstrip("/") or backend.rstrip("/") in ghost
                   for backend in backend_routes)
        ),
        technologies=sorted(technologies),
        tls=tls,
        stats=stats,
        metadata={"fused_from": sources},
    )
    finalize_result(result)
    return result


def diff_runs(prev_data: dict[str, Any], curr_data: dict[str, Any]) -> dict[str, Any]:
    prev_findings = {
        str(raw.get("stable_id") or raw.get("fingerprint")): raw
        for raw in prev_data.get("findings", []) or [] if isinstance(raw, dict)
    }
    curr_findings = {
        str(raw.get("stable_id") or raw.get("fingerprint")): raw
        for raw in curr_data.get("findings", []) or [] if isinstance(raw, dict)
    }
    new_keys = sorted(set(curr_findings) - set(prev_findings))
    resolved_keys = sorted(set(prev_findings) - set(curr_findings))
    changed_keys = sorted(
        key for key in set(curr_findings) & set(prev_findings)
        if curr_findings[key].get("fingerprint") != prev_findings[key].get("fingerprint")
        or curr_findings[key].get("evidence") != prev_findings[key].get("evidence")
    )
    prev_endpoints = set(prev_data.get("endpoints", []) or [])
    curr_endpoints = set(curr_data.get("endpoints", []) or [])

    def severity_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
        counter = Counter(str(row.get("severity", "INFO")) for row in rows)
        return {severity: counter.get(severity, 0) for severity in SEVERITY_ORDER}

    prev_qri = float((prev_data.get("summary") or {}).get("quantum_risk_index", 0) or 0)
    curr_qri = float((curr_data.get("summary") or {}).get("quantum_risk_index", 0) or 0)
    return {
        "generated_at": utc_now_iso(),
        "summary": {
            "new_findings": len(new_keys),
            "resolved_findings": len(resolved_keys),
            "changed_findings": len(changed_keys),
            "unchanged_findings": len(set(curr_findings) & set(prev_findings)) - len(changed_keys),
            "new_endpoints": len(curr_endpoints - prev_endpoints),
            "removed_endpoints": len(prev_endpoints - curr_endpoints),
            "new_by_severity": severity_counts(curr_findings[key] for key in new_keys),
            "quantum_risk_index_before": prev_qri,
            "quantum_risk_index_after": curr_qri,
            "quantum_risk_index_delta": round(curr_qri - prev_qri, 1),
        },
        "new_findings": [curr_findings[key] for key in new_keys],
        "resolved_findings": [prev_findings[key] for key in resolved_keys],
        "changed_findings": [
            {"before": prev_findings[key], "after": curr_findings[key]} for key in changed_keys
        ],
        "new_endpoints": sorted(curr_endpoints - prev_endpoints),
        "removed_endpoints": sorted(prev_endpoints - curr_endpoints),
    }


# ===========================================================================
# 18. Reporters: JSON, SARIF 2.1.0, Markdown, HTML workbench
# ===========================================================================

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def build_sarif_report(
    findings: Sequence[Finding],
    *,
    automation_id: str = "",
    start_time_utc: str | None = None,
    exit_code: int = 0,
) -> dict[str, Any]:
    used_rule_ids = sorted({finding.rule_id for finding in findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(used_rule_ids)}
    rules_sarif = []
    for rule_id in used_rule_ids:
        rule = RULES[rule_id]
        rules_sarif.append({
            "id": rule.rule_id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {
                "text": f"Remediation: {rule.remediation}\nVerification: {rule.verification_hint}",
                "markdown": f"**Remediation**\n\n{rule.remediation}\n\n**Verification**\n\n{rule.verification_hint}",
            },
            "defaultConfiguration": {"level": SARIF_LEVEL.get(rule.severity, "note")},
            "properties": {
                "severity": rule.severity,
                "confidence": rule.confidence,
                "cwe": rule.cwe,
                "vrt": rule.vrt,
                "asvs": rule.asvs,
                "cvss_vector": rule.cvss,
                "cvss_score": rule.cvss_score,
                "tags": list(rule.tags),
            },
        })

    results_sarif = []
    for finding in findings:
        region: dict[str, Any] = {}
        if finding.start_line > 0:
            region = {
                "startLine": finding.start_line,
                "endLine": max(finding.start_line, finding.end_line or finding.start_line),
            }
            if finding.column:
                region["startColumn"] = finding.column
            if finding.snippet:
                region["snippet"] = {"text": finding.snippet}
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index.get(finding.rule_id, 0),
            "level": SARIF_LEVEL.get(finding.severity, "note"),
            "rank": max(0.0, min(100.0, finding.risk_score)),
            "message": {"text": f"{finding.title} [{finding.asvs}] — {finding.evidence}"},
            "partialFingerprints": {
                "bughunterFingerprint/v1": finding.fingerprint,
                "bughunterStableId/v1": finding.stable_id,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.asset.replace("\\", "/")},
                    **({"region": region} if region else {}),
                },
                "logicalLocations": [{"fullyQualifiedName": finding.location, "kind": "module"}],
            }],
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "cwe": finding.cwe,
                "vrt": finding.vrt,
                "asvs": finding.asvs,
                "cvss_vector": finding.cvss_vector,
                "cvss_score": finding.cvss_score,
                "exploitability": finding.exploitability,
                "risk_score": finding.risk_score,
                "attack_paths": finding.attack_path_ids,
            },
        }
        if finding.baseline_state:
            result["baselineState"] = finding.baseline_state
        if finding.suppressed:
            result["suppressions"] = [{
                "kind": "external",
                "justification": finding.suppression_reason or "suppressed by policy",
            }]
        results_sarif.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": VERSION,
                "semanticVersion": VERSION,
                "rules": rules_sarif,
            }
        },
        "results": results_sarif,
        "taxonomies": [
            {
                "name": "CWE",
                "organization": "MITRE",
                "informationUri": "https://cwe.mitre.org/",
                "taxa": [
                    {"id": cwe, "name": cwe.replace("CWE-", "CWE-")}
                    for cwe in sorted({finding.cwe for finding in findings})
                ],
            },
            {
                "name": "OWASP ASVS v5.0.0",
                "organization": "OWASP",
                "informationUri": "https://owasp.org/www-project-application-security-verification-standard/",
                "taxa": [
                    {"id": asvs, "name": asvs}
                    for asvs in sorted({finding.asvs for finding in findings})
                ],
            },
        ],
        "invocations": [{
            "executionSuccessful": exit_code in (0, 2),
            "startTimeUtc": start_time_utc or utc_now_iso(),
            "endTimeUtc": utc_now_iso(),
            "exitCode": exit_code,
        }],
    }
    if automation_id:
        run["automationDetails"] = {"id": automation_id}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def build_markdown_report(findings: Sequence[Finding], payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines: list[str] = [
        f"# {TOOL_NAME} v{VERSION} \"{CODENAME}\" — Security Assessment",
        "",
        f"- **Generated (UTC):** {payload.get('generated_at')}",
        f"- **Artifacts analysed:** {summary.get('files_scanned', 0)}",
        f"- **Unique findings:** {summary.get('total_findings', 0)} "
        f"({summary.get('suppressed_findings', 0)} suppressed)",
        f"- **Quantum Risk Index (QRI):** {summary.get('quantum_risk_index', 0)}/100",
        f"- **Attack paths:** {summary.get('attack_paths', 0)}",
        "",
        "## Severity Breakdown",
        "",
        "| CRITICAL | HIGH | MEDIUM | LOW | INFO |",
        "|---|---|---|---|---|",
        "| " + " | ".join(str((summary.get("severity_counts") or {}).get(s, 0)) for s in SEVERITY_ORDER) + " |",
        "",
    ]
    if payload.get("attack_paths"):
        lines.extend(["## Correlated Attack Paths", ""])
        for path in payload["attack_paths"]:
            lines.extend([
                f"### {path['path_id']} — {path['title']} ({path['severity']}, QRI {path['qri']})",
                "",
                path["narrative"],
                "",
                f"- Rules: {', '.join(path['rule_ids'])}",
                f"- Assets: {', '.join(path['assets'])}",
                "",
            ])

    lines.extend(["## Findings", ""])
    for index, finding in enumerate(findings, start=1):
        state = f" · {finding.baseline_state}" if finding.baseline_state else ""
        suppressed = " · **SUPPRESSED**" if finding.suppressed else ""
        lines.extend([
            f"### {index}. [{finding.severity}] {finding.title} (`{finding.rule_id}`){state}{suppressed}",
            "",
            f"- **CVSS 3.1:** {finding.cvss_score} `{finding.cvss_vector}`",
            f"- **Risk score:** {finding.risk_score}/100 · exploitable≈{finding.exploitability:.2f}",
            f"- **Asset / location:** `{_md_escape(finding.asset)}` · `{_md_escape(finding.location)}`"
            + (f" · line {finding.start_line}" if finding.start_line else ""),
            f"- **Mappings:** {finding.cwe} · `{finding.vrt}` · ASVS `{finding.asvs}`",
            f"- **Fingerprint:** `{finding.fingerprint}` (stable `{finding.stable_id}`)",
            f"- **Evidence:** `{_md_escape(finding.evidence)}`",
        ])
        if finding.snippet:
            lines.append(f"- **Snippet:** `{_md_escape(finding.snippet)}`")
        if finding.attack_path_ids:
            lines.append(f"- **Attack paths:** {', '.join(finding.attack_path_ids)}")
        lines.extend([
            f"- **Remediation:** {finding.remediation}",
            f"- **Verification:** {finding.verification_hint}",
            "",
        ])

    asvs_rows = [row for row in payload.get("asvs_matrix", []) if row["status"] == "FINDINGS_DETECTED"]
    if asvs_rows:
        lines.extend([
            "## OWASP ASVS v5.0.0 Violations",
            "",
            "| Requirement | Findings | Max risk | Mapped rules |",
            "|---|---|---|---|",
        ])
        for row in asvs_rows:
            lines.append(
                f"| `{row['asvs_requirement']}` | {row['finding_count']} | {row['max_risk']} | "
                f"{', '.join(row['mapped_rules'])} |"
            )
        lines.append("")

    lines.extend([
        "---",
        "",
        "_Generated by InnovateIT BugHunter. Offline static analysis only; validate every finding "
        "in an authorized environment before reporting._",
    ])
    return "\n".join(lines)


HTML_DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>__TITLE__</title>
<style>
  :root {
    --bg:#070b14; --panel:#0f1728; --panel-2:#141f36; --text:#e8eefc; --muted:#8fa3c4;
    --border:#22304d; --accent:#38bdf8; --accent-2:#a78bfa; --critical:#f43f5e;
    --high:#fb923c; --medium:#facc15; --low:#60a5fa; --info:#94a3b8; --ok:#34d399;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
         background:radial-gradient(1200px 600px at 15% -10%,#12203b 0%,var(--bg) 55%); color:var(--text); }
  .wrap { max-width:1280px; margin:0 auto; padding:28px 22px 64px; }
  header { display:flex; gap:18px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap;
           border-bottom:1px solid var(--border); padding-bottom:18px; }
  h1 { font-size:1.45rem; margin:0 0 6px; letter-spacing:.2px; }
  h1 span { color:var(--accent); }
  .sub { color:var(--muted); font-size:.86rem; }
  .qri { min-width:210px; background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px 16px; }
  .qri .num { font-size:2.1rem; font-weight:800; line-height:1; }
  .qri .bar { height:6px; border-radius:99px; background:#1e293b; margin-top:10px; overflow:hidden; }
  .qri .bar > i { display:block; height:100%; background:linear-gradient(90deg,var(--ok),var(--medium),var(--critical)); }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(118px,1fr)); gap:10px; margin:20px 0; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:12px 14px; }
  .stat b { display:block; font-size:1.45rem; }
  .stat small { color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:.68rem; }
  .tabs { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 18px; }
  .tab { background:var(--panel); border:1px solid var(--border); color:var(--text); padding:9px 14px;
         border-radius:999px; cursor:pointer; font-size:.84rem; font-weight:600; }
  .tab.active { background:linear-gradient(135deg,#0284c7,#7c3aed); border-color:transparent; }
  .controls { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; }
  input, select, button { font:inherit; color:var(--text); background:var(--panel); border:1px solid var(--border);
                          border-radius:9px; padding:9px 12px; font-size:.84rem; }
  input:focus, select:focus { outline:2px solid #1d4ed8; outline-offset:1px; }
  button.action { cursor:pointer; background:#0e7490; border-color:#0e7490; font-weight:600; }
  button.action:hover { background:#0891b2; }
  .finding { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:15px 16px; margin-bottom:10px; }
  .finding.suppressed { opacity:.55; border-style:dashed; }
  .row { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:center; }
  .badge { display:inline-block; padding:3px 9px; border-radius:6px; font-size:.7rem; font-weight:800; letter-spacing:.04em; }
  .CRITICAL { background:rgba(244,63,94,.18); color:#fda4af; border:1px solid rgba(244,63,94,.5); }
  .HIGH { background:rgba(251,146,60,.16); color:#fdba74; border:1px solid rgba(251,146,60,.45); }
  .MEDIUM { background:rgba(250,204,21,.14); color:#fde68a; border:1px solid rgba(250,204,21,.4); }
  .LOW { background:rgba(96,165,250,.14); color:#bfdbfe; border:1px solid rgba(96,165,250,.4); }
  .INFO { background:rgba(148,163,184,.14); color:#e2e8f0; border:1px solid rgba(148,163,184,.35); }
  code { background:#050a14; border:1px solid #1b2740; padding:1px 6px; border-radius:5px;
         font-size:.8rem; word-break:break-word; }
  .meta { color:var(--muted); font-size:.8rem; margin-top:7px; line-height:1.6; }
  .ev { margin-top:9px; font-size:.84rem; line-height:1.55; }
  .path { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--accent-2);
          border-radius:12px; padding:15px 17px; margin-bottom:12px; }
  .path h3 { margin:0 0 6px; font-size:1rem; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:12px; overflow:hidden; }
  th, td { padding:9px 11px; border-bottom:1px solid var(--border); text-align:left; font-size:.8rem; vertical-align:top; }
  th { background:var(--panel-2); color:var(--accent); font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; }
  tr:last-child td { border-bottom:none; }
  svg { width:100%; background:var(--panel); border:1px solid var(--border); border-radius:12px; }
  .empty { color:var(--muted); padding:24px; text-align:center; }
  .footer { margin-top:34px; color:var(--muted); font-size:.75rem; border-top:1px solid var(--border); padding-top:14px; }
  .pill { font-size:.68rem; color:var(--muted); border:1px solid var(--border); border-radius:99px; padding:2px 8px; }
  a { color:var(--accent); }
  @media (max-width:720px) { .qri { width:100%; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>InnovateIT <span>BugHunter</span> __VERSION__ <span class="pill">__CODENAME__</span></h1>
      <div class="sub">Offline static intelligence · CVSS 3.1 · OWASP ASVS v5.0.0 · SARIF 2.1.0</div>
      <div class="sub" id="meta" style="margin-top:6px;"></div>
    </div>
    <div class="qri">
      <small class="sub">Quantum Risk Index</small>
      <div class="num" id="qri-value">0</div>
      <div class="bar"><i id="qri-bar" style="width:0%"></i></div>
      <div class="sub" id="qri-note" style="margin-top:8px;"></div>
    </div>
  </header>

  <div class="stats" id="stats"></div>

  <div class="tabs" role="tablist">
    <button class="tab active" data-view="findings">Findings</button>
    <button class="tab" data-view="paths">Attack Paths</button>
    <button class="tab" data-view="graph">Attack Graph</button>
    <button class="tab" data-view="asvs">ASVS Matrix</button>
    <button class="tab" data-view="surface">Endpoint Priority</button>
    <button class="tab" data-view="coverage">CWE Coverage</button>
  </div>

  <section id="view-findings">
    <div class="controls">
      <input id="search" placeholder="Search rules, assets, CWE, ASVS, evidence..." style="flex:1;min-width:240px">
      <select id="sev"><option value="ALL">All severities</option></select>
      <select id="triage"><option value="ALL">All triage states</option>
        <option>New</option><option>Triaged</option><option>Ready to Report</option><option>False Positive</option>
      </select>
      <label class="pill" style="display:flex;align-items:center;gap:6px;cursor:pointer">
        <input type="checkbox" id="hide-suppressed" style="width:auto"> hide suppressed
      </label>
    </div>
    <div id="findings"></div>
  </section>

  <section id="view-paths" hidden><div id="paths"></div></section>
  <section id="view-graph" hidden><div id="graph"></div></section>
  <section id="view-asvs" hidden>
    <table><thead><tr><th>ASVS requirement</th><th>Status</th><th>Findings</th><th>Max risk</th><th>Mapped rules</th></tr></thead>
    <tbody id="asvs"></tbody></table>
  </section>
  <section id="view-surface" hidden>
    <table><thead><tr><th>APS</th><th>Endpoint</th><th>Statuses</th><th>Auth</th><th>Params</th><th>Why</th></tr></thead>
    <tbody id="surface"></tbody></table>
  </section>
  <section id="view-coverage" hidden>
    <table><thead><tr><th>CWE</th><th>Top 25</th><th>Findings</th></tr></thead><tbody id="coverage"></tbody></table>
  </section>

  <div class="footer">
    Generated by __TOOL__ v__VERSION__ · non-destructive analysis · validate findings in an authorized environment.
  </div>
</div>

<script>
const REPORT = __REPORT_JSON__;
const TRIAGE_KEY = "__TRIAGE_KEY__";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
let triage = {};
try { triage = JSON.parse(localStorage.getItem(TRIAGE_KEY) || "{}"); } catch (e) { triage = {}; }

const findings = Array.isArray(REPORT.findings) ? REPORT.findings : [];
const paths = Array.isArray(REPORT.attack_paths) ? REPORT.attack_paths : [];
const asvsRows = Array.isArray(REPORT.asvs_matrix) ? REPORT.asvs_matrix : [];
const ranked = Array.isArray(REPORT.ranked_endpoints) ? REPORT.ranked_endpoints : [];
const coverage = Array.isArray(REPORT.cwe_coverage) ? REPORT.cwe_coverage : [];
const summary = REPORT.summary || {};

function esc(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, function (ch) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
  });
}
function short(value, limit) {
  const text = String(value === null || value === undefined ? "" : value);
  return text.length > limit ? text.slice(0, limit - 1) + "…" : text;
}
function saveTriage(fingerprint, value) {
  triage[fingerprint] = value;
  try { localStorage.setItem(TRIAGE_KEY, JSON.stringify(triage)); } catch (e) {}
  renderFindings();
}
function draft(fingerprint) {
  const f = findings.find(function (item) { return item.fingerprint === fingerprint; });
  if (!f) return;
  const md = [
    "## Summary", "**[" + f.severity + "] " + f.title + "** (`" + f.rule_id + "` / " + f.cwe + " / " + f.asvs + ")",
    "", "- **Asset:** `" + f.asset + "`", "- **Location:** `" + f.location + "`",
    "- **CVSS 3.1:** " + f.cvss_score + " `" + f.cvss_vector + "`",
    "- **Bugcrowd VRT:** `" + f.vrt + "`", "", "## Evidence", "```", f.evidence, "```", "",
    "## Remediation", f.remediation, "", "## Verification", f.verification_hint
  ].join("\n");
  const done = function () { window.alert("Report draft copied to clipboard."); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(md).then(done).catch(function () { window.prompt("Copy draft:", md); });
  } else {
    window.prompt("Copy draft:", md);
  }
}

function renderStats() {
  const counts = summary.severity_counts || {};
  document.getElementById("stats").innerHTML = SEVERITIES.map(function (sev) {
    return '<div class="stat"><b class="' + sev + '">' + (counts[sev] || 0) + "</b><small>" + sev + "</small></div>";
  }).join("") +
    '<div class="stat"><b>' + (summary.attack_paths || 0) + "</b><small>attack paths</small></div>" +
    '<div class="stat"><b>' + (summary.suppressed_findings || 0) + "</b><small>suppressed</small></div>" +
    '<div class="stat"><b>' + (summary.files_scanned || 0) + "</b><small>files</small></div>";
  const qri = Number(summary.quantum_risk_index || 0);
  document.getElementById("qri-value").textContent = qri.toFixed(1);
  document.getElementById("qri-bar").style.width = Math.max(0, Math.min(100, qri)) + "%";
  document.getElementById("qri-note").textContent =
    qri >= 80 ? "critical correlated exposure" : qri >= 50 ? "elevated correlated exposure" :
    qri >= 20 ? "moderate exposure" : "low correlated exposure";
  document.getElementById("meta").textContent =
    "Generated " + (REPORT.generated_at || "?") + " · " + (summary.total_findings || 0) + " findings · " +
    (REPORT.stats && REPORT.stats.duration_seconds ? REPORT.stats.duration_seconds + "s" : "n/a");
}

function renderFindings() {
  const query = (document.getElementById("search").value || "").toLowerCase();
  const sev = document.getElementById("sev").value;
  const state = document.getElementById("triage").value;
  const hideSuppressed = document.getElementById("hide-suppressed").checked;
  const filtered = findings.filter(function (f) {
    if (hideSuppressed && f.suppressed) return false;
    if (sev !== "ALL" && f.severity !== sev) return false;
    const triageState = triage[f.fingerprint] || "New";
    if (state !== "ALL" && triageState !== state) return false;
    const hay = [f.rule_id, f.title, f.asset, f.location, f.asvs, f.cwe, f.vrt, f.evidence, f.snippet]
      .join(" ").toLowerCase();
    return hay.indexOf(query) !== -1;
  });
  const host = document.getElementById("findings");
  if (!filtered.length) { host.innerHTML = '<div class="empty">No findings match the current filters.</div>'; return; }
  host.innerHTML = filtered.map(function (f) {
    const triageState = triage[f.fingerprint] || "New";
    const options = ["New", "Triaged", "Ready to Report", "False Positive"].map(function (opt) {
      return '<option' + (opt === triageState ? " selected" : "") + ">" + opt + "</option>";
    }).join("");
    const baseline = f.baseline_state ? ' <span class="pill">' + esc(f.baseline_state) + "</span>" : "";
    const suppressed = f.suppressed ? ' <span class="pill">suppressed: ' + esc(f.suppression_reason) + "</span>" : "";
    const pathTags = (f.attack_path_ids || []).map(function (id) {
      return '<span class="pill">' + esc(id) + "</span>";
    }).join(" ");
    return '<article class="finding' + (f.suppressed ? " suppressed" : "") + '">' +
      '<div class="row"><div>' +
        '<span class="badge ' + esc(f.severity) + '">' + esc(f.severity) + "</span> " +
        "<strong>" + esc(f.title) + "</strong> <code>" + esc(f.rule_id) + "</code> " +
        "<code>" + esc(f.asvs) + "</code>" + baseline + suppressed +
      "</div><div>" +
        '<select aria-label="triage state" data-fp="' + esc(f.fingerprint) + '" class="triage-select">' + options + "</select> " +
        '<button class="action" data-draft="' + esc(f.fingerprint) + '">Copy report draft</button>' +
      "</div></div>" +
      '<div class="meta">Asset <code>' + esc(f.asset) + "</code> · " + esc(f.location) +
        (f.start_line ? " · line " + esc(f.start_line) : "") + " · " + esc(f.cwe) +
        " · confidence " + esc(f.confidence) + " · CVSS " + esc(f.cvss_score) +
        " · risk " + esc(f.risk_score) + "/100</div>" +
      '<div class="ev"><strong>Evidence:</strong> ' + esc(f.evidence) + "</div>" +
      (f.snippet ? '<div class="ev"><strong>Snippet:</strong> <code>' + esc(f.snippet) + "</code></div>" : "") +
      '<div class="meta"><strong>Remediation:</strong> ' + esc(f.remediation) + "</div>" +
      (pathTags ? '<div class="meta">Attack paths: ' + pathTags + "</div>" : "") +
    "</article>";
  }).join("");
  host.querySelectorAll(".triage-select").forEach(function (el) {
    el.addEventListener("change", function () { saveTriage(el.getAttribute("data-fp"), el.value); });
  });
  host.querySelectorAll("[data-draft]").forEach(function (el) {
    el.addEventListener("click", function () { draft(el.getAttribute("data-draft")); });
  });
}

function renderPaths() {
  const host = document.getElementById("paths");
  if (!paths.length) { host.innerHTML = '<div class="empty">No correlated attack paths in this report.</div>'; return; }
  host.innerHTML = paths.map(function (p) {
    return '<article class="path"><h3>' + esc(p.path_id) + " — " + esc(p.title) +
      ' <span class="badge ' + esc(p.severity) + '">' + esc(p.severity) + "</span></h3>" +
      '<div class="meta">QRI ' + esc(p.qri) + "/100 · combined probability " + esc(p.combined_probability) +
      " · rules " + esc((p.rule_ids || []).join(", ")) + "</div>" +
      '<div class="ev">' + esc(p.narrative) + "</div>" +
      '<div class="meta">Assets: ' + esc((p.assets || []).join(", ")) + "</div></article>";
  }).join("");
}

function renderGraph() {
  const sample = findings.filter(function (f) { return !f.suppressed; }).slice(0, 20);
  const host = document.getElementById("graph");
  if (!sample.length) { host.innerHTML = '<div class="empty">No findings to graph.</div>'; return; }
  const assets = Array.from(new Set(sample.map(function (f) { return f.asset; })));
  const rules = Array.from(new Set(sample.map(function (f) { return f.rule_id; })));
  const reqs = Array.from(new Set(sample.map(function (f) { return f.asvs; })));
  const rowHeight = 46;
  const height = Math.max(320, Math.max(assets.length, rules.length, reqs.length) * rowHeight + 60);
  const pos = { a: {}, r: {}, s: {} };
  assets.forEach(function (a, i) { pos.a[a] = 40 + i * rowHeight; });
  rules.forEach(function (r, i) { pos.r[r] = 40 + i * rowHeight; });
  reqs.forEach(function (s, i) { pos.s[s] = 40 + i * rowHeight; });
  let svg = '<svg viewBox="0 0 980 ' + height + '" height="' + height + '" role="img" aria-label="Attack surface graph">';
  sample.forEach(function (f) {
    const y1 = pos.a[f.asset], y2 = pos.r[f.rule_id], y3 = pos.s[f.asvs];
    if (y1 === undefined || y2 === undefined || y3 === undefined) return;
    svg += '<path d="M260 ' + y1 + ' C 390 ' + y1 + ', 390 ' + y2 + ', 500 ' + y2 + '" fill="none" stroke="#334b70" stroke-width="1.4"/>';
    svg += '<path d="M620 ' + y2 + ' C 730 ' + y2 + ', 730 ' + y3 + ', 820 ' + y3 + '" fill="none" stroke="#7c3aed" stroke-width="1.4"/>';
  });
  assets.forEach(function (a) {
    svg += '<rect x="30" y="' + (pos.a[a] - 14) + '" width="230" height="28" rx="7" fill="#132038" stroke="#38bdf8"/>';
    svg += '<text x="145" y="' + (pos.a[a] + 4) + '" fill="#dbeafe" font-size="10.5" text-anchor="middle">' + esc(short(a, 34)) + "</text>";
  });
  rules.forEach(function (r) {
    svg += '<rect x="500" y="' + (pos.r[r] - 14) + '" width="120" height="28" rx="7" fill="#1a1730" stroke="#f59e0b"/>';
    svg += '<text x="560" y="' + (pos.r[r] + 4) + '" fill="#fde68a" font-size="10.5" text-anchor="middle">' + esc(r) + "</text>";
  });
  reqs.forEach(function (s) {
    svg += '<rect x="820" y="' + (pos.s[s] - 14) + '" width="145" height="28" rx="7" fill="#0f2620" stroke="#34d399"/>';
    svg += '<text x="892" y="' + (pos.s[s] + 4) + '" fill="#a7f3d0" font-size="10" text-anchor="middle">' + esc(s) + "</text>";
  });
  svg += "</svg>";
  host.innerHTML = svg;
}

function renderAsvs() {
  document.getElementById("asvs").innerHTML = asvsRows.map(function (row) {
    return "<tr><td><code>" + esc(row.asvs_requirement) + "</code></td><td>" + esc(row.status) +
      "</td><td>" + esc(row.finding_count) + "</td><td>" + esc(row.max_risk) +
      "</td><td>" + esc((row.mapped_rules || []).join(", ")) + "</td></tr>";
  }).join("") || '<tr><td colspan="5">No ASVS rows.</td></tr>';
}

function renderSurface() {
  document.getElementById("surface").innerHTML = ranked.map(function (ep) {
    return "<tr><td><strong>" + esc(ep.aps_score) + "</strong>/100</td><td><code>" + esc(ep.template) +
      "</code></td><td>" + esc((ep.statuses || []).join(", ")) + "</td><td>" +
      (ep.authenticated_seen ? "Yes" : "No") + "</td><td><code>" +
      esc((ep.query_keys || []).join(", ") || "-") + "</code></td><td>" +
      esc((ep.aps_reasons || []).join(" · ")) + "</td></tr>";
  }).join("") || '<tr><td colspan="6">No endpoint telemetry in this report.</td></tr>';
}

function renderCoverage() {
  document.getElementById("coverage").innerHTML = coverage.map(function (row) {
    return "<tr><td><code>" + esc(row.cwe) + "</code></td><td>" + (row.in_top25 ? "yes" : "—") +
      "</td><td>" + esc(row.finding_count) + "</td></tr>";
  }).join("") || '<tr><td colspan="3">No CWE data.</td></tr>';
}

function switchView(name) {
  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.classList.toggle("active", btn.getAttribute("data-view") === name);
  });
  ["findings", "paths", "graph", "asvs", "surface", "coverage"].forEach(function (view) {
    document.getElementById("view-" + view).hidden = view !== name;
  });
  if (name === "graph") renderGraph();
}

document.querySelectorAll(".tab").forEach(function (btn) {
  btn.addEventListener("click", function () { switchView(btn.getAttribute("data-view")); });
});
const sevSelect = document.getElementById("sev");
SEVERITIES.forEach(function (sev) {
  const option = document.createElement("option");
  option.value = sev; option.textContent = sev;
  sevSelect.appendChild(option);
});
document.getElementById("search").addEventListener("input", renderFindings);
sevSelect.addEventListener("change", renderFindings);
document.getElementById("triage").addEventListener("change", renderFindings);
document.getElementById("hide-suppressed").addEventListener("change", renderFindings);

renderStats();
renderFindings();
renderPaths();
renderAsvs();
renderSurface();
renderCoverage();
</script>
</body>
</html>
"""


def build_html_report(payload: dict[str, Any]) -> str:
    safe_payload = json_dumps(payload).replace("</", "<\\/")
    triage_key = "bughunter:triage:" + hashlib.sha256(
        (payload.get("generated_at", "") + str(len(payload.get("findings", [])))).encode()
    ).hexdigest()[:12]
    replacements = {
        "__REPORT_JSON__": safe_payload,
        "__TITLE__": escape_html(f"{TOOL_NAME} v{VERSION} — Security Workbench"),
        "__TOOL__": escape_html(TOOL_NAME),
        "__VERSION__": escape_html(VERSION),
        "__CODENAME__": escape_html(CODENAME),
        "__TRIAGE_KEY__": triage_key,
    }
    rendered = HTML_DASHBOARD_TEMPLATE
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def write_all_reports(
    out_dir: Path,
    prefix: str,
    result: ScanResult,
    formats: Sequence[str] = ("json", "sarif", "markdown", "html"),
    exit_code: int = 0,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = result_to_payload(result)
    paths: dict[str, Path] = {}
    if "json" in formats:
        path = out_dir / f"{prefix}_findings.json"
        path.write_text(json_dumps(payload), encoding="utf-8")
        paths["json"] = path
    if "sarif" in formats:
        path = out_dir / f"{prefix}_report.sarif"
        sarif = build_sarif_report(
            result.findings,
            automation_id=f"{prefix}/{result.stats.started_at or utc_now_iso()}",
            start_time_utc=result.stats.started_at or None,
            exit_code=exit_code,
        )
        path.write_text(json_dumps(sarif), encoding="utf-8")
        paths["sarif"] = path
    if "markdown" in formats:
        path = out_dir / f"{prefix}_report.md"
        path.write_text(build_markdown_report(result.findings, payload), encoding="utf-8")
        paths["markdown"] = path
    if "html" in formats:
        path = out_dir / f"{prefix}_dashboard.html"
        path.write_text(build_html_report(payload), encoding="utf-8")
        paths["html"] = path
    return paths


def evaluate_ci_gate(
    findings: Sequence[Finding],
    fail_on: Sequence[str],
    fail_on_new: bool = False,
    attack_paths: Sequence[AttackPath] = (),
) -> int:
    blocked = {severity.upper() for severity in fail_on}
    triggered = [
        finding for finding in findings
        if not finding.suppressed and finding.severity.upper() in blocked
        and (not fail_on_new or finding.baseline_state in ("new", "updated", ""))
    ]
    if fail_on_new:
        new_fingerprints = {
            finding.fingerprint for finding in findings
            if finding.baseline_state in ("new", "updated") and not finding.suppressed
        }
        triggered_paths = [
            path for path in attack_paths
            if path.severity.upper() in blocked
            and any(fingerprint in new_fingerprints for fingerprint in path.finding_fingerprints)
        ]
    else:
        triggered_paths = [path for path in attack_paths if path.severity.upper() in blocked]
    if triggered or triggered_paths:
        detail = f"{len(triggered)} finding(s)"
        if triggered_paths:
            detail += f" and {len(triggered_paths)} correlated attack path(s)"
        print(
            f"[!] CI gate failed: {detail} at {sorted(blocked)}"
            + (" (new/updated findings only)" if fail_on_new else ""),
            file=sys.stderr,
        )
        return 2
    return 0


# ===========================================================================
# 19. Built-in verification suite
# ===========================================================================

def _selftest_har() -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://app.example.com/api/users/12345?access_token=abc123&next=/dashboard",
                        "headers": [{"name": "Origin", "value": "https://evil.example"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Access-Control-Allow-Origin", "value": "https://evil.example"},
                            {"name": "Access-Control-Allow-Credentials", "value": "true"},
                            {"name": "Set-Cookie", "value": "sessionid=abc; Path=/"},
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Server", "value": "nginx/1.18.0"},
                        ],
                        "content": {
                            "mimeType": "application/javascript",
                            "text": "fetch('/api/internal/export');",
                        },
                    },
                }
            ],
        }
    }


def run_self_test() -> int:
    import tempfile

    failures: list[str] = []
    checks = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(f"{name}{(': ' + detail) if detail else ''}")

    # --- registry & CVSS ---------------------------------------------------
    check("registry has 45 rules", len(RULES) == 45, str(len(RULES)))
    check("known CVSS vector scores 9.8",
          abs(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") - 9.8) < 0.001)
    check("CVSS scope-changed vector is valid",
          0.0 <= cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") <= 10.0)
    check("all rules validate", all(rule.cvss_score >= 0 for rule in RULES.values()))

    # --- primitives --------------------------------------------------------
    check("entropy of repeated char is 0", shannon_entropy("aaaa") == 0.0)
    check("entropy of distinct chars is 3", abs(shannon_entropy("abcdefgh") - 3.0) < 1e-9)
    check("redaction keeps ends", redact_secret("sk_live_ABCDEFGHIJKLMNOP") == "sk_l****MNOP")
    index = LineIndex("alpha\nbeta\ngamma")
    check("line index maps offsets", index.line_col(7) == (2, 2), str(index.line_col(7)))
    check("placeholder filtering", is_probable_placeholder("AKIAIOSFODNN7EXAMPLE")
          and not is_probable_placeholder("AKIA3FJ7Q2WZ8N5R4T6Y"))

    # --- scope guard -------------------------------------------------------
    guard = ScopeGuard(["example.com"])
    check("subdomain in scope", guard.is_domain_in_scope("api.example.com"))
    check("lookalike out of scope", not guard.is_domain_in_scope("evil-example.com"))
    check("ip literal out of scope", not guard.is_domain_in_scope("127.0.0.1"))
    check("metadata ip restricted", guard.is_restricted_ip("169.254.169.254"))
    check("private ip restricted", guard.is_restricted_ip("10.1.2.3"))
    check("public ip allowed", not guard.is_restricted_ip("8.8.8.8"))
    check("bad scheme rejected", _raises(ScopeViolationError, guard.validate_url, "file:///etc/passwd"))
    limiter = TokenBucket(1000, burst=5)
    limiter.acquire(3)
    check("token bucket acquires", True)

    # --- secrets -----------------------------------------------------------
    secret_text = (
        'STRIPE = "sk_live_9fK2mQ7pR4tV8xZ3nB6cL1wY"\n'
        'AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"\n'
        'DB = "postgresql://admin:hunter2secret@db.internal:5432/app"\n'
    )
    secret_findings = scan_text_for_secrets(secret_text, "app.py", "app.py")
    types = {finding.metadata.get("secret_type") for finding in secret_findings}
    check("stripe key detected", "Stripe Live Secret Key" in types, str(types))
    check("database uri detected", "Database Connection URI" in types, str(types))
    check("AWS placeholder ignored", all("AKIAIOSFODNN7EXAMPLE" not in f.evidence for f in secret_findings))
    check("secret redacted in evidence",
          all("51AbCdEfGhIjKlMnOp" not in finding.evidence for finding in secret_findings))
    check("secret finding has line number", all(finding.start_line > 0 for finding in secret_findings))

    # --- JWT ---------------------------------------------------------------
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    none_payload = base64.urlsafe_b64encode(b'{"sub":"1","role":"admin"}').decode().rstrip("=")
    none_token = f"{none_header}.{none_payload}."
    jwt_findings = inspect_jwt_token(none_token, "api", "auth-header")
    jwt_rules = {finding.rule_id for finding in jwt_findings}
    check("alg none detected", "BH-014" in jwt_rules, str(jwt_rules))
    check("missing exp/aud detected", "BH-015" in jwt_rules)
    check("JWT regex matches none token", bool(JWT_REGEX.search(none_token)))

    # --- JavaScript --------------------------------------------------------
    sample_js = """
    //# sourceMappingURL=bundle.js.map
    const rawParam = new URLSearchParams(location.search).get("redirect");
    const cleanAlias = rawParam.trim();
    document.getElementById("banner").innerHTML = cleanAlias;
    function deepMerge(target, src) {
        for (const key in src) { target[key] = src[key]; }
    }
    window.addEventListener("message", (event) => { document.body.innerHTML = event.data; });
    const STRIPE = "sk_live_9fK2mQ7pR4tV8xZ3nB6cL1wY";
    """
    js_findings, js_routes = audit_js_content(sample_js, "bundle.js", "bundle.js")
    js_rules = {finding.rule_id for finding in js_findings}
    check("JS source map", "BH-010" in js_rules, str(js_rules))
    check("JS multi-hop XSS", "BH-011" in js_rules)
    check("JS prototype pollution", "BH-025" in js_rules)
    check("JS secret", "BH-013" in js_rules)
    check("JS postMessage origin", "BH-012" in js_rules)
    check("JS sink line number", any(f.start_line >= 5 for f in js_findings))
    check("JS evidence does not leak secret",
          all("51AbCdEfGhIjKlMnOp" not in finding.evidence for finding in js_findings))
    check("JS ASVS mapping", all(finding.asvs.startswith("v5.0.0-") for finding in js_findings))
    safe_listener = 'window.addEventListener("message", (event) => { if (event.origin !== "https://ok") return; use(event.data); });'
    _, _ = audit_js_content(safe_listener, "safe.js", "safe.js")

    # --- Python AST --------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        py_file = tmp_path / "app.py"
        py_file.write_text(
            "import os, pickle, yaml, hashlib, requests\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    term = request.args.get('q')\n"
            "    query = f\"SELECT * FROM users WHERE name = '{term}'\"\n"
            "    cursor.execute(query)\n"
            "    os.system('ls ' + term)\n"
            "    pickle.loads(term)\n"
            "    yaml.load(term)\n"
            "    requests.get(term, verify=False)\n"
            "    hashlib.md5(term.encode())\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        py_findings, py_routes, py_tech = audit_python_file(py_file, py_file.read_text(encoding="utf-8"))
        py_rules = {finding.rule_id for finding in py_findings}
        check("Python SQLi", "BH-031" in py_rules, str(py_rules))
        check("Python command injection", "BH-032" in py_rules)
        check("Python deserialization", "BH-034" in py_rules)
        check("Python SSRF + TLS", "BH-033" in py_rules and "BH-035" in py_rules)
        check("Python route extraction", "/search" in py_routes, str(py_routes))
        check("Python framework tech", "python:flask" in py_tech)
        check("Python findings carry lines", all(f.start_line > 0 for f in py_findings))

        # --- Dockerfile ----------------------------------------------------
        docker_text = "FROM node:latest\nRUN npm ci\nUSER root\n"
        docker_findings = audit_dockerfile(docker_text, "Dockerfile")
        docker_rules = {finding.rule_id for finding in docker_findings}
        check("Docker root user", "BH-036" in docker_rules, str(docker_rules))
        check("Docker unpinned image", "BH-043" in docker_rules)

        # --- CI workflow ---------------------------------------------------
        ci_text = (
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: |\n"
            "          echo \"${{ github.event.pull_request.title }}\"\n"
        )
        ci_findings = audit_ci_workflow(ci_text, ".github/workflows/ci.yml")
        ci_rules = {finding.rule_id for finding in ci_findings}
        check("CI untrusted checkout", "BH-037" in ci_rules, str(ci_rules))
        check("CI unpinned action", "BH-043" in ci_rules)

        # --- OpenAPI -------------------------------------------------------
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/admin/wipe": {
                    "post": {"security": [], "responses": {"200": {"description": "ok"}}}
                }
            },
            "components": {"schemas": {"User": {"properties": {"passwordHash": {"type": "string"}}}}},
        }
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(spec), encoding="utf-8")
        spec_result = audit_openapi_spec(spec_file)
        spec_rules = {finding.rule_id for finding in spec_result.findings}
        check("OpenAPI security empty", "BH-028" in spec_rules, str(spec_rules))
        check("OpenAPI sensitive schema", "BH-029" in spec_rules)

        # --- HAR -----------------------------------------------------------
        har_file = tmp_path / "capture.har"
        har_file.write_text(json.dumps(_selftest_har()), encoding="utf-8")
        har_result = audit_har_file(har_file)
        har_rules = {finding.rule_id for finding in har_result.findings}
        check("HAR CORS with credentials", "BH-001" in har_rules, str(har_rules))
        check("HAR sensitive query param", "BH-039" in har_rules)
        check("HAR cookie flags", "BH-007" in har_rules)
        check("HAR ghost route", "BH-026" in har_rules, str(har_result.ghost_routes))
        check("HAR APS ranking", bool(har_result.ranked_endpoints))
        check("HAR APS has reasons",
              bool(har_result.ranked_endpoints[0].get("aps_reasons")))

        # --- scanner, suppressions, baseline -------------------------------
        (tmp_path / "Dockerfile").write_text(docker_text, encoding="utf-8")
        repo_result = scan_paths(
            [tmp_path], ScannerConfig(jobs=2), SuppressionSet()
        )
        check("scanner inventories files", repo_result.stats.files_scanned >= 3,
              str(repo_result.stats.files_scanned))
        check("scanner dedupes", len({f.fingerprint for f in repo_result.findings}) == len(repo_result.findings))
        check("scanner ASVS matrix", bool(repo_result.asvs_matrix))
        check("scanner CWE coverage", bool(repo_result.cwe_coverage))
        check("scanner QRI computed", 0 <= repo_result.metadata.get("quantum_risk_index", -1) <= 100)

        suppression = SuppressionSet([Suppression(reason="accepted risk", rule_id="BH-013")])
        suppressed_result = scan_paths([tmp_path], ScannerConfig(jobs=2), suppression)
        check("file suppression applied",
              all(f.suppressed for f in suppressed_result.findings if f.rule_id == "BH-013"))

        inline_file = tmp_path / "inline.js"
        inline_file.write_text(
            'const key = "sk_live_9fK2mQ7pR4tV8xZ3nB6cL1wY"; // bughunter:ignore BH-013 test\n',
            encoding="utf-8",
        )
        inline_result = scan_paths([inline_file], ScannerConfig())
        check("inline suppression applied",
              any(f.rule_id == "BH-013" and f.suppressed for f in inline_result.findings))

        # --- chaining ------------------------------------------------------
        chain_findings = [
            Finding.from_rule("BH-010", "bundle.js", "bundle.js:1", "source map", start_line=1),
            Finding.from_rule("BH-013", "bundle.js", "bundle.js:4", "stripe key sk_l****1234", start_line=4),
        ]
        chain_paths = build_attack_paths(chain_findings)
        check("attack path built", any(path.path_id.startswith("CHAIN-01") for path in chain_paths),
              str([path.path_id for path in chain_paths]))
        if chain_paths:
            check("attack path probability is a bounded chain product",
                  0 < chain_paths[0].combined_probability <= max(f.exploitability for f in chain_findings),
                  str(chain_paths[0].combined_probability))
        check("finding linked to path", bool(chain_findings[0].attack_path_ids))

        # --- reporters -----------------------------------------------------
        result = ScanResult(findings=deduplicate_findings(chain_findings), attack_paths=chain_paths,
                            asvs_matrix=build_asvs_matrix(chain_findings))
        finalize_result(result)
        payload = result_to_payload(result)
        sarif = build_sarif_report(result.findings, automation_id="test/run")
        check("SARIF version", sarif["version"] == "2.1.0")
        check("SARIF results", len(sarif["runs"][0]["results"]) == len(result.findings))
        check("SARIF regions",
              all("region" in r["locations"][0]["physicalLocation"] for r in sarif["runs"][0]["results"]
                  if r["locations"][0]["physicalLocation"].get("uri") == "bundle.js"))
        check("SARIF rule index valid",
              all(0 <= r["ruleIndex"] < len(sarif["runs"][0]["tool"]["driver"]["rules"])
                  for r in sarif["runs"][0]["results"]))
        check("SARIF invocations", bool(sarif["runs"][0]["invocations"]))
        markdown = build_markdown_report(result.findings, payload)
        check("Markdown has severity table", "| CRITICAL | HIGH | MEDIUM | LOW | INFO |" in markdown)

        xss_payload = dict(payload)
        xss_payload["findings"] = [dict(f.to_dict()) for f in result.findings]
        xss_payload["findings"][0]["evidence"] = "</script><script>alert(1)</script>"
        html_report = build_html_report(xss_payload)
        check("HTML escapes script close", "</script><script>alert(1)</script>" not in html_report)
        check("HTML contains report data", "REPORT =" in html_report)

        # --- baseline / diff / fusion --------------------------------------
        baseline_findings = list(result.findings)
        new_finding = Finding.from_rule("BH-032", "x.py", "x.py:3", "os.system")
        apply_baseline(result.findings + [new_finding], baseline_findings)
        check("baseline marks existing", result.findings[0].baseline_state in ("unchanged", "updated"))
        check("baseline marks new", new_finding.baseline_state == "new")
        diff = diff_runs(payload, result_to_payload(ScanResult(findings=[new_finding])))
        check("diff counts new", diff["summary"]["new_findings"] >= 1, str(diff["summary"]))

        artifact_dir = tmp_path / "reports"
        written = write_all_reports(artifact_dir, "selftest", result)
        check("reports written", all(path.is_file() for path in written.values()), str(written))
        fused = fuse_artifact_runs([written["json"]])
        check("fusion reads JSON artifact", len(fused.findings) == len(result.findings))

    if failures:
        print(f"[FAIL] {len(failures)}/{checks} self-test checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"[OK] {TOOL_NAME} v{VERSION} self-test passed "
        f"({checks} checks, {len(RULES)} rules, OWASP ASVS v5.0.0 active)."
    )
    return 0


def _raises(exc_type: type[BaseException], func: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    try:
        func(*args, **kwargs)
    except exc_type:
        return True
    except Exception:
        return False
    return False


# ===========================================================================
# 20. CLI
# ===========================================================================

FORMAT_CHOICES = ("json", "sarif", "markdown", "html")


def _load_suppressions(args: argparse.Namespace) -> SuppressionSet:
    paths = list(getattr(args, "suppress", []) or [])
    default_ignore = Path(".bughunterignore")
    if default_ignore.is_file() and default_ignore not in paths:
        paths.append(default_ignore)
    if not paths:
        return SuppressionSet()
    return SuppressionSet.load(paths)


def _load_baseline(path: Path | None) -> list[Finding]:
    if not path:
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        raw_findings = data.get("findings", [])
    elif isinstance(data, list):
        raw_findings = data
    else:
        raise ValueError(f"Unsupported baseline format: {path}")
    return [Finding.from_dict(raw) for raw in raw_findings if isinstance(raw, dict)]


def _print_summary(label: str, result: ScanResult, paths: dict[str, Path], quiet: bool) -> None:
    if quiet:
        return
    counts = result.metadata.get("finding_counts") or {
        severity: sum(1 for f in result.findings if f.severity == severity and not f.suppressed)
        for severity in SEVERITY_ORDER
    }
    total = sum(counts.values())
    print(f"[+] {label}: {total} findings "
          f"(C:{counts.get('CRITICAL', 0)} H:{counts.get('HIGH', 0)} M:{counts.get('MEDIUM', 0)} "
          f"L:{counts.get('LOW', 0)} I:{counts.get('INFO', 0)}) "
          f"| QRI {result.metadata.get('quantum_risk_index', 0)}/100")
    if result.stats.files_scanned:
        print(f"    files: {result.stats.files_scanned} | bytes: {result.stats.bytes_scanned} | "
              f"time: {result.stats.duration_seconds}s")
    probe_errors = result.metadata.get("probe_errors") or []
    if probe_errors:
        print(f"    warning: {len(probe_errors)} probe(s) failed (TLS/connectivity); "
              f"see report metadata, or use --insecure for self-signed targets")
    for path in result.attack_paths[:5]:
        print(f"    [chain] {path.path_id} [{path.severity}] {path.title} (QRI {path.qri})")
    for finding in result.findings[:5]:
        if finding.suppressed:
            continue
        print(f"    - [{finding.severity}] {finding.rule_id} {finding.title} @ {finding.asset}:"
              f"{finding.start_line or '-'}")
    if len(result.findings) > 5:
        print(f"    ... {len(result.findings) - 5} more")
    for kind, path in paths.items():
        print(f"    {kind}: {path}")


def _add_report_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", type=Path, default=Path("./bh_reports"), help="Output directory.")
    parser.add_argument("--format", nargs="+", choices=FORMAT_CHOICES, default=list(FORMAT_CHOICES),
                        help="Report formats to emit.")
    parser.add_argument("--fail-on", nargs="*", default=[],
                        help="Severities that fail the CI gate (e.g. CRITICAL HIGH).")
    parser.add_argument("--fail-on-new", action="store_true",
                        help="Only fail on findings new relative to --baseline.")
    parser.add_argument("--suppress", type=Path, action="append", default=[],
                        help="Suppression JSON file (repeatable).")
    parser.add_argument("--baseline", type=Path, default=None,
                        help="Previous JSON run used to mark new/unchanged findings.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bughunter",
        description=f"{TOOL_NAME} v{VERSION} \"{CODENAME}\" - offline full-stack security analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  bughunter scan ./src --out reports --fail-on CRITICAL HIGH\n"
            "  bughunter audit-har capture.har --scope example.com --baseline prev.json\n"
            "  bughunter recon https://app.example.com --scope example.com --i-have-authorization\n"
            "  bughunter fuse reports/*_findings.json\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION} ({CODENAME})")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Auto-detect and audit source, JS, IaC, CI, OpenAPI and HAR artifacts.")
    p_scan.add_argument("paths", nargs="+", type=Path)
    p_scan.add_argument("--scope", nargs="*", default=[], help="Authorized domains used to filter HAR entries.")
    p_scan.add_argument("--exclude", nargs="*", default=[], help="Additional directory names to skip.")
    p_scan.add_argument("--jobs", type=int, default=0, help="Worker threads (default: CPU-derived).")
    p_scan.add_argument("--max-file-bytes", type=int, default=2_500_000)
    p_scan.add_argument("--no-inline-suppressions", action="store_true")
    _add_report_flags(p_scan)

    p_har = sub.add_parser("audit-har", help="Offline HAR audit, APS ranking and ghost-route correlation.")
    p_har.add_argument("har_file", type=Path)
    p_har.add_argument("--scope", nargs="*", default=[])
    _add_report_flags(p_har)

    p_roles = sub.add_parser("diff-roles", help="Compare high-privilege vs low-privilege HAR captures.")
    p_roles.add_argument("high_priv_har", type=Path)
    p_roles.add_argument("low_priv_har", type=Path)
    p_roles.add_argument("--scope", nargs="*", default=[])
    _add_report_flags(p_roles)

    p_js = sub.add_parser("audit-js", help="Taint, prototype-pollution and secret audit for JS/TS/source maps.")
    p_js.add_argument("target", type=Path)
    p_js.add_argument("--jobs", type=int, default=1)
    _add_report_flags(p_js)

    p_repo = sub.add_parser("audit-repo", help="Static audit of backend source, Dockerfile, Kubernetes and CI configs.")
    p_repo.add_argument("repo_dir", type=Path)
    p_repo.add_argument("--exclude", nargs="*", default=[])
    p_repo.add_argument("--jobs", type=int, default=0)
    p_repo.add_argument("--max-file-bytes", type=int, default=2_500_000)
    _add_report_flags(p_repo)

    p_spec = sub.add_parser("audit-openapi", help="Offline OpenAPI / Swagger specification audit.")
    p_spec.add_argument("spec_file", type=Path)
    _add_report_flags(p_spec)

    p_jwt = sub.add_parser("inspect-jwt", help="Passive JWT header/claim hygiene inspection.")
    p_jwt.add_argument("token", help="JWT string or path to a file containing JWTs.")
    _add_report_flags(p_jwt)

    p_rec = sub.add_parser("recon", help="Scope-gated passive metadata, TLS and header audit.")
    p_rec.add_argument("url")
    p_rec.add_argument("--scope", nargs="+", required=True)
    p_rec.add_argument("--i-have-authorization", action="store_true", required=True)
    p_rec.add_argument("--rps", type=float, default=2.0)
    p_rec.add_argument("--timeout", type=float, default=8.0)
    p_rec.add_argument("--probe-sensitive", action="store_true",
                       help="Also probe well-known sensitive paths (/.env, /.git/HEAD, ...).")
    p_rec.add_argument("--insecure", action="store_true",
                       help="Accept invalid/self-signed TLS certificates (internal test targets only).")
    _add_report_flags(p_rec)

    p_fuse = sub.add_parser("fuse", help="Merge JSON audit artifacts into one correlated workspace.")
    p_fuse.add_argument("json_files", nargs="+", type=Path)
    _add_report_flags(p_fuse)

    p_diff = sub.add_parser("diff", help="Diff two JSON audit runs and isolate regressions.")
    p_diff.add_argument("prev_json", type=Path)
    p_diff.add_argument("curr_json", type=Path)
    p_diff.add_argument("--out", type=Path, default=Path("./bh_reports"))

    sub.add_parser("self-test", help="Run the built-in verification suite.")

    return parser


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} not found: {path}")


def _run_command(args: argparse.Namespace) -> int:
    started_at = utc_now_iso()

    if args.command == "self-test":
        return run_self_test()

    if args.command == "scan":
        config = ScannerConfig(jobs=args.jobs, max_file_bytes=args.max_file_bytes)
        config.excluded_paths.add(str(args.out.resolve()))
        if args.exclude:
            config.excluded_dirs |= {item.lower() for item in args.exclude}
        guard = ScopeGuard(args.scope) if args.scope else None
        baseline = _load_baseline(args.baseline)
        suppressions = _load_suppressions(args)
        result = scan_paths(
            args.paths, config, suppressions, baseline=baseline, scope_guard=guard
        )
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "scan", result, args.format, exit_code=code)
        _print_summary("Scan", result, paths, args.quiet)
        return code

    if args.command == "audit-har":
        _require_file(args.har_file, "HAR file")
        guard = ScopeGuard(args.scope) if args.scope else None
        result = audit_har_file(args.har_file, scope_guard=guard)
        if args.baseline:
            apply_baseline(result.findings, _load_baseline(args.baseline))
        _load_suppressions(args).apply(result.findings)
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "har_audit", result, args.format, exit_code=code)
        _print_summary("HAR audit", result, paths, args.quiet)
        return code

    if args.command == "diff-roles":
        _require_file(args.high_priv_har, "High-privilege HAR")
        _require_file(args.low_priv_har, "Low-privilege HAR")
        guard = ScopeGuard(args.scope) if args.scope else None
        result = diff_roles_har(args.high_priv_har, args.low_priv_har, scope_guard=guard)
        if args.baseline:
            apply_baseline(result.findings, _load_baseline(args.baseline))
        _load_suppressions(args).apply(result.findings)
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "role_diff", result, args.format, exit_code=code)
        _print_summary("Role diff", result, paths, args.quiet)
        return code

    if args.command in ("audit-js", "audit-repo"):
        target = args.target if args.command == "audit-js" else args.repo_dir
        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target}")
        jobs = getattr(args, "jobs", 0) or 1
        config = ScannerConfig(
            jobs=jobs,
            max_file_bytes=getattr(args, "max_file_bytes", 2_500_000),
        )
        config.excluded_paths.add(str(args.out.resolve()))
        if args.command == "audit-js":
            config.include_suffixes = set(_JS_EXTENSIONS) | {".map"}
        if getattr(args, "exclude", None):
            config.excluded_dirs |= {item.lower() for item in args.exclude}
        baseline = _load_baseline(args.baseline)
        result = scan_paths([target], config, _load_suppressions(args), baseline=baseline)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        prefix = "js_audit" if args.command == "audit-js" else "repo_audit"
        paths = write_all_reports(args.out, prefix, result, args.format, exit_code=code)
        _print_summary("JS audit" if args.command == "audit-js" else "Repo audit", result, paths, args.quiet)
        return code

    if args.command == "audit-openapi":
        _require_file(args.spec_file, "OpenAPI spec")
        result = audit_openapi_spec(args.spec_file)
        if args.baseline:
            apply_baseline(result.findings, _load_baseline(args.baseline))
        _load_suppressions(args).apply(result.findings)
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "openapi_audit", result, args.format, exit_code=code)
        _print_summary("OpenAPI audit", result, paths, args.quiet)
        return code

    if args.command == "inspect-jwt":
        token_path = Path(args.token)
        raw = token_path.read_text(encoding="utf-8", errors="replace") if token_path.is_file() else args.token
        tokens = set(JWT_REGEX.findall(raw))
        if not tokens and raw.count(".") == 2:
            tokens = {raw.strip()}
        findings: list[Finding] = []
        for index, token in enumerate(sorted(tokens), start=1):
            findings.extend(inspect_jwt_token(token, "jwt_input", f"token_{index}"))
        result = ScanResult(findings=deduplicate_findings(findings))
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "jwt_audit", result, args.format, exit_code=code)
        _print_summary("JWT audit", result, paths, args.quiet)
        return code

    if args.command == "recon":
        if not args.i_have_authorization:
            raise ValueError("Recon requires --i-have-authorization.")
        guard = ScopeGuard(args.scope)
        limiter = TokenBucket(args.rps)
        result = passive_recon(
            args.url, guard, limiter, timeout=args.timeout,
            probe_sensitive=args.probe_sensitive, verify_tls=not args.insecure,
        )
        if args.baseline:
            apply_baseline(result.findings, _load_baseline(args.baseline))
        _load_suppressions(args).apply(result.findings)
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "passive_recon", result, args.format, exit_code=code)
        _print_summary("Passive recon", result, paths, args.quiet)
        return code

    if args.command == "fuse":
        for path in args.json_files:
            _require_file(path, "JSON artifact")
        result = fuse_artifact_runs(args.json_files, baseline=_load_baseline(args.baseline))
        _load_suppressions(args).apply(result.findings)
        finalize_result(result)
        code = evaluate_ci_gate(result.findings, args.fail_on, args.fail_on_new, result.attack_paths)
        paths = write_all_reports(args.out, "fused_workspace", result, args.format, exit_code=code)
        _print_summary("Fusion", result, paths, args.quiet)
        return code

    if args.command == "diff":
        prev_data = json.loads(args.prev_json.read_text(encoding="utf-8-sig"))
        curr_data = json.loads(args.curr_json.read_text(encoding="utf-8-sig"))
        diff = diff_runs(prev_data, curr_data)
        args.out.mkdir(parents=True, exist_ok=True)
        out_file = args.out / "diff_report.json"
        out_file.write_text(json_dumps(diff), encoding="utf-8")
        summary = diff["summary"]
        print(f"[+] Diff: +{summary['new_findings']} new, -{summary['resolved_findings']} resolved, "
              f"{summary['changed_findings']} changed | QRI {summary['quantum_risk_index_before']} -> "
              f"{summary['quantum_risk_index_after']} -> {out_file}")
        return 0

    LOG.error("Unknown command: %s", args.command)
    return 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING
    if getattr(args, "verbose", 0) >= 2:
        level = logging.DEBUG
    elif getattr(args, "verbose", 0) == 1:
        level = logging.INFO
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return _run_command(args)
    except KeyboardInterrupt:
        print("[!] Interrupted.", file=sys.stderr)
        return 130
    except (ScopeViolationError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - top-level guard
        LOG.exception("Internal error: %s", exc)
        print(f"[!] Internal error: {exc} (re-run with -vv for a traceback)", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
