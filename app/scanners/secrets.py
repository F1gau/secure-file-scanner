import re
from collections import defaultdict
from dataclasses import dataclass

from app.db.models import Severity
from app.scanners.base import BaseScanner, Finding, ScanContext, line_of
from app.utils.filetype import is_text_mime

MAX_LINES_LISTED = 5
_PLACEHOLDER_FRAGMENTS = (
    "changeme", "change-me", "change_me", "example", "placeholder", "your_", "your-",
    "xxxx", "****", "<", "${", "{{", "%(", "os.environ", "getenv", "none", "null",
)


@dataclass(frozen=True)
class SecretRule:
    rule: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    group: int = 0  # which regex group holds the secret value
    skip_placeholders: bool = False


def _assignment(names: str) -> re.Pattern[str]:
    # Lookarounds instead of \b: "_" is a word character, so \b would miss DB_PASSWORD / MY_SECRET.
    return re.compile(
        rf"""(?ix)(?<![A-Za-z0-9])(?:{names})(?![A-Za-z0-9])["']?\s*[:=]\s*["']?([^\s"'`,;]{{8,}})"""
    )


RULES: tuple[SecretRule, ...] = (
    SecretRule("PRIVATE_KEY", "private_key_marker", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.CRITICAL, 0.95),
    SecretRule("AWS_ACCESS_KEY", "aws_like_access_key",
               re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL, 0.85),
    SecretRule("STRIPE_LIVE_KEY", "stripe_like_live_key",
               re.compile(r"\b[sr]k_live_[0-9A-Za-z]{10,}\b"), Severity.CRITICAL, 0.9),
    SecretRule("STRIPE_TEST_KEY", "stripe_like_test_key",
               re.compile(r"\b[sr]k_test_[0-9A-Za-z]{10,}\b"), Severity.MEDIUM, 0.8),
    SecretRule("GITHUB_TOKEN", "github_like_token",
               re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL, 0.9),
    SecretRule("OPENAI_KEY", "openai_like_key",
               re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL, 0.8),
    SecretRule("JWT_TOKEN", "jwt",
               re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
               Severity.HIGH, 0.7),
    SecretRule("BEARER_TOKEN", "bearer_token",
               re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"), Severity.HIGH, 0.6, 1),
    SecretRule("API_KEY_ASSIGNMENT", "api_key_assignment",
               _assignment(r"api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token"),
               Severity.HIGH, 0.6, 1, True),
    SecretRule("PASSWORD_ASSIGNMENT", "password_assignment",
               _assignment(r"password|passwd|pwd"), Severity.HIGH, 0.6, 1, True),
    SecretRule("SECRET_ASSIGNMENT", "secret_assignment",
               _assignment(r"secret|client[_-]secret|secret[_-]key"), Severity.HIGH, 0.6, 1, True),
)


def mask_secret(value: str) -> str:
    """Never return the full secret. Only long values reveal their last 3 characters."""
    return "****" if len(value) < 16 else "****" + value[-3:]


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS)


class SecretsScanner(BaseScanner):
    """Looks for credentials in text files. Findings never contain the full secret."""

    name = "secrets"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not is_text_mime(ctx.detected_mime):
            return []
        text = ctx.read_text()

        hits: dict[str, list[tuple[int, str]]] = defaultdict(list)
        claimed: list[tuple[int, int]] = []  # spans already matched by a stronger rule
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                start, end = m.span(rule.group)
                if any(start < e and s < end for s, e in claimed):  # value overlaps a stronger rule
                    continue
                value = m.group(rule.group)
                if rule.skip_placeholders and _is_placeholder(value):
                    continue
                claimed.append((start, end))
                hits[rule.rule].append((line_of(text, m.start()), value))

        findings: list[Finding] = []
        for rule in RULES:
            found = hits.get(rule.rule)
            if not found:
                continue
            lines = sorted({line for line, _ in found})[:MAX_LINES_LISTED]
            masked = "" if rule.rule == "PRIVATE_KEY" else f"; sample={mask_secret(found[0][1])}"
            findings.append(Finding(
                self.name, rule.rule, rule.severity,
                f"Potential secret detected: {rule.label} ({len(found)} occurrence"
                f"{'s' if len(found) != 1 else ''})",
                f"type={rule.label}{masked}; lines={','.join(map(str, lines))}",
                rule.confidence,
            ))
        return findings
