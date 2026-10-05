import ipaddress
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from app.db.models import Severity
from app.scanners.base import BaseScanner, Finding, ScanContext, line_of
from app.utils.filetype import is_text_mime

MAX_LINES_LISTED = 5


# ---- checksum validators (reduce false positives) ----

def valid_inn(value: str) -> bool:
    d = [int(c) for c in value]
    if len(d) == 10:
        coef = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        return d[9] == sum(c * x for c, x in zip(coef, d, strict=False)) % 11 % 10
    if len(d) == 12:
        c1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        c2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        n1 = sum(c * x for c, x in zip(c1, d, strict=False)) % 11 % 10
        n2 = sum(c * x for c, x in zip(c2, d, strict=False)) % 11 % 10
        return d[10] == n1 and d[11] == n2
    return False


def valid_snils(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        return False
    total = sum(int(ch) * (9 - i) for i, ch in enumerate(digits[:9]))
    control = int(digits[9:])
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
        expected = 0 if expected == 100 else expected
    return control == expected


def luhn_valid(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|35|6011|62)")


def valid_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return (
        13 <= len(digits) <= 19
        and len(set(digits)) > 1
        and bool(_CARD_PREFIX.match(digits))
        and luhn_valid(digits)
    )


def _valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


# ---- masking: evidence must never contain full values ----

def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return f"{local[:1]}***@{domain}"


def _mask_tail(n: int) -> Callable[[str], str]:
    def mask(v: str) -> str:
        digits = re.sub(r"\D", "", v)
        return "****" + digits[-n:]
    return mask


def _mask_ip(v: str) -> str:
    return v.rsplit(".", 1)[0] + ".***"


def _no_value(_: str) -> str:
    return "(value not stored)"


@dataclass(frozen=True)
class PiiRule:
    rule: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    mask: Callable[[str], str]
    group: int = 0
    validator: Callable[[str], bool] | None = None


RULES: tuple[PiiRule, ...] = (
    PiiRule("PII_EMAIL", "email address", re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        Severity.LOW, 0.7, _mask_email),
    PiiRule("PII_PHONE", "phone number", re.compile(
        r"(?<!\d)(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)"),
        Severity.LOW, 0.6, _mask_tail(2)),
    PiiRule("PII_INN", "Russian INN", re.compile(
        r"(?i)(?:ИНН|INN)\D{0,10}(\d{12}|\d{10})(?!\d)"),
        Severity.HIGH, 0.8, _mask_tail(2), 1, valid_inn),
    PiiRule("PII_SNILS", "Russian SNILS", re.compile(
        r"(?<!\d)\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)"),
        Severity.HIGH, 0.8, _mask_tail(2), 0, valid_snils),
    PiiRule("PII_PASSPORT", "passport-like number", re.compile(
        r"(?i)(?:паспорт|passport)\D{0,15}(\d{2}\s?\d{2}\s?\d{6})(?!\d)"),
        Severity.HIGH, 0.6, _mask_tail(2), 1),
    PiiRule("PII_BANK_CARD", "bank card number", re.compile(
        r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        Severity.HIGH, 0.85, _mask_tail(4), 0, valid_card),
    PiiRule("PII_BANK_ACCOUNT", "bank account number", re.compile(
        r"(?i)(?:счет|счёт|р/с|account|acc\.?)\D{0,15}(\d{20})(?!\d)"),
        Severity.MEDIUM, 0.5, _mask_tail(2), 1),
    PiiRule("PII_IP_ADDRESS", "IP address", re.compile(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        Severity.LOW, 0.4, _mask_ip, 0, _valid_ipv4),
    PiiRule("PII_ADDRESS", "postal address", re.compile(
        r"(?i)(?:\b(?:ул\.|улица|пр-т|проспект|пер\.|переулок)\s+[А-ЯЁа-яё .-]{2,40},?\s*"
        r"(?:д\.|дом)?\s*\d+|\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln)\b)"),
        Severity.LOW, 0.4, _no_value),
)


class PiiScanner(BaseScanner):
    """Flags *potential* personal data in text files. Values are masked, never stored."""

    name = "pii"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not is_text_mime(ctx.detected_mime):
            return []
        text = ctx.read_text()

        hits: dict[str, list[tuple[int, str]]] = defaultdict(list)
        claimed: list[tuple[int, int]] = []
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                start, end = m.span(rule.group)
                if any(start < e and s < end for s, e in claimed):  # value overlaps a stronger rule
                    continue
                value = m.group(rule.group)
                if rule.validator and not rule.validator(value):
                    continue
                claimed.append((start, end))
                hits[rule.rule].append((line_of(text, m.start()), value))

        findings: list[Finding] = []
        for rule in RULES:
            found = hits.get(rule.rule)
            if not found:
                continue
            lines = sorted({line for line, _ in found})[:MAX_LINES_LISTED]
            findings.append(Finding(
                self.name, rule.rule, rule.severity,
                f"Potential PII detected: {rule.label} ({len(found)} occurrence"
                f"{'s' if len(found) != 1 else ''})",
                f"type={rule.rule.lower()}; sample={rule.mask(found[0][1])}; "
                f"lines={','.join(map(str, lines))}",
                rule.confidence,
            ))
        return findings
