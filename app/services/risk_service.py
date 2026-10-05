"""Risk engine.

finding_score = severity_weight * confidence * rule_factor        (0..90)

Scores are combined per rule first (repeated hits of the same rule add less and
less), then across rules as independent evidence:

    total = 100 * (1 - prod(1 - score_i / 100))

so one strong indicator is not diluted, several weak indicators add up, and the
result can never exceed 100. This is deliberately not `len(findings) * 10`.
"""
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from app.db.models import RiskLevel, Severity
from app.scanners.base import Finding

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}

# Rule-type factors: how much a *kind* of indicator is trusted. Default is 1.0.
RULE_FACTORS: dict[str, float] = {
    "SUSPICIOUS_NAME": 0.7,         # weak, social-engineering style hint only
    "DECLARED_MIME_MISMATCH": 0.6,  # client-controlled header, easily wrong
    "ARCHIVE_NESTED_NOT_INSPECTED": 0.6,
}
PII_FACTOR = 0.8  # "potential PII": real impact but frequent false positives

# Same rule repeated: first hit counts fully, then 50%, then 25%, the rest is ignored.
REPEAT_DECAY = (1.0, 0.5, 0.25)

LEVEL_BANDS = ((80, RiskLevel.CRITICAL), (50, RiskLevel.HIGH), (20, RiskLevel.MEDIUM))


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: RiskLevel


def rule_factor(rule: str) -> float:
    if rule.startswith("PII_"):
        return PII_FACTOR
    return RULE_FACTORS.get(rule, 1.0)


def finding_score(finding: Finding) -> float:
    return SEVERITY_WEIGHTS[finding.severity] * finding.confidence * rule_factor(finding.rule)


def level_for(score: int) -> RiskLevel:
    for threshold, level in LEVEL_BANDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def aggregate_score(findings: Iterable[Finding]) -> int:
    by_rule: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule].append(finding_score(f))

    remaining = 1.0
    for scores in by_rule.values():
        for rank, score in enumerate(sorted(scores, reverse=True)[: len(REPEAT_DECAY)]):
            effective = min(score * REPEAT_DECAY[rank], 100.0)
            remaining *= 1.0 - effective / 100.0
    return max(0, min(100, int(100.0 * (1.0 - remaining) + 0.5)))


def assess(findings: Iterable[Finding]) -> RiskAssessment:
    score = aggregate_score(list(findings))
    return RiskAssessment(score=score, level=level_for(score))
