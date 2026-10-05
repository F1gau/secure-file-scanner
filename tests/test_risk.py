import pytest

from app.db.models import RiskLevel, Severity
from app.scanners.base import Finding
from app.services import risk_service as rs


def f(severity=Severity.HIGH, confidence=1.0, rule="R1", scanner="s"):
    return Finding(scanner, rule, severity, "d", None, confidence)


def test_severity_weights_match_spec():
    assert rs.SEVERITY_WEIGHTS == {
        Severity.LOW: 10, Severity.MEDIUM: 30, Severity.HIGH: 60, Severity.CRITICAL: 90,
    }


def test_no_findings_is_zero_low():
    a = rs.assess([])
    assert (a.score, a.level) == (0, RiskLevel.LOW)


@pytest.mark.parametrize("score,level", [
    (0, RiskLevel.LOW), (19, RiskLevel.LOW), (20, RiskLevel.MEDIUM), (49, RiskLevel.MEDIUM),
    (50, RiskLevel.HIGH), (79, RiskLevel.HIGH), (80, RiskLevel.CRITICAL), (100, RiskLevel.CRITICAL),
])
def test_level_boundaries(score, level):
    assert rs.level_for(score) == level


def test_finding_score_is_weight_times_confidence():
    assert rs.finding_score(f(Severity.HIGH, 0.5)) == pytest.approx(30)
    assert rs.finding_score(f(Severity.CRITICAL, 1.0)) == pytest.approx(90)


def test_confidence_changes_the_result():
    assert rs.aggregate_score([f(Severity.HIGH, 1.0)]) > rs.aggregate_score([f(Severity.HIGH, 0.4)])


def test_single_critical_finding_reaches_critical_level():
    assert rs.assess([f(Severity.CRITICAL, 0.95)]).level == RiskLevel.CRITICAL


def test_single_low_finding_stays_low():
    assert rs.assess([f(Severity.LOW, 0.7)]).level == RiskLevel.LOW


def test_not_simply_count_times_ten():
    ten_low = [f(Severity.LOW, 1.0, rule=f"R{i}") for i in range(10)]
    one_critical = [f(Severity.CRITICAL, 1.0)]
    assert rs.aggregate_score(ten_low) != 100
    assert rs.aggregate_score(one_critical) >= 80


def test_different_rules_add_up_but_never_exceed_100():
    many = [f(Severity.CRITICAL, 1.0, rule=f"R{i}") for i in range(50)]
    assert rs.aggregate_score(many) == 100


def test_score_is_monotonic_when_adding_findings():
    base = [f(Severity.MEDIUM, 0.8, "A")]
    assert rs.aggregate_score(base + [f(Severity.LOW, 0.5, "B")]) >= rs.aggregate_score(base)


def test_repeated_same_rule_has_diminishing_effect():
    one = rs.aggregate_score([f(Severity.MEDIUM, 1.0, "SAME")])
    five = rs.aggregate_score([f(Severity.MEDIUM, 1.0, "SAME") for _ in range(5)])
    five_different = rs.aggregate_score([f(Severity.MEDIUM, 1.0, f"R{i}") for i in range(5)])
    assert one < five < five_different


def test_order_of_findings_does_not_matter():
    items = [f(Severity.HIGH, 0.9, "A"), f(Severity.LOW, 0.5, "B"), f(Severity.MEDIUM, 0.7, "C")]
    assert rs.aggregate_score(items) == rs.aggregate_score(list(reversed(items)))


def test_rule_factor_lowers_weak_indicators():
    weak = rs.finding_score(f(Severity.MEDIUM, 1.0, "SUSPICIOUS_NAME"))
    normal = rs.finding_score(f(Severity.MEDIUM, 1.0, "OTHER"))
    assert weak < normal


def test_pii_rules_get_pii_factor():
    assert rs.rule_factor("PII_EMAIL") == rs.PII_FACTOR < 1.0
    assert rs.rule_factor("UNKNOWN_RULE") == 1.0


def test_realistic_double_extension_exe_is_critical():
    findings = [
        f(Severity.HIGH, 0.9, "DANGEROUS_EXTENSION"),
        f(Severity.HIGH, 0.95, "DOUBLE_EXTENSION"),
        f(Severity.HIGH, 0.95, "TYPE_MISMATCH"),
    ]
    assert rs.assess(findings).level == RiskLevel.CRITICAL


def test_email_only_text_is_low():
    assert rs.assess([f(Severity.LOW, 0.7, "PII_EMAIL")]).level == RiskLevel.LOW


def test_score_is_int_within_range():
    score = rs.aggregate_score([f(Severity.CRITICAL, 1.0, f"R{i}") for i in range(3)])
    assert isinstance(score, int) and 0 <= score <= 100
