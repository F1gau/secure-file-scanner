import pytest

from app.db.models import Severity
from app.scanners import FilenameScanner
from app.scanners.archive import ArchiveScanner
from app.scanners.base import Finding
from app.scanners.file_type import FileTypeScanner
from app.scanners.pii import PiiScanner, luhn_valid, valid_inn, valid_snils
from app.scanners.secrets import SecretsScanner, mask_secret
from tests import helpers as h
from tests.helpers import by_rule, make_ctx, rules

# ======================= filename scanner =======================

def scan_name(tmp_path, name, declared=None, content=b"x"):
    return FilenameScanner().scan(make_ctx(tmp_path, name, content, declared, detected="text/plain"))


@pytest.mark.parametrize("name", ["a.exe", "a.dll", "a.bat", "a.cmd", "a.ps1", "a.vbs", "a.js",
                                  "a.scr", "a.msi", "A.EXE"])
def test_dangerous_extensions_detected(tmp_path, name):
    assert "DANGEROUS_EXTENSION" in rules(scan_name(tmp_path, name))


def test_executable_extension_is_high_script_is_medium(tmp_path):
    assert by_rule(scan_name(tmp_path, "tool.exe"), "DANGEROUS_EXTENSION").severity == Severity.HIGH
    assert by_rule(scan_name(tmp_path, "tool.js"), "DANGEROUS_EXTENSION").severity == Severity.MEDIUM


@pytest.mark.parametrize("name", ["report.pdf", "notes.txt", "photo.jpg", "data.csv", "archive.zip"])
def test_harmless_names_have_no_findings(tmp_path, name):
    assert scan_name(tmp_path, name) == []


@pytest.mark.parametrize("name", ["document.pdf.exe", "invoice.docx.exe", "photo.jpg.exe",
                                  "report.pdf.scr", "sheet.xlsx.bat", "doc.txt.js"])
def test_double_extension_detected_as_high(tmp_path, name):
    f = by_rule(scan_name(tmp_path, name), "DOUBLE_EXTENSION")
    assert f.severity == Severity.HIGH


def test_double_extension_not_flagged_for_normal_archives(tmp_path):
    assert "DOUBLE_EXTENSION" not in rules(scan_name(tmp_path, "backup.tar.gz"))
    assert "DOUBLE_EXTENSION" not in rules(scan_name(tmp_path, "report.final.pdf"))


def test_exe_after_unknown_extension_is_not_double_extension(tmp_path):
    assert "DOUBLE_EXTENSION" not in rules(scan_name(tmp_path, "setup.v2.exe"))


@pytest.mark.parametrize("name", ["invoice.exe", "update.exe", "payment.exe", "document.exe"])
def test_suspicious_names_are_a_separate_indicator(tmp_path, name):
    found = scan_name(tmp_path, name)
    assert {"DANGEROUS_EXTENSION", "SUSPICIOUS_NAME"} <= rules(found)


def test_suspicious_name_ignored_for_harmless_extension(tmp_path):
    assert scan_name(tmp_path, "invoice.pdf") == []


def test_right_to_left_override_flagged_and_made_visible(tmp_path):
    name = "photo‮gpj.exe"
    findings = scan_name(tmp_path, name)
    hidden = by_rule(findings, "HIDDEN_EXTENSION")
    assert hidden.severity == Severity.HIGH
    assert "‮" not in hidden.evidence and "\\u202e" in hidden.evidence


def test_many_spaces_before_extension_flagged(tmp_path):
    assert "HIDDEN_EXTENSION" in rules(scan_name(tmp_path, "report.pdf" + " " * 40 + ".exe"))


def test_declared_mime_mismatch_is_low(tmp_path):
    f = by_rule(scan_name(tmp_path, "pic.jpg", declared="application/pdf"), "DECLARED_MIME_MISMATCH")
    assert f.severity == Severity.LOW


def test_declared_mime_match_and_octet_stream_ok(tmp_path):
    assert scan_name(tmp_path, "pic.jpg", declared="image/jpeg") == []
    assert scan_name(tmp_path, "pic.jpg", declared="application/octet-stream") == []
    assert scan_name(tmp_path, "a.txt", declared="text/plain; charset=utf-8") == []


def test_finding_confidence_validated():
    with pytest.raises(ValueError):
        Finding("s", "R", Severity.LOW, "d", confidence=1.5)


# ======================= file type scanner =======================

def scan_type(tmp_path, name, content):
    return FileTypeScanner().scan(make_ctx(tmp_path, name, content))


def test_exe_disguised_as_jpg_is_high_type_mismatch(tmp_path):
    f = by_rule(scan_type(tmp_path, "image.jpg", h.PE_BYTES), "TYPE_MISMATCH")
    assert f.severity == Severity.HIGH


def test_elf_disguised_as_pdf(tmp_path):
    assert by_rule(scan_type(tmp_path, "doc.pdf", h.ELF_BYTES), "TYPE_MISMATCH").severity == Severity.HIGH


def test_real_exe_with_exe_extension_is_not_a_mismatch(tmp_path):
    assert scan_type(tmp_path, "tool.exe", h.PE_BYTES) == []


def test_png_named_jpg_is_medium_mismatch(tmp_path):
    f = by_rule(scan_type(tmp_path, "pic.jpg", h.PNG_BYTES), "TYPE_MISMATCH")
    assert f.severity == Severity.MEDIUM


@pytest.mark.parametrize("name,content", [
    ("pic.jpg", h.JPEG_BYTES), ("pic.png", h.PNG_BYTES), ("doc.pdf", h.PDF_BYTES),
    ("notes.txt", b"plain text\n"), ("data.json", b'{"a": 1}'), ("a.zip", h.make_zip({"a.txt": b"x"})),
    ("noext", b"anything"), ("weird.xyz", h.PNG_BYTES),
])
def test_matching_or_unknown_types_have_no_findings(tmp_path, name, content):
    assert scan_type(tmp_path, name, content) == []


def test_executable_without_extension_is_flagged(tmp_path):
    assert "TYPE_MISMATCH" in rules(scan_type(tmp_path, "download", h.PE_BYTES))


def test_docx_detected_from_zip_structure(tmp_path):
    docx = h.make_zip({"[Content_Types].xml": b"<x/>", "word/document.xml": b"<w/>"})
    assert scan_type(tmp_path, "report.docx", docx) == []
    assert "TYPE_MISMATCH" in rules(scan_type(tmp_path, "report.pdf", docx))


# ======================= secrets scanner =======================

def scan_secrets(tmp_path, text, name="config.txt"):
    return SecretsScanner().scan(make_ctx(tmp_path, name, text.encode()))


@pytest.mark.parametrize("secret,rule", [
    (h.FAKE_STRIPE_LIVE, "STRIPE_LIVE_KEY"),
    (h.FAKE_STRIPE_TEST, "STRIPE_TEST_KEY"),
    (h.FAKE_AWS_KEY, "AWS_ACCESS_KEY"),
    (h.FAKE_GITHUB_TOKEN, "GITHUB_TOKEN"),
    (h.FAKE_OPENAI_KEY, "OPENAI_KEY"),
    (h.FAKE_JWT, "JWT_TOKEN"),
    (h.PRIVATE_KEY_MARKER, "PRIVATE_KEY"),
])
def test_secret_types_detected(tmp_path, secret, rule):
    assert rule in rules(scan_secrets(tmp_path, f"value: {secret}\n"))


def test_bearer_token_detected(tmp_path):
    assert "BEARER_TOKEN" in rules(scan_secrets(tmp_path, "Authorization: Bearer FAKETOKENVALUE1234567890\n"))


@pytest.mark.parametrize("line,rule", [
    ('password = "FAKE_PASSWORD_VALUE"', "PASSWORD_ASSIGNMENT"),
    ("DB_PASSWD: FakeSecretPass99", "PASSWORD_ASSIGNMENT"),
    ('api_key = "TEST_API_KEY_123456"', "API_KEY_ASSIGNMENT"),
    ("SECRET_KEY=FAKE_SECRET_VALUE_9", "SECRET_ASSIGNMENT"),
])
def test_assignments_detected(tmp_path, line, rule):
    assert rule in rules(scan_secrets(tmp_path, line + "\n"))


@pytest.mark.parametrize("line", [
    "password = changeme", 'api_key = "<your-api-key-here>"', "secret = ${SECRET_FROM_ENV}",
    "password = os.environ['PASSWORD_X']", "token = example_token_value", "password=short",
])
def test_placeholders_and_short_values_ignored(tmp_path, line):
    assert scan_secrets(tmp_path, line + "\n") == []


def test_evidence_never_contains_full_secret(tmp_path):
    text = (f"key={h.FAKE_STRIPE_LIVE}\naws={h.FAKE_AWS_KEY}\ntoken={h.FAKE_GITHUB_TOKEN}\n"
            f"jwt={h.FAKE_JWT}\npassword = \"FAKE_PASSWORD_VALUE\"\n")
    for f in scan_secrets(tmp_path, text):
        blob = f"{f.description} {f.evidence}"
        for secret in (h.FAKE_STRIPE_LIVE, h.FAKE_AWS_KEY, h.FAKE_GITHUB_TOKEN, h.FAKE_JWT,
                       "FAKE_PASSWORD_VALUE"):
            assert secret not in blob


def test_evidence_masks_to_at_most_last_three_chars():
    assert mask_secret("short") == "****"
    masked = mask_secret(h.FAKE_STRIPE_LIVE)
    assert masked == "****" + h.FAKE_STRIPE_LIVE[-3:]


def test_private_key_evidence_has_no_value_sample(tmp_path):
    f = by_rule(scan_secrets(tmp_path, h.PRIVATE_KEY_MARKER + "\nFAKEBODY\n"), "PRIVATE_KEY")
    assert "sample=" not in f.evidence
    assert "FAKEBODY" not in f.evidence


def test_occurrences_grouped_with_line_numbers(tmp_path):
    text = f"a\n{h.FAKE_AWS_KEY}\nb\n{h.FAKE_AWS_KEY}\n"
    f = by_rule(scan_secrets(tmp_path, text), "AWS_ACCESS_KEY")
    assert "2 occurrences" in f.description and "lines=2,4" in f.evidence


def test_stripe_key_not_also_reported_as_generic_assignment(tmp_path):
    found = scan_secrets(tmp_path, f"api_key = {h.FAKE_STRIPE_LIVE}\n")
    assert rules(found) == {"STRIPE_LIVE_KEY"}


def test_secrets_scanner_skips_binary_files(tmp_path):
    ctx = make_ctx(tmp_path, "x.png", h.PNG_BYTES + h.FAKE_AWS_KEY.encode())
    assert SecretsScanner().scan(ctx) == []


def test_clean_text_has_no_secrets(tmp_path):
    assert scan_secrets(tmp_path, "Just a normal file.\nNothing to see here: 12345\n") == []


# ======================= PII scanner =======================

def scan_pii(tmp_path, text, name="data.txt"):
    return PiiScanner().scan(make_ctx(tmp_path, name, text.encode()))


def test_email_detected_and_masked(tmp_path):
    f = by_rule(scan_pii(tmp_path, "contact: ivan.petrov@example.org\n"), "PII_EMAIL")
    assert "Potential PII detected" in f.description
    assert "ivan.petrov" not in f.evidence and "i***@example.org" in f.evidence


@pytest.mark.parametrize("phone", ["+7 912 345 67 89", "8 (912) 345-67-89", "+79123456789"])
def test_russian_phone_detected(tmp_path, phone):
    assert "PII_PHONE" in rules(scan_pii(tmp_path, f"tel {phone}\n"))


def test_phone_masked(tmp_path):
    f = by_rule(scan_pii(tmp_path, "+79123456789"), "PII_PHONE")
    assert "79123456789" not in f.evidence and f.evidence.count("****89") == 1


def test_inn_checksum_validation():
    assert valid_inn("7707083893")          # 10-digit legal entity (valid checksum)
    assert valid_inn("500100732259")        # 12-digit individual (valid checksum)
    assert not valid_inn("7707083894")
    assert not valid_inn("123")


def test_inn_detected_only_with_valid_checksum(tmp_path):
    assert "PII_INN" in rules(scan_pii(tmp_path, "ИНН: 7707083893"))
    assert "PII_INN" not in rules(scan_pii(tmp_path, "ИНН: 7707083894"))
    assert "PII_INN" not in rules(scan_pii(tmp_path, "number 7707083893"))  # no keyword


def test_snils_checksum_validation():
    assert valid_snils("112-233-445 95")
    assert not valid_snils("112-233-445 96")


def test_snils_detected(tmp_path):
    assert "PII_SNILS" in rules(scan_pii(tmp_path, "СНИЛС 112-233-445 95"))
    assert "PII_SNILS" not in rules(scan_pii(tmp_path, "СНИЛС 112-233-445 96"))


def test_passport_needs_keyword(tmp_path):
    assert "PII_PASSPORT" in rules(scan_pii(tmp_path, "паспорт 45 12 345678"))
    assert "PII_PASSPORT" not in rules(scan_pii(tmp_path, "id 45 12 345678"))


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_bank_card_detected_via_luhn_and_masked(tmp_path):
    f = by_rule(scan_pii(tmp_path, "card 4111 1111 1111 1111"), "PII_BANK_CARD")
    assert "4111 1111" not in f.evidence and "****1111" in f.evidence


def test_invalid_card_number_ignored(tmp_path):
    assert "PII_BANK_CARD" not in rules(scan_pii(tmp_path, "card 4111 1111 1111 1112"))


def test_bank_account_needs_keyword(tmp_path):
    assert "PII_BANK_ACCOUNT" in rules(scan_pii(tmp_path, "р/с 40817810099910004312"))
    assert "PII_BANK_ACCOUNT" not in rules(scan_pii(tmp_path, "40817810099910004312"))


def test_ip_detected_but_loopback_and_invalid_ignored(tmp_path):
    assert "PII_IP_ADDRESS" in rules(scan_pii(tmp_path, "from 203.0.113.42"))
    assert "PII_IP_ADDRESS" not in rules(scan_pii(tmp_path, "127.0.0.1 and 999.1.1.1 and 1.2.3"))


def test_address_detected_without_storing_value(tmp_path):
    f = by_rule(scan_pii(tmp_path, "г. Волгоград, ул. Мира, д. 12"), "PII_ADDRESS")
    assert "Мира" not in f.evidence


def test_pii_scanner_skips_binary_and_clean_text(tmp_path):
    assert PiiScanner().scan(make_ctx(tmp_path, "a.png", h.PNG_BYTES)) == []
    assert scan_pii(tmp_path, "Nothing personal here.\n") == []


def test_pii_findings_never_contain_raw_values(tmp_path):
    text = "a@example.com +79123456789 4111111111111111 203.0.113.42 ИНН 7707083893"
    for f in scan_pii(tmp_path, text):
        blob = f"{f.description} {f.evidence}"
        for raw in ("a@example.com", "79123456789", "4111111111111111", "203.0.113.42", "7707083893"):
            assert raw not in blob


# ======================= archive scanner =======================

def scan_zip(tmp_path, entries, **limits):
    data = h.make_zip(entries) if isinstance(entries, dict) else entries
    return ArchiveScanner().scan(make_ctx(tmp_path, "archive.zip", data, **limits))


def test_clean_zip_has_no_findings(tmp_path):
    assert scan_zip(tmp_path, {"a.txt": b"hello", "docs/b.txt": b"world"}) == []


def test_non_zip_is_skipped(tmp_path):
    assert ArchiveScanner().scan(make_ctx(tmp_path, "a.txt", b"text")) == []


def test_dangerous_entry_detected(tmp_path):
    f = by_rule(scan_zip(tmp_path, {"readme.txt": b"x", "setup.exe": b"MZ"}), "ARCHIVE_DANGEROUS_ENTRY")
    assert f.severity == Severity.HIGH and "setup.exe" in f.evidence


def test_script_entry_is_medium(tmp_path):
    f = by_rule(scan_zip(tmp_path, {"run.js": b"x"}), "ARCHIVE_DANGEROUS_ENTRY")
    assert f.severity == Severity.MEDIUM


def test_too_many_files_flagged(tmp_path):
    entries = {f"f{i}.txt": b"x" for i in range(20)}
    assert "ARCHIVE_TOO_MANY_FILES" in rules(scan_zip(tmp_path, entries, max_archive_files=10))


def test_file_count_at_limit_is_allowed(tmp_path):
    entries = {f"f{i}.txt": b"x" for i in range(10)}
    assert "ARCHIVE_TOO_MANY_FILES" not in rules(scan_zip(tmp_path, entries, max_archive_files=10))


def test_declared_size_over_limit_flagged(tmp_path):
    assert "ARCHIVE_TOO_LARGE" in rules(
        scan_zip(tmp_path, {"big.txt": b"a" * 5000}, max_extracted_size=1000))


def test_zip_bomb_by_compression_ratio(tmp_path):
    bomb = {"zeros.bin": b"\x00" * (3 * 1024 * 1024)}  # ~3 KB compressed -> ratio > 1000
    f = by_rule(scan_zip(tmp_path, bomb), "ZIP_BOMB_SUSPECTED")
    assert f.severity == Severity.CRITICAL


def test_small_highly_compressible_file_is_not_a_bomb(tmp_path):
    assert "ZIP_BOMB_SUSPECTED" not in rules(scan_zip(tmp_path, {"a.txt": b"a" * 100_000}))


def test_nested_depth_exceeded(tmp_path):
    inner = h.make_zip({"x.txt": b"1"})
    mid = h.make_zip({"inner.zip": inner})
    outer = h.make_zip({"mid.zip": mid})
    assert "ARCHIVE_DEPTH_EXCEEDED" in rules(scan_zip(tmp_path, outer, max_archive_depth=1))


def test_nested_within_depth_is_inspected(tmp_path):
    inner = h.make_zip({"evil.exe": b"MZ"})
    outer = h.make_zip({"inner.zip": inner})
    assert "ARCHIVE_DANGEROUS_ENTRY" in rules(scan_zip(tmp_path, outer, max_archive_depth=2))


def test_nested_file_count_is_cumulative(tmp_path):
    inner = h.make_zip({f"n{i}.txt": b"x" for i in range(8)})
    outer = h.make_zip({f"o{i}.txt": b"x" for i in range(5)} | {"inner.zip": inner})
    assert "ARCHIVE_TOO_MANY_FILES" in rules(scan_zip(tmp_path, outer, max_archive_files=10))


def test_zip_slip_paths_flagged(tmp_path):
    assert "ARCHIVE_PATH_TRAVERSAL" in rules(scan_zip(tmp_path, {"../../etc/evil.txt": b"x"}))
    assert "ARCHIVE_PATH_TRAVERSAL" in rules(scan_zip(tmp_path, {"/abs/evil.txt": b"x"}))


def test_corrupt_zip_reported_not_raised(tmp_path):
    data = h.make_zip({"a.txt": b"x" * 100})
    ctx = make_ctx(tmp_path, "a.zip", data[: len(data) // 2], detected="application/zip")
    assert "ARCHIVE_CORRUPT" in rules(ArchiveScanner().scan(ctx))


def test_archive_scanner_never_extracts_to_disk(tmp_path):
    scan_zip(tmp_path, {"evil.exe": b"MZ", "../escape.txt": b"x"})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["sample.bin"]
