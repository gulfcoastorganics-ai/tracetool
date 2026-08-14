from pathlib import Path

from backend.entropy_assurance.bip39_validation import validate_256_construction, validate_bip39_entropy, validate_mnemonic
from backend.entropy_assurance.models import (
    AssuranceLevel, CheckStatus, GeneratorAuditRequest, RuntimeProbeRequest, SelfAuditRequest, SourceAuditRequest,
)
from backend.entropy_assurance.report import persist_report, sanitize_report
from backend.entropy_assurance.service import assurance_service
from backend.entropy_assurance.source_audit import audit_source


def test_32_secure_bytes_support_256_preserved_bits():
    result = assurance_service.audit_generator(GeneratorAuditRequest(bip39_entropy_hex='00' * 32, source='''def generate():
    try:
        value = secrets.token_bytes(32)
    except Exception:
        raise RuntimeError("CSPRNG unavailable")
    return value
'''))
    assert result.overall_assurance == AssuranceLevel.VERIFIED_CONSTRUCTION
    assert result.maximum_effective_bits == 256
    assert result.discarded_bits == 0
    assert result.bip39.valid is True


def test_16_secure_bytes_maximum_is_128():
    result = audit_source(SourceAuditRequest(source='value = secrets.token_bytes(16)'))
    assert result.maximum_effective_bits == 128
    assert result.assurance == AssuranceLevel.FAILED


def test_4_byte_seed_hashed_to_256_is_at_most_32_bits():
    result = audit_source(SourceAuditRequest(source='seed = random.getrandbits(32)\nvalue = hashlib.sha256(seed.to_bytes(4, "big")).digest()'))
    assert result.maximum_effective_bits == 32
    assert any(item.category == 'DETERMINISTIC_EXPANSION' for item in result.findings)


def test_64_bit_truncation_hashed_to_256_is_at_most_64_bits():
    result = audit_source(SourceAuditRequest(source='value = secrets.token_bytes(32)\nvalue = hashlib.sha256(value[:8]).digest()'))
    assert result.maximum_effective_bits == 64
    assert any(item.category == 'ENTROPY_TRUNCATION' for item in result.findings)


def test_source_api_detection_and_weak_fallback():
    assert audit_source(SourceAuditRequest(source='os.urandom(32)')).source_kind.value == 'OS_CSPRNG'
    assert audit_source(SourceAuditRequest(source='crypto.getRandomValues(new Uint8Array(32))')).source_kind.value == 'WEB_CRYPTO'
    result = assurance_service.audit_generator(GeneratorAuditRequest(source='''try {
  crypto.getRandomValues(buf)
} catch {
  fillUsingMathRandom(buf)
}'''))
    assert result.overall_assurance == AssuranceLevel.FAILED
    assert result.failure_policy.value == 'FAIL_OPEN_WEAK_RANDOMNESS'


def test_fail_closed_path_is_detected():
    result = audit_source(SourceAuditRequest(source='''try:
    value = os.urandom(32)
except Exception as exc:
    raise RuntimeError("entropy unavailable") from exc
'''))
    assert result.failure_policy.value == 'FAIL_CLOSED'


def test_bip39_256_construction_and_checksum():
    result = validate_256_construction('00' * 32)
    assert result.valid is True
    assert result.entropy_bits == 256
    assert result.checksum_bits == 8
    assert result.mnemonic_words == 24
    vector = validate_mnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
    assert vector.valid is True
    assert vector.entropy_bits == 128
    assert vector.checksum_bits == 4


def test_runtime_probe_is_bounded_and_not_a_entropy_proof():
    result = assurance_service.runtime_probe(RuntimeProbeRequest())
    assert result.status == CheckStatus.PASS
    assert result.bytes_returned == 32
    assert 'does not prove' in ' '.join(result.notes)


def test_self_audit_and_secret_free_report_persistence(tmp_path: Path):
    report = assurance_service.self_audit(SelfAuditRequest())
    assert report.overall_assurance == AssuranceLevel.VERIFIED_CONSTRUCTION
    sanitized = sanitize_report(report)
    serialized = str(sanitized).lower()
    assert 'entropy_hex' not in serialized
    assert 'mnemonic' not in serialized or sanitized.get('bip39', {}).get('mnemonic_words') is not None
    path = persist_report(report, tmp_path)
    contents = path.read_text()
    assert 'entropy_hex' not in contents
    assert 'private_key' not in contents
    assert '00' * 32 not in contents


def test_comparison_proves_output_width_is_not_entropy():
    expanded = assurance_service.compare(type('Request', (), {'mode': 'expanded'})())
    truncated = assurance_service.compare(type('Request', (), {'mode': 'truncated'})())
    assert expanded['final_output_bits'] == 256
    assert expanded['maximum_effective_bits'] == 32
    assert truncated['final_output_bits'] == 256
    assert truncated['maximum_effective_bits'] == 64
