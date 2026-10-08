"""Real loopback TLS handshakes: trust isolation, legacy support and weak suites."""

import ssl
from pathlib import Path

import pytest

from scanner.checks.web.tls import TLSCheck, weak_cipher
from scanner.core.config import ScanConfig
from scanner.core.errors import TLSVerificationError, TransportError
from scanner.core.transport import TLSProbeStatus, TLSProfile, diagnostic_tls_context, verified_tls_context
from scanner.safety.policy import ScopeError
from scanner.safety.state import AuthorizationStore
from tests.lab import LAB_HOST
from tests.web_lab import Reply, serve_web_lab
from tests.web_support import web_context


def test_trusted_metadata_preserves_sni_and_never_sends_http(state: AuthorizationStore, tmp_path: Path) -> None:
    """An approved CA and original hostname authenticate the pinned numeric peer."""
    with serve_web_lab(tmp_path) as lab:
        context = web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle))
        observation = context.tcp.inspect_tls(LAB_HOST, lab.port)
        assert observation.certificate_verified and observation.certificate_der
        assert observation.protocol in {"TLSv1.2", "TLSv1.3"}
        assert lab.sni == [LAB_HOST]
        assert not lab.requests


def test_untrusted_metadata_probe_never_weakens_http(state: AuthorizationStore, tmp_path: Path) -> None:
    """Public certificate collection is isolated from all subsequent HTTP validation."""
    with serve_web_lab(tmp_path) as lab:
        lab.routes["/"] = Reply()
        context = web_context(state, lab.url)
        with pytest.raises(TLSVerificationError):
            context.tcp.inspect_tls(LAB_HOST, lab.port)
        result = context.tcp.probe_tls(LAB_HOST, lab.port, TLSProfile.CERTIFICATE_METADATA)
        assert result.status is TLSProbeStatus.NEGOTIATED
        assert result.observation and not result.observation.certificate_verified
        with pytest.raises(TransportError):
            context.http.request(lab.url)
        assert not lab.requests
        assert context.tcp.tls_context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("expired,not_yet", [(True, False), (False, True)])
def test_invalid_dates_report_trust_and_public_metadata(
    state: AuthorizationStore, tmp_path: Path, expired: bool, not_yet: bool
) -> None:
    """Both invalid validity intervals survive the failed verified handshake."""
    with serve_web_lab(tmp_path, expired=expired, not_yet=not_yet) as lab:
        context = web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle, weak_tls_probes=False))
        report = TLSCheck().run(context)
        assert {item.rule_id for item in report.findings} == {"tls.certificate_trust", "tls.certificate_dates"}
        assert not lab.requests
        assert "unverified public certificate" in str(report.findings[1].evidence.observations)


def test_valid_leaf_renewal_window_is_configurable(state: AuthorizationStore, tmp_path: Path) -> None:
    """A 90-day fixture is healthy at 30 days and requires renewal monitoring at 100."""
    with serve_web_lab(tmp_path) as lab:
        for window, expected in [(30, set()), (100, {"tls.expiry_soon"})]:
            config = ScanConfig(ca_bundle=lab.ca_bundle, weak_tls_probes=False, tls_expiry_days=window)
            report = TLSCheck().run(web_context(state, lab.url, config))
            assert {item.rule_id for item in report.findings} == expected
            assert report.status.value == "inconclusive"  # Same-port HTTP counterpart and disabled probes.


@pytest.mark.parametrize(
    "version,profile", [(ssl.TLSVersion.TLSv1, TLSProfile.TLS10), (ssl.TLSVersion.TLSv1_1, TLSProfile.TLS11)]
)
def test_deprecated_protocol_detected_without_application_data(
    state: AuthorizationStore, tmp_path: Path, version: ssl.TLSVersion, profile: TLSProfile
) -> None:
    """Successful legacy negotiation is positive evidence, not cipher-name guessing."""
    with serve_web_lab(tmp_path, tls_version=version, cipher_policy="DEFAULT:@SECLEVEL=0") as lab:
        context = web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle))
        result = context.tcp.probe_tls(LAB_HOST, lab.port, profile)
        if result.status is TLSProbeStatus.UNAVAILABLE:
            pytest.skip("Local OpenSSL disables this legacy profile.")
        assert result.status is TLSProbeStatus.NEGOTIATED
        assert result.observation and result.observation.protocol in {"TLSv1", "TLSv1.1"}
        with pytest.raises(TLSVerificationError):
            context.tcp.inspect_tls(LAB_HOST, lab.port)
        report = TLSCheck().run(web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle)))
        assert "tls.deprecated_protocol" in {item.rule_id for item in report.findings}
        assert not lab.requests


def test_null_cipher_detected_without_sending_application_data(state: AuthorizationStore, tmp_path: Path) -> None:
    """A TLS 1.2 NULL suite must actually negotiate before producing a finding."""
    cipher_policy = "ECDHE-RSA-NULL-SHA:@SECLEVEL=0"
    try:
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.set_ciphers(cipher_policy)
    except ssl.SSLError:
        pytest.skip("Local OpenSSL does not offer the synthetic NULL suite.")
    with serve_web_lab(tmp_path, tls_version=ssl.TLSVersion.TLSv1_2, cipher_policy=cipher_policy) as lab:
        context = web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle))
        result = context.tcp.probe_tls(LAB_HOST, lab.port, TLSProfile.WEAK_CIPHERS)
        assert result.status is TLSProbeStatus.NEGOTIATED
        assert result.observation and weak_cipher(result.observation.cipher[0], result.observation.cipher[2])
        report = TLSCheck().run(web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle)))
        assert "tls.weak_cipher" in {item.rule_id for item in report.findings}
        assert not lab.requests


def test_diagnostic_contexts_ignore_keylog_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No profile inherits environment-controlled TLS session-key logging."""
    destination = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(destination))
    for profile in TLSProfile:
        context = diagnostic_tls_context(profile)
        assert context.keylog_filename is None
        assert context.verify_mode == ssl.CERT_NONE
    assert verified_tls_context().verify_mode == ssl.CERT_REQUIRED
    assert not destination.exists()


def test_tls_probe_scope_refusal_precedes_operation(state: AuthorizationStore) -> None:
    """A diagnostic profile cannot bypass hostname or port permission checks."""
    context = web_context(state, "http://fixture.local:7777")
    with pytest.raises(ScopeError):
        context.tcp.probe_tls("169.254.169.254", 443, TLSProfile.CERTIFICATE_METADATA)
    assert sum(context.budget.control.counts().values()) == 0


@pytest.mark.parametrize(
    "cipher,bits,expected",
    [
        ("TLS_AES_256_GCM_SHA384", 256, False),
        ("ECDHE-RSA-AES128-GCM-SHA256", 128, False),
        ("ADH-AES256-SHA", 256, True),
        ("ECDHE-RSA-NULL-SHA", 0, True),
        ("DES-CBC3-SHA", 168, True),
        ("RC4-SHA", 128, True),
    ],
)
def test_negotiated_cipher_classifier(cipher: str, bits: int, expected: bool) -> None:
    """Authentication and obsolete cipher families matter independently of bit count."""
    assert weak_cipher(cipher, bits) is expected
