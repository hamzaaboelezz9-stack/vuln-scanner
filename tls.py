"""TLS trust/expiry, HTTP enforcement and fixed handshake-only legacy profiles."""

from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

from cryptography import x509

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord
from scanner.core.errors import TLSVerificationError, TransportError
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.session import REDIRECT_STATUSES
from scanner.core.target import ScanMode
from scanner.core.transport import TLSObservation, TLSProbeStatus, TLSProfile
from scanner.safety.policy import ScopeError

TLS_REFERENCE = WSTG_ROOT + "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
DEPRECATED_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1"})
LEGACY_CIPHER_FAMILIES = ("RC4", "3DES", "DES-CBC", "EXP-")
CERTIFICATE_VERIFY_LABELS = {
    9: "certificate not yet valid",
    10: "certificate expired",
    18: "self-signed leaf",
    19: "self-signed chain",
    20: "issuer unavailable",
    21: "unable to verify leaf",
    62: "hostname mismatch",
    64: "IP address mismatch",
}


def weak_cipher(name: str, bits: int) -> bool:
    """Flag unauthenticated, null/export/obsolete or below-128-bit negotiated suites."""
    upper = name.upper()
    return (
        bits < 128
        or any(value in upper for value in ("NULL", "RC4", "3DES", "DES-CBC", "EXP-"))
        or upper.startswith(("ADH-", "AECDH-"))
    )


@register_check(
    CheckInfo(
        "tls",
        ScanMode.WEB,
        "TLS certificate verification/expiry, HTTP upgrade and isolated TLS 1.0/1.1/weak-suite handshakes",
        24,
    )
)
class TLSCheck(WebCheck):
    """Use verified TLS for trust, isolated unverified handshakes only for public diagnostics."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Keep HTTP-enforcement failure from suppressing independent TLS assessment."""
        try:
            self._http_enforcement(context, record)
        except (TransportError, ScopeError):
            record.limit("The approved HTTP counterpart was unavailable; redirect-enforcement coverage is incomplete.")
        _, host, port = next(origin for origin in context.scope.origins if origin[0] == "https")
        endpoint = "https://" + (f"[{host}]" if ":" in host else host) + f":{port}/"
        observation: TLSObservation | None = None
        try:
            observation = context.tcp.inspect_tls(host, port)
        except TLSVerificationError as error:
            if error.verify_code is not None:
                label = CERTIFICATE_VERIFY_LABELS.get(error.verify_code, "certificate verification failure")
                record.findings.append(
                    Finding(
                        "tls.certificate_trust",
                        "TLS certificate verification failed",
                        Severity.MEDIUM,
                        Confidence.CONFIRMED,
                        "OpenSSL rejected the peer under the configured CA/hostname policy. A private deployment may require its intended CA bundle; no HTTP request was made with verification disabled.",
                        Evidence(
                            "TLS",
                            endpoint,
                            ("Verification result: " + label + "; OpenSSL code " + str(error.verify_code) + ".",),
                        ),
                        "Install the correct leaf/intermediate chain and a certificate covering the requested hostname. Renew expired certificates. For a private PKI, configure its trusted CA bundle instead of disabling verification.",
                        (TLS_REFERENCE,),
                    )
                )
            else:
                record.limit("Verified TLS did not negotiate; certificate trust could not be established.")
            metadata = context.tcp.probe_tls(host, port, TLSProfile.CERTIFICATE_METADATA)
            observation = metadata.observation
            if observation is None:
                record.limit("Public TLS certificate metadata was unavailable.")
        if observation and observation.certificate_der:
            self._certificate(observation, endpoint, context, record)
            if weak_cipher(observation.cipher[0], observation.cipher[2]):
                self._weak_cipher(observation, endpoint, record)
        if not context.config.weak_tls_probes:
            record.limit("Legacy TLS protocol/cipher probes were disabled by configuration.")
            return
        for profile in (TLSProfile.TLS10, TLSProfile.TLS11, TLSProfile.WEAK_CIPHERS):
            result = context.tcp.probe_tls(host, port, profile)
            if result.status is TLSProbeStatus.UNAVAILABLE:
                record.limit("At least one requested legacy profile was unavailable in local OpenSSL.")
            if result.observation:
                negotiated = result.observation
                if negotiated.protocol in DEPRECATED_PROTOCOLS:
                    record.findings.append(
                        Finding(
                            "tls.deprecated_protocol",
                            "Deprecated TLS protocol negotiated",
                            Severity.MEDIUM,
                            Confidence.CONFIRMED,
                            "An isolated handshake successfully negotiated the named deprecated protocol. No application data was exchanged. The specific protocol is supported; this is not an exhaustive cipher enumeration.",
                            Evidence(
                                "TLS",
                                endpoint,
                                (
                                    "Negotiated protocol: " + negotiated.protocol,
                                    "Handshake-only diagnostic; certificate validation was not claimed for this probe.",
                                ),
                            ),
                            "Require TLS 1.2 or TLS 1.3 at the server/load balancer. For Nginx, configure ssl_protocols TLSv1.2 TLSv1.3 and test every termination point.",
                            (TLS_REFERENCE,),
                        )
                    )
                if weak_cipher(negotiated.cipher[0], negotiated.cipher[2]):
                    self._weak_cipher(negotiated, endpoint, record)
            if profile is TLSProfile.WEAK_CIPHERS and any(
                not any(family in name.upper() for name in result.offered_cipher_names)
                for family in LEGACY_CIPHER_FAMILIES
            ):
                record.limit(
                    "Locally disabled RC4/DES/3DES/export suites cannot be exhaustively tested; weak-cipher coverage is partial."
                )

    def _http_enforcement(self, context: CheckContext, record: WebRecord) -> None:
        scheme, host, port = next(origin for origin in context.scope.origins if origin[0] == "http")
        authority = (f"[{host}]" if ":" in host else host) + f":{port}"
        parsed = urlsplit(context.target.url)
        url = urlunsplit((scheme, authority, parsed.path, parsed.query, ""))
        response = context.http.request(url, read_body=False)
        locations = response.header_values("location")
        upgraded = False
        if response.status_code in REDIRECT_STATUSES and len(locations) == 1:
            try:
                destination = urlsplit(urljoin(url, locations[0]))
                upgraded = destination.scheme == "https"
            except ValueError:
                pass
        if not upgraded:
            record.add(
                "tls.http_upgrade",
                "HTTP response does not advertise an HTTPS upgrade",
                Severity.LOW,
                "The approved HTTP endpoint responded without a Location redirect to HTTPS. Whether plaintext access is intentional for an isolated lab or exposes sensitive data needs review; no credentials or response body were collected.",
                response,
                (
                    "HTTP response lacked a single HTTPS redirect destination.",
                    "Response body was not read and redirects were not followed.",
                ),
                "On public deployments, redirect HTTP to HTTPS at the reverse proxy and use valid TLS. Add HSTS on the HTTPS origin after verifying coverage. Document any isolated HTTP-only lab exception.",
                (TLS_REFERENCE,),
                Confidence.OBSERVATION,
            )

    def _certificate(
        self, observation: TLSObservation, endpoint: str, context: CheckContext, record: WebRecord
    ) -> None:
        try:
            certificate = x509.load_der_x509_certificate(observation.certificate_der)
        except ValueError:
            record.limit("The peer certificate could not be parsed for dates.")
            return
        now = datetime.now(timezone.utc)
        expiry = certificate.not_valid_after_utc
        not_before = certificate.not_valid_before_utc
        if expiry <= now or not_before > now:
            record.findings.append(
                Finding(
                    "tls.certificate_dates",
                    "TLS certificate is outside its validity period",
                    Severity.MEDIUM,
                    Confidence.CONFIRMED,
                    "The public leaf certificate's validity dates exclude the current UTC time. Certificate metadata may have been collected using an explicitly untrusted diagnostic handshake; no chain validity is implied.",
                    Evidence(
                        "TLS",
                        endpoint,
                        (
                            "Leaf validity dates exclude the current UTC time.",
                            "Metadata trust: "
                            + ("verified" if observation.certificate_verified else "unverified public certificate"),
                        ),
                    ),
                    "Renew/reissue the certificate with correct validity and hostname coverage; verify server/client clocks and deploy the correct full chain.",
                    (TLS_REFERENCE,),
                )
            )
        elif expiry - now <= timedelta(days=context.config.tls_expiry_days):
            record.findings.append(
                Finding(
                    "tls.expiry_soon",
                    "TLS certificate expires within the configured window",
                    Severity.LOW,
                    Confidence.CONFIRMED,
                    "The observed leaf certificate expires soon. This is an operational renewal warning, not evidence of plaintext compromise.",
                    Evidence(
                        "TLS", endpoint, (f"Leaf certificate expires within {context.config.tls_expiry_days} days.",)
                    ),
                    "Enable automated certificate renewal, monitor renewal failures, and verify the served leaf certificate after deployment.",
                    (TLS_REFERENCE,),
                )
            )

    def _weak_cipher(self, observation: TLSObservation, endpoint: str, record: WebRecord) -> None:
        if any(
            item.rule_id == "tls.weak_cipher" and observation.cipher[0] in item.evidence.observations[0]
            for item in record.findings
        ):
            return
        record.findings.append(
            Finding(
                "tls.weak_cipher",
                "Weak or unauthenticated TLS cipher negotiated",
                Severity.MEDIUM,
                Confidence.CONFIRMED,
                "A handshake negotiated a null, anonymous, obsolete/export or below-128-bit suite. No application data was exchanged; attack impact depends on traffic and network access.",
                Evidence(
                    "TLS",
                    endpoint,
                    (
                        "Negotiated cipher: " + observation.cipher[0],
                        "Strength bits reported by OpenSSL: " + str(observation.cipher[2]),
                    ),
                ),
                "Disable anonymous, NULL, EXPORT, DES/3DES and RC4 suites. Prefer an up-to-date TLS 1.2 AEAD policy and TLS 1.3 defaults at every TLS termination point.",
                (TLS_REFERENCE,),
            )
        )
