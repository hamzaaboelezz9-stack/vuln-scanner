"""Exercise real DNS answer parsing using in-memory protocol messages."""

from unittest.mock import patch

import dns.exception
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from scanner.safety.policy import ScopeError
from scanner.safety.resolver import DNSResolver


def test_cname_and_address_extraction() -> None:
    """Return alias names as well as addresses, allowing government alias blocks."""
    name = dns.name.from_text("lab.local")
    query = dns.message.make_query(name, "A")
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text("lab.local.", 60, "IN", "CNAME", "service.gov."))
    response.answer.append(dns.rrset.from_text("service.gov.", 60, "IN", "A", "10.0.0.1"))
    response.index = None  # Appended RRsets must be discoverable by resolve_chaining.
    answer = dns.resolver.Answer(name, dns.rdatatype.A, dns.rdataclass.IN, response)
    empty_response = dns.message.make_response(dns.message.make_query(name, "AAAA"))
    empty_answer = dns.resolver.Answer(name, dns.rdatatype.AAAA, dns.rdataclass.IN, empty_response)
    with patch("dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = [answer, empty_answer]
        result = DNSResolver()("lab.local")
    assert result.addresses == ("10.0.0.1",)
    assert "service.gov" in result.aliases


def test_dns_failure_does_not_accept_partial_answer() -> None:
    """An unresolved address family does not silently hide a possible blocked IP."""
    with patch("dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = dns.exception.Timeout()
        with pytest.raises(ScopeError):
            DNSResolver()("lab.local")
