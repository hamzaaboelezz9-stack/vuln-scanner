# Source and attribution notes

The project's authored code is MIT licensed. Published provider ranges are
third-party factual data and remain subject to their publishers' terms.
Dependencies carry their own licenses.

The range snapshot records URLs, source-byte SHA-256 hashes, publication freshness
anchors and the capture time. A hash identifies bytes; it is not a publisher
signature. Normalization collapses overlapping CIDRs without extending their union.

Primary implementation references:

- [Python ipaddress documentation](https://docs.python.org/3.10/library/ipaddress.html)
- [Python URL parsing documentation](https://docs.python.org/3.10/library/urllib.parse.html)
- [dnspython resolver documentation](https://dnspython.readthedocs.io/en/stable/resolver-class.html)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- [AWS IP range documentation](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- [AWS publication timestamp format](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html)
- [Azure service-tag feed documentation](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview)
- [Microsoft Azure Public Cloud feed](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
- [Google IP feed documentation](https://docs.cloud.google.com/vpc/docs/configure-private-google-access)
- [AWS IPv6 metadata endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Google IPv6 metadata endpoint](https://docs.cloud.google.com/compute/docs/metadata/querying-metadata)
- [Requests transport adapter interface and source](https://requests.readthedocs.io/en/latest/_modules/requests/adapters/)
- [urllib3 connections](https://urllib3.readthedocs.io/en/stable/reference/urllib3.connection.html)
- [urllib3 streaming and Host/SNI guidance](https://urllib3.readthedocs.io/en/stable/advanced-usage.html)
- [Python TLS contexts and socket timeouts](https://docs.python.org/3.10/library/ssl.html)
- [Python HTTP header parsing](https://docs.python.org/3.10/library/http.client.html)
- [PyYAML safe loader documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [cryptography X.509 test-fixture API](https://cryptography.io/en/latest/x509/reference/)

Runtime dependencies are dnspython, requests, urllib3, PyYAML and cryptography.
Cryptography parses public X.509 validity dates and creates ephemeral test
certificates. OpenSSL implements TLS; no custom cryptographic protocol is used.

Web-check references also include:

- [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
- [MDN Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)
- [MDN CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)


- [RFC 6797 HSTS processing](https://www.rfc-editor.org/rfc/rfc6797.html)

Network additions use independently authored passive signatures and curated
coverage lists, referenced to the IANA registry. No Nmap source/data is redistributed.
An operator may optionally supply their installed nmap-services-style frequency
file. NVD public catalog identifiers/vectors retain their source attribution;
cache metadata is not an authenticated installed-software inventory.

- [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/)
- [Nmap scan-state overview](https://nmap.org/book/port-scanning.html)
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD API practices](https://nvd.nist.gov/developers/start-here)
- [NVD OpenSSH portable CPE component mapping](https://nvd.nist.gov/products/cpe/detail/5bc54669-2bfd-43de-86ac-34bc61722d31)

Reporting adds Rich (MIT), Jinja2 and MarkupSafe (BSD-3-Clause), installed as
dependencies rather than vendored. Optional development validation uses jsonschema
(MIT). The HTML template, CSS and Markdown/SARIF mapping are independently authored.
No external assets, fonts, images, scripts or copied report templates are shipped.
The official OASIS schema is downloaded separately for verification and is not
redistributed in this repository. Previously measured synthetic sample data is
retained with explicit provenance and original scan metadata.

- [Rich literal Text API](https://rich.readthedocs.io/en/stable/reference/text.html)
- [Jinja autoescaping](https://jinja.palletsprojects.com/en/stable/api/)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [CSP style hashes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src)
