# Ethical operation

Use the scanner only for systems you own or are explicitly authorized to assess.
Private IP space is not evidence of ownership: a school, employer or neighboring
network can use private addresses too.

Before a scan, agree on exact hosts, networks, ports, timing, traffic limits and
the person to contact if availability changes. Keep that authorization outside
the tool; the saved notice acknowledgment is not a substitute.

The implemented web checks use detection-only probes. They do not exploit
authentication bypasses, extract records or secrets, execute code on a target,
or deliberately issue modifying operations. Even a GET request can have side
effects in a poorly designed application; discovery must avoid known action URLs.

Stop when errors, overload, unexpected destinations or data outside scope appear.
Do not increase the rate merely to finish faster. Respect configured robots rules
while remembering that robots.txt is neither a permission grant nor an access control.

Reports must distinguish observations, potential issues and established findings.
Do not invent proof of exploitation or label an untested check as passed. Report
only minimal redacted evidence, retain it according to the assessment agreement
and disclose findings privately to the authorized owner.

Practice on isolated local training applications. Do not use intentionally
vulnerable applications on public interfaces. The eventual Juice Shop sample
will include actual execution metadata and measured results.
