# Security

Please report suspected vulnerabilities privately through this repository's
GitHub security advisory reporting when available. Do not include credentials,
pairing codes, private network inventories or personal addresses in public issues.

FieldKit 1.0 is the first public source release. Use the newest patch available.
Reports about data exposure, unsafe parsing, unintended network access, signing,
or permission boundaries are particularly useful. Include the affected platform,
version, reproduction steps and a sanitized example.

## Network behavior

Tools send real probes to the addresses and services the user selects. Bounded
LAN and port scans can still generate substantial traffic. Use them only on
networks you administer or have permission to inspect. A timeout does not prove
that a host is absent or a port is filtered.

The app respects operating-system permissions and routing. VPN or enterprise
policy can restrict visibility and reachability. No root or administrator access
is required for ordinary tools; some operating-system diagnostics may be denied.

## Release signing

Private keys, provisioning profiles, passwords and signing certificates are not
part of this repository. Public source and CI artifacts do not confer trust on
an unsigned executable. Use the signing status and SHA-256 manifest accompanying
each release. The earlier private prototype's development key must not be used
as a public production signing key.

Only workflows from trusted branches should receive release signing secrets.
Pull-request checks have read-only permissions and do not use signing secrets.
