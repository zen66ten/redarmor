# redarmor

A TLS certificate expiry tracker. Redarmor connects to a list of hosts, reads
the served certificate, and classifies it as OK, Warning, Critical, or
Expired based on days remaining until `NotAfter`.

## Status

v1 in progress: sequential host checker, stdlib only.

## Design

- `check.go` dials a host with `crypto/tls` and returns the leaf certificate.
  `InsecureSkipVerify` is set deliberately: Redarmor inspects certificates,
  including expired or otherwise invalid ones, rather than trusting them.
- `classify.go` is pure logic: given a certificate and the current time, it
  returns a `Status` (OK / Warning / Critical / Expired / NotYetValid). No
  network, no `time.Now()` inside the function, fully table-testable.

## Dependencies

None. Standard library only for v1.
