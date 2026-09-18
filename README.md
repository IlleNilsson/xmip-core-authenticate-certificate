# xmip-core-authenticate-certificate

Authenticate by certificate: verifies a certificate chain to a configured
trust anchor, validity and revocation as ADR-0033 says. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The first gate (`identify/certificate`) read the peer certificate's subject
and presented it, with the chain the peer sent riding as the
`certificate.chain` proof. This gate walks the chain to one of the anchors
the node holds, at the clock it is given, against the CRLs it was configured
with, then checks that the leaf names the claimed value — as its subject or
one of its DNS names — and that the fingerprint the transport reported is
the leaf's. Every refusal says why in words an operator can act on.

This is the certificate *outside* a TLS handshake — S/MIME in AS2, an OPC UA
instance certificate — so nothing proved it before this gate did, and the
usage the leaf must be for is configuration: any unless said. A certificate
the handshake itself proved is `mutual-tls`, the sibling's.

## Configuration

`Verifier::new(anchors)` with the anchors as PEM, then `.revoking(lists)`
for CRLs, `.for_usage(Usage::ClientAuth)` to require that extended key
usage, and `.with_clock(...)` where a test pins the time. Offline throughout
(ADR-0045): anchors and lists are held, never fetched; OCSP waits for the
`online` switch.

## Dependencies

Its capability with the `x509` feature on, `context` for `Verified` and
`xmip-core` for the mechanism. The chain walk, the names and the revocation
lists are the capability's, shared with `mutual-tls` (ADR-0044); the crypto
beneath is webpki over ring, the one place the estate admits it (ADR-0033).
The tests mint their own chains through the capability's `mint` feature,
which ships in no build.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

`cargo test`: seven tests — a chain to a held anchor naming the claim is
proven; one naming someone else, one expired, one revoked and one whose
reported fingerprint is not the leaf's are refused saying so; a claim
without the chain proof, and another mechanism's claim, are refused by name.
The included workflow is manual-only and calls the versioned shared workflow
at `IlleNilsson/.github@v1`.
