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
the leaf's. A claim that is a user principal name, `jane@partner-x.example`
or `PARTNER-X.EXAMPLE\jane`, is proven by the name a smart-card certificate
carries for its user in its alternative names, compared as accounts
(ADR-0054). Every refusal says why in words an operator can act on.

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

## Hybrid, behind a feature

With `features = ["hybrid"]`, a certificate that also carries an ML-DSA
alternative signature (ITU-T X.509 (10/2019) clause 9.8: classical and
post-quantum in one certificate, legacy verifiers untroubled) has that
signature verified along the same path, under the policy
`.requiring(Hybrid::...)` states: `Ignored`, `WherePresent` (the default;
held to it where carried, classical otherwise) or `Required` (every
certificate on the path, or refused saying which one lacks it). Off, the
extensions are not looked at and no post-quantum code ships (ADR-0033,
amendment 2026-09-18).

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

`cargo test`: nine tests — a chain to a held anchor naming the claim is
proven; one naming someone else, one expired, one revoked and one whose
reported fingerprint is not the leaf's are refused saying so; a claim
without the chain proof, and another mechanism's claim, are refused by name;
a hybrid chain is proven where required and a classical one is not; a
smart-card certificate proves its user principal name in either spelling.
The included workflow is manual-only and calls the versioned shared workflow
at `IlleNilsson/.github@v1`.
