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
the leaf's. A claim that is a user principal name, `jane@party-x.example`
or `PARTY-X.EXAMPLE\jane`, is proven by the name a smart-card certificate
carries for its user in its alternative names, compared as accounts
(ADR-0054). Every refusal says why in words an operator can act on.

**Proven only with possession.** A chain is anyone's to forward: it names
someone and proves nothing about who sent it. The claim is proven only
where the leaf's key signed this arrival — the `certificate.signature`
proof over the `certificate.signed` attributes, a CMS SignerInfo's signed
attributes as S/MIME signs them, whose `messageDigest` must be the
`certificate.digest` the transport measured of this arrival's content, all
base64 — checked by the capability's `x509::possessed`. A chain without
that signature, one another key made, and the holder's own signature taken
from an earlier arrival are each refused (the owner, 2026-11-10; ADR-0019,
amendment 2026-11-11). The proofs carry attributes and a digest, never the
content. The leaf's classical key is the one checked: under
`Hybrid::Required` the path's alternative signatures are verified, and
possession is still by the classical key alone. No transport reports the
three proofs yet, so until one does a `certificate` claim is refused.

This is the certificate *outside* a TLS handshake — S/MIME in AS2, an OPC UA
instance certificate — so nothing proved it before this gate did. The usage
the leaf must be for is configuration, client authentication unless said: a
certificate whose extended key usage names server authentication alone is a
server's, and is refused as a client's. `.for_usage(Usage::Any)` admits any
purpose, where a profile such as S/MIME names another. A certificate the
handshake itself proved is `mutual-tls`, the sibling's.

## Configuration

`Verifier::new(anchors)` with the anchors as PEM, then `.revoking(lists)`
for CRLs, `.for_usage(Usage::Any)` to admit a leaf for any purpose, and
`.with_clock(...)` where a test pins the time. Offline throughout
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

`cargo test`: ten tests — a chain to a held anchor naming the claim, its
key's signature over this arrival beside it, is proven; one naming someone
else, one expired, one revoked and one whose reported fingerprint is not
the leaf's are refused saying so; a certificate without possession — no
signature, another key's, or the holder's own replayed from an earlier
arrival — is not proven; a server's certificate is
refused as a client's unless any usage is said; a claim without the chain
proof is refused by name; a hybrid chain is proven where required and a
classical one is not; a smart-card certificate proves its user principal
name in either spelling.
The included workflow is manual-only and calls the versioned shared workflow
at `IlleNilsson/.github@v1`.
