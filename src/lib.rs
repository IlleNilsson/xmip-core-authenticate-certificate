#![forbid(unsafe_code)]

//! Authenticate by certificate: verifies a certificate chain to a configured
//! trust anchor, validity and revocation as ADR-0033 says.
//!
//! The first gate read the peer certificate's subject and presented it as the
//! claim, with the chain the peer sent riding as the `certificate.chain`
//! proof. This gate walks that chain to one of the anchors the node holds,
//! at the clock it is given, against the revocation lists it was configured
//! with, and then asks whether the leaf it verified names the value that was
//! claimed — as its subject or as one of its DNS names — and whether the
//! fingerprint the transport reported is the leaf's. Offline throughout
//! (ADR-0045): anchors and lists are configuration, never fetched.
//!
//! This is the certificate outside a TLS handshake — S/MIME in AS2, an OPC UA
//! instance certificate — so nothing proved it before this gate did, and the
//! usage it must be for is configuration, `Usage::Any` unless said. The
//! certificate a handshake proved is `mutual-tls`, another gate's.
//!
//! With the `hybrid` feature, a certificate that also carries an ML-DSA
//! alternative signature (ITU-T X.509 (10/2019) clause 9.8) has that
//! verified along the same path, under the [`Hybrid`] policy the node
//! states: ignored, where present, or required end to end.

use authenticate::clock::Clock;
#[cfg(feature = "hybrid")]
pub use authenticate::x509::alt::Hybrid;
use authenticate::x509::{Anchors, Chain, Name, Revocation, Usage, verify};
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use identify::evidence::{self, CERTIFICATE_CHAIN};
use xcore::{Mechanism, mechanism};

/// The certificate authenticator: the anchors the node holds and what it
/// requires of a chain.
pub struct Verifier {
    anchors: Anchors,
    revocation: Option<Revocation>,
    usage: Usage,
    #[cfg(feature = "hybrid")]
    hybrid: Hybrid,
    clock: Clock,
}

impl Verifier {
    /// Verifies against these anchors, for any usage, with no revocation
    /// list and the system clock.
    #[must_use]
    pub fn new(anchors: Anchors) -> Self {
        Self {
            anchors,
            revocation: None,
            usage: Usage::Any,
            #[cfg(feature = "hybrid")]
            hybrid: Hybrid::WherePresent,
            clock: Clock::system(0),
        }
    }

    /// What the node requires of alternative, post-quantum signatures along
    /// the path: where present unless said.
    #[cfg(feature = "hybrid")]
    #[must_use]
    pub const fn requiring(mut self, hybrid: Hybrid) -> Self {
        self.hybrid = hybrid;
        self
    }

    /// Refuse a certificate on any of these lists, and one no list covers.
    #[must_use]
    pub fn revoking(mut self, revocation: Revocation) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// Require the leaf to be for this usage.
    #[must_use]
    pub const fn for_usage(mut self, usage: Usage) -> Self {
        self.usage = usage;
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = self.clock.reading(clock);
        self
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::certificate()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies certificate"
            )));
        }
        let pem = presented
            .proof(evidence::CERTIFICATE_CHAIN)
            .ok_or_else(|| {
                AuthenticateError::new(format!("no {CERTIFICATE_CHAIN} proof was presented"))
            })?;
        let chain = Chain::from_pem(pem)?;

        let path = verify(
            &chain,
            &self.anchors,
            self.usage,
            self.revocation.as_ref(),
            self.clock.now(),
        )?;
        #[cfg(feature = "hybrid")]
        authenticate::x509::alt::verify_alt(&path, self.hybrid)?;
        #[cfg(not(feature = "hybrid"))]
        drop(path);

        if !Name::names(chain.leaf(), &presented.value)? {
            return Err(AuthenticateError::new(format!(
                "the verified certificate does not name '{}'",
                presented.value
            )));
        }

        let reported = presented
            .evidence
            .iter()
            .find(|(evidence, _)| evidence == evidence::TLS_PEER_FINGERPRINT)
            .map(|(_, fingerprint)| fingerprint.trim());
        if let Some(reported) = reported
            && !reported.eq_ignore_ascii_case(&chain.fingerprint())
        {
            return Err(AuthenticateError::new(
                "the fingerprint the transport reported is not the verified leaf's",
            ));
        }

        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::x509::mint::{Authority, Issued};

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn verifier(root: &Authority) -> Verifier {
        Verifier::new(Anchors::from_pem(&root.pem()).expect("anchors")).with_clock(|| NOW)
    }

    fn presented(issued: &Issued, subject: &str) -> Presented {
        Presented::passed(mechanism::certificate(), subject)
            .with_proof(evidence::CERTIFICATE_CHAIN, &issued.pem)
    }

    #[test]
    fn a_chain_to_a_held_anchor_naming_the_claim_is_proven() {
        let root = Authority::root("Partner Root");
        let issuing = root.intermediate("Partner Issuing CA");
        let issued = issuing.issue("partner-x.example", NOW - DAY, NOW + DAY);

        let verified = verifier(&root)
            .verify(&presented(&issued, "O=Partner X, CN=partner-x.example"))
            .expect("proven");
        assert_eq!(verified, Verified::Proven);
    }

    #[test]
    fn a_verified_chain_that_names_someone_else_is_refused() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);

        let failure = verifier(&root)
            .verify(&presented(&issued, "CN=partner-y.example,O=Partner X"))
            .expect_err("refused");
        assert!(failure.message.contains("does not name"), "{failure}");
    }

    #[test]
    fn an_expired_certificate_is_refused_saying_so() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - 2 * DAY, NOW - DAY);

        let failure = verifier(&root)
            .verify(&presented(&issued, "CN=partner-x.example,O=Partner X"))
            .expect_err("refused");
        assert!(failure.message.contains("expired"), "{failure}");
    }

    #[test]
    fn a_revoked_certificate_is_refused_where_a_list_is_held() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let lists = Revocation::from_pem(&root.crl(&[&issued], NOW)).expect("a list");

        let failure = verifier(&root)
            .revoking(lists)
            .verify(&presented(&issued, "CN=partner-x.example,O=Partner X"))
            .expect_err("refused");
        assert!(failure.message.contains("revoked"), "{failure}");
    }

    #[test]
    fn a_fingerprint_the_transport_reported_must_be_the_leafs() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");

        verifier(&root)
            .verify(
                &presented(&issued, "CN=partner-x.example,O=Partner X").with_evidence(
                    evidence::TLS_PEER_FINGERPRINT,
                    chain.fingerprint().to_uppercase(),
                ),
            )
            .expect("the leaf's own");

        let failure = verifier(&root)
            .verify(
                &presented(&issued, "CN=partner-x.example,O=Partner X")
                    .with_evidence(evidence::TLS_PEER_FINGERPRINT, "SHA256:ab12"),
            )
            .expect_err("refused");
        assert!(failure.message.contains("fingerprint"), "{failure}");
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn a_hybrid_chain_is_proven_where_required_and_a_classical_one_is_not() {
        let root = Authority::hybrid_root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let claim = presented(&issued, "CN=partner-x.example,O=Partner X");

        verifier(&root)
            .requiring(Hybrid::Required)
            .verify(&claim)
            .expect("quantum-safe end to end");

        let classical = Authority::root("Partner Root");
        let issued = classical.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let claim = presented(&issued, "CN=partner-x.example,O=Partner X");
        verifier(&classical)
            .verify(&claim)
            .expect("where present, nothing to check");
        let failure = verifier(&classical)
            .requiring(Hybrid::Required)
            .verify(&claim)
            .expect_err("required");
        assert!(
            failure.message.contains("no alternative signature"),
            "{failure}"
        );
    }

    #[test]
    fn a_smart_card_certificate_proves_its_user_principal_name_in_either_spelling() {
        // ADR-0054: a claim that is a user principal name is proven by the
        // name the verified leaf carries for its user, compared as accounts.
        let root = Authority::root("Partner Root");
        let issued = root.issue_for_user("jane", "Jane@Partner-X.Example", NOW - DAY, NOW + DAY);

        for spelling in ["jane@partner-x.example", "PARTNER-X.EXAMPLE\\jane"] {
            let verified = verifier(&root)
                .verify(&presented(&issued, spelling))
                .expect("the same account");
            assert_eq!(verified, Verified::Proven, "{spelling}");
        }

        let failure = verifier(&root)
            .verify(&presented(&issued, "john@partner-x.example"))
            .expect_err("another account");
        assert!(failure.message.contains("does not name"), "{failure}");
    }

    #[test]
    fn a_claim_without_the_chain_proof_cannot_be_verified() {
        let root = Authority::root("Partner Root");
        let claim = Presented::passed(mechanism::certificate(), "CN=partner-x.example");

        let failure = verifier(&root).verify(&claim).expect_err("no proof");
        assert!(
            failure.message.contains(evidence::CERTIFICATE_CHAIN),
            "{failure}"
        );
    }

    #[test]
    fn another_mechanisms_claim_is_refused_by_name() {
        let root = Authority::root("Partner Root");
        let claim = Presented::passed(mechanism::mutual_tls(), "CN=partner-x.example");

        let failure = verifier(&root).verify(&claim).expect_err("not ours");
        assert!(failure.message.contains("mutual-tls"), "{failure}");
    }
}
