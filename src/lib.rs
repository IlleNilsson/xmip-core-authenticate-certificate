#![forbid(unsafe_code)]
//! Authenticate by certificate: verifies a certificate chain to a configured trust anchor,
//! validity and revocation as ADR-0033 says.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authenticator` (ADR-0050).
