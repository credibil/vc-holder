//! # Credibil Holder
//!
//! An SDK for building applications that act as a holder's agent (such as a
//! wallet). It supports `OpenID` for Verifiable Credential Issuance
//! and Presentation and is designed to be used with issuer and verifier
//! services that implement those standards. In particular it is designed to
//! work with services based on `credibil-vc`.
//!
//! The crate does not provide a user or service interface - that is the job of
//! an application implementer. See the examples directory for simple (not
//! full-featured) implementations.
//!
//! # Design
//!
//! ** Flow State **
//!
//! Similar to other general OpenID implementations, the library is based
//! around orchestrating flows for VC issuance or presentation (to a verifier).
//!
//! The client application can interact with types that "remember" the current
//! state of the flow and provide associated methods to use that state to
//! prepare requests and then update the state with responses.
//!
//! A full set of end-to-end tests are provided in the `tests` directory that
//! demonstrate how to use the library with all the possible variations of VC
//! issuance supported by the standards as implemented in `credibil-vc`.
//!
//! At present, the only supported credential data type is the
//! [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
//!
//! ** Provider **
//!
//! In a similar style to `credibil-vc`, implementors make use of 'Provider'
//! traits that are responsible for handling storage, signing and verifying
//! proof of key ownership by resolving distributed identifiers (DIDs). See
//! the `provider` module in this crate for traits specific to
//! holder agents.
//!
//! # Example
//!
//! See the `examples` directory for some simple applications that make use of
//! the SDK and also sample applications that demonstrate services and
//! applications for Issuers and Verifiers using `credibil-vc` and that work
//! in conjunction with the example wallets.

// TODO: implement client registration/ client metadata endpoints

// TODO: support [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)(https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
//        - add Token endpoint
//        - add Metadata endpoint
//        - add Registration endpoint

pub mod credential;
pub mod issuance;
pub mod presentation;
pub mod provider;

pub use credibil_vc::{Kind, Quota, did, infosec, test_utils, urlencode};
