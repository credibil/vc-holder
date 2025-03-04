use credibil_holder::issuance::VerifiableCredential;
use crux_http::HttpError;
use serde::{Deserialize, Serialize};

use crate::capabilities::{key::{KeyStoreEntry, KeyStoreError}, store::StoreError};

/// Events that can be sent to the wallet application that pertain to the
/// issuance of credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum IssuanceEvent {
    /// Event emitted by the shell when the user wants to scan an issuance offer
    /// QR code.
    ScanOffer,

    /// Event emitted by the shell when the user scans an offer QR code.
    Offer(String),

    /// Event emitted by the core when issuer metadata has been received.
    #[serde(skip)]
    Issuer(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's logo has been
    /// fetched.
    #[serde(skip)]
    Logo(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's background image
    /// has been fetched.
    #[serde(skip)]
    Background(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user has accepted an issuance offer.
    Accepted,

    /// Event emitted by the shell when the user has entered a PIN.
    Pin(String),

    /// Event emitted by the core when an access token has been received.
    #[serde(skip)]
    Token(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a proof has been created.
    #[serde(skip)]
    Proof(String),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    DidResolved(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    SigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a credential has been received.
    #[serde(skip)]
    Credential(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a credential response proof has been
    /// verified.
    #[serde(skip)]
    ProofVerified { vc: VerifiableCredential, issued_at: i64 },

    /// Event emitted by the core when a credential has been stored.
    #[serde(skip)]
    Stored(Result<(), StoreError>),

    /// Event emitted by the shell to cancel an issuance.
    Cancel,
}
