use credibil_holder::{credential::Credential, presentation::RequestObject};
use crux_http::HttpError;
use serde::{Deserialize, Serialize};

use crate::capabilities::{key::{KeyStoreEntry, KeyStoreError}, store::{StoreEntry, StoreError}};

/// Events that can be sent to the wallet application that pertain to the
/// issuance of credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PresentationEvent {
    /// Event emitted by the shell when the user wants to scan a presentation
    /// request QR code.
    ScanRequest,

    /// Event emitted by the shell when the user scans a presentation request QR
    /// code.
    ///
    /// We expect the string to be a URL to a presentation request. Cross-device
    /// flow.
    Request(String),

    /// Event emitted by the core when a presentation request has been received.
    #[serde(skip)]
    RequestReceived(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    DidResolved(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when the presentation request has been
    /// verified and decoded.
    #[serde(skip)]
    RequestVerified(Box<RequestObject>),

    /// Event emitted by the core when all credentials have been loaded from
    /// storage, before they are filtered.
    #[serde(skip)]
    CredentialsLoaded(Result<Vec<StoreEntry>, StoreError>),

    /// Event emitted by the core when at least one credential has been found
    /// that matches the presentation request.
    #[serde(skip)]
    CredentialsFound(Vec<Credential>),

    /// Event emitted by the shell when a user approves the presentation of
    /// the credential to the verifier.
    ///
    /// TODO: We only let the user send the first matching credential for now.
    /// If the app extends to support a choice we would need to know which one
    /// has been selected here.
    Approved,

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    SigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a proof has been constructed.
    ///
    /// The string is a proof JWT.
    #[serde(skip)]
    Proof(String),

    /// Event emitted by the core when the verifier responds to the
    /// presentation.
    #[serde(skip)]
    Response(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user wants to cancel a presentation.
    Cancel,
}
