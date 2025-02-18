//! Credential sub-app state.

use serde::{Deserialize, Serialize};
use credibil_holder::credential::Credential;

use crate::capabilities::store::StoreEntry;

/// Application state for the credential sub-app.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialState {
    /// Currently selected credential.
    pub id: Option<String>,

    /// Credentials stored in the wallet.
    pub credentials: Vec<Credential>,
}

impl CredentialState {
    /// Create a new credential state.
    #[must_use]
    pub fn init() -> Self {
        Self {
            id: None,
            credentials: vec![],
        }
    }

    /// Set the credential list from a set of StoreEntries.
    pub fn set_credentials(&mut self, entries: Vec<StoreEntry>) {
        let mut credentials = vec![];
        for entry in entries {
            if let StoreEntry::Data(bytes) = entry {
                let credential: Credential =
                    serde_json::from_slice(&bytes).expect("should deserialize");
                credentials.push(credential);
            }
        }
        self.credentials = credentials;
    }
}
