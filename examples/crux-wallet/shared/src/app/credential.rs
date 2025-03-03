use serde::{Deserialize, Serialize};

use crate::capabilities::store::{StoreEntry, StoreError};

/// Events that can be sent to the wallet application that pertain to
/// managing the wallet's stored credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CredentialEvent {
        /// Event emitted by the shell when the app first loads.
        Ready,

        /// Event emitted by the shell to select a credential from the list of
        /// stored credentials for detailed display.
        Select(String),
    
        /// Event emitted by the shell to delete a credential from the wallet.
        Delete(String),
    
        /// Event emitted by the core when the store capability has loaded
        /// credentials.
        #[serde(skip)]
        Loaded(Result<Vec<StoreEntry>, StoreError>),
    
        /// Event emitted by the core when the store capability has stored a
        /// credential.
        #[serde(skip)]
        Stored(Result<(), StoreError>),
    
        /// Event emitted by the core when the store capability has deleted a
        /// credential.
        #[serde(skip)]
        Deleted(Result<(), StoreError>),    
}
