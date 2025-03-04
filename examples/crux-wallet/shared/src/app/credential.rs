use crux_core::{render::render, Command};
use serde::{Deserialize, Serialize};

use crate::{
    capabilities::store::{Catalog, StoreCommand, StoreEntry, StoreError},
    model::Model,
};
use super::{Effect, Event};

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

/// Credential event processing.
pub fn credential_event(event: CredentialEvent, model: &mut Model) -> Command<Effect, Event> {
    match event {
        CredentialEvent::Ready => {
            *model = model.ready();
            StoreCommand::list(Catalog::Credential.to_string())
                .then_send(|res| Event::Credential(CredentialEvent::Loaded(res)))
        }
        CredentialEvent::Select(id) => {
            *model = model.select_credential(&id);
            render()
        }
        CredentialEvent::Delete(id) => StoreCommand::delete("credential", id)
            .then_send(|res| Event::Credential(CredentialEvent::Deleted(res))),
        CredentialEvent::Loaded(Ok(entries)) => {
            *model = model.credentials_loaded(entries);
            render()
        }
        CredentialEvent::Stored(Ok(())) | CredentialEvent::Deleted(Ok(())) => {
            StoreCommand::list(Catalog::Credential.to_string())
                .then_send(|res| Event::Credential(CredentialEvent::Loaded(res)))
        }
        CredentialEvent::Loaded(Err(error))
        | CredentialEvent::Stored(Err(error))
        | CredentialEvent::Deleted(Err(error)) => {
            *model = model.error(&error.to_string());
            render()
        }
    }
}
