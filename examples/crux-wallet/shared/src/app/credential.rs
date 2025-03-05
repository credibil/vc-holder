use crux_core::{render::render, Command};
use serde::{Deserialize, Serialize};

use super::{Effect, Event};
use crate::{
    capabilities::store::{Catalog, StoreCommand, StoreEntry, StoreError},
    model::Model,
};

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
        CredentialEvent::Ready => ready(model),
        CredentialEvent::Select(id) => select(id, model),
        CredentialEvent::Delete(id) => delete(id),
        CredentialEvent::Loaded(Ok(entries)) => loaded(entries, model),
        CredentialEvent::Stored(Ok(())) | CredentialEvent::Deleted(Ok(())) => refresh_credentials(),
        CredentialEvent::Loaded(Err(error))
        | CredentialEvent::Stored(Err(error))
        | CredentialEvent::Deleted(Err(error)) => store_error(error, model),
    }
}

/// Process a `CredentialEvent::Ready` event. Load the list of credentials from
/// the credential store.
fn ready(model: &mut Model) -> Command<Effect, Event> {
    *model = model.ready();
    refresh_credentials()
}

/// Process a `CredentialEvent::Select` event. Update the model with selected
/// credential identifier.
fn select(id: String, model: &mut Model) -> Command<Effect, Event> {
    *model = model.select_credential(&id);
    render()
}

/// Process a `CredentialEvent::Delete` event. Delete the selected credential
/// from the credential store.
fn delete(id: String) -> Command<Effect, Event> {
    StoreCommand::delete("credential", id)
        .then_send(|res| Event::Credential(CredentialEvent::Deleted(res)))
}

/// Process a `CredentialEvent::Loaded` event. Update the model with the loaded
/// credentials.
pub fn loaded(entries: Vec<StoreEntry>, model: &mut Model) -> Command<Effect, Event> {
    *model = model.credentials_loaded(entries);
    render()
}

/// Process an event that causes the credential list to be refreshed from the
/// credential store.
pub fn refresh_credentials() -> Command<Effect, Event> {
    StoreCommand::list(Catalog::Credential.to_string())
        .then_send(|res| Event::Credential(CredentialEvent::Loaded(res)))
}

/// Process an event that results in an error being returned from the
/// credential store.
pub fn store_error(error: StoreError, model: &mut Model) -> Command<Effect, Event> {
    *model = model.error(&error.to_string());
    render()
}
