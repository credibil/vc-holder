//! # Key Store Capability
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;

use crux_core::capability::{CapabilityContext, Operation};
use crux_core::command::RequestBuilder;
use crux_core::{Capability, Command, Request};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can be returned by the key store capability.
#[derive(Clone, Debug, Deserialize, Serialize, Error, PartialEq, Eq)]
pub enum KeyStoreError {
    /// Invalid request.
    #[error("invalid key store request {message}")]
    InvalidRequest { message: String },

    /// The response from the shell capability was invalid.
    #[error("invalid key store response {message}")]
    InvalidResponse { message: String },
}

/// An entry in the key store.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyStoreEntry {
    /// A serialized private key.
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

impl From<Vec<u8>> for KeyStoreEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            data: bytes,
        }
    }
}

impl From<KeyStoreEntry> for Vec<u8> {
    fn from(entry: KeyStoreEntry) -> Vec<u8> {
        entry.data
    }
}

//--- Command based API --------------------------------------------------------

pub struct KeyStoreCommand<Effect, Event> {
    effect: PhantomData<Effect>,
    event: PhantomData<Event>,
}

type GetResult = Result<KeyStoreEntry, KeyStoreError>;

impl<Effect, Event> KeyStoreCommand<Effect, Event>
where 
    Effect: Send + From<Request<KeyStoreOperation>> + 'static,
    Event: Send + 'static,
{
    pub fn get(id: impl Into<String>, purpose: impl Into<String>) -> RequestBuilder<Effect, Event, impl Future<Output = GetResult>> {
        Command::request_from_shell(KeyStoreOperation::Get {
            id: id.into(),
            purpose: purpose.into(),
        })
        .map(|result| result.unwrap_get())
    }
}

//------------------------------------------------------------------------------

/// Supported operations for the key store capability.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStoreOperation {
    /// Get a serialized private key from the key store. If none exists, one
    /// is generated and stored for future get requests.
    Get { id: String, purpose: String },
}

impl Debug for KeyStoreOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreOperation::Get { id, purpose } => {
                f.debug_struct("Get").field("id", id).field("purpose", purpose).finish()
            }
        }
    }
}

/// The possible responses from the key store capability.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStoreResponse {
    /// The result of a get operation.
    Retrieved { key: KeyStoreEntry },
}

/// The result of an operation on the key store.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStoreResult {
    /// The operation was successful.
    Ok { response: KeyStoreResponse },

    /// The operation failed.
    Err { error: KeyStoreError },
}

impl KeyStoreResult {
    fn unwrap_get(self) -> Result<KeyStoreEntry, KeyStoreError> {
        match self {
            KeyStoreResult::Ok {
                response: KeyStoreResponse::Retrieved { key },
            } => Ok(key),
            KeyStoreResult::Err { error } => Err(error),
        }
    }
}

impl Operation for KeyStoreOperation {
    type Output = KeyStoreResult;
}

/// Capability type for the key store.
pub struct KeyStore<Ev> {
    context: CapabilityContext<KeyStoreOperation, Ev>,
}

impl<Ev> Capability<Ev> for KeyStore<Ev> {
    type MappedSelf<MappedEv> = KeyStore<MappedEv>;
    type Operation = KeyStoreOperation;

    fn map_event<F, NewEv>(&self, f: F) -> Self::MappedSelf<NewEv>
    where
        F: Fn(NewEv) -> Ev + Send + Sync + 'static,
        Ev: 'static,
        NewEv: 'static + Send,
    {
        KeyStore::new(self.context.map_event(f))
    }

    #[cfg(feature = "typegen")]
    fn register_types(generator: &mut crux_core::typegen::TypeGen) -> crux_core::typegen::Result {
        generator.register_type::<KeyStoreResponse>()?;
        generator.register_type::<KeyStoreError>()?;
        generator.register_type::<KeyStoreEntry>()?;
        generator.register_type::<Self::Operation>()?;
        generator.register_type::<<Self::Operation as Operation>::Output>()?;
        Ok(())
    }
}

impl<Ev> Clone for KeyStore<Ev> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<Ev> KeyStore<Ev>
where
    Ev: 'static,
{
    /// Create a new key store capability.
    pub fn new(context: CapabilityContext<KeyStoreOperation, Ev>) -> Self {
        Self { context }
    }

    /// Get a serialized private key from the key store and send an update event
    /// to the application.
    pub fn get<F>(
        &self, id: impl Into<String> + Send + 'static, purpose: impl Into<String> + Send + 'static,
        make_event: F,
    ) where
        F: FnOnce(Result<KeyStoreEntry, KeyStoreError>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let context = self.context.clone();
            async move {
                let response = get(&context, id, purpose).await;
                context.update_app(make_event(response))
            }
        });
    }

    /// Get a serialized private key from the key store.
    pub async fn get_async(
        &self, id: impl Into<String>, purpose: impl Into<String>,
    ) -> Result<KeyStoreEntry, KeyStoreError> {
        get(&self.context, id, purpose).await
    }
}

async fn get<Ev: 'static>(
    context: &CapabilityContext<KeyStoreOperation, Ev>, id: impl Into<String>,
    purpose: impl Into<String>,
) -> Result<KeyStoreEntry, KeyStoreError> {
    context
        .request_from_shell(KeyStoreOperation::Get {
            id: id.into(),
            purpose: purpose.into(),
        })
        .await
        .unwrap_get()
}
