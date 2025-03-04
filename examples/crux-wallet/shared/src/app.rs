//! This module contains the core application fabric for the wallet, including
//! the model, events, and effects that drive the application.

pub mod credential;
pub mod issuance;
pub mod presentation;

use std::ops::Deref;

use credential::{credential_event, CredentialEvent};
use crux_core::render::{render, Render};
use crux_core::Command;
use crux_kv::KeyValue;
use issuance::{issuance_event, IssuanceEvent};
use presentation::{presentation_event, PresentationEvent};
use serde::{Deserialize, Serialize};

use crate::capabilities::key::KeyStore;
use crate::capabilities::sse::ServerSentEvents;
use crate::capabilities::store::Store;
use crate::model::{Model, State};
use crate::view::ViewModel;

/// Aspect of the application (screen or page).
///
/// This allows the UI navigation to be reactive: controlled in response to the
/// user's actions. Although Crux can handle sub-apps, this is the intended way
/// to handle views unless the application is very complex.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Aspect {
    /// Display and deletion of credentials stored in the wallet.
    #[default]
    CredentialList,

    /// Display of a single credential.
    CredentialDetail,

    /// Trigger a credential issuance using an offer QR code.
    IssuanceScan,

    /// View the offer details to decide whether or not to proceed with
    /// issuance.
    IssuanceOffer,

    /// Display user PIN input.
    IssuancePin,

    /// Trigger a credential verification using a presentation request QR code.
    PresentationScan,

    /// View the presentation request details to decide whether or not to
    /// proceed with presentation to the verifier.
    PresentationRequest,

    /// Display a message to the user that the credential verification was
    /// successful.
    PresentationSuccess,

    /// The application is in an error state.
    Error,
}

/// Events that can be sent to the wallet application.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Error event is emitted by the core when an error occurs.
    #[serde(skip)]
    Error(String),

    /// Credential events.
    Credential(CredentialEvent),

    /// Issuance events.
    Issuance(IssuanceEvent),

    // Presentation events.
    Presentation(PresentationEvent),
}

/// Set of capabilities available to the application.
#[cfg_attr(feature = "typegen", derive(crux_core::macros::Export))]
#[derive(crux_core::macros::Effect)]
pub struct Capabilities {
    pub render: Render<Event>,
    pub http: crux_http::Http<Event>,
    pub key_store: KeyStore<Event>,
    pub kv: KeyValue<Event>,
    pub sse: ServerSentEvents<Event>,
    pub store: Store<Event>,
}

#[derive(Default)]
pub struct App;

impl crux_core::App for App {
    type Capabilities = Capabilities;
    type Effect = Effect;
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;

    fn update(
        &self, msg: Self::Event, model: &mut Self::Model, _caps: &Self::Capabilities,
    ) -> Command<Effect, Event> {
        match msg {
            Event::Error(e) => {
                *model = model.error(&e);
                render()
            }
            Event::Credential(ev) => credential_event(ev, model),
            Event::Issuance(ev) => issuance_event(ev, model),
            Event::Presentation(ev) => presentation_event(ev, model),
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        let mut vm = Self::ViewModel {
            active_view: model.active_view.clone(),
            ..Default::default()
        };
        match &model.state {
            State::Credential(state) => {
                vm.credential_view = state.deref().clone().into();
            }
            State::Issuance(state) => {
                vm.issuance_view = state.deref().clone().into();
            }
            State::Presentation(state) => {
                vm.presentation_view = state.deref().clone().into();
            }
            State::Error(error) => {
                vm.error = error.clone();
            }
        }
        vm
    }
}
