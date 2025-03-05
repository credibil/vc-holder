//! Model for the wallet application state.

pub mod credential;
mod issuance;
mod presentation;

use anyhow::bail;
pub use credential::CredentialState;
use credibil_holder::credential::Credential;
use credibil_holder::issuance::proof::Payload;
use credibil_holder::issuance::{
    CredentialRequest, CredentialResponse, Issuer, ProofClaims, TokenRequest, TokenResponse,
    VerifiableCredential,
};
use credibil_holder::presentation::{Constraints, RequestObject, ResponseRequest};
pub use issuance::{IssuanceState, OfferedCredential};
pub use presentation::PresentationState;

use super::Aspect;
use crate::capabilities::store::StoreEntry;

/// State for the wallet application.
#[derive(Clone, Debug)]
pub enum State {
    /// The application is working with stored credentials.
    Credential(Box<CredentialState>),

    /// The application is in an issuance flow.
    Issuance(Box<IssuanceState>),

    /// The application is in a presentation flow.
    Presentation(Box<PresentationState>),

    /// The application is in an error state.
    Error(String),
}

/// Application state model. Combines the aspect (screen or page) with the
/// flow state.
#[derive(Clone, Debug)]
pub struct Model {
    /// Which aspect of the application is currently active.
    pub active_view: Aspect,
    /// Application state.
    pub state: State,
}

impl Default for Model {
    fn default() -> Self {
        Model {
            active_view: Aspect::CredentialList,
            state: State::Credential(Box::default()),
        }
    }
}

/// Event processing methods for the application model. In general, these will
/// validate the model state against the event and return a new model state.
impl Model {
    /// An error has occurred. Set the error state.
    pub fn error(&self, error: &str) -> Self {
        Self {
            active_view: Aspect::Error,
            state: State::Error(error.into()),
        }
    }

    /// Set up the model with an initial state.
    pub fn ready(&self) -> Self {
        Self {
            active_view: Aspect::CredentialList,
            state: State::Credential(Box::new(CredentialState::init())),
        }
    }

    /// Set the active view on the model directly.
    pub fn active_view(&self, view: Aspect) -> Self {
        Self {
            active_view: view,
            state: self.state.clone(),
        }
    }

    /// Get the current credential state or error if current state is not a
    /// credential state.
    fn credential_state(&self) -> anyhow::Result<&CredentialState> {
        if let State::Credential(state) = &self.state {
            Ok(state)
        } else {
            bail!("not in credential state");
        }
    }

    /// Get the current issuance state or error if current state is not an
    /// issuance state.
    fn issuance_state(&self) -> anyhow::Result<&IssuanceState> {
        if let State::Issuance(state) = &self.state {
            Ok(state)
        } else {
            bail!("not in issuance state");
        }
    }

    /// Get the current presentation state or error if current state is not a
    /// presentation state.
    fn presentation_state(&self) -> anyhow::Result<&PresentationState> {
        if let State::Presentation(state) = &self.state {
            Ok(state)
        } else {
            bail!("not in presentation state");
        }
    }

    //--- Credential state -----------------------------------------------------

    /// The user has selected a credential in their wallet to view.
    pub fn select_credential(&self, id: &str) -> Self {
        if let Ok(cred_state) = self.credential_state() {
            let mut new_state = cred_state.clone();
            new_state.id = Some(id.into());
            Self {
                active_view: Aspect::CredentialDetail,
                state: State::Credential(Box::new(new_state)),
            }
        } else {
            self.ready()
        }
    }

    /// The credentials have been retrieved from the wallet's store.
    pub fn credentials_loaded(&self, entries: Vec<StoreEntry>) -> Self {
        let mut new_state = CredentialState::init();
        new_state.set_credentials(entries);
        Self {
            active_view: Aspect::CredentialList,
            state: State::Credential(Box::new(new_state)),
        }
    }

    //--- Issuance state -------------------------------------------------------

    /// The user wants to scan an issuance offer QR code.
    pub fn scan_issuance_offer(&self) -> Self {
        Self {
            active_view: Aspect::IssuanceScan,
            state: State::Issuance(Box::default()),
        }
    }

    /// The user has scanned an issuance offer QR code so we can initiate a
    /// pre-authorized issuance flow.
    pub fn issuance_offer(&self, encoded_offer: &str) -> anyhow::Result<Self> {
        let state = IssuanceState::from_offer(encoded_offer)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(state)),
        })
    }

    /// The app has received the issuer metadata.
    pub fn issuer_metadata(&self, issuer: Issuer) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.issuer_metadata(issuer)?;
        Ok(Self {
            active_view: Aspect::IssuanceOffer,
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Get the first offered credential from issuance state.
    /// TODO: Add support for multiple offered credentials.
    pub fn get_offered_credential(&self) -> Option<OfferedCredential> {
        let Ok(state) = self.issuance_state() else {
            return None;
        };
        state.get_offered_credential()
    }

    /// The app has received display logo information.
    pub fn issuance_logo(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.logo(image_data, media_type)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// The app has received display background image information.
    pub fn issuance_background(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.background(image_data, media_type)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// The user has accepted the issuance offer (but has not entered a PIN).
    pub fn issuance_accept(&self) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.accept()?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Check to see if the issuance flow needs a PIN.
    pub fn issuance_needs_pin(&self) -> bool {
        if let State::Issuance(state) = &self.state {
            return state.needs_pin();
        };
        false
    }

    /// Get the issuer metadata for the current issuance flow.
    pub fn issuer(&self) -> Option<Issuer> {
        if let State::Issuance(state) = &self.state {
            return state.issuer();
        };
        None
    }

    /// Construct a token request from issuance state.
    pub fn get_token_request(&self) -> anyhow::Result<TokenRequest> {
        let state = self.issuance_state()?;
        state.token_request()
    }

    /// The user has entered their PIN to prove they are in control of the
    /// wallet.
    pub fn issuance_pin(&self, pin: &str) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.pin(pin)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Update the model state with a token response.
    pub fn issuance_token(&self, token: &TokenResponse) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.token(token)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Get proof claims from issuance flow state.
    pub fn get_proof_claims(&self) -> anyhow::Result<ProofClaims> {
        let state = self.issuance_state()?;
        state.get_proof_claims()
    }

    /// Update the model with encoded proof.
    pub fn issuance_proof(&self, encoded_proof: &str) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.proof(encoded_proof)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Get a credential request for the first offered credential.
    /// TODO: Add support for multiple offered credentials.
    pub fn get_credential_request(&self, jwt: &str) -> anyhow::Result<(String, CredentialRequest)> {
        let state = &self.issuance_state()?;
        state.get_credential_request(jwt)
    }

    /// Retrieve the access token from the issuance flow state.
    pub fn get_issuance_token(&self) -> anyhow::Result<String> {
        let state = &self.issuance_state()?;
        state.get_token()
    }

    /// Update the model with a credential response.
    pub fn issuance_issued(
        &self, credential_response: &CredentialResponse,
    ) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.issued(credential_response)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Get the credential response from the issuance state.
    pub fn get_issued_credential(&self) -> Option<CredentialResponse> {
        let Ok(state) = self.issuance_state() else {
            return None;
        };
        state.get_issued_credential()
    }

    /// Add the issued credential to issuance flow state. (This is separated
    /// from `issuance_issued` to allow for async verification of the credential
    /// response).
    pub fn issuance_add_credential(
        &self, vc: &VerifiableCredential, issued_at: &i64,
    ) -> anyhow::Result<Self> {
        let state = self.issuance_state()?;
        let new_state = state.add_credential(vc, issued_at)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Issuance(Box::new(new_state)),
        })
    }

    /// Get the credential from the issuance flow that is in a format suitable
    /// for storage and display in the wallet.
    /// TODO: Add support for multiple credentials.
    pub fn get_storable_credential(&self) -> anyhow::Result<Credential> {
        let state = self.issuance_state()?;
        state.get_storable_credential()
    }

    //--- Presentation state ---------------------------------------------------

    /// The user wants to scan an issuance offer QR code.
    pub fn scan_presentation_request(&self) -> Self {
        Self {
            active_view: Aspect::PresentationScan,
            state: State::Presentation(Box::default()),
        }
    }

    /// A request has been received but not yet decoded or verified.
    pub fn presentation_request(&self, request_payload: &str) -> Self {
        Self {
            active_view: self.active_view.clone(),
            state: State::Presentation(Box::new(PresentationState::Requested {
                request_payload: request_payload.into(),
            })),
        }
    }

    /// Get the presentation request back from state.
    pub fn get_presentation_request(&self) -> Option<String> {
        let Ok(state) = self.presentation_state() else {
            return None;
        };
        state.get_request()
    }

    /// The presentation request has been decoded and verified.
    pub fn presentation_request_verified(&self, request: &RequestObject) -> anyhow::Result<Self> {
        let state = self.presentation_state()?;
        let new_state = state.request_verified(request)?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Presentation(Box::new(new_state)),
        })
    }

    /// Get a credential filter from the presentation flow state.
    pub fn get_presentation_filter(&self) -> anyhow::Result<Constraints> {
        let state = self.presentation_state()?;
        state.get_filter()
    }

    /// Credentials that match the presentation request have been identified.
    /// Add them to the model and set the active view to enable the user to
    /// approve the presentation.
    pub fn presentation_credentials(&self, credentials: &[Credential]) -> anyhow::Result<Self> {
        let state = self.presentation_state()?;
        let new_state = state.credentials(credentials)?;
        Ok(Self {
            active_view: Aspect::PresentationRequest,
            state: State::Presentation(Box::new(new_state)),
        })
    }

    /// User authorizes the presentation.
    pub fn presentation_approve(&self) -> anyhow::Result<Self> {
        let state = self.presentation_state()?;
        let new_state = state.approve()?;
        Ok(Self {
            active_view: self.active_view.clone(),
            state: State::Presentation(Box::new(new_state)),
        })
    }

    /// Construct a presentation payload from the presentation flow state.
    pub fn get_presentation_payload(&self, kid: &str) -> anyhow::Result<Payload> {
        let state = self.presentation_state()?;
        state.get_payload(kid)
    }

    /// Construct a presentation response request.
    pub fn create_response_request(
        &self, jws: &str,
    ) -> anyhow::Result<(ResponseRequest, Option<String>)> {
        let state = self.presentation_state()?;
        state.create_response_request(jws)
    }
}
