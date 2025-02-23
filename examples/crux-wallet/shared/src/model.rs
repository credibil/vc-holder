//! Model for the wallet application state.

pub mod credential;
mod issuance;
mod presentation;

use std::ops::{Deref, DerefMut};

use anyhow::bail;
use base64ct::{Base64, Encoding};
pub use credential::CredentialState;
use credibil_holder::credential::{Credential, ImageData};
use credibil_holder::issuance::proof::Payload;
use credibil_holder::issuance::{
    CredentialRequest, CredentialResponse, CredentialResponseType, IssuanceFlow, Issuer,
    NotAccepted, PreAuthorized, ProofClaims, TokenRequest, TokenResponse, VerifiableCredential,
    WithOffer, WithoutToken,
};
use credibil_holder::presentation::{
    Constraints, NotAuthorized, PresentationFlow, RequestObject as VerifierRequestObject,
    ResponseRequest,
};
pub use issuance::{IssuanceState, OfferedCredential};
pub use presentation::PresentationState;

use super::Aspect;
use crate::capabilities::store::StoreEntry;
use crate::config;

/// State for the wallet application.
#[derive(Clone, Debug)]
pub enum Model {
    /// The application is working with stored credentials.
    Credential {
        /// Which aspect of the application is currently active.
        active_view: Aspect,
        /// Credential state.
        state: Box<CredentialState>,
    },

    /// The application is in an issuance flow.
    Issuance {
        /// Which aspect of the application is currently active.
        active_view: Aspect,
        /// Issuance state.
        state: Box<IssuanceState>,
    },

    /// The application is in a presentation flow.
    Presentation {
        /// Which aspect of the application is currently active.
        active_view: Aspect,
        // /// Presentation state.
        state: Box<PresentationState>,
    },

    /// An error has occurred.
    Error {
        /// Which aspect of the application is currently active.
        active_view: Aspect,
        /// Error message.
        error: String,
    },
}

impl Default for Model {
    fn default() -> Self {
        Model::Credential {
            active_view: Aspect::CredentialList,
            state: Box::new(CredentialState::default()),
        }
    }
}

/// Methods to set the application state based on events.
impl Model {
    /// An error has occurred. Set the error state.
    pub fn error(&self, error: &str) -> Self {
        Model::Error {
            active_view: Aspect::Error,
            error: error.into(),
        }
    }

    /// Set up the model with an initial state.
    pub fn ready(&self) -> Self {
        Model::Credential {
            active_view: Aspect::CredentialList,
            state: Box::new(CredentialState::init()),
        }
    }

    /// Set the active view on the model directly.
    pub fn active_view(&self, view: Aspect) -> Self {
        match self {
            Model::Credential { state, .. } => Model::Credential {
                active_view: view,
                state: state.clone(),
            },
            Model::Issuance { state, .. } => Model::Issuance {
                active_view: view,
                state: state.clone(),
            },
            Model::Presentation { state, .. } => Model::Presentation {
                active_view: view,
                state: state.clone(),
            },
            Model::Error { error, .. } => Model::Error {
                active_view: view,
                error: error.clone(),
            },
        }
    }

    //--- Credential state -----------------------------------------------------

    /// The user has selected a credential in their wallet to view.
    pub fn select_credential(&self, id: &str) -> Self {
        let mut cred_state = match self {
            Model::Credential { state, .. } => state.clone(),
            _ => Box::new(CredentialState::init()),
        };
        cred_state.id = Some(id.into());
        Self::Credential {
            active_view: Aspect::CredentialDetail,
            state: cred_state,
        }
    }

    /// The credentials have been retrieved from the wallet's store.
    pub fn credentials_loaded(&self, entries: Vec<StoreEntry>) -> Self {
        let mut new_state = CredentialState::init();
        new_state.set_credentials(entries);
        Self::Credential {
            active_view: Aspect::CredentialList,
            state: Box::new(new_state),
        }
    }

    //--- Issuance state -------------------------------------------------------

    /// Get the issuer metadata for the current issuance flow.
    pub fn issuer(&self) -> Option<Issuer> {
        if let Model::Issuance { state, .. } = self {
            return state.issuer();
        };
        None
    }

    /// The user wants to scan an issuance offer QR code.
    pub fn scan_issuance_offer(&self) -> Self {
        Model::Issuance {
            active_view: Aspect::IssuanceScan,
            state: Box::new(IssuanceState::default()),
        }
    }

    /// The user has scanned an issuance offer QR code so we can initiate a
    /// pre-authorized issuance flow.
    pub fn issuance_offer(&self, encoded_offer: &str) -> anyhow::Result<Self> {
        let state = IssuanceState::from_offer(encoded_offer)?;
        let active_view = match self {
            Model::Issuance { active_view, .. } => active_view.clone(),
            _ => bail!("unexpected issuance state to apply offer"),
        };
        Ok(Model::Issuance {
            active_view,
            state: Box::new(state),
        })
    }

    /// The app has received the issuer metadata.
    pub fn issuer_metadata(&mut self, issuer: Issuer) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply issuer metadata");
        };
        let IssuanceState::Offered { offer, grant } = state.deref_mut() else {
            bail!("unexpected issuance state to apply issuer metadata");
        };
        let flow = IssuanceFlow::<WithOffer, PreAuthorized, NotAccepted, WithoutToken>::new(
            &config::client_id(),
            &config::subject_id(),
            issuer.clone(),
            offer.clone(),
            grant.clone(),
        );
        let mut creds = Vec::<OfferedCredential>::new();
        for config_id in &offer.credential_configuration_ids {
            if let Some(config) = issuer.credential_configurations_supported.get(config_id) {
                creds.push(OfferedCredential {
                    config_id: config_id.clone(),
                    config: config.clone(),
                    logo: None,
                    background: None,
                });
            }
        }
        let new_state = IssuanceState::IssuerMetadata { flow, offered: creds };
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Get the first offered credential from issuance state.
    /// TODO: Add support for multiple offered credentials.
    pub fn get_offered_credential(&self) -> Option<OfferedCredential> {
        let Model::Issuance { state, .. } = self else {
            return None;
        };
        match state.deref() {
            IssuanceState::IssuerMetadata { offered, .. }
            | IssuanceState::Accepted { offered, .. }
            | IssuanceState::Token { offered, .. }
            | IssuanceState::Proof { offered, .. } => offered.first().cloned(),
            _ => None,
        }
    }

    /// The app has received display logo information.
    /// TODO: Add support for multiple offered credentials.
    pub fn issuance_logo(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply logo");
        };
        let IssuanceState::IssuerMetadata { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to apply logo");
        };
        if let Some(credential) = offered.clone().first_mut() {
            credential.logo = Some(ImageData {
                data: Base64::encode_string(image_data),
                media_type: media_type.into(),
            });
            let new_state = IssuanceState::IssuerMetadata {
                flow: flow.clone(),
                offered: vec![credential.clone()],
            };
            Ok(Model::Issuance {
                active_view: active_view.clone(),
                state: Box::new(new_state),
            })
        } else {
            Ok(self.clone())
        }
    }

    /// The app has received display background image information.
    /// TODO: Add support for multiple offered credentials.
    pub fn issuance_background(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply background image");
        };
        let IssuanceState::IssuerMetadata { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to apply background image");
        };
        if let Some(credential) = offered.clone().first_mut() {
            credential.background = Some(ImageData {
                data: Base64::encode_string(image_data),
                media_type: media_type.into(),
            });
            let new_state = IssuanceState::IssuerMetadata {
                flow: flow.clone(),
                offered: vec![credential.clone()],
            };
            Ok(Model::Issuance {
                active_view: active_view.clone(),
                state: Box::new(new_state),
            })
        } else {
            Ok(self.clone())
        }
    }

    /// The user has accepted the issuance offer (but has not entered a PIN).
    pub fn issuance_accept(&self) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to accept offer");
        };
        if let IssuanceState::Accepted { .. } = state.deref() {
            return Ok(self.clone());
        };
        let IssuanceState::IssuerMetadata { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to accept offer");
        };
        let updated_flow = flow.clone().accept(&None, None);
        let new_state = IssuanceState::Accepted {
            flow: updated_flow,
            offered: offered.clone(),
        };
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Check to see if the issuance flow needs a PIN.
    pub fn issuance_needs_pin(&self) -> bool {
        if let Model::Issuance { state, .. } = self {
            return state.needs_pin();
        };
        false
    }

    /// The user has entered their PIN to prove they are in control of the
    /// wallet.
    pub fn issuance_pin(&self, pin: &str) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply PIN");
        };
        let IssuanceState::Accepted { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to apply PIN");
        };
        let mut updated_flow = flow.clone();
        updated_flow.set_pin(pin);
        let new_state = IssuanceState::Accepted {
            flow: updated_flow,
            offered: offered.clone(),
        };
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Construct a token request from issuance state.
    pub fn get_token_request(&self) -> anyhow::Result<TokenRequest> {
        let Model::Issuance { state, .. } = self else {
            bail!("no issuance state to get token request");
        };
        let IssuanceState::Accepted { flow, .. } = state.deref() else {
            bail!("unexpected issuance state to get token request");
        };
        Ok(flow.token_request())
    }

    /// Update the model state with a token response.
    pub fn issuance_token(&self, token: &TokenResponse) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply access token");
        };
        let IssuanceState::Accepted { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to apply access token");
        };
        let updated_flow = flow.clone().token(token.clone());
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(IssuanceState::Token {
                flow: updated_flow,
                offered: offered.clone(),
            }),
        })
    }

    /// Retrieve the access token from the issuance flow state.
    pub fn get_issuance_token(&self) -> anyhow::Result<String> {
        let Model::Issuance { state, .. } = self else {
            bail!("no issuance state to get access token");
        };
        match state.deref() {
            IssuanceState::Token { flow, .. }
            | IssuanceState::Proof { flow, .. }
            | IssuanceState::Issued { flow, .. } => {
                let token_response = flow.get_token();
                Ok(token_response.access_token)
            }
            _ => bail!("unexpected issuance state to get access token"),
        }
    }

    /// Get proof claims from issuance flow state.
    pub fn get_proof_claims(&self) -> anyhow::Result<ProofClaims> {
        let Model::Issuance { state, .. } = self else {
            bail!("unexpected issuance state to get proof claims");
        };
        let IssuanceState::Token { flow, .. } = state.deref() else {
            bail!("unexpected issuance state to get proof claims");
        };
        Ok(flow.proof())
    }

    /// Update the model with encoded proof.
    /// TODO: Could extend this to review and refresh existing proof if
    /// proof has expired.
    pub fn issuance_proof(&self, encoded_proof: &str) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply proof");
        };
        let IssuanceState::Token { flow, offered } = state.deref() else {
            bail!("unexpected issuance state to apply proof");
        };
        let issuance = IssuanceState::Proof {
            flow: flow.clone(),
            offered: offered.clone(),
            proof: encoded_proof.into(),
        };
        Ok(Self::Issuance {
            active_view: active_view.clone(),
            state: Box::new(issuance),
        })
    }

    /// Get a credential request for the first offered credential.
    /// TODO: Add support for multiple offered credentials.
    pub fn get_credential_request(&self, jwt: &str) -> anyhow::Result<(String, CredentialRequest)> {
        let Model::Issuance { state, .. } = self else {
            bail!("unexpected issuance state to get credential request");
        };
        let IssuanceState::Proof { flow, .. } = state.deref() else {
            bail!("unexpected issuance state to get authorization details");
        };
        let tr = flow.get_token();
        let Some(authorized) = tr.authorization_details else {
            bail!("no authorized details in token response");
        };
        let Some(auth) = authorized.first() else {
            bail!("empty authorized details in token response");
        };
        let Some(cred_id) = auth.credential_identifiers.first() else {
            bail!("empty credential identifiers in authorized details");
        };
        let identifiers = vec![cred_id.clone()];
        let requests = flow.credential_requests(&identifiers, jwt);
        let Some(request) = requests.first() else {
            bail!("no credential request for first credential identifier");
        };
        Ok(request.clone())
    }

    /// Update the model with a credential response.
    pub fn issuance_issued(
        &self, credential_response: &CredentialResponse,
    ) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to apply credential response");
        };
        let IssuanceState::Proof { flow, offered, proof } = state.deref() else {
            bail!("unexpected issuance state to apply credential response");
        };
        let new_state = IssuanceState::Issued {
            flow: flow.clone(),
            offered: offered.clone(),
            proof: proof.clone(),
            issued: credential_response.clone(),
        };
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Get the credential response from the issuance state.
    pub fn get_issued_credential(&self) -> Option<CredentialResponse> {
        let Model::Issuance { state, .. } = self else {
            return None;
        };
        match state.deref() {
            IssuanceState::Issued { issued, .. } => Some(issued.clone()),
            _ => None,
        }
    }

    /// Add the issued credential to issuance flow state. (This is separated
    /// from `issuance_issued` to allow for async verification of the credential
    /// response).
    pub fn issuance_add_credential(
        &self, vc: &VerifiableCredential, issued_at: &i64,
    ) -> anyhow::Result<Self> {
        let Model::Issuance { active_view, state } = self else {
            bail!("no issuance state to add credential");
        };
        let IssuanceState::Issued {
            flow,
            offered,
            proof,
            issued,
        } = state.deref()
        else {
            bail!("unexpected issuance state to add credential");
        };
        let CredentialResponseType::Credential(vc_kind) = &issued.response else {
            bail!("unexpected credential response type");
        };
        let Some(cred) = offered.first() else {
            bail!("no offered credential to add credential");
        };
        let mut updated_flow = flow.clone();
        updated_flow.add_credential(
            vc,
            vc_kind,
            issued_at,
            &cred.config_id,
            cred.logo.clone(),
            cred.background.clone(),
        )?;

        let new_state = IssuanceState::Issued {
            flow: updated_flow,
            offered: offered.clone(),
            proof: proof.clone(),
            issued: issued.clone(),
        };
        Ok(Model::Issuance {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Get the credential from the issuance flow that is in a format suitable
    /// for storage and display in the wallet.
    /// TODO: Add support for multiple credentials.
    pub fn get_storable_credential(&self) -> anyhow::Result<Credential> {
        let Model::Issuance { state, .. } = self else {
            bail!("no issuance state to get storable credential");
        };
        let IssuanceState::Issued { flow, .. } = state.deref() else {
            bail!("unexpected issuance state to get storable credential");
        };
        let flow_credentials = flow.credentials();
        let Some(credential) = flow_credentials.first() else {
            bail!("no credential in issuance flow");
        };
        Ok(credential.clone())
    }

    //--- Presentation state ---------------------------------------------------

    /// The user wants to scan an issuance offer QR code.
    pub fn scan_presentation_request(&self) -> Self {
        Model::Presentation {
            active_view: Aspect::PresentationScan,
            state: Box::new(PresentationState::default()),
        }
    }

    /// A request has been received but not yet decoded or verified.
    pub fn presentation_request(&self, request_payload: &str) -> anyhow::Result<Self> {
        let Model::Presentation { active_view, .. } = self else {
            bail!("no presentation state to apply request");
        };
        Ok(Model::Presentation {
            active_view: active_view.clone(),
            state: Box::new(PresentationState::Requested {
                request_payload: request_payload.into(),
            }),
        })
    }

    /// Get the presentation request back from state.
    pub fn get_presentation_request(&self) -> Option<String> {
        let Model::Presentation { state, .. } = self else {
            return None;
        };
        match state.deref() {
            PresentationState::Requested { request_payload } => Some(request_payload.clone()),
            _ => None,
        }
    }


    /// The presentation request has been decoded and verified.
    pub fn presentation_request_verified(
        &self, request: &VerifierRequestObject,
    ) -> anyhow::Result<Self> {
        let Model::Presentation { active_view, state } = self else {
            bail!("no presentation state to apply verified request");
        };
        let PresentationState::Requested { .. } = state.deref() else {
            bail!("unexpected presentation state to apply verified request");
        };
        let flow = PresentationFlow::<NotAuthorized>::new(request.clone())?;
        let new_state = PresentationState::Verified { flow };
        Ok(Model::Presentation {
            active_view: active_view.clone(),
            state: Box::new(new_state),
        })
    }

    /// Get a credential filter from the presentation flow state.
    pub fn get_presentation_filter(&self) -> anyhow::Result<Constraints> {
        let Model::Presentation { state, .. } = self else {
            bail!("no presentation state to get filter");
        };
        match state.deref() {
            PresentationState::Verified { flow } => Ok(flow.filter()?),
            _ => bail!("unexpected presentation state to get filter"),
        }
    }

    /// Credentials that match the presentation request have been identified.
    /// Add them to the model and set the active view to enable the user to
    /// approve the presentation.
    pub fn presentation_credentials(&self, credentials: &[Credential]) -> anyhow::Result<Self> {
        let Model::Presentation { state, .. } = self else {
            bail!("no presentation state to apply credentials");
        };
        let PresentationState::Verified { flow } = state.deref() else {
            bail!("unexpected presentation state to apply credentials");
        };
        let new_state = PresentationState::Credentials {
            flow: flow.clone(),
            credentials: credentials.to_vec(),
        };
        Ok(Model::Presentation {
            active_view: Aspect::PresentationRequest,
            state: Box::new(new_state),
        })
    }

    /// User authorizes the presentation.
    pub fn presentation_approve(&self) -> anyhow::Result<Self> {
        let Model::Presentation { active_view, state } = self else {
            bail!("no presentation state to approve");
        };
        let PresentationState::Credentials { flow, credentials } = state.deref() else {
            bail!("unexpected presentation state to approve");
        };
        let updated_flow = flow.clone().authorize(credentials);
        Ok(Model::Presentation {
            active_view: active_view.clone(),
            state: Box::new(PresentationState::Approved {
                flow: updated_flow,
                credentials: credentials.to_vec(),
            }),
        })
    }

    /// Construct a presentation payload from the presentation flow state.
    pub fn get_presentation_payload(&self, kid: &str) -> anyhow::Result<Payload> {
        let Model::Presentation { state, .. } = self else {
            bail!("no presentation state to get payload");
        };
        match state.deref() {
            PresentationState::Approved { flow, .. } => Ok(flow.payload(kid)?),
            _ => bail!("unexpected presentation state to get payload"),
        }
    }

    /// Construct a presentation response request.
    pub fn create_response_request(
        &self, jws: &str,
    ) -> anyhow::Result<(ResponseRequest, Option<String>)> {
        let Model::Presentation { state, .. } = self else {
            bail!("no presentation state to create response request");
        };
        match state.deref() {
            PresentationState::Approved { flow, .. } => Ok(flow.create_response_request(jws)),
            _ => bail!("unexpected presentation state to create response request"),
        }
    }
}
