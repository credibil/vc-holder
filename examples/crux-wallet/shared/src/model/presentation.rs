//! Presentation sub-app state.

use anyhow::bail;
use credibil_holder::credential::Credential;
use credibil_holder::issuance::proof::Payload;
use credibil_holder::presentation::{Authorized, NotAuthorized, PresentationFlow, RequestObject, ResponseRequest};
use credibil_holder::provider::Constraints;

/// Application state for the presentation sub-app.
#[derive(Clone, Debug, Default)]
pub enum PresentationState {
    /// No presentation is in progress.
    #[default]
    Inactive,

    /// A presentation request has been received but not yet decoded or
    /// verified.
    Requested { request_payload: String },

    /// The presentation request has been decoded and verified.
    Verified { flow: PresentationFlow<NotAuthorized> },

    /// Credentials have been identified that match the request.
    Credentials { flow: PresentationFlow<NotAuthorized>, credentials: Vec<Credential> },

    /// The user has approved the presentation.
    Approved { flow: PresentationFlow<Authorized>, credentials: Vec<Credential> },
}

impl PresentationState {
    /// Get the presentation request back from state.
    pub fn get_request(&self) -> Option<String> {
        match self {
            PresentationState::Requested { request_payload } => Some(request_payload.clone()),
            _ => None,
        }
    }

    /// Update the flow after a presentation request has been verified.
    pub fn request_verified(&self, request: &RequestObject) -> anyhow::Result<Self> {
        match self {
            Self::Requested { .. } => {
                let flow = PresentationFlow::<NotAuthorized>::new(request.clone())?;
                Ok(Self::Verified { flow })
            }
            _ => bail!("unexpected presentation state to apply verified request"),
        }
    }

    /// Get a credential filter from the presentation flow state.
    pub fn get_filter(&self) -> anyhow::Result<Constraints> {
        match self {
            PresentationState::Verified { flow } => Ok(flow.filter()?),
            _ => bail!("unexpected presentation state to get filter"),
        }
    }

    /// Update state after credentials have been identified.
    pub fn credentials(&self, credentials: &[Credential]) -> anyhow::Result<Self> {
        let Self::Verified { flow } = self else {
            bail!("unexpected presentation state to apply credentials");
        };
        Ok(Self::Credentials {
            flow: flow.clone(),
            credentials: credentials.to_vec(),
        })
    }

    /// Update state after the user has approved the presentation.
    pub fn approve(&self) -> anyhow::Result<Self> {
        let Self::Credentials { flow, credentials } = self else {
            bail!("unexpected presentation state to approve");
        };
        let updated_flow = flow.clone().authorize(credentials);
        Ok(Self::Approved {
            flow: updated_flow,
            credentials: credentials.to_vec(),
        })
    }

    /// Construct a presentation payload from the presentation flow state.
    pub fn get_payload(&self, kid: &str) -> anyhow::Result<Payload> {
        match self {
            PresentationState::Approved { flow, .. } => Ok(flow.payload(kid)?),
            _ => bail!("unexpected presentation state to get payload"),
        }
    }

    /// Construct a presentation response request.
    pub fn create_response_request(
        &self, jws: &str,
    ) -> anyhow::Result<(ResponseRequest, Option<String>)> {
        match self {
            PresentationState::Approved { flow, .. } => Ok(flow.create_response_request(jws)),
            _ => bail!("unexpected presentation state to create response request"),
        }
    }
}
