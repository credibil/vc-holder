//! Presentation flow view models.

use serde::{Deserialize, Serialize};

use super::credential::Credential;
use crate::model::PresentationState;

/// View model for a presentation flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PresentationView {
    /// Credentials requested to be presented.
    /// (TODO: App only supports the first one in the list at this time.)
    pub credentials: Vec<Credential>,
}

impl From<PresentationState> for PresentationView {
    fn from(model_state: PresentationState) -> Self {
        match model_state {
            PresentationState::Inactive
            | PresentationState::Requested { .. }
            | PresentationState::Verified { .. } => Self::default(),
            PresentationState::Credentials { credentials, .. }
            | PresentationState::Approved { credentials, .. } => {
                let view_credentials = credentials.into_iter().map(Into::into).collect();
                Self {
                    credentials: view_credentials,
                }
            }
        }
    }
}
