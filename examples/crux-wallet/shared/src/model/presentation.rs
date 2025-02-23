//! Presentation sub-app state.

use credibil_holder::credential::Credential;
use credibil_holder::presentation::{Authorized, NotAuthorized, PresentationFlow};

/// Application state for the presentation sub-app.
#[derive(Clone, Debug, Default)]
pub enum PresentationState {
    /// No presentation is in progress.
    #[default]
    Inactive,

    /// A presentation request has been received but not yet decoded or
    /// verified.
    Requested {
        request_payload: String,
    },

    /// The presentation request has been decoded and verified.
    Verified {
        flow: PresentationFlow<NotAuthorized>,
    },

    /// Credentials have been identified that match the request.
    Credentials {
        flow: PresentationFlow<NotAuthorized>,
        credentials: Vec<Credential>,
    },

    /// The user has approved the presentation.
    Approved {
        flow: PresentationFlow<Authorized>,
        credentials: Vec<Credential>,
    },
}
