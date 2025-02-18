//! # View Model
//! 
pub mod credential;
pub mod issuance;
pub mod presentation;

use credential::CredentialView;
use issuance::IssuanceView;
use presentation::PresentationView;
use serde::{Deserialize, Serialize};

use super::Aspect;

/// View model for the wallet application.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ViewModel {
    /// Which aspect of the application is currently active.
    pub active_view: Aspect,

    /// Credential view model.
    pub credential_view: CredentialView,

    /// Issuance view model.
    pub issuance_view: IssuanceView,

    /// Presentation view model.
    pub presentation_view: PresentationView,

    /// Error message.
    pub error: String,
}
