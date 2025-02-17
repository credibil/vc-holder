//! Issuance flow view models.

use serde::{Deserialize, Serialize};

use super::credential::Credential;
use crate::model::IssuanceState;

/// View-friendly representation of a transaction code specification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxCode {
    /// The type of characters expected. Will be "numeric" or "text".
    pub input_mode: String,

    /// The number of characters expected. Zero if not applicable.
    pub length: i32,

    /// Helper text to display to the user.
    pub description: String,
}

impl Default for TxCode {
    fn default() -> Self {
        Self {
            input_mode: "numeric".into(),
            length: 0,
            description: "".into(),
        }
    }
}

impl From<Option<credibil_holder::issuance::TxCode>> for TxCode {
    fn from(tx_code: Option<credibil_holder::issuance::TxCode>) -> Self {
        match tx_code {
            Some(tx_code) => Self {
                input_mode: tx_code.input_mode.unwrap_or("numeric".into()),
                length: tx_code.length.unwrap_or_default(),
                description: tx_code.description.unwrap_or_default(),
            },
            None => Self::default(),
        }
    }
}

/// View model for an issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct IssuanceView {
    /// Credentials on offer.
    pub credentials: Vec<Credential>,

    /// PIN as entered by the user.
    pub pin: String,

    /// PIN requirements.
    pub tx_code: TxCode,
}

impl From<IssuanceState> for IssuanceView {
    fn from(model_state: IssuanceState) -> Self {
        let mut credentials = Vec::new();

        let (on_offer, issuer, offer, pin) = match model_state {
            IssuanceState::Inactive | IssuanceState::Offered { .. } => return Self::default(),
            IssuanceState::IssuerMetadata { flow, offered } => {
                (offered, flow.issuer(), flow.offer(), None)
            }
            IssuanceState::Accepted { flow, offered } => {
                (offered, flow.issuer(), flow.offer(), flow.pin())
            }
            IssuanceState::Token { flow, offered } => {
                (offered, flow.issuer(), flow.offer(), flow.pin())
            }
            IssuanceState::Proof { flow, offered, .. } => {
                (offered, flow.issuer(), flow.offer(), flow.pin())
            }
            IssuanceState::Issued { flow, offered, .. } => {
                (offered, flow.issuer(), flow.offer(), flow.pin())
            }
        };

        for offered_credential in &on_offer {
            let name = issuer.display_name(None).unwrap_or_default();
            let cred = Credential::from_offer(
                &issuer.credential_issuer,
                &name,
                offered_credential.clone(),
            );
            credentials.push(cred);
        }

        let tx_code = match offer.pre_authorized_code() {
            Some(grant) => TxCode::from(grant.tx_code.clone()),
            None => TxCode::default(),
        };

        Self {
            credentials,
            pin: pin.unwrap_or_default(),
            tx_code,
        }
    }
}
