//! Issuance sub-app state.
use anyhow::bail;
use credibil_holder::credential::ImageData;
use credibil_holder::issuance::{
    Accepted, CredentialConfiguration, CredentialOffer, CredentialResponse, IssuanceFlow, Issuer,
    NotAccepted, PreAuthorized, PreAuthorizedCodeGrant, WithOffer, WithToken, WithoutToken,
};
use credibil_holder::urlencode;

/// Configuration and image information for an offered credential.
#[derive(Clone, Debug, Default)]
pub struct OfferedCredential {
    /// Credential configuration identifier.
    pub config_id: String,

    /// Credential configuration.
    pub config: CredentialConfiguration,

    /// Logo image data.
    pub logo: Option<ImageData>,

    /// Background image data.
    pub background: Option<ImageData>,
}

impl OfferedCredential {
    /// Determine if the credential logo needs to be fetched.
    pub fn logo_url(&self) -> Option<String> {
        if self.logo.is_some() {
            return None;
        }
        if let Some(display) = &self.config.display {
            if let Some(logo) = &display[0].logo {
                return logo.uri.clone();
            }
        }
        None
    }

    /// Determine if the credential background needs to be fetched.
    pub fn background_url(&self) -> Option<String> {
        if self.background.is_some() {
            return None;
        }
        if let Some(display) = &self.config.display {
            if let Some(background) = &display[0].background_image {
                return background.uri.clone();
            }
        }
        None
    }
}

/// Application state for the issuance sub-app.
///
/// Note: We use a `Vec` to store the offered credentials because the standard
/// allows for multiple credentials to be offered at once. However, the
/// application event model only supports a single credential at this point in
/// time. The first credential encountered in the offer is the one that will
/// move through the issuance process. Perhaps the solution to this is to
/// check state of each credential and keep raising the same event on each step,
/// but thought is required on the user experience in controlling this "loop".
#[derive(Clone, Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub enum IssuanceState {
    /// No issuance is in progress.
    #[default]
    Inactive,

    /// An offer has been received
    Offered { offer: CredentialOffer, grant: PreAuthorizedCodeGrant },

    /// Issuer metadata has been received. Can use this state to keep updating
    /// the offered credentials' logo and background images.
    IssuerMetadata {
        flow: IssuanceFlow<WithOffer, PreAuthorized, NotAccepted, WithoutToken>,
        offered: Vec<OfferedCredential>,
    },

    /// The offer has been accepted by the user. Can use this state to update
    /// the PIN number if needed.
    Accepted {
        flow: IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithoutToken>,
        offered: Vec<OfferedCredential>,
    },

    /// An access token has been received.
    Token {
        flow: IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithToken>,
        offered: Vec<OfferedCredential>,
    },

    /// A proof has been created. Can use this state to receive credentials and
    /// update the offered list to keep track of outstanding credentials. Can
    /// also use it to keep track of the credentials stored.
    Proof {
        flow: IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithToken>,
        offered: Vec<OfferedCredential>,
        proof: String,
    },

    /// A credential response has been received.
    Issued {
        flow: IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithToken>,
        offered: Vec<OfferedCredential>,
        proof: String,
        issued: CredentialResponse,
    },
}

/// State change implementation.
impl IssuanceState {
    /// Create an issuance state from a URL-encoded offer.
    pub fn from_offer(encoded_offer: &str) -> anyhow::Result<Self> {
        // let Ok(offer_str) = urlencoding::decode(encoded_offer) else {
        //     bail!("failed to url decode offer string");
        // };
        // let Ok(offer) = serde_json::from_str::<CredentialOffer>(&offer_str) else {
        //     bail!("failed to deserialize offer string");
        // };
        let Ok(offer) = urlencode::from_str::<CredentialOffer>(encoded_offer) else {
            bail!("failed to deserialize offer string");
        };

        // Check the offer has a pre-authorized grant. This is the only flow
        // type supported by this wallet (for now).
        let Some(pre_auth_code_grant) = offer.pre_authorized_code() else {
            bail!("grant other than pre-authorized code is not supported");
        };

        Ok(Self::Offered {
            offer,
            grant: pre_auth_code_grant,
        })
    }

    /// Determine if a PIN is required.
    pub fn needs_pin(&self) -> bool {
        match self {
            Self::Accepted { flow, .. } => {
                if flow.pin().is_some() {
                    return false;
                }
                if let Some(pre_auth) = flow.offer().pre_authorized_code() {
                    return pre_auth.tx_code.is_some();
                }
                false
            }
            _ => false,
        }
    }

    /// Cancel the issuance process.
    pub fn cancel(&mut self) -> anyhow::Result<()> {
        // TODO: Reset state
        Ok(())
    }

    /// Get the issuer metadata.
    pub fn issuer(&self) -> Option<Issuer> {
        match self {
            Self::Inactive | Self::Offered { .. } => None,
            Self::IssuerMetadata { flow, .. } => Some(flow.issuer().clone()),
            Self::Accepted { flow, .. } => Some(flow.issuer().clone()),
            Self::Token { flow, .. } => Some(flow.issuer().clone()),
            Self::Proof { flow, .. } => Some(flow.issuer().clone()),
            Self::Issued { flow, .. } => Some(flow.issuer().clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Creating an issuance state from an offer query string yields expected
    // result.
    #[test]
    fn from_offer() {
        let encoded_offer = "credential_issuer=https%3A%2F%2Flight-sheep-safe.ngrok-free.app&credential_configuration_ids=%5B%22EmployeeID_JWT%22%5D&grants=%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22TWxBc3Q0d1poZjg2cVd-UEVWT1k1UE0kWmhyb3QjdUM%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A6%2C%22description%22%3A%22Please%20provide%20the%20one-time%20code%20received%22%7D%7D%7D";
        let state = match IssuanceState::from_offer(encoded_offer) {
            Ok(state) => state,
            Err(e) => panic!("failed to create issuance state: {}", e),
        };
        match state {
            IssuanceState::Offered { offer, grant } => {
                assert_eq!(offer.credential_issuer, "https://light-sheep-safe.ngrok-free.app");
                assert_eq!(offer.credential_configuration_ids, vec!["EmployeeID_JWT"]);
                assert_eq!(
                    grant.pre_authorized_code,
                    "TWxBc3Q0d1poZjg2cVd-UEVWT1k1UE0kWmhyb3QjdUM"
                );
            }
            _ => panic!("unexpected state"),
        }
    }
}
