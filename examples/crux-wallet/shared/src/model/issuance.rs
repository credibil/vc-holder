//! Issuance sub-app state.
use anyhow::bail;
use base64ct::{Base64, Encoding};
use credibil_holder::credential::{Credential, ImageData};
use credibil_holder::issuance::{
    Accepted, CredentialConfiguration, CredentialOffer, CredentialResponse, CredentialResponseType,
    IssuanceFlow, Issuer, NotAccepted, PreAuthorized, PreAuthorizedCodeGrant, ProofClaims,
    VerifiableCredential, WithOffer, WithToken, WithoutToken,
};
use credibil_holder::provider::{CredentialRequest, TokenRequest, TokenResponse};
use credibil_holder::urlencode;

use crate::config;

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

    /// Update flow based on receiving issuer metadata.
    pub fn issuer_metadata(&self, issuer: Issuer) -> anyhow::Result<Self> {
        let Self::Offered { offer, grant } = self else {
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
        let new_state = Self::IssuerMetadata { flow, offered: creds };
        Ok(new_state)
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

    /// Get the offered credentials.
    pub fn get_offered_credential(&self) -> Option<OfferedCredential> {
        match self {
            Self::IssuerMetadata { offered, .. }
            | Self::Accepted { offered, .. }
            | Self::Token { offered, .. }
            | Self::Proof { offered, .. } => offered.first().cloned(),
            _ => None,
        }
    }

    /// Update the state with credential logo image data.
    /// TODO: Add support for multiple offered credentials.
    pub fn logo(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let Self::IssuerMetadata { flow, offered } = self else {
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
            Ok(new_state)
        } else {
            Ok(self.clone())
        }
    }

    /// Update the state with credential background image data.
    /// TODO: Add support for multiple offered credentials.
    pub fn background(&self, image_data: &[u8], media_type: &str) -> anyhow::Result<Self> {
        let Self::IssuerMetadata { flow, offered } = self else {
            bail!("unexpected issuance state to apply logo");
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
            Ok(new_state)
        } else {
            Ok(self.clone())
        }
    }

    /// Update the flow state with the user accepting the offer (but not yet
    /// providing a PIN).
    pub fn accept(&self) -> anyhow::Result<Self> {
        if let Self::Accepted { .. } = self {
            return Ok(self.clone());
        };
        let Self::IssuerMetadata { flow, offered } = self else {
            bail!("unexpected issuance state to accept offer");
        };
        let updated_flow = flow.clone().accept(&None, None);
        let new_state = Self::Accepted {
            flow: updated_flow,
            offered: offered.clone(),
        };
        Ok(new_state)
    }

    /// Get a token request from the flow state.
    pub fn token_request(&self) -> anyhow::Result<TokenRequest> {
        if let Self::Accepted { flow, .. } = self {
            Ok(flow.token_request())
        } else {
            bail!("unexpected issuance state to get token request");
        }
    }

    /// Add a user-entered PIN to flow state.
    pub fn pin(&self, pin: &str) -> anyhow::Result<Self> {
        let Self::Accepted { flow, offered } = self else {
            bail!("unexpected issuance state to add PIN");
        };
        let mut updated_flow = flow.clone();
        updated_flow.set_pin(pin);
        let new_state = Self::Accepted {
            flow: updated_flow,
            offered: offered.clone(),
        };
        Ok(new_state)
    }

    /// Update state with a token response.
    pub fn token(&self, token: &TokenResponse) -> anyhow::Result<Self> {
        let Self::Accepted { flow, offered } = self else {
            bail!("unexpected issuance state to add token");
        };
        let updated_flow = flow.clone().token(token.clone());
        let new_state = Self::Token {
            flow: updated_flow,
            offered: offered.clone(),
        };
        Ok(new_state)
    }

    /// Get proof claims from the flow state.
    pub fn get_proof_claims(&self) -> anyhow::Result<ProofClaims> {
        let Self::Token { flow, .. } = self else {
            bail!("unexpected issuance state to get proof claims");
        };
        Ok(flow.proof())
    }

    /// Update state with a proof.
    /// TODO: Could extend this to review and refresh existing proof if
    /// proof has expired.
    pub fn proof(&self, encoded_proof: &str) -> anyhow::Result<Self> {
        let Self::Token { flow, offered } = self else {
            bail!("unexpected issuance state to add proof");
        };
        let new_state = Self::Proof {
            flow: flow.clone(),
            offered: offered.clone(),
            proof: encoded_proof.into(),
        };
        Ok(new_state)
    }

    /// Get a credential request for the first offered credential.
    /// TODO: Add support for multiple offered credentials.
    pub fn get_credential_request(&self, jwt: &str) -> anyhow::Result<(String, CredentialRequest)> {
        let Self::Proof { flow, .. } = self else {
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

    /// Retrieve the access token from the flow.
    pub fn get_token(&self) -> anyhow::Result<String> {
        match self {
            Self::Token { flow, .. } | Self::Proof { flow, .. } | Self::Issued { flow, .. } => {
                let token_response = flow.get_token();
                Ok(token_response.access_token)
            }
            _ => bail!("unexpected issuance state to get access token"),
        }
    }

    /// Update state with a credential response.
    pub fn issued(&self, response: &CredentialResponse) -> anyhow::Result<Self> {
        let Self::Proof { flow, offered, proof } = self else {
            bail!("unexpected issuance state to add credential response");
        };
        let new_state = Self::Issued {
            flow: flow.clone(),
            offered: offered.clone(),
            proof: proof.clone(),
            issued: response.clone(),
        };
        Ok(new_state)
    }

    /// Get the credential response from the issuance state.
    pub fn get_issued_credential(&self) -> Option<CredentialResponse> {
        match self {
            Self::Issued { issued, .. } => Some(issued.clone()),
            _ => None,
        }
    }

    /// Add the issued credential to issuance flow state. (This is separated
    /// from `issuance_issued` to allow for async verification of the credential
    /// response).
    /// TODO: Add support for different credential formats.
    pub fn add_credential(
        &self, vc: &VerifiableCredential, issued_at: &i64,
    ) -> anyhow::Result<Self> {
        let Self::Issued {
            flow,
            offered,
            proof,
            issued,
        } = self
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
        Ok(new_state)
    }

    /// Get the credential from the issuance flow that is in a format suitable
    /// for storage and display in the wallet.
    /// TODO: Add support for multiple credentials.
    pub fn get_storable_credential(&self) -> anyhow::Result<Credential> {
        let Self::Issued { flow, .. } = self else {
            bail!("unexpected issuance state to get storable credential");
        };
        let flow_credentials = flow.credentials();
        let Some(credential) = flow_credentials.first() else {
            bail!("no credential in issuance flow");
        };
        Ok(credential.clone())
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
