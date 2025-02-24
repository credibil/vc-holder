//! Credential view models

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use credibil_holder::credential::{Credential as CredentialModel, ImageData};

use crate::model::{CredentialState, OfferedCredential};

/// View model for nested claims
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimView {
    /// The claim name.
    pub name: String,

    /// The claim value.
    pub value: String,
}

impl From<(String, String)> for ClaimView {
    fn from((name, value): (String, String)) -> Self {
        Self { name, value }
    }
}

/// View model for a verifiable credential.
///
/// Matches the `Credential` model from the `credibil-holder` crate as closely
/// as possible but caters for ease of code generation for shells.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Credential {
    /// Credential `id` is the credential's unique identifier
    /// (from Verifiable Credential `id` or generated if credential has no
    /// `id`).
    pub id: String,

    /// The credential issuer ID.
    pub issuer: String,

    /// The issuer's name.
    ///
    /// Empty string if not provided in metadata or if the name is the same as
    /// the issuer ID.
    pub issuer_name: String,

    /// The Verifiable Credential as issued, for use in Presentation
    /// Submissions. This could be a base64-encoded JWT or 'stringified'
    /// JSON.
    pub issued: String,

    /// The credential type. Used to determine whether a credential matches a
    /// presentation request.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// Credential format. Information on how the encoded credential is
    /// formatted.
    pub format: String,

    /// Claims display. The key is the subject ID and the value is the claims
    /// displayed as labelled strings
    pub claims: HashMap<String, Vec<ClaimView>>,

    /// The date the credential was issued as an RFC2822 string.
    pub issuance_date: String,

    /// The date the credential is valid from as an RFC2822 string. Empty string
    /// if not applicable.
    pub valid_from: String,

    /// The date the credential is valid until (expiry) as an RFC2822 string.
    /// Empty string if not applicable.
    pub valid_until: String,

    /// Name from issuer's metadata.
    pub name: String,

    /// Description from issuer's metadata.
    pub description: String,

    /// Background color from issuer's metadata. Empty string if not applicable.
    pub background_color: String,

    /// Text color from issuer's metadata. Empty string if not applicable.
    pub text_color: String,

    /// A base64-encoded logo image for the credential ingested from the logo
    /// url in the display section of the metadata.
    ///
    /// The elements of `ImageData` will be empty strings if the logo has not
    /// been set.
    pub logo: ImageData,

    /// A base64-encoded background image for the credential ingested from the
    /// url in the display section of the metadata.
    ///
    /// The elements of `ImageData` will be empty strings if the background has
    /// not been set.
    pub background: ImageData,
}

impl From<CredentialModel> for Credential {
    fn from(credential: CredentialModel) -> Self {
        let mut claims = HashMap::new();
        for sub_claims in &credential.subject_claims {
            let claims_display = credential.claims_display(sub_claims.id.as_deref(), None);
            let mut claims_view = Vec::new();
            for (name, value) in claims_display {
                claims_view.push((name, value).into());
            }
            claims.insert(sub_claims.id.clone().unwrap_or_default(), claims_view);
        }
        let (name, description, background_color, text_color) = match credential.display {
            Some(display_list) => {
                // TODO: Locale support.
                let display = display_list
                    .clone()
                    .into_iter()
                    .find(|display| display.locale.is_none())
                    .unwrap_or_else(|| display_list[0].clone());
                (
                    display.name,
                    display.description.unwrap_or_default(),
                    display.background_color.unwrap_or_default(),
                    display.text_color.unwrap_or_default(),
                )
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        Self {
            id: credential.id,
            issuer: credential.issuer,
            issuer_name: credential.issuer_name,
            issued: credential.issued,
            type_: credential.type_,
            format: credential.format,
            claims,
            issuance_date: credential.issuance_date.format("%a, %d %b %Y").to_string(),
            valid_from: credential
                .valid_from
                .map_or_else(String::new, |date| date.format("%a, %d %b %Y").to_string()),
            valid_until: credential
                .valid_until
                .map_or_else(String::new, |date| date.format("%a, %d %b %Y").to_string()),
            name,
            description,
            background_color,
            text_color,
            logo: credential.logo.unwrap_or_default(),
            background: credential.background.unwrap_or_default(),
        }
    }
}

impl Credential {
    /// Convert an offer into a credential view.
    ///
    /// Some data is empty. We just use the credential data shape as a template.
    pub fn from_offer(issuer: &str, issuer_name: &str, offered: OfferedCredential) -> Self {
        let mut claims = HashMap::new();
        let claims_display = offered.config.claims_display(None);
        let mut claims_view = Vec::new();
        for name in claims_display {
            claims_view.push((name, String::new()).into());
        }
        claims.insert(String::new(), claims_view);
        let (name, description, background_color, text_color) = match offered.config.display {
            Some(display_list) => {
                // TODO: Locale support.
                let display = display_list
                    .clone()
                    .into_iter()
                    .find(|display| display.locale.is_none())
                    .unwrap_or_else(|| display_list[0].clone());
                (
                    display.name,
                    display.description.unwrap_or_default(),
                    display.background_color.unwrap_or_default(),
                    display.text_color.unwrap_or_default(),
                )
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        Self {
            issuer: issuer.into(),
            issuer_name: issuer_name.into(),
            claims,
            name,
            description,
            background_color,
            text_color,
            logo: offered.logo.unwrap_or_default(),
            background: offered.background.unwrap_or_default(),
            ..Default::default()
        }
    }
}

/// View for the verifiable credential sub-app
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CredentialView {
    /// Currently active credential ID
    pub id: Option<String>,

    /// List of stored credentials
    pub credentials: Vec<Credential>,
}

impl From<CredentialState> for CredentialView {
    fn from(state: CredentialState) -> Self {
        Self {
            id: state.id,
            credentials: state.credentials.into_iter().map(Credential::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot;
    use credibil_holder::issuance::CredentialConfiguration;

    use super::*;

    // Test conversion of a `Credential` model to a `Credential` view.
    #[test]
    fn test_credential_from_model() {
        let json = include_bytes!("../model/credentials.json");
        let credentials: Vec<CredentialModel> =
            serde_json::from_slice(json).expect("should deserialize");
        assert_eq!(credentials.len(), 2);

        let credential = Credential::from(credentials[0].clone());
        assert_yaml_snapshot!("employee", credential, {
            ".claims.**" => insta::sorted_redaction()
        });

        let credential = Credential::from(credentials[1].clone());
        assert_yaml_snapshot!("developer", credential,{
            ".claims.**" => insta::sorted_redaction()
        });
    }

    // Test conversion of an offer to a `Credential` view.
    #[test]
    fn test_credential_from_offer() {
        let json = serde_json::json!({
            "format": "jwt_vc_json",
            "scope": "EmployeeIDCredential",
            "cryptographic_binding_methods_supported": [
                "did:key",
                "did:web"
            ],
            "credential_signing_alg_values_supported": [
                "ES256K",
                "EdDSA"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256K",
                        "EdDSA"
                    ]
                }
            },
            "display": [
                {
                    "name": "Employee ID",
                    "description": "Credibil employee ID credential",
                    "locale": "en-NZ",
                    "logo": {
                        "uri": "https://credibil.io/assets/employee.png",
                        "alt_text": "Employee ID Logo"
                    },
                    "text_color": "#ffffff",
                    "background_color": "#323ed2",
                    "background_image": {
                        "uri": "https://credibil.io/assets/employee-background.png",
                        "alt_text": "Employee Background"
                    }
                }
            ],
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ],
                "credentialSubject": {
                    "email": {
                        "mandatory": true,
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Email",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "family_name": {
                        "mandatory": true,
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Family name",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "given_name": {
                        "mandatory": true,
                        "value_type": "string",
                        "display": [
                            {
                                "name": "Given name",
                                "locale": "en-NZ"
                            }
                        ]
                    },
                    "address": {
                        "street_address": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Street Address",
                                    "locale": "en-NZ"
                                }
                            ]
                        },
                        "locality": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Locality",
                                    "locale": "en-NZ"
                                }
                            ]
                        },
                        "region": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Region",
                                    "locale": "en-NZ"
                                }
                            ]
                        },
                        "country": {
                            "value_type": "string",
                            "display": [
                                {
                                    "name": "Country",
                                    "locale": "en-NZ"
                                }
                            ]
                        }
                    }
                }
            }
        });
        let config: CredentialConfiguration =
            serde_json::from_value(json.clone()).expect("should deserialize from json");
        let offer = OfferedCredential {
            config_id: "EmployeeID_JWT".into(),
            config,
            logo: None,
            background: None,
        };
        let credential = Credential::from_offer("issuer", "Issuer", offer);
        assert_yaml_snapshot!("offer", credential, {
            ".claims.**" => insta::sorted_redaction()
        });
    }
}
