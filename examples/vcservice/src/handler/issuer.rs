//! # Request handlers for issuer endpoints.

use std::collections::HashMap;
use std::vec;

use anyhow::anyhow;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Result;
use axum::{Form, Json};
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use credibil_vc::issuer::{
    CredentialDisplay, CredentialRequest, CredentialResponse, Image, MetadataRequest, MetadataResponse, OfferType, SendType, TokenRequest, TokenResponse
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use typeshare::typeshare;

use super::{AppError, AppJson};
use crate::AppState;

/// Create offer request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[typeshare]
pub struct CreateOfferRequest {
    /// Credential issuer identifier (URL).
    pub credential_issuer: String,

    /// Issuer's identifier of the intended holder of the credential.
    pub subject_id: String,

    /// The identifier of the type of credential to be issued.
    pub credential_configuration_id: String,

    /// Type of authorization grant to include in the offer.
    pub grant_type: String,

    /// Whether or not a PIN is required to validate requester of the credential
    /// offer is the person accepting the credential.
    pub tx_code_required: bool,
}

/// Create offer response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[typeshare]
pub struct CreateOfferResponse {
    /// QR code for the credential offer
    pub qr_code: String,

    /// PIN code required to accept the credential offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,

    /// Contents of the offer as a JSON string.
    pub offer_json: String,
}

// Create a credential offer
#[axum::debug_handler]
pub async fn create_offer(
    State(state): State<AppState>, Json(req): Json<CreateOfferRequest>,
) -> Result<AppJson<CreateOfferResponse>, AppError> {
    let gt = format!("\"{}\"", req.grant_type);
    let Ok(grant_type) = serde_json::from_str(&gt) else {
        return Err(anyhow!("invalid grant type: {}", req.grant_type).into());
    };

    let request = credibil_vc::issuer::CreateOfferRequest {
        credential_issuer: state.issuer.to_string(),
        subject_id: Some(req.subject_id),
        credential_configuration_ids: vec![req.credential_configuration_id.clone()],
        grant_types: Some(vec![grant_type]),
        tx_code_required: req.tx_code_required,
        send_type: SendType::ByVal,
    };

    let response: credibil_vc::issuer::CreateOfferResponse =
        credibil_vc::issuer::create_offer(state.issuer_provider, request).await?;
    let mut offer = match response.offer_type {
        OfferType::Object(offer) => offer,
        OfferType::Uri(s) => return Err(anyhow!("unexpected URI offer {s}").into()),
    };
    if offer.credential_configuration_ids.len() != 1 {
        return Err(anyhow!("expected 1 credential configuration ID").into());
    }
    if offer.credential_configuration_ids[0] != req.credential_configuration_id {
        return Err(anyhow!("unexpected credential configuration ID").into());
    }

    // Override the issuer's identifier with the environment variable if it
    // exists so our hardcoded data can work with our hosting location.
    offer.credential_issuer = state.external_address.to_string();

    let qr_code = offer.to_qrcode("openid-credential-offer://credential_offer=")?;
    let offer_json = serde_json::to_string(&offer).map_err(|e| anyhow!(e))?;
    let rsp = CreateOfferResponse {
        qr_code,
        tx_code: response.tx_code,
        offer_json,
    };

    Ok(AppJson(rsp))
}

// Metadata endpoint
#[axum::debug_handler]
pub async fn metadata(
    headers: HeaderMap, State(state): State<AppState>,
) -> Result<AppJson<MetadataResponse>, AppError> {
    let request = MetadataRequest {
        credential_issuer: state.issuer.to_string(),
        languages: headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string),
    };
    let mut response =
        credibil_vc::issuer::metadata(state.issuer_provider.clone(), request).await?;

    // Override the issuer's endpoint information with the environment variable
    // if it exists so our hardcoded data can work with our hosting location.
    let existing_issuer = response.credential_issuer.credential_issuer.clone();
    tracing::debug!("existing issuer: {existing_issuer}");
    response.credential_issuer.credential_issuer = state.external_address.to_string();
    response.credential_issuer.credential_endpoint =
        format!("{}/credential", state.external_address);
    response.credential_issuer.deferred_credential_endpoint =
        Some(format!("{}/deferred", state.external_address));
    // Display image file URLs
    let mut updated_supported =
        response.credential_issuer.credential_configurations_supported.clone();
    for (id, config) in &response.credential_issuer.credential_configurations_supported {
        let mut updated_config = config.clone();
        if let Some(config_display) = &config.display {
            let mut display = Vec::<CredentialDisplay>::new();
            for locale in config_display {
                let mut updated_locale = locale.clone();
                if let Some(logo) = &locale.logo {
                    if let Some(uri) = &logo.uri {
                        let updated_uri = uri.replace(&existing_issuer, &state.external_address);
                        updated_locale.logo = Some(Image {
                            uri: Some(updated_uri),
                            alt_text: logo.alt_text.clone(),
                        })
                    }
                }
                if let Some(background) = &locale.background_image {
                    if let Some(uri) = &background.uri {
                        let updated_uri = uri.replace(&existing_issuer, &state.external_address);
                        updated_locale.background_image = Some(Image {
                            uri: Some(updated_uri),
                            alt_text: background.alt_text.clone(),
                        })
                    }
                }
                display.push(updated_locale);
            }
            updated_config.display = Some(display);
        }
        updated_supported.insert(id.clone(), updated_config);
    }
    response.credential_issuer.credential_configurations_supported = updated_supported;

    Ok(AppJson(response))
}

// DID document endpoint
#[axum::debug_handler]
pub async fn did(State(state): State<AppState>) -> Result<AppJson<Value>, AppError> {
    let val = did_json(&state.external_address)?;
    Ok(AppJson(val))
}

// DID document as JSON to be used in handler or can be called directly (see
// verifier provider for example).
pub fn did_json(external_address: &str) -> anyhow::Result<Value> {
    let did_json = r#"{
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": "did:web:credibil.io",
        "verificationMethod": [
            {
            "id": "did:web:credibil.io#key-0",
            "controller": "did:web:credibil.io",
            "type": "Multikey",
            "publicKeyMultibase": "z6MkqvVfz2B1brqmXTWgMAQQZXwgy3h5Xx4iJ5yvfnr4UGhP"
            }
        ],
        "authentication": [
            "did:web:credibil.io#key-0"
        ],
        "assertionMethod": [
            "did:web:credibil.io#key-0"
        ],
        "keyAgreement": [
            {
            "id": "did:web:credibil.io#key-1",
            "controller": "did:web:credibil.io",
            "type": "Multikey",
            "publicKeyMultibase": "z6LSjMo5EKYp5HujrgoRCSmTA1w3ei6cNVQpP7dFhcu65PTc"
            }
        ],
        "capabilityInvocation": [
            "did:web:credibil.io#key-0"
        ],
        "capabilityDelegation": [
            "did:web:credibil.io#key-0"
        ]
        }"#;
    let parts = external_address.split("//").collect::<Vec<&str>>();
    let override_domain = *parts.get(1).unwrap_or(&"credibil.io");
    let did_json = did_json.replace("credibil.io", override_domain);
    let val = serde_json::from_str(&did_json).map_err(|e| anyhow!(e))?;
    Ok(val)
}

// Token endpoint
#[axum::debug_handler]
pub async fn token(
    State(state): State<AppState>, Form(req): Form<HashMap<String, String>>,
) -> Result<AppJson<TokenResponse>, AppError> {
    tracing::debug!("raw token request: {req:?}");
    let Ok(mut token_request) = TokenRequest::form_decode(&req) else {
        return Err(AppError::Status(
            StatusCode::BAD_REQUEST,
            format!("unable to turn HashMap {req:?} into TokenRequest"),
        ));
    };
    token_request.credential_issuer = state.issuer.to_string();
    tracing::debug!("decoded token request: {token_request:?}");

    let response = credibil_vc::issuer::token(state.issuer_provider.clone(), token_request).await?;
    Ok(AppJson(response))
}

// Credential endpoint
#[axum::debug_handler]
pub async fn credential(
    State(state): State<AppState>, TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(mut req): Json<CredentialRequest>,
) -> Result<AppJson<CredentialResponse>, AppError> {
    req.credential_issuer = state.issuer.to_string();
    req.access_token = auth.token().to_string();

    let response = credibil_vc::issuer::credential(state.issuer_provider.clone(), req).await?;
    Ok(AppJson(response))
}
