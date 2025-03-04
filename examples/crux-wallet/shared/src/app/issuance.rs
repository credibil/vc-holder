use credibil_holder::{
    did::Document,
    infosec::{jose::JwsBuilder, Jws},
    issuance::{
        proof::{self, Payload, Type, Verify},
        CredentialResponseType, Issuer, VerifiableCredential,
    },
    provider::{CredentialResponse, TokenResponse},
    Kind,
};
use crux_core::{render::render, Command};
use crux_http::{command::Http, http::mime, HttpError};
use serde::{Deserialize, Serialize};

use std::ops::DerefMut;

use crate::{
    capabilities::{
        key::{KeyStoreCommand, KeyStoreEntry, KeyStoreError},
        store::{Catalog, StoreCommand, StoreError},
    },
    did_resolver::DidResolverProvider,
    model::{IssuanceState, Model, State},
    signer::SignerProvider,
};

use super::{credential::CredentialEvent, Aspect, Effect, Event};

/// Events that can be sent to the wallet application that pertain to the
/// issuance of credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum IssuanceEvent {
    /// Event emitted by the shell when the user wants to scan an issuance offer
    /// QR code.
    ScanOffer,

    /// Event emitted by the shell when the user scans an offer QR code.
    Offer(String),

    /// Event emitted by the core when issuer metadata has been received.
    #[serde(skip)]
    Issuer(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's logo has been
    /// fetched.
    #[serde(skip)]
    Logo(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's background image
    /// has been fetched.
    #[serde(skip)]
    Background(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user has accepted an issuance offer.
    Accepted,

    /// Event emitted by the shell when the user has entered a PIN.
    Pin(String),

    /// Event emitted by the core when an access token has been received.
    #[serde(skip)]
    Token(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a proof has been created.
    #[serde(skip)]
    Proof(String),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    DidResolved(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    SigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a credential has been received.
    #[serde(skip)]
    Credential(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a credential response proof has been
    /// verified.
    #[serde(skip)]
    ProofVerified { vc: VerifiableCredential, issued_at: i64 },

    /// Event emitted by the core when a credential has been stored.
    #[serde(skip)]
    Stored(Result<(), StoreError>),

    /// Event emitted by the shell to cancel an issuance.
    Cancel,
}

/// Issuance event processing.
pub fn issuance_event(event: IssuanceEvent, model: &mut Model) -> Command<Effect, Event> {
    match event {
        IssuanceEvent::ScanOffer => {
            *model = model.scan_issuance_offer();
            render()
        }
        IssuanceEvent::Offer(encoded_offer) => {
            // We have an encoded offer. Parse it and set issuance state.
            *model = match model.issuance_offer(&encoded_offer) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };

            // Fetch issuer metadata.
            let State::Issuance(mut state) = model.state.clone() else {
                return Command::event(Event::Error("unexpected issuance state".into()));
            };
            let IssuanceState::Offered { offer, .. } = state.deref_mut() else {
                return Command::event(Event::Error("expected issuance offer state".into()));
            };
            let issuer_url =
                format!("{}/.well-known/openid-credential-issuer", offer.credential_issuer);
            Http::get(issuer_url)
                .build()
                .then_send(|res| Event::Issuance(IssuanceEvent::Issuer(res)))
        }
        IssuanceEvent::Issuer(Ok(res)) => {
            if !res.status().is_success() {
                return Command::event(Event::Error("issuer metadata fetch failed".into()));
            }
            let Some(body) = &res.body() else {
                return Command::event(Event::Error("no issuer metadata returned".into()));
            };
            let Ok(issuer) = serde_json::from_slice::<Issuer>(body) else {
                return Command::event(Event::Error(
                    "issuer metadata deserialization failed".into(),
                ));
            };

            // Update state with issuer metadata
            *model = match model.issuer_metadata(issuer) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };

            // Fetch logo and background image.
            let Some(cred_info) = model.get_offered_credential() else {
                return Command::event(Event::Error(
                    "no credential configuration found in issuance state".into(),
                ));
            };

            let logo_command: Command<Effect, Event> = match cred_info.logo_url() {
                Some(logo_url) => Http::get(logo_url)
                    .header("accept", "image/*")
                    .build()
                    .then_send(|res| Event::Issuance(IssuanceEvent::Logo(res))),
                None => Command::done(),
            };
            let background_command: Command<Effect, Event> = match cred_info.background_url() {
                Some(background_url) => Http::get(background_url)
                    .header("accept", "image/*")
                    .build()
                    .then_send(|res| Event::Issuance(IssuanceEvent::Background(res))),
                None => Command::done(),
            };
            Command::all([logo_command, background_command, render()])
        }
        IssuanceEvent::Logo(Ok(mut res)) => {
            if !res.status().is_success() {
                return Command::event(Event::Error("credential logo fetch failed".into()));
            }
            let media_type = match res.header("content-type") {
                Some(mt) => mt.to_string(),
                None => "image/*".into(),
            };
            let Ok(image_bytes) = &res.body_bytes() else {
                return Command::event(Event::Error("no logo image bytes returned".into()));
            };
            *model = match model.issuance_logo(image_bytes, &media_type) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            render()
        }
        IssuanceEvent::Background(Ok(mut res)) => {
            if !res.status().is_success() {
                return Command::event(Event::Error(
                    "credential background image fetch failed".into(),
                ));
            }
            let media_type = match res.header("content-type") {
                Some(mt) => mt.to_string(),
                None => "image/*".into(),
            };
            let Ok(image_bytes) = &res.body_bytes() else {
                return Command::event(Event::Error("no background image bytes returned".into()));
            };
            *model = match model.issuance_background(image_bytes, &media_type) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            render()
        }
        IssuanceEvent::Accepted => {
            *model = match model.issuance_accept() {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            if model.issuance_needs_pin() {
                *model = model.active_view(Aspect::IssuancePin);
                return render();
            }

            // Request an access token.
            let Some(issuer) = model.issuer() else {
                return Command::event(Event::Error("expected issuer metadata on state".into()));
            };
            let token_url = format!("{}/token", issuer.credential_issuer);
            let token_request = match model.get_token_request() {
                Ok(tr) => tr,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            let Ok(token_requst_form) = token_request.form_encode() else {
                return Command::event(Event::Error("failed to encode token request form".into()));
            };
            let http_request = match Http::<Effect, Event>::post(token_url)
                .header("accept", mime::JSON)
                .body_form(&token_requst_form)
            {
                Ok(hr) => hr,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            http_request.build().then_send(|res| Event::Issuance(IssuanceEvent::Token(res)))
        }
        IssuanceEvent::Pin(pin) => {
            // Set the PIN then just raise an accepted event again to
            // trigger the next steps.
            *model = match model.issuance_pin(&pin) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            Command::event(Event::Issuance(IssuanceEvent::Accepted))
        }
        IssuanceEvent::Token(Ok(res)) => {
            // Set the token on state.
            if !res.status().is_success() {
                return Command::event(Event::Error("access token request failed".into()));
            }
            let Some(body) = &res.body() else {
                return Command::event(Event::Error("no access token returned".into()));
            };
            let Ok(token_response) = serde_json::from_slice::<TokenResponse>(body) else {
                return Command::event(Event::Error(
                    "token response deserialization failed".into(),
                ));
            };
            *model = match model.issuance_token(&token_response) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };

            // Get a signing key.
            KeyStoreCommand::get("credential", "signing")
                .then_send(|res| Event::Issuance(IssuanceEvent::SigningKey(res)))
        }
        IssuanceEvent::Proof(jws) => {
            *model = match model.issuance_proof(&jws) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            let (_config_id, credential_request) = match model.get_credential_request(&jws) {
                Ok(cr) => cr,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            let Some(issuer) = model.issuer() else {
                return Command::event(Event::Error("expected issuer metadata on state".into()));
            };
            let credential_url = format!("{}/credential", issuer.credential_issuer);
            let access_token = match model.get_issuance_token() {
                Ok(at) => at,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            let http_request = match Http::<Effect, Event>::post(credential_url)
                .header("accept", mime::JSON)
                .header("Authorization", format!("Bearer {}", access_token))
                .body_json(&credential_request)
            {
                Ok(hr) => hr,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            http_request.build().then_send(|res| Event::Issuance(IssuanceEvent::Credential(res)))
        }
        IssuanceEvent::DidResolved(Ok(res)) => {
            if !res.status().is_success() {
                return Command::event(Event::Error("DID document request failed".into()));
            }
            let Some(body) = &res.body() else {
                return Command::event(Event::Error("no DID document returned".into()));
            };
            let Ok(did_document) = serde_json::from_slice::<Document>(body) else {
                return Command::event(Event::Error("DID document deserialization failed".into()));
            };
            println!(">>> DID document: {:#?}", did_document);
            let resolver = DidResolverProvider::new(&did_document);
            let Some(credential_response) = model.get_issued_credential() else {
                return Command::event(Event::Error(
                    "unable to retrieve credential response from model".into(),
                ));
            };
            println!(">>> Credential response: {credential_response:?}");
            match credential_response.response {
                CredentialResponseType::Credential(vc_kind) => {
                    // Single credential in response.
                    Command::new(|ctx| async move {
                        let Payload::Vc { vc, issued_at } =
                            (match proof::verify(Verify::Vc(&vc_kind), resolver).await {
                                Ok(vc) => vc,
                                Err(e) => {
                                    return ctx.send_event(Event::Error(e.to_string()));
                                }
                            })
                        else {
                            return ctx
                                .send_event(Event::Error("unable to verify credential".into()));
                        };
                        ctx.send_event(Event::Issuance(IssuanceEvent::ProofVerified {
                            vc,
                            issued_at,
                        }))
                    })
                }
                _ => Command::event(Event::Error("expected single credential in response".into())),
            }
        }
        IssuanceEvent::SigningKey(Ok(key)) => {
            // Get proof claims
            let bytes: Vec<u8> = key.into();
            let signer = match SignerProvider::new(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            let proof_claims = match model.get_proof_claims() {
                Ok(pc) => pc,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };

            Command::new(|ctx| async move {
                if let Ok(jws) = JwsBuilder::new()
                    .jwt_type(Type::Openid4VciProofJwt)
                    .payload(proof_claims)
                    .add_signer(&signer)
                    .build()
                    .await
                {
                    if let Ok(compact_jws) = jws.encode() {
                        ctx.send_event(Event::Issuance(IssuanceEvent::Proof(compact_jws)))
                    } else {
                        ctx.send_event(Event::Error("unable to encode proof".into()))
                    }
                } else {
                    ctx.send_event(Event::Error("unable to construct proof".into()))
                }
            })
        }
        IssuanceEvent::Credential(Ok(res)) => {
            if !res.status().is_success() {
                return Command::event(Event::Error("credential request failed".into()));
            }
            let Some(body) = &res.body() else {
                return Command::event(Event::Error("no credential returned".into()));
            };
            let Ok(credential_response) = serde_json::from_slice::<CredentialResponse>(body) else {
                return Command::event(Event::Error(
                    "credential response deserialization failed".into(),
                ));
            };
            *model = match model.issuance_issued(&credential_response) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            match credential_response.response {
                CredentialResponseType::Credential(vc_kind) =>
                // Single credential in response.
                // Crux won't let us pass a DID resolver that needs to
                // use the shell, so we have to unpack the JWS and get
                // the key ID and parse the URL to get the DID document.
                // TODO: Support methods other than did:web
                {
                    let Kind::String(compact) = &vc_kind else {
                        return Command::event(Event::Error(
                            "expected response as compact JWT".into(),
                        ));
                    };
                    let jws: Jws = match compact.parse() {
                        Ok(jws) => jws,
                        Err(e) => {
                            return Command::event(Event::Error(e.to_string()));
                        }
                    };
                    let Some(signature) = jws.signatures.first() else {
                        return Command::event(Event::Error(
                            "expected at least one signature in credential response".into(),
                        ));
                    };
                    let header = &signature.protected;
                    let Some(key_id) = header.kid() else {
                        return Command::event(Event::Error(
                            "expected key ID in credential response".into(),
                        ));
                    };
                    let parts = key_id.split('#').collect::<Vec<&str>>();
                    let Some(url_part) = parts.first() else {
                        return Command::event(Event::Error(
                            "expected key ID to contain a URL".into(),
                        ));
                    };
                    println!(">>> Key part: {url_part}");
                    let url = match credibil_holder::did::DidWeb::url(url_part) {
                        Ok(url) => {
                            println! {">>> DidWeb URL: {url}"};
                            url
                        }
                        Err(e) => {
                            return Command::event(Event::Error(e.to_string()));
                        }
                    };
                    Http::get(url)
                        .build()
                        .then_send(|res| Event::Issuance(IssuanceEvent::DidResolved(res)))
                }
                CredentialResponseType::Credentials(_creds) =>
                // Multiple credentials in response.
                // TODO: support this
                {
                    Command::event(Event::Error(
                        "multiple credentials returned but not supported".into(),
                    ))
                }
                CredentialResponseType::TransactionId(_tx_id) =>
                // Deferred transaction ID.
                // TODO: support this
                {
                    Command::event(Event::Error(
                        "deferred transaction ID returned but not supported".into(),
                    ))
                }
            }
        }
        IssuanceEvent::ProofVerified { vc, issued_at } => {
            // Update the model with issued credential information.
            *model = match model.issuance_add_credential(&vc, &issued_at) {
                Ok(m) => m,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            // Store the credential.
            let credential = match model.get_storable_credential() {
                Ok(c) => c,
                Err(e) => {
                    return Command::event(Event::Error(e.to_string()));
                }
            };
            StoreCommand::save(Catalog::Credential.to_string(), credential.id.clone(), credential)
                .then_send(|res| Event::Issuance(IssuanceEvent::Stored(res)))
        }
        IssuanceEvent::Stored(Ok(())) => StoreCommand::list(Catalog::Credential.to_string())
            .then_send(|res| Event::Credential(CredentialEvent::Loaded(res))),
        IssuanceEvent::Cancel => {
            *model = model.ready();
            StoreCommand::list(Catalog::Credential.to_string())
                .then_send(|res| Event::Credential(CredentialEvent::Loaded(res)))
        }
        IssuanceEvent::Stored(Err(error)) => {
            *model = model.error(&error.to_string());
            render()
        }
        IssuanceEvent::Issuer(Err(error))
        | IssuanceEvent::Logo(Err(error))
        | IssuanceEvent::Background(Err(error))
        | IssuanceEvent::Token(Err(error))
        | IssuanceEvent::Credential(Err(error))
        | IssuanceEvent::DidResolved(Err(error)) => {
            *model = model.error(&error.to_string());
            render()
        }
        // Key store errors
        IssuanceEvent::SigningKey(Err(error)) => {
            *model = model.error(&error.to_string());
            render()
        }
    }
}
