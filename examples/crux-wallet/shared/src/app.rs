//! This module contains the core application fabric for the wallet, including
//! the model, events, and effects that drive the application.

use std::ops::{Deref, DerefMut};

use credibil_holder::Kind;
use credibil_holder::credential::Credential;
use credibil_holder::did::Document;
use credibil_holder::infosec::jose::{Jws, JwsBuilder};
use credibil_holder::issuance::proof::{self, Payload, Type, Verify};
use credibil_holder::issuance::{
    CredentialResponse, CredentialResponseType, Issuer, TokenResponse, VerifiableCredential,
};
use credibil_holder::presentation::{
    self, RequestObject as VerifierRequestObject, RequestObjectResponse, RequestObjectType,
    parse_request_object_jwt,
};
use crux_core::Command;
use crux_core::render::{Render, render};
use crux_http::HttpError;
use crux_http::command::Http;
use crux_http::http::mime;
use crux_kv::KeyValue;
use serde::{Deserialize, Serialize};

use crate::capabilities::key::{KeyStore, KeyStoreCommand, KeyStoreEntry, KeyStoreError};
use crate::capabilities::sse::ServerSentEvents;
use crate::capabilities::store::{Catalog, Store, StoreCommand, StoreEntry, StoreError};
use crate::did_resolver::DidResolverProvider;
use crate::model::{IssuanceState, Model};
use crate::signer::SignerProvider;
use crate::view::ViewModel;

/// Aspect of the application.
///
/// This allows the UI navigation to be reactive: controlled in response to the
/// user's actions. Although Crux can handle sub-apps, this is the intended way
/// to handle views unless the application is very complex.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Aspect {
    /// Display and deletion of credentials stored in the wallet.
    #[default]
    CredentialList,

    /// Display of a single credential.
    CredentialDetail,

    /// Trigger a credential issuance using an offer QR code.
    IssuanceScan,

    /// View the offer details to decide whether or not to proceed with
    /// issuance.
    IssuanceOffer,

    /// Display user PIN input.
    IssuancePin,

    /// Trigger a credential verification using a presentation request QR code.
    PresentationScan,

    /// View the presentation request details to decide whether or not to
    /// proceed with presentation to the verifier.
    PresentationRequest,

    /// Display a message to the user that the credential verification was
    /// successful.
    PresentationSuccess,

    /// The application is in an error state.
    Error,
}

/// Events that can be sent to the wallet application.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Error event is emitted by the core when an error occurs.
    #[serde(skip)]
    Error(String),

    //--- Credential events ----------------------------------------------------
    /// Event emitted by the shell when the app first loads.
    Ready,

    /// Event emitted by the shell to select a credential from the list of
    /// stored credentials for detailed display.
    SelectCredential(String),

    /// Event emitted by the shell to delete a credential from the wallet.
    DeleteCredential(String),

    /// Event emitted by the core when the store capability has loaded
    /// credentials.
    #[serde(skip)]
    CredentialsLoaded(Result<Vec<StoreEntry>, StoreError>),

    /// Event emitted by the core when the store capability has stored a
    /// credential.
    #[serde(skip)]
    CredentialStored(Result<(), StoreError>),

    /// Event emitted by the core when the store capability has deleted a
    /// credential.
    #[serde(skip)]
    CredentialDeleted(Result<(), StoreError>),

    //--- Issuance events ------------------------------------------------------
    /// Event emitted by the shell when the user wants to scan an issuance offer
    /// QR code.
    ScanIssuanceOffer,

    /// Event emitted by the shell when the user scans an offer QR code.
    IssuanceOffer(String),

    /// Event emitted by the core when issuer metadata has been received.
    #[serde(skip)]
    IssuanceIssuer(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's logo has been
    /// fetched.
    #[serde(skip)]
    IssuanceLogo(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when an offered credential's background image
    /// has been fetched.
    #[serde(skip)]
    IssuanceBackground(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user has accepted an issuance offer.
    IssuanceAccepted,

    /// Event emitted by the shell when the user has entered a PIN.
    IssuancePin(String),

    /// Event emitted by the core when an access token has been received.
    #[serde(skip)]
    IssuanceToken(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a proof has been created.
    #[serde(skip)]
    IssuanceProof(String),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    IssuanceDidResolve(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    IssuanceSigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a credential has been received.
    #[serde(skip)]
    IssuanceCredential(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a credential response proof has been
    /// verified.
    #[serde(skip)]
    IssuanceProofVerified { vc: VerifiableCredential, issued_at: i64 },

    /// Event emitted by the core when a credential has been stored.
    #[serde(skip)]
    IssuanceStored(Result<(), StoreError>),

    /// Event emitted by the shell to cancel an issuance.
    CancelIssuance,

    //--- Presentation events --------------------------------------------------
    /// Event emitted by the shell when the user wants to scan a presentation
    /// request QR code.
    ScanPresentationRequest,

    /// Event emitted by the shell when the user scans a presentation request QR
    /// code.
    ///
    /// We expect the string to be a URL to a presentation request. Cross-device
    /// flow.
    PresentationRequest(String),

    /// Event emitted by the core when a presentation request has been received.
    #[serde(skip)]
    PresentationRequestReceived(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    PresentationDidResolve(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when the presentation request has been
    /// verified and decoded.
    #[serde(skip)]
    PresentationRequestVerified(Box<VerifierRequestObject>),

    /// Event emitted by the core when all credentials have been loaded from
    /// storage, before they are filtered.
    #[serde(skip)]
    PresentationCredentialsLoaded(Result<Vec<StoreEntry>, StoreError>),

    /// Event emitted by the core when at least one credential has been found
    /// that matches the presentation request.
    #[serde(skip)]
    PresentationCredentialsFound(Vec<Credential>),

    /// Event emitted by the shell when a user approves the presentation of
    /// the credential to the verifier.
    ///
    /// TODO: We only let the user send the first matching credential for now.
    /// If the app extends to support a choice we would need to know which one
    /// has been selected here.
    PresentationApproved,

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    PresentationSigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a proof has been constructed.
    ///
    /// The string is a proof JWT.
    #[serde(skip)]
    PresentationProof(String),

    /// Event emitted by the core when the verifier responds to the
    /// presentation.
    #[serde(skip)]
    PresentationResponse(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user wants to cancel a presentation.
    CancelPresentation,
}

/// Set of capabilities available to the application.
#[cfg_attr(feature = "typegen", derive(crux_core::macros::Export))]
#[derive(crux_core::macros::Effect)]
pub struct Capabilities {
    pub render: Render<Event>,
    pub http: crux_http::Http<Event>,
    pub key_store: KeyStore<Event>,
    pub kv: KeyValue<Event>,
    pub sse: ServerSentEvents<Event>,
    pub store: Store<Event>,
}

#[derive(Default)]
pub struct App;

impl crux_core::App for App {
    type Capabilities = Capabilities;
    type Effect = Effect;
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;

    fn update(
        &self, msg: Self::Event, model: &mut Self::Model, _caps: &Self::Capabilities,
    ) -> Command<Effect, Event> {
        match msg {
            Event::Error(e) => {
                *model = model.error(&e);
                render()
            }
            Event::Ready | Event::CancelIssuance | Event::CancelPresentation => {
                *model = model.ready();
                StoreCommand::list(Catalog::Credential.to_string())
                    .then_send(Event::CredentialsLoaded)
            }
            Event::SelectCredential(id) => {
                *model = model.select_credential(&id);
                render()
            }
            Event::DeleteCredential(id) => {
                StoreCommand::delete("credential", id).then_send(Event::CredentialDeleted)
            }
            Event::CredentialsLoaded(Ok(entries)) => {
                *model = model.credentials_loaded(entries);
                render()
            }
            Event::CredentialStored(Ok(())) | Event::CredentialDeleted(Ok(())) => {
                StoreCommand::list(Catalog::Credential.to_string())
                    .then_send(Event::CredentialsLoaded)
            }
            Event::ScanIssuanceOffer => {
                *model = model.scan_issuance_offer();
                render()
            }
            Event::IssuanceOffer(encoded_offer) => {
                // We have an encoded offer. Parse it and set issuance state.
                *model = match model.issuance_offer(&encoded_offer) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };

                // Fetch issuer metadata.
                let Model::Issuance { state, .. } = model else {
                    return Command::event(Event::Error("unexpected issuance state".into()));
                };
                let IssuanceState::Offered { offer, .. } = state.deref_mut() else {
                    return Command::event(Event::Error("expected issuance offer state".into()));
                };
                let issuer_url =
                    format!("{}/.well-known/openid-credential-issuer", offer.credential_issuer);
                Http::get(issuer_url).build().then_send(Event::IssuanceIssuer)
            }
            Event::IssuanceIssuer(Ok(res)) => {
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
                *model = model.active_view(Aspect::IssuanceOffer);

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
                        .then_send(Event::IssuanceLogo),
                    None => Command::done(),
                };
                let background_command: Command<Effect, Event> = match cred_info.background_url() {
                    Some(background_url) => Http::get(background_url)
                        .header("accept", "image/*")
                        .build()
                        .then_send(Event::IssuanceBackground),
                    None => Command::done(),
                };
                Command::all([logo_command, background_command, render()])
            }
            Event::IssuanceLogo(Ok(mut res)) => {
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
            Event::IssuanceBackground(Ok(mut res)) => {
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
                    return Command::event(Event::Error(
                        "no background image bytes returned".into(),
                    ));
                };
                *model = match model.issuance_background(image_bytes, &media_type) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                *model = model.active_view(Aspect::IssuanceOffer);
                render()
            }
            Event::IssuanceAccepted => {
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
                    return Command::event(Event::Error(
                        "expected issuer metadata on state".into(),
                    ));
                };
                let token_url = format!("{}/token", issuer.credential_issuer);
                let token_request = match model.get_token_request() {
                    Ok(tr) => tr,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let Ok(token_requst_form) = token_request.form_encode() else {
                    return Command::event(Event::Error(
                        "failed to encode token request form".into(),
                    ));
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
                http_request.build().then_send(Event::IssuanceToken)
            }
            Event::IssuancePin(pin) => {
                // Set the PIN then just raise an accepted event again to
                // trigger the next steps.
                *model = match model.issuance_pin(&pin) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                Command::event(Event::IssuanceAccepted)
            }
            Event::IssuanceToken(Ok(res)) => {
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
                KeyStoreCommand::get("credential", "signing").then_send(Event::IssuanceSigningKey)
            }
            Event::IssuanceSigningKey(Ok(key)) => {
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
                            ctx.send_event(Event::IssuanceProof(compact_jws))
                        } else {
                            ctx.send_event(Event::Error("unable to encode proof".into()))
                        }
                    } else {
                        ctx.send_event(Event::Error("unable to construct proof".into()))
                    }
                })
            }
            Event::IssuanceProof(jws) => {
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
                    return Command::event(Event::Error(
                        "expected issuer metadata on state".into(),
                    ));
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
                http_request.build().then_send(Event::IssuanceCredential)
            }
            Event::IssuanceCredential(Ok(res)) => {
                if !res.status().is_success() {
                    return Command::event(Event::Error("credential request failed".into()));
                }
                let Some(body) = &res.body() else {
                    return Command::event(Event::Error("no credential returned".into()));
                };
                let Ok(credential_response) = serde_json::from_slice::<CredentialResponse>(body)
                else {
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
                        Http::get(url).build().then_send(Event::IssuanceDidResolve)
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
            Event::IssuanceDidResolve(Ok(res)) => {
                if !res.status().is_success() {
                    return Command::event(Event::Error("DID document request failed".into()));
                }
                let Some(body) = &res.body() else {
                    return Command::event(Event::Error("no DID document returned".into()));
                };
                let Ok(did_document) = serde_json::from_slice::<Document>(body) else {
                    return Command::event(Event::Error(
                        "DID document deserialization failed".into(),
                    ));
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
                                return ctx.send_event(Event::Error(
                                    "unable to verify credential".into(),
                                ));
                            };
                            ctx.send_event(Event::IssuanceProofVerified { vc, issued_at })
                        })
                    }
                    _ => Command::event(Event::Error(
                        "expected single credential in response".into(),
                    )),
                }
            }
            Event::IssuanceProofVerified { vc, issued_at } => {
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
                StoreCommand::save(
                    Catalog::Credential.to_string(),
                    credential.id.clone(),
                    credential,
                )
                .then_send(Event::IssuanceStored)
            }
            Event::IssuanceStored(Ok(())) => StoreCommand::list(Catalog::Credential.to_string())
                .then_send(Event::CredentialsLoaded),
            Event::ScanPresentationRequest => {
                *model = model.scan_presentation_request();
                render()
            }
            Event::PresentationRequest(url) => {
                println!(">>> Presentation request URL: {url}");
                // Fetch the presentation request from the verifier's service.
                Http::get(url).build().then_send(Event::PresentationRequestReceived)
            }
            Event::PresentationRequestReceived(Ok(res)) => {
                if !res.status().is_success() {
                    return Command::event(Event::Error(
                        "presentation request fetch failed".into(),
                    ));
                }
                let Some(body) = &res.body() else {
                    return Command::event(Event::Error("no presentation request returned".into()));
                };
                let Ok(request_object_response) =
                    serde_json::from_slice::<RequestObjectResponse>(body)
                else {
                    return Command::event(Event::Error(
                        "presentation request deserialization failed".into(),
                    ));
                };
                let RequestObjectType::Jwt(token) = request_object_response.request_object else {
                    return Command::event(Event::Error(
                        "expected presentation request as JWT".into(),
                    ));
                };
                let jws: Jws = match token.parse() {
                    Ok(jws) => jws,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                // Store the payload in state while we deal with the DID.
                *model = match model.presentation_request(&token) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let Some(signature) = jws.signatures.first() else {
                    return Command::event(Event::Error(
                        "expected at least one signature in presentation request".into(),
                    ));
                };
                let header = &signature.protected;
                let Some(key_id) = header.kid() else {
                    return Command::event(Event::Error(
                        "expected key ID in presentation request".into(),
                    ));
                };
                let parts = key_id.split('#').collect::<Vec<&str>>();
                let Some(url_part) = parts.first() else {
                    return Command::event(Event::Error("expected key ID to contain a URL".into()));
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
                Http::get(url).build().then_send(Event::PresentationDidResolve)
            }
            Event::PresentationDidResolve(Ok(res)) => {
                if !res.status().is_success() {
                    return Command::event(Event::Error("DID document request failed".into()));
                }
                let Some(body) = &res.body() else {
                    return Command::event(Event::Error("no DID document returned".into()));
                };
                let Ok(did_document) = serde_json::from_slice::<Document>(body) else {
                    return Command::event(Event::Error(
                        "DID document deserialization failed".into(),
                    ));
                };
                println!(">>> DID document: {:#?}", did_document);
                let resolver = DidResolverProvider::new(&did_document);
                let Some(presentation_request) = model.get_presentation_request() else {
                    return Command::event(Event::Error(
                        "unable to retrieve presentation request from model".into(),
                    ));
                };
                Command::new(|ctx| async move {
                    let req_obj =
                        match parse_request_object_jwt(&presentation_request, resolver).await {
                            Ok(jwt) => jwt,
                            Err(e) => {
                                return ctx.send_event(Event::Error(e.to_string()));
                            }
                        };
                    ctx.send_event(Event::PresentationRequestVerified(Box::new(req_obj)));
                })
            }
            Event::PresentationRequestVerified(req) => {
                *model = match model.presentation_request_verified(&req) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                // Load credentials from storage.
                StoreCommand::list(Catalog::Credential.to_string())
                    .then_send(Event::PresentationCredentialsLoaded)
            }
            Event::PresentationCredentialsLoaded(Ok(entries)) => {
                // Find credentials that match the request.
                let filter = match model.get_presentation_filter() {
                    Ok(f) => f,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let mut credentials = vec![];
                for entry in entries {
                    if let StoreEntry::Data(bytes) = entry {
                        let credential: Credential =
                            serde_json::from_slice(&bytes).expect("should deserialize");
                        match filter.satisfied(&credential) {
                            Ok(true) => credentials.push(credential.clone()),
                            Ok(false) => continue,
                            Err(e) => {
                                return Command::event(Event::Error(e.to_string()));
                            }
                        }
                    }
                }
                Command::event(Event::PresentationCredentialsFound(credentials))
            }
            Event::PresentationCredentialsFound(creds) => {
                if creds.is_empty() {
                    return Command::event(Event::Error("No matching credentials found".into()));
                }
                // Present the credentials to the user.
                *model = match model.presentation_credentials(&creds) {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                render()
            }
            Event::PresentationApproved => {
                // Authorize the presentation.
                *model = match model.presentation_approve() {
                    Ok(m) => m,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                // Get a signing key.
                KeyStoreCommand::get("credential", "signing")
                    .then_send(Event::PresentationSigningKey)
            }
            Event::PresentationSigningKey(Ok(key)) => {
                let bytes: Vec<u8> = key.into();
                let signer = match SignerProvider::new(&bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let kid = match signer.verification_method_sync() {
                    Ok(kid) => kid,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let vp = match model.get_presentation_payload(&kid) {
                    Ok(vp) => vp,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let Payload::Vp { vp, client_id, nonce } = vp else {
                    return Command::event(Event::Error("expected presentation payload".into()));
                };
                Command::new(|ctx| async move {
                    match presentation::proof::create(
                        presentation::proof::W3cFormat::JwtVcJson,
                        Payload::Vp { vp, client_id, nonce },
                        &signer,
                    )
                    .await
                    {
                        Ok(jws) => ctx.send_event(Event::PresentationProof(jws)),
                        Err(e) => ctx.send_event(Event::Error(e.to_string())),
                    }
                })
            }
            Event::PresentationProof(jws) => {
                let (res_req, uri) = match model.create_response_request(&jws) {
                    Ok(rr) => rr,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                let Some(res_uri) = uri else {
                    return Command::event(Event::Error("no URI to send presentation to".into()));
                };
                println!(">>> Presentation response URI: {res_uri}");
                let Ok(res_req_form) = res_req.form_encode() else {
                    return Command::event(Event::Error(
                        "failed to encode presentation response form".into(),
                    ));
                };
                println!(">>> Presentation response request: {:#?}", res_req_form);
                let http_request = match Http::<Effect, Event>::post(res_uri)
                    .header("accept", mime::JSON)
                    .body_form(&res_req_form)
                {
                    Ok(hr) => hr,
                    Err(e) => {
                        return Command::event(Event::Error(e.to_string()));
                    }
                };
                http_request.build().then_send(Event::PresentationResponse)
            }
            Event::PresentationResponse(Ok(res)) => {
                if !res.status().is_success() {
                    return Command::event(Event::Error("credential verification failed".into()));
                }
                *model = model.active_view(Aspect::PresentationSuccess);
                render()
            }
            // Store errors
            Event::CredentialsLoaded(Err(error))
            | Event::CredentialStored(Err(error))
            | Event::CredentialDeleted(Err(error))
            | Event::IssuanceStored(Err(error))
            | Event::PresentationCredentialsLoaded(Err(error)) => {
                *model = model.error(&error.to_string());
                render()
            }
            // HTTP errors
            Event::IssuanceIssuer(Err(error))
            | Event::IssuanceLogo(Err(error))
            | Event::IssuanceBackground(Err(error))
            | Event::IssuanceToken(Err(error))
            | Event::IssuanceCredential(Err(error))
            | Event::IssuanceDidResolve(Err(error))
            | Event::PresentationRequestReceived(Err(error))
            | Event::PresentationResponse(Err(error))
            | Event::PresentationDidResolve(Err(error)) => {
                *model = model.error(&error.to_string());
                render()
            }
            // Key store errors
            Event::IssuanceSigningKey(Err(error)) | Event::PresentationSigningKey(Err(error)) => {
                *model = model.error(&error.to_string());
                render()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        let mut vm = Self::ViewModel::default();
        match model {
            Model::Credential { active_view, state } => {
                vm.active_view = active_view.clone();
                vm.credential_view = state.deref().clone().into();
            }
            Model::Issuance { active_view, state } => {
                vm.active_view = active_view.clone();
                vm.issuance_view = state.deref().clone().into();
            }
            Model::Presentation { active_view, state } => {
                vm.active_view = active_view.clone();
                vm.presentation_view = state.deref().clone().into();
            }
            Model::Error { active_view, error } => {
                vm.active_view = active_view.clone();
                vm.error = error.clone();
            }
        }
        vm
    }
}
