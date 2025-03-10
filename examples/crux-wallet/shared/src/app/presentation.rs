use credibil_holder::{
    credential::Credential,
    did::Document,
    infosec::Jws,
    issuance::proof::Payload,
    presentation::{
        parse_request_object_jwt, RequestObject, RequestObjectResponse, RequestObjectType,
    },
};
use crux_core::{render::render, Command};
use crux_http::{command::Http, http::mime, HttpError, Response};
use serde::{Deserialize, Serialize};

use crate::{
    capabilities::{
        key::{KeyStoreCommand, KeyStoreEntry, KeyStoreError},
        store::{Catalog, StoreCommand, StoreEntry, StoreError},
    },
    did_resolver::DidResolverProvider,
    model::Model,
    signer::SignerProvider,
};

use super::{credential::CredentialEvent, Aspect, Effect, Event};

/// Events that can be sent to the wallet application that pertain to the
/// issuance of credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PresentationEvent {
    /// Event emitted by the shell when the user wants to scan a presentation
    /// request QR code.
    ScanRequest,

    /// Event emitted by the shell when the user scans a presentation request QR
    /// code.
    ///
    /// We expect the string to be a URL to a presentation request. Cross-device
    /// flow.
    Request(String),

    /// Event emitted by the core when a presentation request has been received.
    #[serde(skip)]
    RequestReceived(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when a DID document has been resolved.
    #[serde(skip)]
    DidResolved(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the core when the presentation request has been
    /// verified and decoded.
    #[serde(skip)]
    RequestVerified(Box<RequestObject>),

    /// Event emitted by the core when all credentials have been loaded from
    /// storage, before they are filtered.
    #[serde(skip)]
    CredentialsLoaded(Result<Vec<StoreEntry>, StoreError>),

    /// Event emitted by the core when at least one credential has been found
    /// that matches the presentation request.
    #[serde(skip)]
    CredentialsFound(Vec<Credential>),

    /// Event emitted by the shell when a user approves the presentation of
    /// the credential to the verifier.
    ///
    /// TODO: We only let the user send the first matching credential for now.
    /// If the app extends to support a choice we would need to know which one
    /// has been selected here.
    Approved,

    /// Event emitted by the core when a signing key has been retrieved from
    /// the key store capability.
    #[serde(skip)]
    SigningKey(Result<KeyStoreEntry, KeyStoreError>),

    /// Event emitted by the core when a proof has been constructed.
    ///
    /// The string is a proof JWT.
    #[serde(skip)]
    Proof(String),

    /// Event emitted by the core when the verifier responds to the
    /// presentation.
    #[serde(skip)]
    Response(Result<crux_http::Response<Vec<u8>>, HttpError>),

    /// Event emitted by the shell when the user wants to cancel a presentation.
    Cancel,
}

/// Presentation event processing.
pub fn presentation_event(event: PresentationEvent, model: &mut Model) -> Command<Effect, Event> {
    match event {
        PresentationEvent::ScanRequest => scan_request(model),
        PresentationEvent::Request(url) => request(&url),
        PresentationEvent::RequestReceived(Ok(res)) => request_received(res, model),
        PresentationEvent::DidResolved(Ok(res)) => did_resolved(res, model),
        PresentationEvent::RequestVerified(req) => request_verified(req, model),
        PresentationEvent::CredentialsLoaded(Ok(entries)) => credentials_loaded(entries, model),
        PresentationEvent::CredentialsFound(creds) => credentials_found(creds, model),
        PresentationEvent::Approved => approved(model),
        PresentationEvent::SigningKey(Ok(key)) => signing_key(key, model),
        PresentationEvent::Proof(jws) => proof(&jws, model),
        PresentationEvent::Response(Ok(res)) => response(res, model),
        PresentationEvent::Cancel => cancel(model),
        PresentationEvent::CredentialsLoaded(Err(error)) => store_error(error, model),
        PresentationEvent::RequestReceived(Err(error))
        | PresentationEvent::Response(Err(error))
        | PresentationEvent::DidResolved(Err(error)) => http_error(error, model),
        PresentationEvent::SigningKey(Err(error)) => keystore_error(error, model),
    }
}

/// Process a `PresentationEvent::ScanRequest` event.
fn scan_request(model: &mut Model) -> Command<Effect, Event> {
    *model = model.scan_presentation_request();
    render()
}

/// Process a `PresentationEvent::Request` event.
fn request(url: &str) -> Command<Effect, Event> {
    println!(">>> Presentation request URL: {url}");
    // Fetch the presentation request from the verifier's service.
    Http::get(url)
        .build()
        .then_send(|res| Event::Presentation(PresentationEvent::RequestReceived(res)))
}

/// Process a `PresentationEvent::RequestReceived` event.
fn request_received(res: Response<Vec<u8>>, model: &mut Model) -> Command<Effect, Event> {
    if !res.status().is_success() {
        return Command::event(Event::Error("presentation request fetch failed".into()));
    }
    let Some(body) = &res.body() else {
        return Command::event(Event::Error("no presentation request returned".into()));
    };
    let Ok(request_object_response) = serde_json::from_slice::<RequestObjectResponse>(body) else {
        return Command::event(Event::Error("presentation request deserialization failed".into()));
    };
    let RequestObjectType::Jwt(token) = request_object_response.request_object else {
        return Command::event(Event::Error("expected presentation request as JWT".into()));
    };
    let jws: Jws = match token.parse() {
        Ok(jws) => jws,
        Err(e) => {
            return Command::event(Event::Error(e.to_string()));
        }
    };
    // Store the payload in state while we deal with the DID.
    *model = model.presentation_request(&token);
    let Some(signature) = jws.signatures.first() else {
        return Command::event(Event::Error(
            "expected at least one signature in presentation request".into(),
        ));
    };
    let header = &signature.protected;
    let Some(key_id) = header.kid() else {
        return Command::event(Event::Error("expected key ID in presentation request".into()));
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
    Http::get(url).build().then_send(|res| Event::Presentation(PresentationEvent::DidResolved(res)))
}

/// Process a `PresentationEvent::DidResolved` event.
fn did_resolved(res: Response<Vec<u8>>, model: &Model) -> Command<Effect, Event> {
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
    let Some(presentation_request) = model.get_presentation_request() else {
        return Command::event(Event::Error(
            "unable to retrieve presentation request from model".into(),
        ));
    };
    Command::new(|ctx| async move {
        let req_obj = match parse_request_object_jwt(&presentation_request, resolver).await {
            Ok(jwt) => jwt,
            Err(e) => {
                return ctx.send_event(Event::Error(e.to_string()));
            }
        };
        ctx.send_event(Event::Presentation(PresentationEvent::RequestVerified(Box::new(req_obj))));
    })
}

/// Process a `PresentationEvent::RequestVerified` event.
fn request_verified(req: Box<RequestObject>, model: &mut Model) -> Command<Effect, Event> {
    *model = match model.presentation_request_verified(&req) {
        Ok(m) => m,
        Err(e) => {
            return Command::event(Event::Error(e.to_string()));
        }
    };
    // Load credentials from storage.
    StoreCommand::list(Catalog::Credential.to_string())
        .then_send(|res| Event::Presentation(PresentationEvent::CredentialsLoaded(res)))
}

/// Process a `PresentationEvent::CredentialsLoaded` event.
fn credentials_loaded(entries: Vec<StoreEntry>, model: &Model) -> Command<Effect, Event> {
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
    Command::event(Event::Presentation(PresentationEvent::CredentialsFound(credentials)))
}

/// Process a `PresentationEvent::CredentialsFound` event.
fn credentials_found(creds: Vec<Credential>, model: &mut Model) -> Command<Effect, Event> {
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

/// Process a `PresentationEvent::Approved` event.
fn approved(model: &mut Model) -> Command<Effect, Event> {
    // Authorize the presentation.
    *model = match model.presentation_approve() {
        Ok(m) => m,
        Err(e) => {
            return Command::event(Event::Error(e.to_string()));
        }
    };
    // Get a signing key.
    KeyStoreCommand::get("credential", "signing")
        .then_send(|res| Event::Presentation(PresentationEvent::SigningKey(res)))
}

/// Process a `PresentationEvent::SigningKey` event.
fn signing_key(key: KeyStoreEntry, model: &Model) -> Command<Effect, Event> {
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
        match credibil_holder::presentation::proof::create(
            credibil_holder::presentation::proof::W3cFormat::JwtVcJson,
            Payload::Vp { vp, client_id, nonce },
            &signer,
        )
        .await
        {
            Ok(jws) => ctx.send_event(Event::Presentation(PresentationEvent::Proof(jws))),
            Err(e) => ctx.send_event(Event::Error(e.to_string())),
        }
    })
}

/// Process a `PresentationEvent::Proof` event.
fn proof(jws: &str, model: &Model) -> Command<Effect, Event> {
    let (res_req, uri) = match model.create_response_request(jws) {
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
        return Command::event(Event::Error("failed to encode presentation response form".into()));
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
    http_request.build().then_send(|res| Event::Presentation(PresentationEvent::Response(res)))
}

/// Process a `PresentationEvent::Response` event.
fn response(res: Response<Vec<u8>>, model: &mut Model) -> Command<Effect, Event> {
    if !res.status().is_success() {
        return Command::event(Event::Error("credential verification failed".into()));
    }
    *model = model.active_view(Aspect::PresentationSuccess);
    render()
}

/// Process a `PresentationEvent::Cancel` event.
fn cancel(model: &mut Model) -> Command<Effect, Event> {
    *model = model.ready();
    StoreCommand::list(Catalog::Credential.to_string())
        .then_send(|res| Event::Credential(CredentialEvent::Loaded(res)))
}

/// Process a credential store error.
fn store_error(error: StoreError, model: &mut Model) -> Command<Effect, Event> {
    *model = model.error(&error.to_string());
    render()
}

/// Process an HTTP error.
fn http_error(error: HttpError, model: &mut Model) -> Command<Effect, Event> {
    *model = model.error(&error.to_string());
    render()
}

/// Process a key store error.
fn keystore_error(error: KeyStoreError, model: &mut Model) -> Command<Effect, Event> {
    *model = model.error(&error.to_string());
    render()
}
