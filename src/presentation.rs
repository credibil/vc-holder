//! # Presentation
//!
//! Types needed to implement a credential presentation flow.
use std::fmt::Debug;
use std::vec;

use anyhow::{anyhow, bail};
use credibil_vc::did::{DidResolver, Resource, dereference};
use credibil_vc::infosec::jose::jws;
pub use credibil_vc::verifier::proof;
// Re-export types from `credibil-vc` for use in the presentation module.
pub use credibil_vc::verifier::{
    Constraints, DescriptorMap, Field, Filter, FilterValue, InputDescriptor, PathNested,
    PresentationSubmission, RequestObject, RequestObjectRequest, RequestObjectResponse,
    RequestObjectType, ResponseRequest, ResponseResponse, VerifiablePresentation,
};
use credibil_vc::{Kind, urlencode};
use uuid::Uuid;

use crate::credential::Credential;

/// Utility to extract a presentation `RequestObject` from a URL-encoded string.
/// If the request string can be decoded but appears to be something other than
/// a `RequestObject`, None is returned.
///
/// Wrapper to the function `credibil_vc::core::urlencode`.
///
/// # Errors
/// If the string cannot be decoded or appears to be an encoded `RequestObject`
/// but cannot be successfully deserialized, an error is returned.
pub fn parse_request_object(request: &str) -> anyhow::Result<Option<RequestObject>> {
    let req_obj = if request.contains("&presentation_definition") {
        Some(
            urlencode::from_str::<RequestObject>(request)
                .map_err(|e| anyhow!("failed to parse request object: {e}"))?,
        )
    } else {
        None
    };

    Ok(req_obj)
}

/// A presentation flow is used to orchestrate the change in state as the
/// wallet progresses through a credential verification.
#[derive(Clone, Debug)]
pub struct PresentationFlow<A> {
    authorize: A,

    /// Perhaps useful to the wallet for tracking a particular flow instance.
    id: String,
    request: RequestObject,
    submission: PresentationSubmission,
}

impl<A> PresentationFlow<A> {
    /// Get the ID of the issuance flow.
    pub fn id(&self) -> String {
        self.id.clone()
    }
}

/// Type guard for a `PresentationFlow` that has been authorized.
#[derive(Clone, Debug)]
pub struct Authorized(Vec<Credential>);
/// Type guard for a `PresentationFlow` that has not been authorized.
#[derive(Clone, Debug)]
pub struct NotAuthorized;

impl PresentationFlow<NotAuthorized> {
    /// Create a new presentation flow with a request object.
    ///
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn new(request: RequestObject) -> anyhow::Result<Self> {
        let submission = create_submission(&request)?;
        Ok(Self {
            authorize: NotAuthorized,

            id: Uuid::new_v4().to_string(),
            request,
            submission,
        })
    }

    /// Get a filter from the request object on the state.
    ///
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn filter(&self) -> anyhow::Result<Constraints> {
        let pd = match &self.request.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };
        if pd.input_descriptors.is_empty() {
            bail!("no input descriptors found");
        }
        let constraints = pd.input_descriptors[0].constraints.clone();

        Ok(constraints)
    }

    /// Authorize the presentation flow.
    #[must_use]
    pub fn authorize(self, credentials: &[Credential]) -> PresentationFlow<Authorized> {
        PresentationFlow {
            authorize: Authorized(credentials.to_vec()),

            id: self.id,
            request: self.request,
            submission: self.submission,
        }
    }
}

impl PresentationFlow<Authorized> {
    /// Construct a presentation payload.
    ///
    /// # Errors
    /// Will return an error if the request object does not contain a
    /// presentation definition object: this is the only currently supported
    /// type.
    pub fn payload(&self, key_identifier: &str) -> anyhow::Result<proof::Payload> {
        let holder_did = key_identifier.split('#').collect::<Vec<&str>>()[0];

        // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
        let mut builder = VerifiablePresentation::builder()
            .add_context(Kind::String("https://www.w3.org/2018/credentials/examples/v1".into()))
            .holder(holder_did);

        let pd = match &self.request.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };

        for input in &pd.input_descriptors {
            if let Some(fields) = &input.constraints.fields {
                for field in fields {
                    if let Some(filter) = &field.filter {
                        if let FilterValue::Const(val) = &filter.value {
                            builder = builder.add_type(val.clone());
                        }
                    }
                }
            }
        }

        for c in &self.authorize.0 {
            builder = builder.add_credential(Kind::String(c.issued.clone()));
        }
        let vp = builder.build()?;

        let payload = proof::Payload::Vp {
            vp,
            client_id: self.request.client_id.clone(),
            nonce: self.request.nonce.clone(),
        };

        Ok(payload)
    }

    /// Create a presentation response request and the presentation URI from the
    /// current flow state and the provided proof.
    #[must_use]
    pub fn create_response_request(&self, jwt: &str) -> (ResponseRequest, Option<String>) {
        let res_req = ResponseRequest {
            vp_token: Some(vec![Kind::String(jwt.into())]),
            presentation_submission: Some(self.submission.clone()),
            state: self.request.state.clone(),
        };
        let res_uri =
            self.request.response_uri.clone().map(|uri| uri.trim_end_matches('/').to_string());
        (res_req, res_uri)
    }

    /// Get the credentials from the authorized presentation flow.
    #[must_use]
    pub fn credentials(&self) -> Vec<Credential> {
        self.authorize.0.clone()
    }
}

/// Utility to extract a presentation `RequestObject` from a
/// `RequestObjectResponse`. Uses a DID resolver to verify the JWT.
///
/// # Errors
/// If decoding or verifying the JWT fails an error is returned.
pub async fn parse_request_object_response(
    res: &RequestObjectResponse, resolver: impl DidResolver,
) -> anyhow::Result<RequestObject> {
    let RequestObjectType::Jwt(token) = &res.request_object else {
        bail!("no serialized JWT found in response");
    };
    parse_request_object_jwt(token, resolver).await
}

/// Parse a JWT into a `RequestObjectResponse`. Uses a DID resolver to verify
/// the JWT.
///
/// # Errors
/// If decoding or verifying the JWT fails an error is returned.
pub async fn parse_request_object_jwt(
    token: &str, resolver: impl DidResolver,
) -> anyhow::Result<RequestObject> {
    let jwt: jws::Jwt<RequestObject> = jws::decode(token, move |kid| {
        let local_resolver = resolver.clone();
        async move {
            let resp = dereference(&kid, None, local_resolver)
                .await
                .map_err(|e| anyhow!("issue dereferencing DID: {e}"))?;
            let Some(Resource::VerificationMethod(vm)) = resp.content_stream else {
                return Err(anyhow!("Verification method not found"));
            };
            vm.method_type.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
        }
    })
    .await
    .map_err(|e| anyhow!("failed to parse JWT: {e}"))?;

    Ok(jwt.claims)
}

// Construct a presentation submission from a request object.
fn create_submission(request: &RequestObject) -> anyhow::Result<PresentationSubmission> {
    let pd = match &request.presentation_definition {
        Kind::Object(pd) => pd,
        Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
    };

    let mut desc_map: Vec<DescriptorMap> = vec![];
    for n in 0..pd.input_descriptors.len() {
        let in_desc = &pd.input_descriptors[n];
        let dm = DescriptorMap {
            id: in_desc.id.clone(),
            path: "$".to_string(),
            path_nested: PathNested {
                format: "jwt_vc_json".to_string(),
                // URGENT: index matched VCs not input descriptors!!
                path: "$.verifiableCredential[0]".to_string(),
            },
            format: "jwt_vc_json".to_string(),
        };
        desc_map.push(dm);
    }
    Ok(PresentationSubmission {
        id: Uuid::new_v4().to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: desc_map,
    })
}
