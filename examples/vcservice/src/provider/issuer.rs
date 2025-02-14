//! # Issuer Service Callbacks
//!
//! Provider implementation for the issuer aspect of the service.

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use credibil_vc::issuer::provider::{
    Algorithm, Client, Dataset, DidResolver, Document, Issuer, Metadata, PublicKey, Receiver,
    Result, Server, SharedSecret, Signer, StateStore, Status, Subject,
};
use credibil_vc::test_utils::store::{issuance, resolver, state};
use ed25519_dalek::{SecretKey, Signer as _, SigningKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

const ISSUER_DID: &str = "did:web:vercre.io";
const ISSUER_VERIFY_KEY: &str = "key-0";
const ISSUER_SECRET: &str = "4gSrKc8qg5Hib0atH9QtLEZOuMgkuP9vnxTij8ekrJs";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    pub client: issuance::ClientStore,
    pub issuer: issuance::IssuerStore,
    pub server: issuance::ServerStore,
    pub subject: issuance::DatasetStore,
    pub state: state::Store,
    pub external_address: String,
}

impl Provider {
    #[must_use]
    pub fn new(external_address: &str) -> Self {
        Self {
            client: issuance::ClientStore::new(),
            issuer: issuance::IssuerStore::new(),
            server: issuance::ServerStore::new(),
            subject: issuance::DatasetStore::new(),
            state: state::Store::new(),
            external_address: external_address.into(),
        }
    }
}

impl credibil_vc::issuer::provider::Provider for Provider {}

impl Metadata for Provider {
    async fn client(&self, client_id: &str) -> Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        self.client.add(client)
    }

    async fn issuer(&self, issuer_id: &str) -> Result<Issuer> {
        self.issuer.get(issuer_id)
    }

    async fn server(&self, server_id: &str, _issuer_id: Option<&str>) -> Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for Provider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        self.subject.authorize(subject_id, credential_configuration_id)
    }

    async fn dataset(&self, subject_id: &str, credential_identifier: &str) -> Result<Dataset> {
        self.subject.dataset(subject_id, credential_identifier)
    }
}

impl StateStore for Provider {
    async fn put(&self, key: &str, state: impl Serialize + Send, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
    }
}
impl Signer for Provider {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(ISSUER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(ISSUER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    async fn verification_method(&self) -> Result<String> {
        let parts = self.external_address.split("//").collect::<Vec<&str>>();
        let override_domain = *parts.get(1).unwrap_or(&"vercre.io");
        let did = ISSUER_DID.replace("vercre.io", override_domain);
        Ok(format!("{did}#{ISSUER_VERIFY_KEY}"))
    }
}

impl Receiver for Provider {
    fn key_id(&self) -> String {
        todo!()
    }

    async fn shared_secret(&self, _sender_public: PublicKey) -> Result<SharedSecret> {
        todo!()
    }
}

impl Status for Provider {}
