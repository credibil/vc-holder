use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use credibil_vc::test_utils::store::{presentation, state};
use credibil_vc::verifier::provider::{
    Algorithm, DidResolver, Document, Metadata, PublicKey, Receiver, Result, SharedSecret, Signer,
    StateStore, Verifier, Wallet,
};
use ed25519_dalek::{SecretKey, Signer as _, SigningKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

const VERIFIER_DID: &str = "did:web:credibil.io:verifier";
const VERIFIER_VERIFY_KEY: &str = "key-0";
const VERIFIER_SECRET: &str = "AjKuj65-q7ZtITalC_evigRLeXXOsf7RjTrYOvyUO_I";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    verifier_id: String,
    verifier: presentation::Store,
    state: state::Store,
    external_address: String,
}

impl Provider {
    #[must_use]
    pub fn new(external_address: &str, verifier_id: &str) -> Self {
        Self {
            verifier_id: verifier_id.into(),
            verifier: presentation::Store::new(),
            state: state::Store::new(),
            external_address: external_address.into(),
        }
    }
}

impl credibil_vc::verifier::provider::Provider for Provider {}

impl Metadata for Provider {
    async fn verifier(&self, verifier_id: &str) -> Result<Verifier> {
        let mut verifier_meta = self.verifier.get(&self.verifier_id)?;
        verifier_meta.oauth.client_id = verifier_id.into();
        Ok(verifier_meta)
    }

    async fn register(&self, verifier: &Verifier) -> Result<Verifier> {
        self.verifier.add(verifier)
    }

    async fn wallet(&self, _wallet_id: &str) -> Result<Wallet> {
        unimplemented!("WalletMetadata")
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

// This resolver will be bypassed for did:key DIDs. That is, when the verifier
// is verifying the wallet's presentation proof, it will not call this resolver.
// However, it will subsequently unpack the VC from the presentation and verify
// the issuer's DID. So this resolver will go get the issuer's DID document. In
// this contrived situation where the issuer and verifier are run on the same
// web-service we just return a canned DID document to avoid the set-up needed
// to make outbound HTTP requests. A real implementation would call out to the
// issuer's DID document endpoint.
impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        tracing::debug!(">>> resolving DID: {}", url);
        if url.starts_with("did:key:") {
            bail!("unexpected resolution of a DID key method: {}", url);
        }
        let json = crate::handler::issuer::did_json(&self.external_address)?;
        let doc: Document = serde_json::from_value(json)?;
        Ok(doc)
    }
}

impl Signer for Provider {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(VERIFIER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(VERIFIER_SECRET)?;
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
        let override_domain = *parts.get(1).unwrap_or(&"credibil.io");
        let did = VERIFIER_DID.replace("credibil.io", override_domain);
        Ok(format!("{did}#{VERIFIER_VERIFY_KEY}"))
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
