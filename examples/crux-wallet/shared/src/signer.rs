//! Signer provider callbacks for creating proofs

use ed25519_dalek::{ed25519::signature::Signer as _, Signature, SigningKey};
use credibil_holder::provider::{Algorithm, Signer};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

pub struct SignerProvider {
    signing_key: SigningKey,
}

impl SignerProvider {
    /// Create a new provider.
    pub fn new(secret: &[u8]) -> anyhow::Result<Self> {
        let bytes: [u8; 32] = secret.try_into()?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }
}

/// Implementation of the `credibil-infosec::Signer` traits.
impl Signer for SignerProvider {
    /// Sign is a convenience method for infallible Signer implementations.
    async fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.try_sign(msg).await.expect("should sign")
    }

    /// Attempt to sign a message.
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature: Signature = self.signing_key.sign(msg);
        Ok(signature.to_vec())
    }

    /// The public key of the key pair used in signing.
    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        let vk = self.signing_key.verifying_key();
        Ok(vk.as_bytes().to_vec())
    }

    /// The algorithm used in signing.
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    /// The verification method the verifier should use to verify the signature.
    async fn verification_method(&self) -> anyhow::Result<String> {
        self.verification_method_sync()
    }
}

impl SignerProvider {
    /// The verification method the verifier should use to verify the signature.
    pub fn verification_method_sync(&self) -> anyhow::Result<String> {
        let vk = self.signing_key.verifying_key();
        let mut multi_bytes = ED25519_CODEC.to_vec();
        multi_bytes.extend_from_slice(&vk.to_bytes());
        let verifying_multi = multibase::encode(multibase::Base::Base58Btc, &multi_bytes);
        let did = format!("did:key:{verifying_multi}#{verifying_multi}");
        Ok(did)
    }
}
