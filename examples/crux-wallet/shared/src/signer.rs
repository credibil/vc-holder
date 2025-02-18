//! Signer provider callbacks for creating proofs

use anyhow::bail;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{ed25519::signature::Signer as _, Signature, SigningKey, VerifyingKey};
use credibil_holder::did::{CreateOptions, Curve, DidKey, DidOperator, KeyPurpose, KeyType, PublicKeyJwk};
use credibil_holder::provider::{Algorithm, Signer};

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

/// Implementation of the `vercre-infosec::Signer` traits.
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
        let op = Operator::new(vk);
        let options = CreateOptions::default();
        let did = DidKey::create(&op, options)?;
        let Some(vm) = did.verification_method else {
            bail!("no verification methods on DID");
        };
        let Some(vm) = vm.first() else {
            bail!("empty verification methods on DID");
        };
        Ok(vm.id.clone())
    }
}

struct Operator {
    verifying_key: VerifyingKey,
}

impl Operator {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self {
            verifying_key,
        }
    }
}

impl DidOperator for Operator {
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
        match purpose {
            KeyPurpose::VerificationMethod => {
                let key = self.verifying_key.to_bytes().to_vec();
                Some(PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&key),
                    ..Default::default()
                })
            }
            _ => None,
        }
    }
}
