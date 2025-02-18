//! DID Resolver provider callbacks for resolving DID documents.

use credibil_holder::did::{DidResolver, Document};

/// DID Resolver provider.
#[derive(Clone)]
pub struct DidResolverProvider {
    did_document: Document,
}

impl DidResolverProvider {
    /// Create a new provider.
    pub fn new(did_document: &Document) -> Self {
        Self { did_document: did_document.clone() }
    }
}

impl DidResolver for DidResolverProvider {
    /// Resolve the DID URL to a DID Document.
    ///
    /// # Errors
    ///
    /// Does not return an error, but has a `Result` return type to satisfy the
    /// trait.
    async fn resolve(&self, _url:  &str) -> anyhow::Result<Document> {
        Ok(self.did_document.clone())
    }
}