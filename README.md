# Holder

This crate provides an opinionated API for building applications that can act as an agent for the holder of verifiable credentials (typically a wallet). It manages the receipt of credentials via the OpenID for Verifiable Credentials (OIDC4VC) protocol and the presentation of credentials via the OpenID for Verifiable Presentation (VP) protocol.

All of the code is an example of interacting with services based on the `credibil-vc` crate for issuing and verifying verifiable credentials using OpenID flows. See the documentation for that
crate for more details. While the `credibil-vc` crate attempts to adhere to open standards, this crate in itself is not standards-based.

## Getting Started

At the least, this crate provides some examples of how to use `credibil-vc`. The `tests` directory has end-to-end tests that show flows for VC issuance and presentation (to a verifier) which are a good starting point.

The `examples` directory has some basic services for issuance and verification which can be used alongside an example mobile application and an example desktop application. See the README files in those crates for more information on how to get started with those examples. The goal of the examples directory is to contain starter projects from which you might build out complete issuer, verifier and holder services.

