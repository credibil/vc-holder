# Credibil Example Tauri Wallet

The Credibil Crux Wallet is a simple example of a wallet that can be used to receive, store and present Verifiable Credentials. It is a demonstration of the interactions between a wallet and issuance service that conforms to [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and a verification service that conforms to [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

A conformant issuer service can be constructed using the `credibil-vc` crate with `issuer` feature, and a conformant verification service can be constructed using the `credibil-vc` crate with `verifier` feature. The examples folder provides a simple `vcservice` that does this (issuer and verifier) in a single service that can be used with this wallet example.

This wallet is built using the `credibil-holder` crate which provides a set of convenient data types and functions for constructing a wallet or similar holder agent. The `credibil-holder` crate and this wallet, while adhering to the OpenID standards for issuance and presentation flows do not conform internally to any standards but simply provide a "for-instance" example you may wish to use to influence your own wallet project for use with standards-compliant issuers and verifiers. See the open source [`credibil-vc`](https://github.com/credibil/vc) repository for details.

## Why not Crux?

See the `examples/crux-wallet` for a multi-platform approach to building wallets with Rust as the core programming language and native-language shells for various operating system targets (such as Swift for iOS). This Tauri wallet could have been included as an example shell in that framework but the goal of this example is to have an end-to-end Rust example that is as simple as possible for a Rust developer to follow without needing to understand Crux.

## Getting Started

### Prerequisites

Make sure your Rust toolchain and local compilation targets are up-to-date

```shell
rustup update
```

### Sample Issuance and Verification

To demonstrate the wallet you can use the services and web applications provided in the `vcservice` and `vcweb` folders.

You can run these applications somewhere accessible to your desktop or use the following steps to build and run locally using a Docker runtime and [ngrok](https://ngrok.com/) to expose localhost services to the internet.

By default the web application will be available at http://localhost:3000 and the service at http://localhost:8080.

In order to serve the API over the internet so your desktop device can interact with it (for issuance or verification), point an ngrok domain to http://localhost:8080.

Set up an [ngrok](https://ngrok.com/) account if you don't already have one then [install and configure the cli](https://dashboard.ngrok.com/get-started/setup/macos)

Create a `.env` file in the root folder of this workspace and add the following:

```shell
RUST_LOG=debug # or exclude to have info as default
CREDIBIL_HTTP_ADDRESS=<your ngrok url>
```

Build and run containers

```shell
docker compose build
docker compose up
```

Point ngrok to your instance of the API:

```shell
ngrok config add-authtoken <your authtoken>
ngrok http --url <your ngrok url> 8080
```

Test ngrok is working by navigating to the root of that URL (browser/curl/Postman, etc) on a separate device and you should receive a valid response.

### Tauri Wallet Application

```shell
cd examples/tauri-wallet
pnpm install
pnpm tauri dev
```
