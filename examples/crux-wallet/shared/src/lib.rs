// The following is needed for uniffi generated code to pass linting.
#![allow(clippy::empty_line_after_doc_comments)]

pub mod app;
pub mod capabilities;
mod config;
mod did_resolver;
mod signer;
mod model;
pub mod view;

use lazy_static::lazy_static;
use wasm_bindgen::prelude::wasm_bindgen;

pub use crux_core::bridge::{Bridge, Request};
pub use crux_core::Core;
pub use crux_http as http;

pub use app::*;
pub use capabilities::sse;

uniffi::include_scaffolding!("wallet");

lazy_static! {
    static ref CORE: Bridge<App> = Bridge::new(Core::new());
}

#[wasm_bindgen]
pub fn process_event(data: &[u8]) -> Vec<u8> {
    CORE.process_event(data)
}

#[wasm_bindgen]
pub fn handle_response(id: u32, data: &[u8]) -> Vec<u8> {
    CORE.handle_response(id, data)
}

#[wasm_bindgen]
pub fn view() -> Vec<u8> {
    CORE.view()
}
