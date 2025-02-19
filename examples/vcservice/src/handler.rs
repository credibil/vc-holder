use axum::extract::State;
use serde::Serialize;

use crate::{AppError, AppJson, AppState};

pub mod assets;
pub mod issuer;
pub mod verifier;

#[derive(Serialize)]
pub struct GreetingResponse {
    pub message: String,
    pub address: String,
}

// Hello World handler
#[axum::debug_handler]
pub async fn index(State(state): State<AppState>) -> Result<AppJson<GreetingResponse>, AppError> {
    Ok(AppJson(GreetingResponse {
        message: "Vercre Demonstration Service".into(),
        address: state.external_address.into(),
    }))
}
