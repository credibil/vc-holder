//! # Request handlers for static assets.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::Response;

use crate::AppError;

/// Return hard-coded file contents.
#[axum::debug_handler]
pub async fn asset(Path(filename): Path<String>) -> Result<Response, AppError> {
    let body = match filename.as_str() {
        "employee.png" => Body::from(include_bytes!("assets/employee_logo.png").to_vec()),
        "employee_background.png" => {
            Body::from(include_bytes!("assets/employee_background.png").to_vec())
        }
        "developer.png" => Body::from(include_bytes!("assets/developer_logo.png").to_vec()),
        "developer_background.png" => {
            Body::from(include_bytes!("assets/developer_background.png").to_vec())
        }
        _ => return Err(AppError::Status(StatusCode::NOT_FOUND, format!("Unknown asset {filename}"))),
    };
    let res = Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "image/png")
        .body(body)
        .unwrap();
    Ok(res)
}
