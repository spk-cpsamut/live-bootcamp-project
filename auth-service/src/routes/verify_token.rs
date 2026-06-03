use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};


#[tracing::instrument(name = "verify_token", skip_all)]
pub async fn verify_token(
    State(AppState {
        banned_token_store, ..
    }): State<AppState>,
    Json(body): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = body.token;

    let _ = validate_token(&token, banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
