use axum::{body, extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
};

pub async fn login(
    State(AppState { user_store, .. }): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(body.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(body.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store_read = user_store.read().await;

    let _ = user_store_read
        .validate_user(&email, &password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;
    Ok(())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}
