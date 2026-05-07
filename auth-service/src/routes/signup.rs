use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, User}};

pub async fn signup(
    State(AppState { user_store, .. }): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let user = User::new(payload.email, payload.password, payload.requires_2fa);

    if user.email.is_empty() || !user.email.contains("@") || user.password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let mut user_store_write = user_store.write().await;

    if let Ok(_) = user_store_write.get_user(&user.email).await {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    let _ = user_store_write.add_user(user).await.map_err(|_| AuthAPIError::UnexpectedError);

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
