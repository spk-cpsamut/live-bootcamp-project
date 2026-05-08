use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, User}};

pub async fn signup(
    State(AppState { user_store, .. }): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {

    let email = Email::parse(payload.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(payload.password).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let user = User::new(email, password, payload.requires_2fa);

    let mut user_store_write = user_store.write().await;

    if let Ok(_) = user_store_write.get_user(user.email.as_ref()).await {
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
