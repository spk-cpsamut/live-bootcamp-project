use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{email_client, AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

pub async fn verify_2fa(
    State(AppState {
        two_fa_code_store, ..
    }): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Ok(email) = Email::parse(body.email) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let Ok(login_attempt_id) = LoginAttemptId::parse(body.login_attempt_id) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let Ok(two_fa_code) = TwoFACode::parse(body.two_fa_code) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let mut two_fa_code_store = two_fa_code_store.write().await;

    let Ok(code_tuple) = two_fa_code_store.get_code(&email).await else {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };

    if (login_attempt_id, two_fa_code) != code_tuple {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (jar, Err(AuthAPIError::UnexpectedError));
    };

    if two_fa_code_store.remove_code(&email).await.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    };

    let update_jar = jar.add(auth_cookie);
    (update_jar, Ok(StatusCode::OK))
}

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,

    #[serde(rename = "2FACode")]
    two_fa_code: String,
}
