use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::{AppState, EmailClientType, TwoFACodeStoreType},
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "login", skip_all)]
pub async fn login(
    State(AppState {
        user_store,
        two_fa_code_store,
        email_client,
        ..
    }): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Ok(email) = Email::parse(body.email) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let user_store_read = user_store.read().await;

    let Ok(_) = user_store_read
        .validate_user(&email, &body.password.expose_secret())
        .await
    else {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };
    let Ok(user) = user_store_read.get_user(&email).await else {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };

    match user.requires_2fa {
        true => handle_2fa(email, &two_fa_code_store, &email_client, jar).await,
        false => handle_no_2fa(&email, jar).await,
    }
}

#[tracing::instrument(name = "handle_2fa", skip_all)]
async fn handle_2fa(
    email: Email,
    two_fa_code_store: &TwoFACodeStoreType,
    email_client: &EmailClientType,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    if let Err(e) = two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    if let Err(e) = email_client
        .send_email(&email, "2FA code", two_fa_code.as_ref().expose_secret())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e)));
    };

    (
        jar,
        Ok((
            StatusCode::PARTIAL_CONTENT,
            Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
                message: "2FA required".to_owned(),
                login_attempt_id: login_attempt_id.as_ref().expose_secret().to_owned(),
            })),
        )),
    )
}

#[tracing::instrument(name = "handle_no_2fa", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: SecretString,
    password: SecretString,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
