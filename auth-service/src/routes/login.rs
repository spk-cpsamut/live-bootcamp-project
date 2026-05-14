use axum::{body, extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(AppState { user_store, .. }): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let mut auth_cookie = None;

    let result: Result<(), AuthAPIError> = async {
        let email = Email::parse(body.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
        let password =
            Password::parse(body.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

        let user_store_read = user_store.read().await;

        let _ = user_store_read
            .validate_user(&email, &password)
            .await
            .map_err(|_| AuthAPIError::IncorrectCredentials)?;

        auth_cookie = Some(generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError)?);

        Ok(())
    }
    .await;
    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.

    match auth_cookie {
        Some(auth_cookie) => {
            let updated_jar = jar.add(auth_cookie);
            return (updated_jar, result);
        },
        None => {
            return (jar, result)
        },
    }
    

    // let updated_jar = jar.add(auth_cookie.unwrap());

    (jar, result)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}
