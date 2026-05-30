use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{
    cookie::{self, Cookie},
    CookieJar,
};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(AppState {
        banned_token_store, ..
    }): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token = cookie.value().to_owned();

    if validate_token(&token, banned_token_store.clone()).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let mut banned_token_store_write = banned_token_store.write().await;
    let _ = banned_token_store_write.add_token_to_ban_list(token).await;

    let jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
