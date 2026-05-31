use std::collections::HashMap;

use auth_service::{
    domain::BannedTokenStoreError,
    utils::constants::{JWT_COOKIE_NAME, JWT_SECRET},
};
use reqwest::{cookie::CookieStore, Url};
use serde_json;

use crate::helper::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        "invalid_name=shoud_fail",
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;

    let sign_up_response = app.sign_up(&serde_json::json!({"email": "supra_test@gmail.com", "password": "123456789", "requires2FA": false})).await;

    assert_eq!(sign_up_response.status().as_u16(), 201);

    let response = app
        .login(&serde_json::json!({"email": "supra_test@gmail.com", "password": "123456789"}))
        .await;

    assert_eq!(response.status().as_u16(), 200);

    let cookies: HashMap<String, String> = app
        .cookie_jar
        .cookies(&Url::parse(&app.address).expect("Failed to parse URL"))
        .into_iter()
        .map(|x| {
            let a: Vec<&str> = x.to_str().unwrap().split("=").collect();
            (a.get(0).unwrap().to_string(), a.get(1).unwrap().to_string())
        })
        .collect();

    let token = cookies
        .get(JWT_COOKIE_NAME)
        .expect("no cookie found")
        .to_owned();

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 200);
    let read_banned_token_state = app.banned_token_state.read().await;

    assert_eq!(
        read_banned_token_state.is_token_not_banned(&token).await,
        Err(BannedTokenStoreError::TokenBanned)
    )
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;

    let sign_up_response = app.sign_up(&serde_json::json!({"email": "supra_test_1@gmail.com", "password": "123456789", "requires2FA": false})).await;

    assert_eq!(sign_up_response.status().as_u16(), 201);

    let response = app
        .login(&serde_json::json!({"email": "supra_test_1@gmail.com", "password": "123456789"}))
        .await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.logout().await;
    assert_eq!(response.status().as_u16(), 400);
}
