use crate::helper::{get_random_email, TestApp};
use auth_service::{domain::Email, utils::auth};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let payload = serde_json::json!({});
    let response = app.post_verify_token(&payload).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let email = auth_service::domain::Email::parse(get_random_email().to_owned().into()).unwrap();
    let token = auth_service::utils::auth::generate_auth_cookie(&email)
        .unwrap()
        .value()
        .to_owned();
    let response = app
        .post_verify_token(&serde_json::json!({"token": token}))
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let payload = serde_json::json!({"token": "invalid"});

    let response = app.post_verify_token(&payload).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let token = auth::generate_auth_cookie(&Email::parse(get_random_email().to_owned().into()).unwrap())
        .unwrap()
        .value()
        .to_owned();

    let mut banned_token_state_write = app.banned_token_state.write().await;

    let _ = banned_token_state_write
        .add_token_to_ban_list(token.to_owned())
        .await;

    drop(banned_token_state_write);

    let response = app
        .post_verify_token(&serde_json::json!({"token": token}))
        .await;

    assert_eq!(response.status().as_u16(), 401)
}
