use crate::helper::TestApp;

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

    let email = auth_service::domain::Email::parse("test@example.com".to_owned()).unwrap();
    let token = auth_service::utils::auth::generate_auth_cookie(&email)
        .unwrap()
        .value()
        .to_owned();
    let response = app.post_verify_token(&serde_json::json!({"token": token})).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let payload = serde_json::json!({"token": "invalid"});

    let response = app.post_verify_token(&payload).await;

    assert_eq!(response.status().as_u16(), 401);
}
