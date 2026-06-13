use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use secrecy::ExposeSecret;

use crate::helper::{get_random_email, TestApp};

// #[tokio::test]
// async fn login() {
//     let app = TestApp::new().await;

//     let response = app.login().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let body = serde_json::json!({"tets": "failed"});
    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 422)
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.

    let empty_email = serde_json::json!({"email": "", "password": "12345678"});
    let invalid_email = serde_json::json!({"email": "noway.com", "password": "1234578"});

    let test_cases = [empty_email, invalid_email];

    let app = TestApp::new().await;

    for test_case in test_cases.iter() {
        let response = app.login(test_case).await;
        assert_eq!(response.status().as_u16(), 400);
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.
    let app = TestApp::new().await;

    app.sign_up(&serde_json::json!({"email": "wonderful@gmail.com", "password": "123456789"}))
        .await;

    let invalid_email_case =
        serde_json::json!({"email": "wrong@gmail.com", "password": "123456789"});
    let invalid_password_case =
        serde_json::json!({"email": "wonderful@gmail.com", "password": "12345678"});
    let test_cases = [invalid_email_case, invalid_password_case];

    for test_case in test_cases.iter() {
        let response = app.login(test_case).await;
        assert_eq!(response.status().as_u16(), 401);
    }
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.sign_up(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": random_email.clone(),
        "password": password,
        "requires2FA": true
    });

    let response = app.sign_up(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.clone(),
        "password": password,
        "requires2FA": true,
    });
    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(random_email.clone().into()).expect("valid email");

    let (login_attmpt_id, _) = app
        .two_fa_code_state
        .read()
        .await
        .get_code(&email)
        .await
        .expect("found code");

    assert_eq!(json_body.login_attempt_id, login_attmpt_id.as_ref().expose_secret());
}
