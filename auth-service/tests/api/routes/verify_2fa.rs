use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode},
    routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};

use crate::helper::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let empty = serde_json::json!({});
    let only_email = serde_json::json!({"email": "test@gmail.com"});
    let only_login_attempt_id = serde_json::json!({"loginAttemptId": "uuid"});

    let test_cases = vec![empty, only_email, only_login_attempt_id];

    let app = TestApp::new().await;

    for test_case in test_cases.iter() {
        let res = app.verify_2fa(test_case).await;

        assert_eq!(res.status().as_u16(), 422);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let invalid_email = serde_json::json!({"email": "invalid", "loginAttemptId": "123e4567-e89b-12d3-a456-426614174000", "2FACode": "123456"});
    let invalid_login_attempt_id = serde_json::json!({"email": "test1@gmail.com", "loginAttemptId": "not-uuid", "2FACode": "123456"});
    let invalid_2_fa_code = serde_json::json!({"email": "test2@gmail.com", "loginAttemptId": "123e4567-e89b-12d3-a456-426614174000", "2FACode": "12345"});

    let test_cases = vec![invalid_email, invalid_login_attempt_id, invalid_2_fa_code];

    for test_case in test_cases.iter() {
        let res = app.verify_2fa(test_case).await;

        assert_eq!(res.status().as_u16(), 400);
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let email = Email::parse("test3@gmail.com".to_owned()).expect("valid email");
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();
    let _ = app
        .two_fa_code_state
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code.clone())
        .await;

    let not_found_email_case = serde_json::json!({"email": "notfound@gmail.com", "loginAttemptId": login_attempt_id.clone().clone().as_ref(), "2FACode": code.clone().as_ref()});
    let not_match_login_attempt_id = serde_json::json!({"email": email.clone().as_ref(), "loginAttemptId": "123e4567-e89b-12d3-a456-426614174000", "2FACode": code.clone().as_ref()});
    let not_match_two_fa_code = serde_json::json!({"email": email.clone().as_ref(), "loginAttemptId": login_attempt_id.clone().clone().as_ref(), "2FACode": "000111"});
    let test_cases = vec![
        not_found_email_case,
        not_match_login_attempt_id,
        not_match_two_fa_code,
    ];

    for test_case in test_cases.iter() {
        let res = app.verify_2fa(test_case).await;

        assert_eq!(res.status().as_u16(), 401);
    }
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.sign_up(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    // First login call

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let login_attempt_id = response_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_state
        .read()
        .await
        .get_code(&Email::parse(random_email.clone()).unwrap())
        .await
        .unwrap();

    let code = code_tuple.1.as_ref();

    // Second login call

    let response = app.login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    // 2FA attempt with old login_attempt_id and code

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code
    });

    let response = app.verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;

    let email = Email::parse("test4@gmail.com".to_owned()).expect("valid email");

    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    app.two_fa_code_state
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code.clone())
        .await
        .expect("add code successfully");

    let body = serde_json::json!({"email": email.as_ref().to_owned(), "loginAttemptId": login_attempt_id.as_ref(), "2FACode": code.as_ref()});

    let res = app.verify_2fa(&body).await;

    assert_eq!(res.status().as_u16(), 200);

    let auth_cookie = res
    .cookies()
    .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
    .expect("No auth cookie found");

assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let app = TestApp::new().await;

    let email = Email::parse("test5@gmail.com".to_owned()).expect("valid email");

    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    app.two_fa_code_state
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code.clone())
        .await
        .expect("add code successfully");

        let body = serde_json::json!({"email": email.as_ref().to_owned(), "loginAttemptId": login_attempt_id.as_ref(), "2FACode": code.as_ref()});

    let res = app.verify_2fa(&body).await;

    assert_eq!(res.status().as_u16(), 200);

    let res = app.verify_2fa(&body).await;

    assert_eq!(res.status().as_u16(), 401);
}
