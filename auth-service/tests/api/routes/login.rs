use crate::helper::TestApp;

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
