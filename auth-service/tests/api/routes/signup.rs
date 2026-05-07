use auth_service::{ErrorResponse, routes::SignupResponse};

use crate::helper::{get_random_email, TestApp};

// #[tokio::test]
// async fn signup() {
//     let app = TestApp::new().await;

//     let response = app.sign_up().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({"password": "password123", "requires2FA": true}),
        serde_json::json!({"email": random_email, "password": "password123"}),
    ];

    for test_case in test_cases.iter() {
        let response = app.sign_up(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let response = app
        .sign_up(
            &serde_json::json!({"email": random_email, "password": "password123", "requires2FA": true}),
        )
        .await;
    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.

    let empty_email =
        serde_json::json!({"email": "", "password": "123456789", "requires2FA": true});
    let invalid_email =
        serde_json::json!({"email": "supra.com", "password": "123456789", "requires2FA": true});
    let password_too_short =
        serde_json::json!({"email": "supra@gmail.com", "password": "1234567", "requires2FA": true});
    let test_cases = [empty_email, invalid_email, password_too_short];

    let app = TestApp::new().await;

    for test_case in test_cases.iter() {
        let response = app.sign_up(test_case).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", test_case);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let payload = serde_json::json!({"email": "supra@gmail.com", "password": "123456789", "requires2FA": true});
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let _ = app.sign_up(&payload).await;
    let response = app.sign_up(&payload).await;

    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
