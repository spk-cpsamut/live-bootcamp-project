use axum::http::response;

use crate::helper::TestApp;


#[tokio::test]
async fn root_return_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}


#[tokio::test]
async fn signup() {
    let app = TestApp::new().await;

    let response = app.sign_up().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn login() {
    let app = TestApp::new().await;

    let response = app.login().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout() {
    let app = TestApp::new().await;

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verrify_2fa() {
    let app = TestApp::new().await;

    let response = app.verrify_2fa().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verrify_token() {
    let app = TestApp::new().await;

    let response = app.verrify_token().await;

    assert_eq!(response.status().as_u16(), 200);
}


