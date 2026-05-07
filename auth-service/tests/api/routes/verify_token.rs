use crate::helper::TestApp;



#[tokio::test]
async fn verify_token() {
    let app = TestApp::new().await;

    let response = app.verify_token().await;

    assert_eq!(response.status().as_u16(), 200);
}