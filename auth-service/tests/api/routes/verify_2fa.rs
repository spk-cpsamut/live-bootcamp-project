use crate::helper::TestApp;



#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    let response = app.verify_2fa().await;

    assert_eq!(response.status().as_u16(), 200);
}