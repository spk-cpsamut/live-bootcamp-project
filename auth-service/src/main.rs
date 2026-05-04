use axum::{response::Html};
use auth_service::Application;

#[tokio::main]
async fn main() {
    let app = Application::build("0.0.0.0:3000").await.expect("fail to build app");

    app.run().await.expect("Failed to run app")
}

async fn hello_handler() -> Html<&'static str> {
    Html("<h1> Hello, Rusty!</h1>")
}
