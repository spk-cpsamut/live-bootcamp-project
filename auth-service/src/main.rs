use std::{collections::HashMap, sync::Arc};

use auth_service::{app_state, services::hashmap_user_store::HashmapUserStore, Application};
use axum::response::Html;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_state = Arc::new(RwLock::new(HashmapUserStore {
        email_map: HashMap::new(),
    }));
    let app_state = app_state::AppState::new(user_state);
    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("fail to build app");

    app.run().await.expect("Failed to run app")
}

async fn hello_handler() -> Html<&'static str> {
    Html("<h1> Hello, Rusty!</h1>")
}
