use std::{collections::HashMap, sync::Arc};

use auth_service::{
    Application, app_state, get_postgres_pool, services::{
        hashmap_banned_token_store::HashmapBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        mock_email_client::MockEmailClient,
    }, utils::constants::{DATABASE_URL, prod}
};
use axum::response::Html;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {

    let pg_pool = configure_postgresql().await;


    let user_state = Arc::new(RwLock::new(HashmapUserStore {
        email_map: HashMap::new(),
    }));

    let banned_token_state = Arc::new(RwLock::new(HashmapBannedTokenStore {
        banned_tokens: HashMap::new(),
    }));

    let two_fa_code_state = Arc::new(RwLock::new(HashmapTwoFACodeStore::new()));

    let email_client = Arc::new(MockEmailClient);
    let app_state = app_state::AppState::new(
        user_state,
        banned_token_state,
        two_fa_code_state,
        email_client,
    );
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("fail to build app");

    app.run().await.expect("Failed to run app")
}

async fn hello_handler() -> Html<&'static str> {
    Html("<h1> Hello, Rusty!</h1>")
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
