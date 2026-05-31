use std::{collections::HashMap, sync::Arc};

use auth_service::{
    app_state, get_postgres_pool, get_redis_client,
    services::{
        hashmap_banned_token_store::HashmapBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        mock_email_client::MockEmailClient, postgres_user_store::PostgresUserStore,
        redis_banned_token_store::RedisBannedTokenStore,
    },
    utils::constants::{prod, DATABASE_URL, REDIS_HOST_NAME},
    Application,
};
use axum::response::Html;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;

    let redis_connection = configure_redis();
    let arc_rw_redis_conn = Arc::new(RwLock::new(redis_connection));

    let user_state = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));

    let banned_token_state = Arc::new(RwLock::new(RedisBannedTokenStore::new(arc_rw_redis_conn)));

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

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
