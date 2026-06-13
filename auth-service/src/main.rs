use std::sync::Arc;

use auth_service::{
    Application, app_state::{self}, domain::Email, get_postgres_pool, get_redis_client, services::{
        mock_email_client::MockEmailClient, postgres_user_store::PostgresUserStore, postmark_email_client::PostmarkEmailClient, redis_banned_token_store::RedisBannedTokenStore, redis_two_fa_code_store::RedisTwoFACodeStore
    }, utils::{
        constants::{DATABASE_URL, POSTMARK_AUTH_TOKEN, REDIS_HOST_NAME, prod},
        tracing::init_tracing,
    }
};
use reqwest::Client;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");
    let pg_pool = configure_postgresql().await;

    let redis_connection = configure_redis();
    let arc_rw_redis_conn = Arc::new(RwLock::new(redis_connection));

    let user_state = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));

    let banned_token_state = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        arc_rw_redis_conn.clone(),
    )));

    let two_fa_code_state = Arc::new(RwLock::new(RedisTwoFACodeStore::new(arc_rw_redis_conn)));

    let email_client = Arc::new(configure_postmark_email_client());
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

fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        Email::parse(prod::email_client::SENDER.to_owned().into()).unwrap(),
        POSTMARK_AUTH_TOKEN.to_owned(),
        http_client,
    )
}
