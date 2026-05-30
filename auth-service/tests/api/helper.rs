use std::{collections::HashMap, sync::Arc};

use auth_service::{
    app_state::{self, BannedTokenStoreType, TwoFACodeStoreType},
    get_postgres_pool,
    services::{
        hashmap_banned_token_store::HashmapBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        mock_email_client::MockEmailClient, postgres_user_store::PostgresUserStore,
    },
    utils::constants::{test, DATABASE_URL},
    Application,
};
use reqwest::cookie::Jar;
use serde;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_token_state: BannedTokenStoreType,
    pub two_fa_code_state: TwoFACodeStoreType,
    pub pool: PgPool,
    pub db_name: String,
}

impl TestApp {
    pub async fn new() -> Self {
        let db_name = Uuid::new_v4().to_string();
        let pg_pool = configure_postgresql(db_name.clone()).await;

        let user_state = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool.clone())));

        let banned_token_state = Arc::new(RwLock::new(HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        }));

        let two_fa_code_state = Arc::new(RwLock::new(HashmapTwoFACodeStore::new()));
        let email_client = Arc::new(MockEmailClient);
        let app_state = app_state::AppState::new(
            user_state,
            banned_token_state.clone(),
            two_fa_code_state.clone(),
            email_client,
        );
        let cookie_jar = Arc::new(Jar::default());

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("failed to build app");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            address,
            cookie_jar,
            http_client,
            banned_token_state,
            two_fa_code_state,
            db_name,
            pool: pg_pool.clone(),
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(format!("{}/", self.address))
            .send()
            .await
            .expect("fail to execute request")
    }

    pub async fn sign_up<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/signup", self.address))
            .json(body)
            .send()
            .await
            .expect("failed to excute request")
    }

    pub async fn login(&self, body: &impl serde::Serialize) -> reqwest::Response {
        self.http_client
            .post(format!("{}/login", self.address))
            .json(body)
            .send()
            .await
            .expect("failed to execute request")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/logout", self.address))
            .send()
            .await
            .expect("failed to execute request")
    }

    pub async fn verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify_2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify_token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        let admin_conn_url = DATABASE_URL.to_owned();

        // Cannot use block_on on the test runtime's worker thread; spin up a
        // separate thread with its own runtime for sync cleanup in Drop.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            rt.block_on(delete_database(&admin_conn_url, &db_name));
        })
        .join()
        .expect("Failed to join database cleanup thread");
    }
}

async fn delete_database(admin_conn_url: &str, db_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_conn_url)
        .await
        .expect("Failed to connect to admin DB");

    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(db_name)
    .execute(&admin)
    .await
    .expect("Failed to terminate connections");

    sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{}";"#, db_name))
        .execute(&admin)
        .await
        .expect("Failed to drop database");
}
pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql(db_name: String) -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);

    // Create a new connection pool and return it
    get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    sqlx::query(&format!(r#"CREATE DATABASE "{}";"#, db_name))
        .execute(&connection)
        .await
        .expect("Failed to create database.");

    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}
