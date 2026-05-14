use std::{collections::HashMap, error::Error, sync::Arc};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::services::ServeDir;

use crate::{
    routes::{login, logout, signup, verify_2fa, verify_token},
    services::hashmap_user_store::HashmapUserStore,
};

pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

pub mod app_state {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::domain::UserStore;

    // Using a type alias to improve readability!
    pub type UserStoreType = Arc<RwLock<dyn UserStore>>;

    #[derive(Clone)]
    pub struct AppState {
        pub user_store: UserStoreType,
    }

    impl AppState {
        pub fn new(user_store: UserStoreType) -> Self {
            Self { user_store }
        }
    }
}

use app_state::AppState;
use domain::AuthAPIError;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "incorrect credential"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let assets_dir = ServeDir::new("assets");
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify_2fa", post(verify_2fa))
            .route("/verify_token", post(verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
