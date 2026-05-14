use std::{collections::HashMap, sync::Arc};

use auth_service::{Application, app_state, services::hashmap_user_store::HashmapUserStore, utils::constants::test};
use reqwest::cookie::Jar;
use serde;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_state = Arc::new(RwLock::new(HashmapUserStore {
            email_map: HashMap::new(),
        }));
        let app_state = app_state::AppState::new(user_state);
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

    pub async fn verify_2fa(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/verify_2fa", self.address))
            .send()
            .await
            .expect("failed to execute request")
    }

    pub async fn verify_token(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/verify_token", self.address))
            .send()
            .await
            .expect("failed to execute request")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
