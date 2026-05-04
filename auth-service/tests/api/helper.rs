use auth_service::Application;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("failed to build app");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new();

        Self {
            address,
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

    pub async fn sign_up(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/signup", self.address))
            .send()
            .await
            .expect("failed to excute request")
    }

    pub async fn login(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/login", self.address))
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

    pub async fn verrify_2fa(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/verrify_2fa", self.address))
            .send()
            .await
            .expect("failed to execute request")
    }

    pub async fn verrify_token(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/verrify_token", self.address))
            .send()
            .await
            .expect("failed to execute request")
    }
}
