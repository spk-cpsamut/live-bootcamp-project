use std::sync::Arc;

use redis::{Commands, Connection};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};
use color_eyre::eyre::Context;

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {

    #[tracing::instrument(name = "add_code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        // 1. Create a new key using the get_key helper function.
        let key = get_key(&email);
        // 2. Create a TwoFATuple instance.
        let two_fa_tuple = (login_attempt_id, code);
        // 3. Use serde_json::to_string to serialize the TwoFATuple instance into a JSON string.
        let serialized_two_fa = serde_json::to_string(&two_fa_tuple)
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e))?;
        // 4. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL).
        self.conn
            .write()
            .await
            .set_ex::<std::string::String, std::string::String, ()>(
                key,
                serialized_two_fa,
                TEN_MINUTES_IN_SECONDS,
            )
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(email);
        // 2. Call the del command on the Redis connection to delete the 2FA code entry.
        self.conn
            .write()
            .await
            .del(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }


    #[tracing::instrument(name = "get_code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(email);
        // 2. Call the get command on the Redis connection to get the value stored for the key.
        let Some(val): Option<String> = self
            .conn
            .write()
            .await
            .get(key)
            .wrap_err("failed to get 2FA tuple Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?
        else {
            return Err(TwoFACodeStoreError::LoginAttemptIdNotFound);
        };
        // Return TwoFACodeStoreError::LoginAttemptIdNotFound if the operation fails.
        // If the operation succeeds, call serde_json::from_str to parse the JSON string into a TwoFATuple.
        let deserialized = serde_json::from_str::<(LoginAttemptId, TwoFACode)>(&val)
        .wrap_err("failed to deserialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        // Then, parse the login attempt ID string and 2FA code string into a LoginAttemptId and TwoFACode type respectively.
        // Return TwoFACodeStoreError::UnexpectedError if parsing fails.
        Ok(deserialized)
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
