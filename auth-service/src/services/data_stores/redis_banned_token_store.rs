use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token_to_ban_list(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(&token);
        // 2. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL).
        let mut redis_writer = self.conn.write().await;

        redis_writer
            .set_ex::<std::string::String, bool, u64>(key, true, TOKEN_TTL_SECONDS as u64)
            .map_err(|_| BannedTokenStoreError::Unexpected)?;

        Ok(())
    }

    async fn is_token_not_banned(&self, token: &str) -> Result<(), BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection

        let mut redis = self.conn.write().await;

        let key = get_key(token);
        let value = redis
            .exists::<std::string::String, bool>(key)
            .map_err(|_| BannedTokenStoreError::Unexpected)?;

        if value {
            return Err(BannedTokenStoreError::TokenBanned);
        }

        Ok(())
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
