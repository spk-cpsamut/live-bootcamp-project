use std::collections::HashMap;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

pub struct HashmapBannedTokenStore {
    pub banned_tokens: HashMap<String, bool>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashmapBannedTokenStore {
    async fn add_token_to_ban_list(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token, true);
        Ok(())
    }

    async fn is_token_not_banned(&self, token: &str) -> Result<(), BannedTokenStoreError> {
        let is_token_banned = self.banned_tokens.get(token).unwrap_or(&false);

        if *is_token_banned {
            return Err(BannedTokenStoreError::TokenBanned);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_token_to_ban_list() {
        let token = "test_token".to_owned();

        let mut store = HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        };

        let _ = store.add_token_to_ban_list(token.clone()).await;

        assert_eq!(store.banned_tokens.get(&token).unwrap_or(&false), &true);
    }

    #[tokio::test]
    async fn should_return_TokenBanned_if_token_is_banned() {
        let token = "test_token".to_owned();

        let mut store = HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        };

        let _ = store.add_token_to_ban_list(token.clone()).await;

        let ret = store.is_token_not_banned(&token).await;

        assert_eq!(ret, Err(BannedTokenStoreError::TokenBanned));
    }

    #[tokio::test]
    async fn should_return_ok_if_token_is_notbanned() {
        let token = "test_token".to_owned();

        let store = HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        };

        let ret = store.is_token_not_banned(&token).await;

        assert_eq!(ret.is_ok(), true);
    }
}
