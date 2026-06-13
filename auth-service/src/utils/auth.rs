use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::{app_state::BannedTokenStoreType, domain::Email};

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use thiserror::Error;

#[tracing::instrument(name = "generate_auth_cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

#[tracing::instrument(name = "create_auth_cookie", skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    cookie
}

pub const TOKEN_TTL_SECONDS: i64 = 600;


#[tracing::instrument(name = "generate_auth_token", skip_all)]
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
        "failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims)
}


#[tracing::instrument(name = "validate_token", skip_all)]
pub async fn validate_token(
    token: &str,
    banned_token_store: BannedTokenStoreType,
) -> Result<Claims> {
    match banned_token_store.read().await.is_token_not_banned(token).await {
        Ok(value) => {
            if value {
                return Err(eyre!("token is banned"));
            }
        }
        Err(e) => return Err(e.into()),
    }

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

#[tracing::instrument(name = "create_token", skip_all)]
fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug)]
pub enum ValidateTokenError {
    InvalidToken,
    BannedToken,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use tokio::sync::RwLock;

    use crate::{
        domain::BannedTokenStore,
        services::hashmap_banned_token_store::{self, HashmapBannedTokenStore},
    };

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned().into()).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned().into()).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned().into()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let hashmap_banned_token_store = Arc::new(RwLock::new(HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        }));
        let result = validate_token(&token, hashmap_banned_token_store)
            .await
            .unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let hashmap_banned_token_store = Arc::new(RwLock::new(HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        }));
        let token = "invalid_token".to_owned();
        let result = validate_token(&token, hashmap_banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned().into()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let hashmap_banned_token_store = Arc::new(RwLock::new(HashmapBannedTokenStore {
            banned_tokens: HashMap::new(),
        }));

        let hashmap_banned_token_store_clone = hashmap_banned_token_store.clone();
        let mut hashmap_banned_token_store_clone_write =
            hashmap_banned_token_store_clone.write().await;
        let _ = hashmap_banned_token_store_clone_write
            .add_token_to_ban_list(token.clone())
            .await;
        drop(hashmap_banned_token_store_clone_write);
        let result = validate_token(&token, hashmap_banned_token_store.clone()).await;
        assert_eq!(result.is_err(), true);
    }
}
