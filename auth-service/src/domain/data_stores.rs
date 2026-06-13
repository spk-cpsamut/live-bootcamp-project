use crate::domain::{Email, HashedPassword};

use super::User;

use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("unexpedted error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for BannedTokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn add_token_to_ban_list(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn is_token_not_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Serialize for LoginAttemptId {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        let _ = uuid::Uuid::parse_str(&id.expose_secret()).wrap_err("Invalid FA code")?;

        Ok(LoginAttemptId(id))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        let uuid = uuid::Uuid::new_v4();

        Self(uuid.to_string().into())
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TwoFACode(SecretString);

impl TwoFACode {
    pub fn parse(code: SecretString) -> Result<Self> {
        if code.expose_secret().len() != 6 {
            return Err(eyre!("Invalid Code".to_owned()));
        }

        Ok(Self(code))
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Serialize for TwoFACode {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::rng();
        let n: u32 = rng.random_range(100_000..=999_999);

        Self(n.to_string().into())
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}
