use color_eyre::eyre::eyre;
use sqlx::PgPool;

use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        sqlx::query!(
            r#"
        INSERT INTO users (email, password_hash, requires_2fa)
        VALUES ( $1, $2, $3 )
        "#,
            user.email.as_ref(),
            user.password.as_ref(),
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let res = sqlx::query!(
            r#"
            SELECT * FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        let user = res.ok_or_else(|| UserStoreError::UserNotFound)?;

        let email = Email::parse(user.email).map_err(|e| UserStoreError::UnexpectedError(eyre!("unexpected email error")))?;
        let hashed_password = HashedPassword::parse_password_hash(user.password_hash)
            .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        Ok(User::new(email, hashed_password, user.requires_2fa))
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}
