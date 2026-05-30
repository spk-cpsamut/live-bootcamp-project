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
        .map_err(|_| UserStoreError::UserAlreadyExists)?;

        Ok(())
    }
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
        .map_err(|_| UserStoreError::UnexpectedError)?;

        let user = res.ok_or_else(|| UserStoreError::UserNotFound)?;

        let email = Email::parse(user.email).map_err(|_| UserStoreError::UnexpectedError)?;
        let hashed_password = HashedPassword::parse_password_hash(user.password_hash)
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(User::new(email, hashed_password, user.requires_2fa))
    }
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}
