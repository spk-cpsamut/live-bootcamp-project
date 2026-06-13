use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::error::Error;

#[derive(Clone, Debug)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl HashedPassword {
    pub async fn parse(password: SecretString) -> Result<HashedPassword, PasswordError> {
        if password.expose_secret().len() < 8 {
            return Err(PasswordError::PasswordTooShort);
        }

        let hashed = compute_password_hash(&password)
            .await
            .map_err(|_| PasswordError::UnexpectedError)?;

        Ok(Self(hashed.into()))
    }

    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword, String> {
        match PasswordHash::new(&hash.expose_secret().as_ref()) {
            Ok(_) => Ok(HashedPassword(hash.into())),
            Err(_) => Err("parse password failed".to_owned()),
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(
        &self,
        password_candidate: &SecretString,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();

        let blocking_task = tokio::task::spawn_blocking(move || {
            // This code block ensures that the operations within the closure are executed within the context of the current span.
            // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
            current_span.in_scope(|| {
                let expected_password_hash: PasswordHash<'_> =
                    PasswordHash::new(&password_hash.expose_secret())?;
                let res: Result<(), Box<dyn Error + Send + Sync>> = Argon2::default()
                    .verify_password(
                        password_candidate.expose_secret().to_owned().as_bytes(),
                        &expected_password_hash,
                    )
                    .map_err(|e| e.into());

                res
            })
        });

        let _ = blocking_task.await??;

        Ok(())
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(
    password: &SecretString,
) -> Result<SecretString, Box<dyn Error + Send + Sync>> {
    let current_span = tracing::Span::current();
    let password = password.to_owned();

    let block_task = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.expose_secret().as_bytes(), &salt)?
            .to_string();

            Ok::<SecretString, Box<dyn Error + Send + Sync>>(SecretString::new(
                password_hash.into_boxed_str(),
            ))
        })
    });

    let hashed = block_task.await??;

    Ok(hashed.into())
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

pub enum PasswordError {
    PasswordTooShort,
    UnexpectedError,
}

#[cfg(test)]
mod tests {
    use super::HashedPassword; // updated!
    use argon2::{
        // new
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm,
        Argon2,
        Params,
        PasswordHasher,
        Version,
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;
    use secrecy::{ExposeSecret, SecretBox, SecretString};

    // updated!
    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = "".to_owned();

        // updated!
        assert!(HashedPassword::parse(password.into()).await.is_err());
    }

    // updated!
    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_owned();
        // updated!
        assert!(HashedPassword::parse(password.into()).await.is_err());
    }

    // new
    #[test]
    fn can_parse_valid_argon2_hash() {
        // Arrange - Create a valid Argon2 hash
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Act
        let hash_password =
            HashedPassword::parse_password_hash(hash_string.clone().into()).unwrap();

        // Assert
        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));
    }

    // new
    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password =
            HashedPassword::parse_password_hash(hash_string.clone().into()).unwrap();

        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));

        // TODO: Use verify_raw_password to verify the password match
        let result = hash_password;

        // TODO: Assert the verification succeeds assert_eq!(result, ())
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password: String = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password.into())
        }
    }

    // updated!
    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok() // updated!
    }
}
