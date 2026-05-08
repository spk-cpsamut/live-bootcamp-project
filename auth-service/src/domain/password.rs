
#[derive(Clone)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password, PasswordError> {
        if password.len() < 8 {
            return Err(PasswordError::PasswordTooShort);
        }

        Ok(Password(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub enum PasswordError {
    PasswordTooShort,
}
