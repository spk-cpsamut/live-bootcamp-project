use std::hash::{Hash, Hasher};

use secrecy::{ExposeSecret, SecretString};

#[derive(Clone, Debug)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl Eq for Email {}

impl Hash for Email {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Email {
    pub fn parse(email: SecretString) -> Result<Email, EmailError> {
        if !email.expose_secret().contains("@") || email.expose_secret().is_empty() {
            return Err(EmailError::InvalidEmail);
        }

        Ok(Email(email))
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Debug)]
pub enum EmailError {
    InvalidEmail,
}
