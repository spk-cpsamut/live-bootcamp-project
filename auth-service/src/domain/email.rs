
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email, EmailError> {
        if !email.contains("@") || email.is_empty() {
            return Err(EmailError::InvalidEmail);
        }

        Ok(Email(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub enum EmailError {
    InvalidEmail,
}
