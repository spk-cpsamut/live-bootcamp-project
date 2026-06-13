use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes
            .remove(email)
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let (id, code) = self
            .codes
            .get(email)
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        Ok((id.clone(), code.clone()))
    }
}

impl HashmapTwoFACodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_code_should_add_code_correctly() {
        let mut code_store = HashmapTwoFACodeStore {
            codes: HashMap::new(),
        };

        let email = Email::parse("test@gmail.com".to_owned().into()).expect("Invalid email");
        let id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let res = code_store
            .add_code(email.clone(), id.clone(), code.clone())
            .await;

        assert_eq!(res.is_ok(), true);

        assert_eq!(code_store.codes.get(&email).is_some(), true);
        assert_eq!(code_store.codes.get(&email), Some(&(id, code)));
    }

    #[tokio::test]
    async fn test_remove_code_correctly() {
        let mut code_store = HashmapTwoFACodeStore {
            codes: HashMap::new(),
        };

        let email = Email::parse("test@gmail.com".to_owned().into()).expect("Invalid email");
        let id = LoginAttemptId::default();
        let code = TwoFACode::default();

        code_store
            .codes
            .insert(email.clone(), (id.clone(), code.clone()));

        let res = code_store.remove_code(&email).await;

        assert_eq!(res.is_ok(), true);

        assert_eq!(code_store.codes.get(&email), None);
    }

    #[tokio::test]
    async fn test_remove_code_notfound() {
        let mut code_store = HashmapTwoFACodeStore {
            codes: HashMap::new(),
        };

        let email = Email::parse("test@gmail.com".to_owned().into()).expect("Invalid email");
        let id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let email2 = Email::parse("tt01@gmail.com".to_owned().into()).expect("Invalid email");

        code_store
            .codes
            .insert(email.clone(), (id.clone(), code.clone()));

        let res = code_store.remove_code(&email2).await;

        assert_eq!(res, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));

        assert_eq!(code_store.codes.get(&email).is_some(), true);
    }

    #[tokio::test]
    async fn test_get_code_correctly() {
        let mut code_store = HashmapTwoFACodeStore {
            codes: HashMap::new(),
        };

        let email = Email::parse("test@gmail.com".to_owned().into()).expect("Invalid email");
        let id = LoginAttemptId::default();
        let code = TwoFACode::default();

        code_store
            .codes
            .insert(email.clone(), (id.clone(), code.clone()));

        let res = code_store.get_code(&email).await;

        assert_eq!(res, Ok((id.clone(), code.clone())))
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let mut code_store = HashmapTwoFACodeStore {
            codes: HashMap::new(),
        };

        let email = Email::parse("test@gmail.com".to_owned().into()).expect("Invalid email");
        let id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let email2 = Email::parse("tt01@gmail.com".to_owned().into()).expect("Invalid email");

        code_store
            .codes
            .insert(email.clone(), (id.clone(), code.clone()));

        let res = code_store.get_code(&email2).await;

        assert_eq!(res, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));
    }
}
