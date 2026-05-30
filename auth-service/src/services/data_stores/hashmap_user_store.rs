use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};

pub struct HashmapUserStore {
    pub email_map: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        match self.email_map.entry(user.email.clone()) {
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
            Entry::Vacant(entry) => {
                entry.insert(user);
                Ok(())
            }
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user = self
            .email_map
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)?;

        Ok(user)
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        
        user.password // updated password verification
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     fn test_add_user() {
//         todo!()
//     }

//     #[tokio::test]
//     fn test_get_user() {
//         todo!()
//     }

//     #[tokio::test]
//     fn test_validate_user() {
//         todo!()
//     }
// }
