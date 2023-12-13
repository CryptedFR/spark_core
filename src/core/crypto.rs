use std::hash;

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2,
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use rand_core::RngCore;

use crate::error::Error;

pub fn derive_password_encryption_key(salt: [u8; 16], password: &str, password_hash: &str) -> Result<[u8; 32], Error> {
    // Verifying if the password is valid
    let parsed_hash: PasswordHash<'_> = PasswordHash::new(password_hash)?;
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash)?;

    let key: &mut [u8; 32] = &mut [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, key)?;

    Ok(*key)
}

pub fn create_password(password: &str) -> Result<String, Error> {

    // Generate random salt for password
    let password_salt: SaltString = SaltString::generate(&mut OsRng);
    
    let password: &[u8] = password.as_bytes();

    let argon2: Argon2<'_> = Argon2::default();

    let password_hash: String = argon2.hash_password(password, &password_salt)?.to_string();
    
    Ok(password_hash)
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt: [u8; 16] = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}


pub fn encrypt_data(key: [u8; 32], data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key: &Key<Aes256Gcm> = &key.into();

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypting data
    let cipher_text: Vec<u8> = cipher.encrypt(&nonce, data)?;

    // Concatenate nonce and encrypted data
    let mut encrypted_data: Vec<u8> = Vec::with_capacity(nonce.len() + cipher_text.len());
    encrypted_data.extend_from_slice(nonce.as_slice());
    encrypted_data.extend_from_slice(&cipher_text);

    Ok(encrypted_data)
}

pub fn decrypt_data(key: [u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key: &Key<Aes256Gcm> = &key.into();

    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::clone_from_slice(&encrypted_data[0..12]);

    let cipher_text: &[u8] = &encrypted_data[12..];

    let data: Vec<u8> = cipher.decrypt(&nonce, cipher_text)?;

    Ok(data)
}


#[cfg(test)]
mod tests {
    use super::*;

    // Derive password into encryption key
    #[test]
    fn test_derive_encryption_key() {
        let password_salt: SaltString = SaltString::generate(&mut OsRng);
        let password: String = String::from("clemenflo");
        let password_hash: String = Argon2::default().hash_password(password.as_bytes(), &password_salt).unwrap().to_string();


        let derivation_salt: [u8; 16] = generate_salt();
        let key = derive_password_encryption_key(derivation_salt, &password, &password_hash);

        assert!(key.is_ok());

        let key = key.unwrap();
        assert_eq!(key.len(), 32);
    }

    // Creating password test
    #[test]
    fn test_create_password() {

        let password_string = String::from("clemenflo");

        let password_hash: Result<String, Error> = create_password(&password_string);

        assert!(password_hash.is_ok());

        let password_hash: String = password_hash.unwrap();
        assert!(!password_hash.is_empty());


        let parsed_hash: PasswordHash<'_> = PasswordHash::new(&password_hash).unwrap();
        let password_check = Argon2::default().verify_password(&password_string.as_bytes(), &parsed_hash);
        assert!(password_check.is_ok());
    }

    // Encrypting data
    #[test]
    fn test_encrypt_data() {
        let key = [0u8; 32];
        let data = b"data to encrypt";

        let result = encrypt_data(key, data);

        assert!(result.is_ok());

        let encrypted_data = result.unwrap();

        assert_ne!(encrypted_data, data);

        let nonce_len: usize = 12;
        let tag_len: usize = 16;

        assert_eq!(encrypted_data.len(), nonce_len + data.len() + tag_len);
    }

    // Decrypting data
    #[test]
    fn test_decrypt_data() {
        let key = [0u8; 32];
        let data = b"data to encrypt";

        let encrypted_data = encrypt_data(key, data).unwrap();

        assert_ne!(encrypted_data, data);

        let result = decrypt_data(key, &encrypted_data);

        assert!(result.is_ok());

        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data, data);
    }

    // Generating salt test
    #[test]
    fn test_generate_salt() {
        let salt: [u8; 16] = generate_salt();
        assert_eq!(salt.len(), 16);
    }
}