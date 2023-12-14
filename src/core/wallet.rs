/*
*** @author: Clément Caillat
*** @project: spark_core
*** @created: 12/12/2023
*** @description: Wallet implementation for Sparkwallet
*/

// use serde::{Serialize, Deserialize};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use crate::error::Error;
use super::crypto;
use super::database::WalletDatabase;
use super::address::Address;


pub struct Wallet {
    db: WalletDatabase,
    pub address: String,
}


impl Wallet {
    pub fn init(path: &str, password: &str) -> Result<Wallet, Error> {
        <Wallet as Initiator>::init(path, password)
    }

    pub fn open(path: &str) -> Result<Wallet, Error> {
        <Wallet as Opener>::open(path)
    }
}

trait Opener {
    fn open(path: &str) -> Result<Wallet, Error>;
}

impl Opener for Wallet {
    fn open(path: &str) -> Result<Wallet, Error> {
        let db: WalletDatabase = WalletDatabase::open(path)?;
        let address: String = db.get_address()?;

        Ok(Wallet {
            db,
            address
        })
    }

}

trait Initiator {
    fn init(path: &str, password: &str) -> Result<Wallet, Error>;
    fn create_key_pair() -> ([u8; 32], String);
    fn get_encryption_key(salt: [u8; 16], password: &str, password_hash: &str) -> Result<[u8; 32], Error>;
    fn get_password_hash(password: &str) -> Result<String, Error>;
}

impl Initiator for Wallet {
    fn init(path: &str, password: &str) -> Result<Self, Error> {
        let db: WalletDatabase = WalletDatabase::open(path)?;
        
        let keypair: ([u8; 32], String) = Self::create_key_pair();
        
        let password_hash: String = Self::get_password_hash(password)?;

        let salt: [u8; 16] = crypto::generate_salt();

        let encryption_key: [u8; 32] = Self::get_encryption_key(salt, password, &password_hash)?;
        
        let encrypted_private_key = crypto::encrypt_data(encryption_key, &keypair.0)?;
        
        
        let address = keypair.1.clone();
        
        db.store_salt(salt)?;
        
        db.store_private_key(encrypted_private_key)?;
        
        db.store_address(keypair.1)?;

        db.store_password(password_hash)?;

        Ok(Wallet {
            db,
            address
        })
    }

    fn create_key_pair() -> ([u8; 32], String) {
        let mut rng: OsRng = OsRng;

        let private_key = SigningKey::random(&mut rng);
        let public_key = private_key.verifying_key().clone();

        let private_key: [u8; 32] = private_key.to_bytes().into();
        let public_key = public_key.to_encoded_point(false);
        
        let address: String = Address::new(public_key.as_bytes());

        (private_key, address)
    }

    fn get_password_hash(password: &str) -> Result<String, Error>{
        let password_hash: String = crypto::create_password(password)?;
        Ok(password_hash)
    }

    fn get_encryption_key(salt: [u8; 16] ,password: &str, password_hash: &str) -> Result<[u8; 32], Error> {
        crypto::derive_password_encryption_key(salt, password, password_hash)
    }


}