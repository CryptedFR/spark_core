use crate::error::Error;
use sled::Db;
use std::path::PathBuf;

pub struct WalletDatabase {
    database: Db
}

impl WalletDatabase {
    pub fn open(path: &str) -> Result<Self, Error> {

        let mut path_buf: PathBuf = PathBuf::from(path);
        path_buf.push("data_storage");

        let db = sled::open(&path_buf)?;

        Ok(WalletDatabase {
            database: db
        })
    }

    pub fn close(self) -> Result<(), Error>{
        self.database.flush()?;
        drop(self.database);
        Ok(())
    }

    pub fn store_password(&self, password_hash: String) -> Result<(), Error> {
        self.database.insert(b"password", password_hash.as_str())?;
        Ok(())
    }

    pub fn store_private_key(&self, private_key: Vec<u8>) -> Result<(), Error> {
        self.database.insert(b"private_key", private_key)?;
        Ok(())
    }

    pub fn store_address(&self, address: String) -> Result<(), Error> {
        self.database.insert(b"address", address.as_bytes())?;
        Ok(())
    }

    pub fn store_salt(&self, salt: [u8; 16]) -> Result<(), Error> {
        self.database.insert(b"salt", &salt)?;
        Ok(())
    }

    #[cfg(test)]
    pub fn delete(path: &str) {
        std::fs::remove_dir_all(path).unwrap();
    }
}