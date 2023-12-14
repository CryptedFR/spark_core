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

    pub fn get_address(&self) -> Result<String, Error> {
        let result = self.database.get(b"address")?;
        let address = result.unwrap();
        let address = std::str::from_utf8(address.as_ref()).unwrap();
        Ok(String::from(address))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_address() {
        let db = WalletDatabase::open("F:/Dev/Web3/libs/spark_core/test_storage").unwrap();
        let result = db.store_address(String::from("1c58uBkR6arPznA7XHiyhjH9ScYDsise8mTWKa2"));
        assert!(result.is_ok());
        drop(result);

        let result = db.get_address();
        assert!(result.is_ok());
        let address = result.unwrap();

        assert_eq!(address, "1c58uBkR6arPznA7XHiyhjH9ScYDsise8mTWKa2");

        db.close().unwrap();

        WalletDatabase::delete("F:/Dev/Web3/libs/spark_core/test_storage");

    }
}