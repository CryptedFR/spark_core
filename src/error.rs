#[derive(Debug)]
pub enum Error {
    SledError(sled::Error),
    IoError(std::io::Error),
    Argon2Error(argon2::Error),
    AesGcmError(aes_gcm::Error),
    PasswordHashError(argon2::password_hash::Error),
}

impl From<sled::Error> for Error {
    fn from(err: sled::Error) -> Error {
        Error::SledError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Error {
        Error::Argon2Error(err)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(err: aes_gcm::Error) -> Error {
        Error::AesGcmError(err)
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from (err: argon2::password_hash::Error) -> Error {
        Error::PasswordHashError(err)
    }
}
