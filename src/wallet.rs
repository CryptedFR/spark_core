use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    key_pair: KeyPair,
    address: String,
    path: String
}