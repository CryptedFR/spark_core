/*
*** @author: Clément Caillat
*** @project: Sparkwallet
*** @created: 04/12/2023
*** @description: Bitcoin address generation implementation (will later be updated to implement our own mechanism)
*/

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;


// Public struct for address
pub struct Address {
    pub value: String,
}

// Generator trait creation for address
trait Generator {
    // Declaration of functions for Generator trait
    fn new(public_key: &[u8]) -> String;
    fn generate_address(public_key: &[u8]) -> String;
    fn hash_sha256_public_key(pk: &[u8]) -> [u8; 32];
    fn hash_ripemd160_pk(pk_hash: [u8; 32]) -> [u8; 20];
    fn add_network_prefix(pk_ripmed_hash: [u8; 20]) -> [u8; 21];
    fn double_hash_ripmed_network_prefix(hash_ripmed_network_prefix: [u8; 21]) -> [u8; 8];
    fn build_address(prefixed_hash: [u8; 21], checksum: [u8; 8]) -> [u8; 29];
    fn encode_address(address: [u8; 29]) -> String;
}

// New function implementation for address generator
impl Address {
    pub fn new(public_key: &[u8]) -> String {
        <Address as Generator>::new(public_key)
    }
}


impl Generator for Address{

    // Function that takes public_key as &str (later takes that argument into bytes directly)
    fn new(public_key: &[u8]) -> String {
        Self::generate_address(public_key)
    }

    // Main function for address generation
    fn generate_address(public_key: &[u8]) -> String {
        let pk_hash: [u8; 32] = Self::hash_sha256_public_key(public_key);
        let pk_ripmed_hash: [u8; 20] = Self::hash_ripemd160_pk(pk_hash);
        let prefixed_ripemd_hash: [u8; 21] = Self::add_network_prefix(pk_ripmed_hash);
        let checksum: [u8; 8] = Self::double_hash_ripmed_network_prefix(prefixed_ripemd_hash);
        let built_address = Self::build_address(prefixed_ripemd_hash, checksum);
        let address = Self::encode_address(built_address);
        address
    }

    // First implementation of address generation by hashing (sha256) our public key and return a bytes array of the hash
    fn hash_sha256_public_key(pk: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(pk);
        let hash = hasher.finalize();
        hash.into()
    }

    // Second implementation of address generation by hashing (ripemd160) our public key hash and return a bytes array of the hash
    fn hash_ripemd160_pk(pk_hash: [u8; 32]) -> [u8; 20] {
        let mut hasher = Ripemd160::new();
        hasher.update(pk_hash);
        hasher.finalize().into()
    }

    // Third implementation of address generation by adding network prefix at the start of our ripemd160 hash
    fn add_network_prefix(pk_ripmed_hash: [u8; 20]) -> [u8; 21] {
        let mut vtx: [u8; 21] = [0u8; 21];
        vtx[0] = 0x00;
        vtx[1..].copy_from_slice(&pk_ripmed_hash);
        vtx
    }

    // Fourth implementation of address generation by calculating the checksum of the hashed public key (4 last bytes of the double hash)
    fn double_hash_ripmed_network_prefix(hash_ripmed_network_prefix: [u8; 21]) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(hash_ripmed_network_prefix);
        let first_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first_hash);
        let hash = hasher.finalize();
        
        let mut checksum: [u8; 8] = [0u8; 8];
        checksum.copy_from_slice(&hash[0..8]);
        checksum
    }

    // Fifth implementation of address generation by concatenate the network prefix, the ripemd160 hash of the public key and the checksum
    fn build_address(prefixed_hash: [u8; 21], checksum: [u8; 8]) -> [u8; 29] {
        let mut built_address: [u8; 29] = [0u8; 29];
        built_address[..21].copy_from_slice(&prefixed_hash);
        built_address[21..].copy_from_slice(&checksum);
        built_address
    }

    // Finally, encoding the address with Base58
    fn encode_address(address: [u8; 29]) -> String {
        bs58::encode(address).into_string()
    }
}

// Unit testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_sha256_public_key_type() {
        let pk: &[u8] = "045994d78264e6d70d60653421007d8f0ad2c5d22f768c6a97969a01269691ee06643aa64a96d8669e51d1dfc7decfbb64b968c4a59ed1a7d3a21a45143abab57d".as_bytes();
        let pk_hash: [u8; 32] = Address::hash_sha256_public_key(pk);
        let expected_hash: String = String::from("960166e8e702b7f53d4b71205316fb14f86799ecc5fc1bda7f94ec016ad5b353");
        assert_eq!(hex::encode(&pk_hash), expected_hash, "Le hash n'est pas le bon");
    }
}
