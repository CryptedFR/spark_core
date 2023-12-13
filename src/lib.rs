pub mod error;
mod core;

#[cfg(test)]
mod tests {
    use std::panic;

    use super::*;

    #[test]
    fn test_init(){
        let address = core::wallet::Wallet::init("F:/Dev/Web3/libs/spark_core", "Clemenflo").unwrap();

        println!("{}", address);

        core::database::WalletDatabase::delete("F:/Dev/Web3/libs/spark_core/data_storage");
    }
    
}
