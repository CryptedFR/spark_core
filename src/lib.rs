pub mod error;
mod core;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        let result: Result<core::wallet::Wallet, error::Error> = core::wallet::Wallet::init("F:/Dev/Web3/libs/spark_core", "Clemenflo");
        
        assert!(result.is_ok());

        // let address = result.unwrap().address;

        // println!("Generated address : {}", address);

        core::database::WalletDatabase::delete("F:/Dev/Web3/libs/spark_core/data_storage");
    }

    // #[test]
    // fn test_open() {
    //     let result = core::wallet::Wallet::open("F:/Dev/Web3/libs/spark_core");

    //     assert!(result.is_ok());

    //     let wallet = result.unwrap();

    //     let address = wallet.address;

    //     let result = core::address::Address::verify(address);

    //     assert!(result.is_ok());

    //     let address_check = result.unwrap();

    //     assert_eq!(address_check, true);


    //     core::database::WalletDatabase::delete("F:/Dev/Web3/libs/spark_core/data_storage");
    // }
}
