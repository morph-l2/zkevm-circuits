use dotenv::dotenv;
use env_logger::Env;
use std::env::var;
use std::str::FromStr;
use std::sync::Arc;

use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use std::time::Duration;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    run().await;
    println!("tx complete");
}

async fn run() {
    dotenv().ok();
    let private_key = var("PRIVATE_KEY").expect("Cannot detect PRIVATE_KEY env var");
    let eth_rpc = var("ETH_RPC").expect("Cannot detect ETH_RPC env var");

    let l2_provider: Provider<Http> = Provider::<Http>::try_from(eth_rpc.as_str()).unwrap();
    let chain_id = l2_provider.get_chainid().await.unwrap().as_u64();
    //1212121212121212121212121212121212121212121212121212121212121212
    //3e4bde571b86929bf08e2aaad9a6a1882664cd5e65b96fff7d03e1c4e6dfa15c
    let l2_signer = Arc::new(SignerMiddleware::new(
        l2_provider.clone(),
        Wallet::from_str(private_key.as_str()).unwrap().with_chain_id(chain_id),
    ));

    let signer_balance = l2_provider.get_balance(l2_signer.address(), None).await.unwrap();
    log::info!("signer_eth_balance: {:#?}", signer_balance);

    let count = l2_provider.get_transaction_count(l2_signer.address(), None).await;
    println!("tx count: {:?}", count.unwrap());

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    for _i in 1..5 {
        let target_wallet = Wallet::new(&mut rng).with_chain_id(chain_id);
        let tx = TransactionRequest::new()
            .to(target_wallet.address())
            .value(10u64.pow(18));
        l2_signer.send_transaction(tx, None).await.unwrap();
        std::thread::sleep(Duration::from_secs(10));
        let balance = l2_provider.get_balance(target_wallet.address(), None).await.unwrap();
        log::info!("eth balance: {:#?}", balance);
        assert!(balance == U256::from(10u64.pow(18)), "Balance is not as expected");
        log::info!(
            "==========>block_number_end:{:?}",
            l2_provider.get_block_number().await.unwrap()
        );
    }
}
