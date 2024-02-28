use dotenv::dotenv;
use env_logger::Env;
use std::env::var;
use std::str::FromStr;
use std::sync::Arc;

use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use ethers::types::Address;
use std::time::Duration;
use tx_gen::abi::token_abi::Token;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    run().await;
    println!("tx complete");
}

async fn run() {
    dotenv().ok();
    let token_address = var("TOKEN_ADDRESS").expect("Cannot detect TOKEN_ADDRESS env var");
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

    let token: Token<SignerMiddleware<Provider<Http>, _>> =
        Token::new(Address::from_str(token_address.as_str()).unwrap(), l2_signer.clone());

    let count = l2_provider.get_transaction_count(l2_signer.address(), None).await;
    log::info!("tx count: {:#?}", count.unwrap());

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let target_wallet = Wallet::new(&mut rng).with_chain_id(chain_id);
    let tx = token.transfer(target_wallet.address(), U256::from(100)).legacy();
    let rt: Result<_, _> = tx.send().await;
    let pending_tx = match rt {
        Ok(pending_tx) => {
            log::info!("transfer erc20 success:  {:#?}", pending_tx);
            pending_tx
        }
        Err(e) => {
            log::error!("transfer erc20 failed: {:#?}", e);
            return;
        }
    };
    //Waiting for tx confirmed
    std::thread::sleep(Duration::from_secs(10));
    let balance = token.balance_of(target_wallet.address()).await.unwrap();
    log::info!("erc20 token balance: {:#?}", balance);
    // assert!(balance == U256::from(100), "erc20 token balance is not as expected");

    let check_receipt = || async {
        let receipt = l2_provider.get_transaction_receipt(pending_tx.tx_hash()).await;
        if let Err(e) = receipt {
            log::error!("get receipt error, msg: {:#?}", e);
            return false;
        }
        match receipt.unwrap() {
            Some(tr) => {
                // Either 1 (success) or 0 (failure).
                match tr.status.unwrap_or_default().as_u64() {
                    1 => {
                        log::info!("prove_state receipt success, block_number: {:#?}", tr.block_number)
                    }
                    _ => {
                        log::error!("prove_state receipt fail: {:#?}", tr)
                    }
                };
                return true;
            }
            // Maybe still pending
            None => {
                log::info!("prove_state tx is pending: {:#?}", pending_tx.tx_hash());
                return false;
            }
        }
    };
    for _ in 1..10 {
        std::thread::sleep(Duration::from_secs(2));
        if check_receipt().await {
            return;
        };
    }
}
