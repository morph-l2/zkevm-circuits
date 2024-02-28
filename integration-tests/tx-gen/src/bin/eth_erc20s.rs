use dotenv::dotenv;
use env_logger::Env;
use std::env::var;
use std::str::FromStr;
use std::sync::Arc;

use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use ethers::types::Address;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tx_gen::abi::token_abi::Token;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    run().await;
    log::info!("run complete");
}

async fn run() {
    dotenv().ok();
    let token_address = var("TOKEN_ADDRESS").expect("Cannot detect TOKEN_ADDRESS env var");
    let private_key = var("PRIVATE_KEY").expect("Cannot detect PRIVATE_KEY env var");
    let eth_rpc = var("ETH_RPC").expect("Cannot detect ETH_RPC env var");

    let l2_provider: Provider<Http> = Provider::<Http>::try_from(eth_rpc.as_str()).unwrap();
    let chain_id = l2_provider.get_chainid().await.unwrap().as_u64();
    let l2_signer = Arc::new(SignerMiddleware::new(
        l2_provider.clone(),
        Wallet::from_str(private_key.as_str()).unwrap().with_chain_id(chain_id),
    ));

    let token: Token<SignerMiddleware<Provider<Http>, _>> =
        Token::new(Address::from_str(token_address.as_str()).unwrap(), l2_signer.clone());

    let count = l2_provider.get_transaction_count(l2_signer.address(), None).await;
    log::info!(
        "l2_signer.address: {:#?}, tx count: {:#?}",
        l2_signer.address(),
        count.unwrap()
    );

    let mut wallet_vec = Vec::<(
        Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
        Token<SignerMiddleware<Provider<Http>, _>>,
    )>::new();

    let mut i: i32 = 0;
    //Prepare balance
    while i < 10 {
        i += 1;
        let mut rng = rand::thread_rng();
        let wallet = Wallet::new(&mut rng).with_chain_id(chain_id);

        //ETH
        let tx = TransactionRequest::new().to(wallet.address()).value(1 * 10u64.pow(18));
        l2_signer.send_transaction(tx, None).await.unwrap();
        std::thread::sleep(Duration::from_secs(2));

        //Token
        let tx1 = token.transfer(wallet.address(), U256::from(10000)).legacy();
        let rt: Result<_, _> = tx1.send().await;
        let pending_tx = match rt {
            Ok(pending_tx) => pending_tx,
            Err(e) => {
                log::info!("prepare fail: {:?}", e);
                continue;
            }
        };
        std::thread::sleep(Duration::from_secs(2));
        log::info!(
            "==========>Prepare balance block_number:{:?}",
            l2_provider.get_block_number().await.unwrap()
        );

        let receipt = l2_provider.get_transaction_receipt(pending_tx.tx_hash()).await.unwrap();
        match receipt {
            Some(receipt) => {
                match receipt.status.unwrap().as_u64() {
                    1 => (),
                    _ => {
                        log::info!("prepare fail");
                        continue;
                    }
                };
            }
            // Maybe still pending
            None => {
                log::info!("prepare pending");
                // continue;
            }
        }

        let balance = token.balance_of(wallet.address()).await.unwrap();
        assert!(balance == U256::from(10000), "token balance is not as expected");
        log::info!("prepare success, index = {:?}", i);

        let singer = Arc::new(SignerMiddleware::new(l2_provider.clone(), wallet));
        let token_ts: Token<SignerMiddleware<Provider<Http>, _>> =
            Token::new(Address::from_str(token_address.as_str()).unwrap(), singer.clone());

        wallet_vec.push((singer.clone(), token_ts));
    }

    // token_vec.spl
    log::info!("waiting for start eth_erc20 tx");
    std::thread::sleep(Duration::from_secs(5));
    log::info!("current time: {:?}", SystemTime::now());
    log::info!(
        "==========>block_number_start:{:?}",
        l2_provider.get_block_number().await.unwrap()
    );

    // ETH and erc20 concurrent transfer
    for i in 1..100 {
        for chunk in wallet_vec.chunks(2) {
            let mut handles: Vec<JoinHandle<()>> = Vec::new();
            for token_ts in chunk.to_owned() {
                if handles.len() % 2 == 1 {
                    let handle = tokio::spawn(async move {
                        let tx = TransactionRequest::new().to(Address::random()).value(1);
                        let rt = token_ts.0.send_transaction(tx, None).await;
                        match rt {
                            Ok(pending_tx) => {
                                log::info!("transfer eth success:  {:#?}", pending_tx.tx_hash());
                            }
                            Err(e) => log::error!("transfer ETH fail: {:?}", e),
                        }
                    });
                    handles.push(handle);
                } else {
                    let handle: JoinHandle<()> = tokio::spawn(async move {
                        let tx = token_ts
                            .1
                            .transfer(Address::random(), U256::from(1))
                            .gas(60000)
                            .legacy();
                        let rt = tx.send().await;
                        match rt {
                            Ok(pending_tx) => {
                                log::info!("transfer erc20 success:  {:#?}", pending_tx.tx_hash());
                            }
                            Err(e) => log::error!("transfer erc20 fail: {:?}", e),
                        }
                    });
                    handles.push(handle);
                }
            }
            std::thread::spawn(|| async {
                for h in handles {
                    h.await.unwrap();
                }
            });
            log::info!("chunk starting");
            std::thread::sleep(Duration::from_millis(500));
        }

        log::info!(
            "==========>epoch: {:?} complete, block_number: {:?}",
            i,
            l2_provider.get_block_number().await.unwrap()
        );
    }
    log::info!(
        "==========>block_number_end:{:?}",
        l2_provider.get_block_number().await.unwrap()
    );
    log::info!("current time: {:?}", SystemTime::now());

    std::thread::sleep(Duration::from_secs(20));
}
