use eth_types::{sign_types::SignData, Address, Field, ToLittleEndian, ToScalar, Word, U256};
use bls12_381::{Scalar as Fp};

use super::{block::Block,Transaction};

const MAX_BLOB_DATA_SIZE: usize = 4096 * 31 - 4;
#[derive(Clone, Debug, Default)]
pub struct BlobValue(Vec<u8>);

#[derive(Clone, Debug, Default)]
pub struct BlockBlob{
    /// batch_commit
    pub batch_commit: Word,
    /// challenge_point
    pub x: Word,
    /// index
    pub index: usize,
    /// partial polynomial result
    pub p_y: Word,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitBlob<F>{
    /// commit of batch
    pub batch_commit: F,
    /// challenge point x
    pub z: Fp,
    /// index of blob element    
    pub index: usize,
    /// partial blob element    
    pub partial_blob: Vec<Fp>,
    /// partial result
    pub p_y: Fp,
}

// impl BlobValue{
//     pub fn to_scalar(&self)->Vec<Fp> {
//         match blob_from_tx(txs) {
//             Ok(blob) => {
//                 let mut result: Vec<Fp> = Vec::new();
//                 for chunk in blob.chunks(32) {
//                     let reverse: Vec<u8> = chunk.iter().rev().cloned().collect();  
//                     result.push(Fp::from_bytes(reverse.as_slice().try_into().unwrap()).unwrap());
//                 }
//                 log::trace!("partial blob: {:?}", result);
//                 result
                
//             }
//             Err(_) => Vec::new(),
//         }
//     }
// }

impl BlockBlob{ 
    pub fn default()-> Self{
        BlockBlob { batch_commit: Word::zero(), x: Word::zero(), index: 0, p_y: Word::zero() }
    }
}

impl<F: Field> CircuitBlob<F> {
    pub fn new(batch_commit:F, z:Fp, index:usize, partial_blob:Vec<Fp>, p_y: Fp)->Self{
        CircuitBlob{
            batch_commit,
            z,
            index,
            partial_blob,
            p_y
        }
    }

    pub fn new_from_block(block:&Block<F>)->Self{
        let block_blob = &block.blob;
        CircuitBlob{
            batch_commit: block_blob.batch_commit.to_scalar().unwrap(), 
            z: Fp::from_bytes(&block_blob.x.to_le_bytes()).unwrap(),
            index: block_blob.index,
            partial_blob: partial_blob_from_tx(&block.txs),
            p_y: Fp::from_bytes(&block_blob.p_y.to_le_bytes()).unwrap(),
        }
    }
    
}
pub fn partial_blob_from_tx(txs: &Vec<Transaction>) -> Vec<Fp> {
    match blob_from_tx(txs) {
        Ok(blob) => {
            let mut result: Vec<Fp> = Vec::new();
            for chunk in blob.0.chunks(32) {
                let reverse: Vec<u8> = chunk.iter().rev().cloned().collect();  
                result.push(Fp::from_bytes(reverse.as_slice().try_into().unwrap()).unwrap());
            }
            log::trace!("partial blob: {:?}", result);
            result
            
        }
        Err(_) => Vec::new(),
    }
}

pub fn blob_from_tx(txs: &Vec<Transaction>) -> Result<BlobValue, String> {
    // get data from block.txs.rlp_signed
    let data: Vec<u8> = txs
        .iter()
        .flat_map(|tx| &tx.rlp_signed)
        .cloned()
        .collect();

    if data.len() > MAX_BLOB_DATA_SIZE {
        return Err(format!("data is too large for blob. len={}", data.len()));
    }

    let mut result:Vec<u8> = vec![];

    result.push(0);
    result.extend_from_slice(&(data.len() as u32).to_le_bytes());
    let offset = std::cmp::min(27, data.len());
    result.extend_from_slice(&data[..offset]);

    if data.len() <= 27 {
        for _ in 0..(27 - data.len()) {
            result.push(0);
        }
        return Ok(result);
    }
    
    for chunk in data[27..].chunks(31) {
        let len = std::cmp::min(31, chunk.len());
        result.push(0);
        result.extend_from_slice(&chunk[..len]);
        for _ in 0..(31 - len) {
            result.push(0);
        }
    }

    Ok(result)
}