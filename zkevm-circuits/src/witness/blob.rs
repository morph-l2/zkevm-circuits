use std::marker::PhantomData;

use eth_types::{sign_types::SignData, Address, Field, ToLittleEndian, ToScalar, Word, U256};
use bls12_381::{Scalar as Fp};

use super::{block::Block,Transaction};

const MAX_BLOB_DATA_SIZE: usize = 4096 * 31 - 4;
#[derive(Clone, Debug, Default)]
pub struct BlobValue(pub Vec<u8>);

#[derive(Clone, Debug, Default)]
pub struct BlockBlob{
    /// batch_commit
    pub batch_commit: Word,
    /// challenge_point
    pub z: Word,
    /// index
    pub index: usize,
    /// partial polynomial result
    pub p_y: Word,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitBlob<F>{
    /// index of blob element    
    pub index: usize,
    /// challenge point x
    pub z: Fp,
    /// partial blob element    
    pub partial_blob: Vec<Fp>,
    /// partial result
    pub p_y: Fp,
    _marker: PhantomData<F>,
}

impl BlobValue{
    pub fn from_tx(txs: &Vec<Transaction>) -> Result<Self, String> {
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
            return Ok(BlobValue(result));
        }
        
        for chunk in data[27..].chunks(31) {
            let len = std::cmp::min(31, chunk.len());
            result.push(0);
            result.extend_from_slice(&chunk[..len]);
            for _ in 0..(31 - len) {
                result.push(0);
            }
        }
    
        Ok(BlobValue(result))
    }

    pub fn to_coefficient(&self)->Vec<Fp> {
        let mut result: Vec<Fp> = Vec::new();
        for chunk in self.0.chunks(32) {
            let reverse: Vec<u8> = chunk.iter().rev().cloned().collect();  
            result.push(Fp::from_bytes(reverse.as_slice().try_into().unwrap()).unwrap());
        }
        log::trace!("partial blob: {:?}", result);
        result        
    }
}

impl BlockBlob{ 
    pub fn default()-> Self{
        BlockBlob { batch_commit: Word::zero(), z: Word::zero(), index: 0, p_y: Word::zero() }
    }
}

impl<F: Field> CircuitBlob<F> {
    pub fn new( z:Fp, index:usize, partial_blob:Vec<Fp>, p_y: Fp)->Self{
        CircuitBlob{
            z,
            index,
            partial_blob,
            p_y,
            _marker: PhantomData,
        }
    }

    pub fn new_from_block(block:&Block<F>)->Self{
        let block_blob = &block.blob;
        let blob = BlobValue::from_tx(&block.txs);
        let partial_blob = match blob {
            Ok(blob) => {
            blob.to_coefficient() 
            }
            Err(_) => Vec::new(),
        };
        CircuitBlob{ 
            z: Fp::from_bytes(&block_blob.z.to_le_bytes()).unwrap(),
            index: block_blob.index,
            partial_blob: partial_blob,
            p_y: Fp::from_bytes(&block_blob.p_y.to_le_bytes()).unwrap(),
            _marker: PhantomData,
        }
    }
    
}
// pub fn partial_blob_from_tx(txs: &Vec<Transaction>) -> Vec<Fp> {
//     match blob_from_tx(txs) {
//         Ok(blob) => {
//             let mut result: Vec<Fp> = Vec::new();
//             for chunk in blob.0.chunks(32) {
//                 let reverse: Vec<u8> = chunk.iter().rev().cloned().collect();  
//                 result.push(Fp::from_bytes(reverse.as_slice().try_into().unwrap()).unwrap());
//             }
//             log::trace!("partial blob: {:?}", result);
//             result
            
//         }
//         Err(_) => Vec::new(),
//     }
// }

// pub fn blob_from_tx(txs: &Vec<Transaction>) -> Result<BlobValue, String> {
//     // get data from block.txs.rlp_signed
//     let data: Vec<u8> = txs
//         .iter()
//         .flat_map(|tx| &tx.rlp_signed)
//         .cloned()
//         .collect();

//     if data.len() > MAX_BLOB_DATA_SIZE {
//         return Err(format!("data is too large for blob. len={}", data.len()));
//     }

//     let mut result:Vec<u8> = vec![];

//     result.push(0);
//     result.extend_from_slice(&(data.len() as u32).to_le_bytes());
//     let offset = std::cmp::min(27, data.len());
//     result.extend_from_slice(&data[..offset]);

//     if data.len() <= 27 {
//         for _ in 0..(27 - data.len()) {
//             result.push(0);
//         }
//         return Ok(BlobValue(result));
//     }
    
//     for chunk in data[27..].chunks(31) {
//         let len = std::cmp::min(31, chunk.len());
//         result.push(0);
//         result.extend_from_slice(&chunk[..len]);
//         for _ in 0..(31 - len) {
//             result.push(0);
//         }
//     }

//     Ok(BlobValue(result))
// }