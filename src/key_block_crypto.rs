
use std::{cmp::min };

use cbc_mac::{Mac};
use cmac::{self, Cmac};
use ctr::{self, Ctr32BE};

use aead::{AeadCore, AeadInPlace};

use cipher::typenum::{ IsLess, U256, Le, NonZero, Unsigned, U16, U4, U1, PartialDiv};
use cipher::block_padding::NoPadding ;
use cipher::generic_array::GenericArray;
use cipher::{BlockSizeUser, KeySizeUser, BlockCipher, BlockEncrypt, KeyInit, KeyIvInit, BlockEncryptMut, 
     StreamCipher, BlockDecrypt, BlockDecryptMut, IvSizeUser, AlgorithmName, ArrayLength, Block};

use dbl::Dbl;


#[derive(Clone, Copy)]
pub enum VariantValue {
    Encryption = 0x45,
    MAC = 0x4d,
}

#[derive(Clone, Copy, PartialEq)]
pub enum KeyUsageIndicatorForKeyDerivation {
    EncryptionCBC = 0x0000,
    MAC = 0x0001,
    EncryptionCTR = 0x0002,

}

#[derive(Clone, Copy, PartialEq)]
pub enum KBPKAlgorithm {
    Unknown = -1,
    Tdes2Key = 0,
    Tdes3Key = 1,
    Aes128 = 2,
    Aes192 = 3,
    Aes256 = 4,
}

/// Cryptographic operations for KeyBlocks using CBC mode for encryption and a truncated CBC_MAC for authentication.
/// Encryption and authentication keys are variants of the key block protection key
/// Used in Key Block versions A & C
pub struct KeyBlockCrypto1 <TCphr: KeySizeUser + BlockSizeUser> 
{
    kbak: GenericArray::<u8, TCphr::KeySize>,
    kbek: GenericArray::<u8, TCphr::KeySize>,
}
impl<TCphr> AeadCore for KeyBlockCrypto1<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type NonceSize = U16;
    type TagSize = U4;
    type CiphertextOverhead = TCphr::BlockSize;
}
impl<TCphr> KeySizeUser for KeyBlockCrypto1<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type KeySize = TCphr::KeySize;
}
impl<TCphr> BlockSizeUser for KeyBlockCrypto1<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type BlockSize = TCphr::BlockSize;
}



impl<TCphr> KeyBlockCrypto1<TCphr>
    where TCphr: KeySizeUser + BlockSizeUser,
{
    fn variant_key (kpbk: &GenericArray<u8,TCphr::KeySize>, variant_value: VariantValue ) -> GenericArray<u8,TCphr::KeySize>
    {
        let mut newkey = kpbk.clone();
        
        newkey.iter_mut().for_each ( |v| *v ^= variant_value as u8);
        return newkey;
    }
}

impl<TCphr> KeyInit for KeyBlockCrypto1<TCphr>
where TCphr: KeyInit + BlockSizeUser
{
    fn new(key: &aead::Key<Self>) -> Self {
        Self { 
            kbak: KeyBlockCrypto1::<TCphr>::variant_key(&key, VariantValue::MAC),
            kbek: KeyBlockCrypto1::<TCphr>::variant_key(&key, VariantValue::Encryption),
        }
    }
}


impl<TCphr> AeadInPlace for KeyBlockCrypto1<TCphr>
where TCphr: BlockSizeUser+ KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
{
    fn encrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8], confidential_data: &mut [u8] ) -> aead::Result<aead::Tag<Self>> {

        let ivlen = <cbc::Encryptor::<TCphr> as IvSizeUser>::IvSize::to_usize();

        let encryptor = <cbc::Encryptor::<TCphr> as KeyIvInit>::new(&self.kbek, nonce[0..ivlen].into());
        match encryptor.encrypt_padded_mut::<NoPadding>(confidential_data, confidential_data.len()) {
            Err(_) => return Err(aead::Error),
            Ok(_) => (),
        };

        let mut mac = <cbc_mac::CbcMac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
        
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data);
                
        let tag_bytes = mac.finalize().into_bytes();
                      
        return Ok(GenericArray::<u8, Self::TagSize>::clone_from_slice(&tag_bytes[..Self::TagSize::to_usize()]));
    }

    fn decrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8], confidential_data: &mut [u8], macv: &aead::Tag<Self> ) -> aead::Result<()> {

        let mut mac = <cbc_mac::CbcMac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data);
        
        match mac.verify_truncated_left ( macv.as_slice() ) {
            Err(_) => return Err(aead::Error),
            Ok(_) => (),
        }

        let ivlen = <cbc::Decryptor::<TCphr> as IvSizeUser>::IvSize::to_usize();
        let decryptor = <cbc::Decryptor::<TCphr> as KeyIvInit>::new(&self.kbek, nonce[0..ivlen].into());
        match decryptor.decrypt_padded_mut::<NoPadding>( confidential_data) {
            Err(_) => return Err(aead::Error),
            Ok(_) => return Ok(())
        }
    }


    
}













/// Cryptographic operations for KeyBlocks using CBC mode for encryption and C_MAC for authentication.
/// Encryption and authentication keys are derived from the key block protection key using CMAC as a one-way function
/// Used in Key Block versions B & D

pub struct KeyBlockCrypto2 <TCphr: KeySizeUser + BlockSizeUser> 
{
    kbak: GenericArray::<u8, TCphr::KeySize>,
    kbek: GenericArray::<u8, TCphr::KeySize>,
}

impl<TCphr> AeadCore for KeyBlockCrypto2<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type NonceSize = U16;
    type TagSize = TCphr::BlockSize;
    type CiphertextOverhead = TCphr::BlockSize;
}
impl<TCphr> KeySizeUser for KeyBlockCrypto2<TCphr>
where
    TCphr: KeySizeUser + BlockSizeUser,
{
    type KeySize = TCphr::KeySize;
}
impl<TCphr> BlockSizeUser for KeyBlockCrypto2<TCphr>
where
    TCphr: KeySizeUser + BlockSizeUser,
{
    type BlockSize = TCphr::BlockSize;
}



impl<TCphr> KeyBlockCrypto2<TCphr>
where TCphr: BlockSizeUser + KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt + AlgorithmName,
    cipher::Block<TCphr>: Dbl,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
    <TCphr as cipher::BlockSizeUser>::BlockSize: PartialDiv::<U4>,
    <<TCphr as cipher::BlockSizeUser>::BlockSize as PartialDiv<U4>>::Output: cipher::ArrayLength<u32>,
{
    fn derive_key (kpbk: &GenericArray::<u8,TCphr::KeySize>, algorithm: KBPKAlgorithm, keyusageindicator: KeyUsageIndicatorForKeyDerivation) -> GenericArray<u8,TCphr::KeySize>
    {
        let keysize = TCphr::key_size();
        let mut newkey = GenericArray::<u8,TCphr::KeySize>::default();

        let mut derivation_data = [ 0u8, 0u8, keyusageindicator as u8, 0, 0, algorithm as u8, ((keysize*8)>> 8)as u8, (keysize*8) as u8 ];
        
        let mut i = 0;
        while i < keysize
        {
            derivation_data[0] += 1;
            
            let mut mac2 = <Cmac::<TCphr> as cbc_mac::Mac>::new(kpbk);

            mac2.update ( &derivation_data);
            let out = mac2.finalize().into_bytes();
            
            newkey[i..min(i+out.len(),keysize)].clone_from_slice(&out);
            i = i + out.len();
        }
        return newkey;
    }

    fn get_kbpk_algorithm2 () -> KBPKAlgorithm
    {
        match ( TCphr::block_size(), TCphr::key_size() ) {
            (8, 16) => KBPKAlgorithm::Tdes2Key,
            (8, 24) => KBPKAlgorithm::Tdes3Key,
            (16, 16) => KBPKAlgorithm::Aes128,
            (16, 24) => KBPKAlgorithm::Aes192,
            (16, 32) => KBPKAlgorithm::Aes256,
            _ => KBPKAlgorithm::Unknown
        }
    }
}

impl<TCphr> KeyInit for KeyBlockCrypto2<TCphr>
where TCphr: BlockSizeUser + KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt + AlgorithmName,
    Block<TCphr>: dbl::Dbl,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
    <TCphr as cipher::BlockSizeUser>::BlockSize: PartialDiv::<U4>,
    <<TCphr as cipher::BlockSizeUser>::BlockSize as PartialDiv<U4>>::Output: ArrayLength<u32>
{
    fn new(key: &aead::Key<Self>) -> Self {
        let kbpk_alg = KeyBlockCrypto2::<TCphr>::get_kbpk_algorithm2();
        let kbak = KeyBlockCrypto2::<TCphr>::derive_key(&key, kbpk_alg, KeyUsageIndicatorForKeyDerivation::MAC);
        let kbek =KeyBlockCrypto2::<TCphr>::derive_key(&key, kbpk_alg, KeyUsageIndicatorForKeyDerivation::EncryptionCBC);
        Self { kbak: kbak, kbek: kbek }
    }
}

impl<TCphr> AeadInPlace for KeyBlockCrypto2<TCphr>
where TCphr: BlockSizeUser+ KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt + AlgorithmName,
    cipher::Block<TCphr>: dbl::Dbl,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
    <TCphr as cipher::BlockSizeUser>::BlockSize: PartialDiv::<U4>,
    <<TCphr as cipher::BlockSizeUser>::BlockSize as PartialDiv<U4>>::Output: ArrayLength<u32>,    
{
    fn encrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8], confidential_data: &mut [u8] ) -> aead::Result<aead::Tag<Self>> {
        let mut mac = <Cmac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data);
         
        let macv = mac.finalize().into_bytes(); 

        let encryptor = <cbc::Encryptor::<TCphr> as KeyIvInit>::new(&self.kbek, &macv);
        match encryptor.encrypt_padded_mut::<NoPadding>(confidential_data, confidential_data.len()) {
            Err(_) => return Err(aead::Error),
            Ok(_) => (),
        };

        return Ok(macv);
    }

    fn decrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8], confidential_data: &mut [u8], macv: &aead::Tag<Self> ) -> aead::Result<()> {
        let decryptor = <cbc::Decryptor::<TCphr> as KeyIvInit>::new(&self.kbek, macv.into());
     
        match decryptor.decrypt_padded_mut::<NoPadding>( confidential_data) {
            Err(_) => return Err(aead::Error),
            Ok(_) => ()
        }

        let mut mac = <cmac::Cmac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
    
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data );
        
        match mac.verify ( macv.into() ) {
            Err(_) => return Err(aead::Error),
            Ok(_) => return Ok(())
        }
    }
}



    








/// Cryptographic operations for KeyBlocks using CTR mode for encryption and C_MAC for authentication.
/// Encryption and authentication keys are derived from the key block protection key using CMAC as a one-way function
/// Used in Key Block versions E
pub struct KeyBlockCrypto3 <TCphr: KeySizeUser + BlockSizeUser> 
{
    kbak: GenericArray::<u8, TCphr::KeySize>,
    kbek: GenericArray::<u8, TCphr::KeySize>,
}
impl<TCphr> AeadCore for KeyBlockCrypto3<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type NonceSize = U16;
    type TagSize = TCphr::BlockSize;
    type CiphertextOverhead = U1;
}
impl<TCphr> KeySizeUser for KeyBlockCrypto3<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type KeySize = TCphr::KeySize;
}
impl<TCphr> BlockSizeUser for KeyBlockCrypto3<TCphr>
where TCphr: KeySizeUser + BlockSizeUser,
{
    type BlockSize = TCphr::BlockSize;
}

impl<TCphr> KeyInit for KeyBlockCrypto3<TCphr>
where TCphr: BlockSizeUser + KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt + AlgorithmName,
    Block<TCphr>: dbl::Dbl,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
    <TCphr as cipher::BlockSizeUser>::BlockSize: PartialDiv::<U4>,
    <<TCphr as cipher::BlockSizeUser>::BlockSize as PartialDiv<U4>>::Output: ArrayLength<u32>

{
    fn new(key: &aead::Key<Self>) -> Self {
        let kbpk_alg = KeyBlockCrypto2::<TCphr>::get_kbpk_algorithm2();
        let kbak = KeyBlockCrypto2::<TCphr>::derive_key(&key, kbpk_alg, KeyUsageIndicatorForKeyDerivation::MAC);
        let kbek =KeyBlockCrypto2::<TCphr>::derive_key(&key, kbpk_alg, KeyUsageIndicatorForKeyDerivation::EncryptionCTR);
        Self { kbak: kbak, kbek: kbek }
    }
}



impl<TCphr> AeadInPlace for KeyBlockCrypto3<TCphr>
where TCphr: BlockSizeUser+ KeySizeUser + BlockCipher + Clone + BlockEncrypt + KeyInit + BlockDecrypt + AlgorithmName,
    cipher::Block<TCphr>: dbl::Dbl,
    TCphr::BlockSize: IsLess<U256>,
    Le<TCphr::BlockSize, U256>: NonZero,
    <TCphr as cipher::BlockSizeUser>::BlockSize: PartialDiv::<U4>,
    <<TCphr as cipher::BlockSizeUser>::BlockSize as PartialDiv<U4>>::Output: ArrayLength<u32>,
{
    fn encrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8],confidential_data: &mut [u8] ) -> aead::Result<aead::Tag<Self>> {
        let mut mac = <cmac::Cmac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
    
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data);
         
        let macv = mac.finalize().into_bytes(); 

        let mut decryptor2 = <ctr::Ctr32BE::<TCphr> as KeyIvInit>::new(&self.kbek, &macv.clone().into());
        decryptor2.apply_keystream(confidential_data);

        return Ok(macv);
    }

    fn decrypt_in_place_detached( &self, nonce: &aead::Nonce<Self>, associated_data: &[u8], confidential_data: &mut [u8], macv: &aead::Tag<Self> ) -> aead::Result<()> {
        let mut decryptor2 = <Ctr32BE::<TCphr> as KeyIvInit>::new(&self.kbek, macv.into());
        decryptor2.apply_keystream(confidential_data);

        let mut mac = <cmac::Cmac::<TCphr> as cbc_mac::Mac>::new(&self.kbak);
    
        mac.update ( nonce.as_slice() );
        mac.update ( associated_data );
        mac.update ( confidential_data );
        
        match mac.verify ( macv.into() ) {
            Err(_) => return Err(aead::Error),
            Ok(_) => return Ok(())
        }
    }
}







