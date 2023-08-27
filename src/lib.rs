//! Implementation of Key Blocks as used by the financial industry for cryptographic key exchange
//! Implemented in pure Rust and generic over block cipher.
//!
//! 
//! This implementation implements the following standards
//! 1. [ASC X9 TR 31-2018] - TDES and AES key blocks without key length obfuscation
//! 2. [ANSI X9.143-2022] - TDES and AES key blocks with key length obfuscation
//! 3. [ISO 20028:2018] - AES key blocks with optional CTR mode encryption
//! 
//! 
//!
//! # Examples
//!
//! ```
//! use keyblock::*;
//! use hex_literal::hex;
//!
//! let mut key_block_factory =  KeyBlockTypeDAes256::new ( &hex!("3235362d 62697420 41455320 77726170 70696e67 20284953 4f203230 30333829" ).into());
//! 
//! let mut key_block =  KeyBlockFields::new();
//!     key_block
//!       .set_secret (&hex!("76736170 70646420 32454552 206B6479"))
//!       .set_usage (  KeyUsage::M3_MAC_KEY_ISO_9797_1_MAC_ALG_3)
//!       .set_algorithm (  KeyAlgorithm::TDES)
//!       .set_keyversion("16")
//!       .set_mode (  KeyMode::V_VERIFY_ONLY)
//!       .set_exportability( KeyExportability::N_NON_EXPORTABLE);
//! 
//! let wrapped_key = key_block_factory.wrap (&mut key_block);
//! 
//! let mut recovered_block = key_block_factory.unwrap(expected_result).unwrap();
//! assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
//! assert_eq! ( recovered_block.get_version(), key_block.get_version());
//! assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
//! assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
//! assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
//! ```
//!
//! [ASC X9 TR 31-2018]: https://webstore.ansi.org/standards/ascx9/ascx9tr312018
//! [ANSI X9.143-2022]: https://webstore.ansi.org/standards/ascx9/ansix91432022
//! [ISO 20028:2018]: https://www.iso.org/standard/64400.html
//!  
//! 
use aead::{ KeySizeUser, AeadCore, AeadMutInPlace };
use des::{TdesEde2};
use aes::{Aes128, Aes256};
pub use aead::KeyInit;

use getrandom;

use std::{ str::Utf8Error};
use cipher::{crypto_common::{
    typenum::{ Unsigned}
}};

pub mod key_block_crypto;
pub mod tr34;
pub mod tr34openssl;
//pub mod keyblockfactory;
//mod tests;



pub use key_block_crypto::{KeyBlockCrypto1, KeyBlockCrypto2, KeyBlockCrypto3};

pub type KeyBlockATdes2 = KeyBlockFactory::<KeyBlockCrypto1::<TdesEde2>,'A'>;
pub type KeyBlockBTdes2 = KeyBlockFactory::<KeyBlockCrypto2::<TdesEde2>,'B'>;
pub type KeyBlockCTdes2 = KeyBlockFactory::<KeyBlockCrypto1::<TdesEde2>,'C'>;
pub type KeyBlockDAes128 = KeyBlockFactory::<KeyBlockCrypto2::<Aes128>,'D'>;
pub type KeyBlockDAes256 = KeyBlockFactory::<KeyBlockCrypto2::<Aes256>,'D'>;
pub type KeyBlockEAes256 = KeyBlockFactory::<KeyBlockCrypto3::<Aes256>,'E'>;

// mod crypto;

use cipher::{
    generic_array::GenericArray,
    BlockSizeUser,
    //KeyInit,
};

pub type Result<T> = core::result::Result<T, Error>;


#[derive(Debug)]
pub enum Error {
    InvalidDataSize,
    TooLong,

    IntegrityCheckFailed,

    LenExceeded(usize),

    ParseIntError,
    FromHexError,
    Utf8Error,
}

impl From<std::num::ParseIntError> for Error {
    fn from(_err: std::num::ParseIntError) -> Error {
        Error::ParseIntError
    }
}

impl From<hex::FromHexError> for Error {
    fn from(_err: hex::FromHexError) -> Error {
        Error::FromHexError
    }
}
impl From<Utf8Error> for Error {
    fn from(_err: Utf8Error) -> Error {
        Error::Utf8Error
    }
}



/// Version of key block specification. See ANSI X9.143 or ISO 20038 for details
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBlockVersion (
    pub char 
);

impl KeyBlockVersion {
    /// Defined in ANSI X9.143 and ANSI TR-31
    pub const A_KEY_VARIANT: KeyBlockVersion = KeyBlockVersion('A');
    /// Defined in ANSI X9.143 and ANSI TR-31
    pub const B_TDES_DERIVATION: KeyBlockVersion = KeyBlockVersion('B');
    /// Defined in ANSI X9.143 and ANSI TR-31
    pub const C_TDES_BINDING: KeyBlockVersion = KeyBlockVersion('C');
    /// Defined in ANSI X9.143, ANSI TR-31 and ISO 20038
    pub const D_AES_CBC: KeyBlockVersion = KeyBlockVersion('D');
    /// Defined in ISO 20038
    pub const E_AES_CTR: KeyBlockVersion = KeyBlockVersion('E'); 
}

/// Type of use allowed for key. See ANSI X9.143 or ISO 20038 for details
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct KeyUsage<'a> ( pub &'a str );

impl KeyUsage<'_> {
    pub const B0_BDK:KeyUsage<'_> = KeyUsage("B0");
    pub const B1_IPEK:KeyUsage<'_> = KeyUsage("B1");
    pub const B2_BASE_KEY_VARIANT_KEY:KeyUsage<'_> = KeyUsage("B2");
    pub const C0_CARD_VERIFICATION_KEY: KeyUsage<'_> = KeyUsage("C0");
    pub const D0_SYMMETRIC_KEY_FOR_DATA_ENCRYPTION: KeyUsage<'_> = KeyUsage("D0");
    pub const D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION: KeyUsage<'_> = KeyUsage("D1");
    pub const D2_DATA_ENCRYPTION_KEY_FOR_DECIMILIZATION_TABLE: KeyUsage<'_> = KeyUsage("D2");
    pub const D3_DATA_ENCRYPTION_KEY_FOR_SENSITIVE_DATA: KeyUsage<'_> = KeyUsage("D3");
    pub const M0_MAC_KEY_ISO_16609_MAC_ALG_1:KeyUsage<'_> = KeyUsage("M0");
    pub const M1_MAC_KEY_ISO_9797_1_MAC_ALG_1:KeyUsage<'_> = KeyUsage("M1");
    pub const M2_MAC_KEY_ISO_9797_1_MAC_ALG_2:KeyUsage<'_> = KeyUsage("M2");
    pub const M3_MAC_KEY_ISO_9797_1_MAC_ALG_3:KeyUsage<'_> = KeyUsage("M3");
    pub const P0_PIN_ENCRYPTION_KEY: KeyUsage<'_> = KeyUsage("P0");
    pub const S0_ASYMMETRIC_KEY_PAIR_FOR_DIGITAL_SIGNATURE:KeyUsage<'_> = KeyUsage("S0");
    pub const V0_PIN_VERIFICATION_VISA_PVV:KeyUsage<'_> = KeyUsage("V0");
}


/// Type of key to be transported in the key block. 
#[derive(Clone, Copy, PartialEq)]
pub struct KeyAlgorithm ( pub char );

impl KeyAlgorithm {
    pub const AES:KeyAlgorithm = KeyAlgorithm('A');
    pub const ECC:KeyAlgorithm = KeyAlgorithm('E');
    pub const HMAC:KeyAlgorithm = KeyAlgorithm('H');
    pub const RSA:KeyAlgorithm = KeyAlgorithm('R');
    pub const TDES:KeyAlgorithm = KeyAlgorithm('T');
    
}


/// Mode of use for key being transported
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct KeyMode ( pub char );

impl KeyMode {
    //pub const Unknown: KeyMode = KeyMode('0');
    pub const B_ENCRYPT_WRAP_DECRYPT_UNWRAP : KeyMode = KeyMode('B');
    pub const C_GENERATE_VERIFY: KeyMode = KeyMode('C');
    pub const D_DECRYPT_UNWRAP_ONLY: KeyMode = KeyMode ('D');
    pub const E_ENCRYPT_WRAP_ONLY : KeyMode = KeyMode( 'E');
    pub const G_GENERATE_ONLY: KeyMode = KeyMode ('G');
    pub const N_NO_SPECIAL_RESTRCTIONS: KeyMode = KeyMode ( 'N');
    pub const S_SIGNATURE_ONLY : KeyMode = KeyMode( 'S' );
    pub const T_BOTH_SIGN_AND_DECRYPT: KeyMode = KeyMode ( 'T' );
    pub const V_VERIFY_ONLY : KeyMode = KeyMode( 'V');
    pub const X_KEY_DERIVATION_KEY : KeyMode = KeyMode('X');
    pub const Y_KEY_VARIANT_KEY: KeyMode = KeyMode('Y');
    
}

/// Exportability rules for key, see ANSI X9.143 or ISO 20038 for details
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct KeyExportability ( pub char );

impl KeyExportability {
    pub const E_EXPORTABLE: KeyExportability = KeyExportability('E');
    pub const N_NON_EXPORTABLE: KeyExportability = KeyExportability('N');
    pub const S_EXPORTABLE_UNDER_ANY_KEY: KeyExportability = KeyExportability('S');
}

#[derive(Clone, Copy)]
/// Context rules for key, see ANSI X9.143 or ISO 20038 for details
pub struct KeyContext ( pub char );

impl KeyContext {
    pub const STORAGE_OR_EXCHANGE_0: KeyContext = KeyContext('0');
    pub const STORAGE_ONLY_1: KeyContext = KeyContext('1');
    pub const EXCHANGE_ONLY_2: KeyContext = KeyContext('2');
}


pub struct OptionalKeyBlockId<'a> ( pub &'a str );

impl<'a> OptionalKeyBlockId<'a> {
    pub const KS_KEY_SERIAL: OptionalKeyBlockId<'a> = OptionalKeyBlockId("KS");
    pub const PB_PADDING_BLOCK: OptionalKeyBlockId<'a> = OptionalKeyBlockId("PB");
}


#[allow(unused_must_use)]
fn default_rng ( buffer:&mut [u8] ) -> i32 {    
    getrandom::getrandom(buffer);
    return 1;
}

/// Fields within the key block as defined in ANSI X9.143 or ISO 20038
pub struct KeyBlockFields
{
    fixed_header: [u8;16],
    optional_blocks_str: String,
    key: Vec<u8>,
    
} 

impl KeyBlockFields {
    pub fn new() -> Self {
        KeyBlockFields { 
            fixed_header: [b'0';16],
            optional_blocks_str: String::new(),
            key: Vec::new(),
        }
    }

    fn set_version ( &mut self, version:KeyBlockVersion ) -> &mut KeyBlockFields{
        self.fixed_header[0] = version.0 as u8;
        return self;
    }
    pub fn get_version ( &self ) -> KeyBlockVersion {
        return KeyBlockVersion(self.fixed_header[0] as char);
    }
    fn set_key_block_length ( &mut self, len: usize ) -> Result<()>{
        if len >= 10000 { return Err(Error::LenExceeded(len)) }
        self.fixed_header[1..5].clone_from_slice(format!("{:04}", len).as_bytes());
        return Ok(());
    }
    pub fn get_key_block_length( &self ) -> Result<usize> {
        let s = std::str::from_utf8(&self.fixed_header[1..5])?;
        let num = usize::from_str_radix(s, 10 )?;
        return Ok(num);
    }

     pub fn set_usage ( &mut self, keyusage:KeyUsage ) -> &mut KeyBlockFields {
        self.fixed_header[5..7].clone_from_slice(keyusage.0.as_bytes());
        return self;
    }
        
    pub fn get_usage ( &self ) -> KeyUsage {
        return KeyUsage(&std::str::from_utf8(&self.fixed_header.as_slice()[5..7]).unwrap());
    }
    pub fn set_algorithm ( &mut self, algorithm: KeyAlgorithm ) -> &mut KeyBlockFields {
        self.fixed_header[7] = algorithm.0 as u8;
        return self;
    }
    pub fn get_algorithm ( &self ) -> KeyAlgorithm {
        return KeyAlgorithm ( self.fixed_header[7] as char);
    }
    pub fn set_mode ( &mut self, mode: KeyMode ) -> &mut KeyBlockFields {
        self.fixed_header[8] = mode.0 as u8;
        return self;
    }
    pub fn get_mode ( &self ) -> KeyMode {
        return KeyMode ( self.fixed_header[8] as char );
    }
       
    pub fn set_keyversion ( &mut self, keyversion: &str ) -> &mut KeyBlockFields{
        self.fixed_header[9..11].clone_from_slice(keyversion.as_bytes());
        return self;
    }
    pub fn set_exportability ( &mut self, exportability: KeyExportability ) -> &mut KeyBlockFields  {
        self.fixed_header[11] = exportability.0 as u8;
        return self;
    }
    pub fn get_exportability ( &self ) -> KeyExportability  {
         return KeyExportability(self.fixed_header[11] as char)
        
    }
    pub fn set_num_optional_blocks ( &mut self, len: usize ) -> &mut KeyBlockFields{
        self.fixed_header[12..14].clone_from_slice(format!("{:02X}", len).as_bytes());
        return self;
    }
    pub fn get_num_optional_blocks ( &self ) -> Result<usize> {
        let s = std::str::from_utf8(&self.fixed_header[12..14])?;
        let num = usize::from_str_radix(s, 10 )?;
        return Ok(num);
    }
    pub fn set_context ( &mut self, context: KeyContext ) -> &mut KeyBlockFields {
        self.fixed_header[14] = context.0 as u8;
        return self;
    }
    
    pub fn add_optional_block ( &mut self, block_id:&str, block_data:&str) -> &mut KeyBlockFields {
        self.optional_blocks_str.push_str ( &(if block_data.len() <= 0xFF {
                format! ( "{:2}{:02X}{}", block_id, block_data.len()+4, block_data )
            } else {
                format! ( "{}0004{:04X}{}", block_id, block_data.len()+10, block_data )
            }
        ));
        self.set_num_optional_blocks(self.get_num_optional_blocks().unwrap()+1);
        
        return self;
    }

    pub fn get_optional_block (&self, index: usize) -> Result<(&str, &str)> {
        let mut i = 0;
        let mut pos = 0;
        
        while i < self.get_num_optional_blocks()? {
        
            let mut lenfield = usize::from_str_radix ( &self.optional_blocks_str[pos+2..pos+4], 16 )?;
            let mut payloadoffset = 4;

            if lenfield == 0 {
                lenfield = usize::from_str_radix ( &self.optional_blocks_str[pos+6..pos+10], 16)?;
                payloadoffset = 10;
            }


            if i == index {
                return Ok (( &self.optional_blocks_str[pos..pos+2], &self.optional_blocks_str[pos+payloadoffset..pos+lenfield]));
            }
            i += 1;
            pos += lenfield;

        } 
        return Err(Error::LenExceeded(pos));

        
    }
   
  
    
    pub fn set_secret ( &mut self, secret: &[u8] ) -> &mut KeyBlockFields  {
        self.key = secret.to_vec();
        return self;
    }
    pub fn get_secret ( &mut self ) -> &[u8]  {
        return &self.key;
    }

}


/// Factory used to convert from plaintext key material and associated data (fields) into a complete key block where
/// sensitive data is encrypted and the entire message is protected against modification with a MAC.
pub struct KeyBlockFactory<TKeyBlockCrypto, const ID: char>
{
    rng_func: fn(&mut [u8]) -> i32,
    keyblockcrypto: TKeyBlockCrypto,
    key_length_obfuscation: bool,
}

impl<TKeyBlockCrypto, const ID: char> KeySizeUser for KeyBlockFactory<TKeyBlockCrypto, ID>
    where TKeyBlockCrypto: KeySizeUser
{
    type KeySize = TKeyBlockCrypto::KeySize;
   
}

impl<TKeyBlockCrypto, const ID: char> KeyInit for KeyBlockFactory<TKeyBlockCrypto, ID>
    where TKeyBlockCrypto: KeyInit
{
    fn new(key: &aead::Key<Self>) -> Self {
        return Self { 
            keyblockcrypto: TKeyBlockCrypto::new(key), 
            rng_func: default_rng, 
            key_length_obfuscation: true, }
    }
}

impl<TKeyBlockCrypto, const ID: char> KeyBlockFactory<TKeyBlockCrypto, ID>
    where TKeyBlockCrypto: KeySizeUser + BlockSizeUser + AeadCore + AeadMutInPlace + KeyInit
{
    /// Function to allow the manual selection of a random number generator to be used during padding creation
    /// Defaults to the getrandom::getrandom function which uses the OS RNG    
    pub fn set_rng ( &mut self, f: fn(&mut [u8]) -> i32 ) -> &mut KeyBlockFactory<TKeyBlockCrypto, ID> {
        self.rng_func = f;
        return self;
    }
    /// Key length obfuscation was introduced in ANSI X9.143:2021 and pads all symmetric keys to be the maximum size applicable to that
    /// algorithm type (192 bits for TDES or 256 bits for AES). Defaults to true, but can be disabled for compatibility with TR-31 key blocks
    pub fn set_key_length_obfuscation (&mut self, key_length_obfuscation: bool ) -> &mut KeyBlockFactory<TKeyBlockCrypto, ID> {
        self.key_length_obfuscation = key_length_obfuscation;
        return self;
    }

    /// Create an encrypted and MACd message which can be passed over potentially insecure communications or stored.
    /// Output is an ascii string containing the plaintext header, encryped secret value and a MAC
    pub fn wrap(&mut self, block: &mut KeyBlockFields) -> Result<String> {
        block.set_version(KeyBlockVersion(ID));
        
        /* Pad optional blocks to be a multiple of cipher block size */
        let block_size = TKeyBlockCrypto::block_size();
        if block.optional_blocks_str.len() % block_size > 0 {
            let paddinglen = ( block_size*2 - block.optional_blocks_str.len() % block_size - 4 ) % block_size;
            block.add_optional_block("PB", &"0".repeat(paddinglen));
        }

        /* Form confidential data field */
        let mut confidential_data = self.create_confidential_data2(&block);

        block.set_key_block_length ( block.fixed_header.len() + block.optional_blocks_str.len() + confidential_data.len()*2  + TKeyBlockCrypto::TagSize::to_usize()*2)?;

        let mac = self.keyblockcrypto.encrypt_in_place_detached(
                &GenericArray::<u8, TKeyBlockCrypto::NonceSize>::clone_from_slice(&block.fixed_header),
                block.optional_blocks_str.as_bytes(),
                &mut confidential_data
        );

        match mac {
            Err(_) => Err(Error::IntegrityCheckFailed),
            Ok(_) => Ok(format!("{}{}{}{}", std::str::from_utf8(&block.fixed_header)?, block.optional_blocks_str, hex::encode_upper(confidential_data), hex::encode_upper(&mac.unwrap()))),
        }
        
    }

    /// Verify an encrypted key block and decrypt the secret key.
    /// Output is a KeyBlockFields struct and the individual get functions can be used to extract the different fields
    pub fn unwrap(&mut self, assembledblock: &str) -> core::result::Result<KeyBlockFields, Error> {
        let mut keyblock = KeyBlockFields::new();

        keyblock.fixed_header.clone_from_slice(&assembledblock.as_bytes()[0..16]);
        
        if keyblock.get_key_block_length()? != assembledblock.len() {
            return Err(Error::InvalidDataSize)
        }
        
        let optionallen = self.parse_optional_blocks ( &assembledblock[16..], keyblock.get_num_optional_blocks()? )?;
        
        keyblock.optional_blocks_str = assembledblock[16..16+optionallen].to_owned();
       
        let maclength = TKeyBlockCrypto::TagSize::to_usize()*2;

        let mut confidential_data = hex::decode(&assembledblock[16+optionallen..assembledblock.len()-maclength])?;
        let mac = hex::decode(&assembledblock[assembledblock.len()-maclength..assembledblock.len()])?;
       
        let res = self.keyblockcrypto.decrypt_in_place_detached(
            &GenericArray::<u8, TKeyBlockCrypto::NonceSize>::clone_from_slice(&keyblock.fixed_header),
            &keyblock.optional_blocks_str.as_bytes(),
            &mut confidential_data,
            &GenericArray::<u8, TKeyBlockCrypto::TagSize>::clone_from_slice(&mac),
        );
    
        match res {
            Err(_) => return Result::Err(Error::IntegrityCheckFailed),
            Ok(_) => (),
        }

        let keylen = u16::from_be_bytes(confidential_data[0..2].try_into().unwrap()) as usize;
        keyblock.set_secret(&confidential_data[2..2+keylen/8]);

        return Ok(keyblock);
        
    }


    fn create_confidential_data2 (&self, keyblock: &KeyBlockFields) -> Vec<u8> {
        
        let mut raw_confidential_data = Vec::new();
        raw_confidential_data.extend ((( keyblock.key.len() * 8 )as u16 ).to_be_bytes());
        raw_confidential_data.extend ( &keyblock.key );

        let mut paddinglen =  
            if self.key_length_obfuscation == false {
                0
            } else if keyblock.get_algorithm() == KeyAlgorithm::AES { 
                32 - keyblock.key.len()
            } else if keyblock.get_algorithm() == KeyAlgorithm::TDES {
                24 - keyblock.key.len()
            } else { 
                0 
            };

        if TKeyBlockCrypto::CiphertextOverhead::to_usize() > 1 {
            paddinglen += TKeyBlockCrypto::CiphertextOverhead::to_usize() - ((keyblock.key.len() + paddinglen +2 ) % TKeyBlockCrypto::CiphertextOverhead::to_usize());
        }

        if paddinglen > 0 {
            let prepaddedlen = raw_confidential_data.len(); 
            raw_confidential_data.resize ( prepaddedlen + paddinglen, 0);
            (self.rng_func) (&mut raw_confidential_data[prepaddedlen..]);
        }

        return raw_confidential_data;
    }

    
    fn parse_optional_blocks (&self, optionalblockstring: &str, mut numoptionalblocks:  usize  ) ->  Result<usize>{

        let mut i = 0;
        
        while numoptionalblocks > 0 {
            let mut len = usize::from_str_radix ( &optionalblockstring[i+2..i+4], 16 )?;
            if len == 0 {
                let len3 = usize::from_str_radix ( &optionalblockstring[i+4..i+6], 16)?;
                len = usize::from_str_radix (&optionalblockstring[i+6..i+6+len3], 16)?;
            }
            if i+len > optionalblockstring.len() { 
                return Err (Error::InvalidDataSize)
            }
            i+= len;
            numoptionalblocks -= 1;
        }
        return Ok(i)
    }

}




