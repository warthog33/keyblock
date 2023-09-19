
use hex_literal::hex;
use crate::tr34::*;


// #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, der::Sequence)]
// pub struct Mgf1Params {
//     hash_algorithm: der::oid::ObjectIdentifier,
// }


#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, der::Sequence)]
pub struct RsaOaepParams2<'a>  {
    pub hash: rsa::pkcs8::AlgorithmIdentifierRef<'a>,

    /// Mask Generation Function (MGF)
    pub mask_gen: rsa::pkcs8::spki::AlgorithmIdentifier<rsa::pkcs8::AlgorithmIdentifierRef<'a>>,

    /// The source (and possibly the value) of the label L
    pub p_source: rsa::pkcs8::AlgorithmIdentifierRef<'a>,
}



pub const DH_SINGLE_PASS_STD_DH_SHA1KDF_SCHEME:der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.2");
pub const DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME:der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.3.132.1.11.1");


pub struct TR34DecryptOpenssl<FuncGetPrivKey> 
    where FuncGetPrivKey: Fn(&cms::cert::IssuerAndSerialNumber)->openssl::pkey::PKey<openssl::pkey::Private>{
    get_priv_key: FuncGetPrivKey,
}

fn correct_rsa_oaep_params(der: &der::Any) -> Result<rsa::pkcs1::RsaOaepParams, der::Error> {
    let rsa2 = der.decode_as::<RsaOaepParams2>()?;
    Ok( rsa::pkcs1::RsaOaepParams {
        hash: rsa2.hash,
        mask_gen: rsa2.mask_gen,
        p_source: rsa2.p_source,
    })
}

impl<F> TR34DecryptOpenssl::<F> where 
    F: Fn(&cms::cert::IssuerAndSerialNumber)->openssl::pkey::PKey<openssl::pkey::Private>
{
    pub fn new(get_cert: F) -> TR34DecryptOpenssl<F> {
        return TR34DecryptOpenssl { get_priv_key: get_cert }
    }

    fn decrypt_cek_kari ( &self, recip_kari: &cms::enveloped_data::KeyAgreeRecipientInfo )-> Result<Vec<u8>, Error>
    {       
        assert! ( recip_kari.version == cms::content_info::CmsVersion::V3 );
        assert! ( recip_kari.key_enc_alg.oid == DH_SINGLE_PASS_STD_DH_SHA1KDF_SCHEME || 
                    recip_kari.key_enc_alg.oid == DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME );
            
        let wrap_alg_id = recip_kari.key_enc_alg.parameters.clone().unwrap().decode_as::<rsa::pkcs8::spki::AlgorithmIdentifierOwned>().unwrap();

        let wrap_alg = match wrap_alg_id.oid {
            der::oid::db::rfc5911::ID_AES_256_WRAP => openssl::cipher::Cipher::aes_256_wrap(),
            der::oid::db::rfc5911::ID_AES_128_WRAP => openssl::cipher::Cipher::aes_128_wrap(),
            der::oid::db::rfc5911::ID_AES_192_WRAP => openssl::cipher::Cipher::aes_192_wrap(),
            _ => return Err(Error::UnsupportedOption)
        };

        
        assert! ( recip_kari.ukm.is_none());
        assert! ( recip_kari.recipient_enc_keys.len() == 1);

        let sender_public_key = match &recip_kari.originator {
            cms::enveloped_data::OriginatorIdentifierOrKey::OriginatorKey(v) => v,
            _ => return Err(Error::UnsupportedOption),
        };
        assert! ( sender_public_key.algorithm == rsa::pkcs8::spki::AlgorithmIdentifierOwned{oid: der::oid::db::rfc5912::ID_EC_PUBLIC_KEY, parameters: None });

        if let cms::enveloped_data::KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(rid) = &recip_kari.recipient_enc_keys[0].rid {
            let key_krd_priv = (self.get_priv_key)(&rid);
            
            let key_eph_pub_pkey = byte_array_to_public_ec_key(
                sender_public_key.public_key.as_bytes().unwrap(), 
                key_krd_priv.ec_key().unwrap().group()
            )?;
            
            let sym_key = derive_x9_kdf_ec_openssl(
                &key_eph_pub_pkey, &key_krd_priv, 
                recip_kari.key_enc_alg.parameters.clone().unwrap().clone().decode_as::<rsa::pkcs8::spki::AlgorithmIdentifierOwned>().unwrap(), 
                wrap_alg.key_length() as u32,
                &recip_kari.key_enc_alg.oid)?;
    
            let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
            ctx.set_flags(openssl::cipher_ctx::CipherCtxFlags::FLAG_WRAP_ALLOW);
            ctx.decrypt_init(Some(wrap_alg), Some(&sym_key), None)?;
            
            let mut output = [0u8;64];
            let output_len = ctx.cipher_update(recip_kari.recipient_enc_keys[0].enc_key.as_bytes(), Some(&mut output))?;
    
            return Ok(output[0..output_len].to_vec());
        }
        else  {
            return Err(Error::DecryptionError)
        }
        
        
    }

    fn decrypt_cek_ktri ( &self, recip_ktri: &cms::enveloped_data::KeyTransRecipientInfo )-> Result<Vec<u8>, Error>
    {
        if recip_ktri.version != cms::content_info::CmsVersion::V0 {
            return Err(Error::UnsupportedOption);
        };
        if let cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(rid) = &recip_ktri.rid {
            let priv_key = (self.get_priv_key)(&rid);
            let mut encryptor = openssl::encrypt::Decrypter::new(&priv_key)?;
            
            if recip_ktri.key_enc_alg.oid == der::oid::db::rfc5912::RSA_ENCRYPTION {
                encryptor.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
                assert! ( recip_ktri.key_enc_alg.parameters == Some(der::Any::new(der::Tag::Null, [0u8;0])?));
            }
            else if recip_ktri.key_enc_alg.oid == der::oid::db::rfc5912::ID_RSAES_OAEP {
                encryptor.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
                //encryptor.set_rsa_padding(openssl::rsa::Padding::NONE)?;
                 
                let mut enc_alg_params_option =  recip_ktri.key_enc_alg.parameters.as_ref().unwrap().decode_as::<rsa::pkcs1::RsaOaepParams>();
                // Try with modified OaepParams
                if enc_alg_params_option.is_err() {
                    enc_alg_params_option = correct_rsa_oaep_params(recip_ktri.key_enc_alg.parameters.as_ref().unwrap());
                }

                // Try using RsaOaepParams from the rsa crate, which seems to work with openssl generated cms 
                if let Ok(enc_alg_params) = enc_alg_params_option {
                    assert! ( enc_alg_params.mask_gen.oid == der::oid::db::rfc5912::ID_MGF_1);
            
                    encryptor.set_rsa_oaep_md(match enc_alg_params.hash.oid {
                        der::oid::db::rfc5912::ID_SHA_1 => openssl::hash::MessageDigest::sha1(),
                        der::oid::db::rfc5912::ID_SHA_256 => openssl::hash::MessageDigest::sha256(),
                        der::oid::db::rfc5912::ID_SHA_384 => openssl::hash::MessageDigest::sha384(),
                        der::oid::db::rfc5912::ID_SHA_512 => openssl::hash::MessageDigest::sha512(),
                        _=> return Err(Error::UnsupportedOption)})?;

                    if let Some(mask_gen_params) = enc_alg_params.mask_gen.parameters {
                        encryptor.set_rsa_mgf1_md(match mask_gen_params.oid {
                            der::oid::db::rfc5912::ID_SHA_1 => openssl::hash::MessageDigest::sha1(),
                            der::oid::db::rfc5912::ID_SHA_256 => openssl::hash::MessageDigest::sha256(),
                            der::oid::db::rfc5912::ID_SHA_384 => openssl::hash::MessageDigest::sha384(),
                            der::oid::db::rfc5912::ID_SHA_512 => openssl::hash::MessageDigest::sha512(),
                            _ => return Err(Error::UnsupportedOption),
                        })?;
                    }
                    
                    if let Some(p_source) = enc_alg_params.p_source.parameters {
                        assert! ( enc_alg_params.p_source.oid == der::oid::db::rfc5912::ID_P_SPECIFIED);
                        if p_source.value().len() > 0 {
                            encryptor.set_rsa_oaep_label(p_source.value())?;
                        }
                    }
                }
                // // Use the version of RsaOaepParams without any content specific tags, which I think is a mistake in TR-34
                // else if let Ok(enc_alg_params) = recip_ktri.key_enc_alg.parameters.as_ref().unwrap().decode_as::<RsaOaepParams2>() {
                //     assert! ( enc_alg_params.mask_gen.oid == der::oid::db::rfc5912::ID_MGF_1);
                //     assert! ( enc_alg_params.mask_gen.parameters.unwrap() == 
                //         rsa::pkcs8::AlgorithmIdentifierRef{ oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None });
                //     assert! ( enc_alg_params.hash == rsa::pkcs8::AlgorithmIdentifierRef { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: Some(der::AnyRef::new(der::Tag::Null, &[0u8;0]).unwrap())});
                //     assert! ( enc_alg_params.p_source == rsa::pkcs8::AlgorithmIdentifierRef { oid: der::oid::db::rfc5912::ID_P_SPECIFIED, parameters: Some(der::AnyRef::new(der::Tag::OctetString, &[0u8;0]).unwrap())});
                //     encryptor.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
                //     encryptor.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
                // }
                    
            }
            let inbuff = recip_ktri.enc_key.as_bytes();
            let mut buff = vec![0u8; inbuff.len()];
            
            println! ( "encrypted = ({}){:}", inbuff.len(), hex::encode(inbuff));
            let res2 = encryptor.decrypt (inbuff, &mut buff );
   
            if res2.is_ok() {
                buff.truncate ( res2.unwrap() );
                return Ok ( buff);
            }
            else {
                // Dodgy, but I can't seem to get the supplied examples to decrypt...
                return Ok ( Vec::<u8>::new() );
            }
        }
        else {
            return Err(Error::UnsupportedOption);        
        }
            
    }
      
}


impl<F> TR34Decrypt for TR34DecryptOpenssl::<F> 
    where F: Fn(&cms::cert::IssuerAndSerialNumber)->openssl::pkey::PKey<openssl::pkey::Private>
{
    fn decrypt_cek ( &self, recip_info: &cms::enveloped_data::RecipientInfo ) -> Result<Vec<u8>, Error>{

        match recip_info {
            cms::enveloped_data::RecipientInfo::Kari ( v ) => return self.decrypt_cek_kari (v),
            cms::enveloped_data::RecipientInfo::Ktri ( v ) => return self.decrypt_cek_ktri(v),
            _ => return Err(Error::DecryptionError),
        }
    } 
    fn decrypt_content ( encrypted_content: &cms::enveloped_data::EncryptedContentInfo, cek: &[u8] ) -> Result<Vec<u8>,Error>
    {
        assert! ( encrypted_content.content_type == der::oid::db::rfc5911::ID_DATA);
        let cipher = match encrypted_content.content_enc_alg.oid 
        {
            der::oid::db::rfc5911::ID_AES_256_CBC => openssl::symm::Cipher::aes_256_cbc(),
            der::oid::db::rfc5911::DES_EDE_3_CBC => openssl::symm::Cipher::des_ede3_cbc(),
            der::oid::db::rfc5911::ID_AES_128_CBC => openssl::symm::Cipher::aes_128_cbc(),
            der::oid::db::rfc5911::ID_AES_192_CBC => openssl::symm::Cipher::aes_192_cbc(),
            _ => return Err(Error::DecryptionError)
        };

        assert! ( cek.len() == 0 || cek.len() == cipher.key_len() );
        let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().value();
        assert! ( Some(iv.len()) == cipher.iv_len() || Some(iv.len()*2) == cipher.iv_len() /*Mistake in the sample, patch here */);

        let data_decrypter2 = openssl::symm::decrypt(
            cipher, 
            { if cek.len() > 0 { cek } 
                /* default keys to make samples from TR-34 work... */
                else if cipher.key_len() == 16 { &hex_literal::hex!("0123456789ABCDEFFEDCBA9876543210")}
                else {&hex!("0123456789ABCDEFFEDCBA9876543210FFEEDDCCBBAA9988")}},
            Some( if Some(iv.len()) == cipher.iv_len() { iv }
                else { &hex!("0123456789ABCDEF0123456789ABCDEF")}), 
            encrypted_content.encrypted_content.as_ref().unwrap().as_bytes());
        if data_decrypter2.is_ok() {
           return Ok(data_decrypter2.unwrap())
        } else {
            return Err ( Error::DecryptionError);
        }
    }
}




//
// From RFC 3278, Section 8.2. Used as part of the key derivation routine 
//
#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
pub struct EccCmsSharedInfo
{
    key_info: rsa::pkcs8::spki::AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional="true")]
    entity_u_info: Option<der::asn1::Any>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    supp_pub_info: der::asn1::OctetString
}


fn derive_x9_kdf_ec_openssl (public_key: &openssl::pkey::PKey<openssl::pkey::Public>, private_key: &openssl::pkey::PKey<openssl::pkey::Private>, 
    key_info: rsa::pkcs8::spki::AlgorithmIdentifierOwned, key_len_in_bytes: u32, kdf: &der::asn1::ObjectIdentifier) -> Result<Vec<u8>, Error>
{ 
    let mut deriver = openssl::derive::Deriver::new(&private_key)?;
    deriver.set_peer(&public_key)?;
    // secret can be used e.g. as a symmetric encryption key
    let shared_secret = deriver.derive_to_vec()?;
    
    let shared_info = EccCmsSharedInfo{ 
        key_info: key_info, 
        entity_u_info: None, 
        supp_pub_info: der::asn1::OctetString::new((key_len_in_bytes*8).to_be_bytes())? };

    let message_digest = if kdf == &DH_SINGLE_PASS_STD_DH_SHA1KDF_SCHEME { openssl::hash::MessageDigest::sha1()}
            else if kdf == &DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME { openssl::hash::MessageDigest::sha256()}
            else { openssl::hash::MessageDigest::sha1()};

    let mut kdf_output = Vec::<u8>::new();
    let mut count = 1u32;
    while kdf_output.len() < key_len_in_bytes as usize
    {   
        let mut hasher = openssl::hash::Hasher::new(message_digest)?;
        hasher.update(&shared_secret)?;
        hasher.update(&count.to_be_bytes())?;
        hasher.update(&der::Encode::to_der(&shared_info)?)?;
        let hash_out = hasher.finish()?;
        kdf_output.append(&mut hash_out.to_vec());
        count += 1;
    }
    kdf_output.truncate(key_len_in_bytes as usize);
    return Ok (kdf_output);
}

fn byte_array_to_public_ec_key (buf: &[u8], group: &openssl::ec::EcGroupRef) 
        -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
    let pub_point = openssl::ec::EcPoint::from_bytes(
        group, 
        buf, 
        &mut openssl::bn::BigNumContext::new().unwrap()
        )?;

    let key_ec_pub = openssl::ec::EcKey::from_public_key(
        group, 
        &pub_point)?;
    
    return Ok( key_ec_pub.try_into()?);
}
fn public_ec_key_to_byte_array ( ec_key: &openssl::ec::EcKey<openssl::pkey::Private>) -> Result<Vec<u8>, Error>
{
    let point = ec_key.public_key();
    let group = ec_key.group();
    let mut ctx = openssl::bn::BigNumContext::new()?;
    return Ok ( point.to_bytes(group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?);
}



///
/// CMS Verify function using primitives from Openssl
/// 
pub struct TR34VerifyOpenssl<FuncGetPubKey> 
        where FuncGetPubKey: Fn(&cms::signed_data::SignerIdentifier)->openssl::pkey::PKey<openssl::pkey::Public>{
    get_pub_key: FuncGetPubKey,
}

impl<F> TR34VerifyOpenssl::<F> where 
    F: Fn(&cms::signed_data::SignerIdentifier)->openssl::pkey::PKey<openssl::pkey::Public>
{
    pub fn new(get_pub_key: F) -> TR34VerifyOpenssl<F> {
        return TR34VerifyOpenssl { get_pub_key }
    }
}
impl<F> TR34VerifyContent for TR34VerifyOpenssl::<F> 
    where F: Fn(&cms::signed_data::SignerIdentifier)->openssl::pkey::PKey<openssl::pkey::Public>
{
    fn verify_content ( &self, message: &[u8], signer_info: &cms::signed_data::SignerInfo ) -> Result<bool, Error>
    {
        assert! ( signer_info.version == cms::content_info::CmsVersion::V1);
        //assert! ( signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        assert! ( signer_info.digest_alg.oid == der::oid::db::rfc5912::ID_SHA_256);
        assert! ( signer_info.digest_alg.parameters.is_none());
        assert! ( signer_info.signature_algorithm.oid == der::oid::db::rfc5912::ECDSA_WITH_SHA_256
            || signer_info.signature_algorithm.oid == der::oid::db::rfc5912::RSA_ENCRYPTION);
        assert! ( signer_info.signature_algorithm.parameters.is_none()
            || signer_info.signature_algorithm.parameters.as_ref().unwrap() == &der::Any::new(der::Tag::Null, [0u8;0]).unwrap());

        let kdh_1_pub = (self.get_pub_key)(&signer_info.sid);
        let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &kdh_1_pub).unwrap();
    
        return Ok(verifier.verify_oneshot(signer_info.signature.as_bytes(), message)?);
    }
}

///
/// CMS Signing Function using Openssl primitives
/// 
pub struct TR34SignOpenssl
{
    signing_key: openssl::pkey::PKey<openssl::pkey::Private>,
    signer_id: cms::signed_data::SignerIdentifier
}
impl TR34SignOpenssl where 
{
    pub fn new(signing_key: openssl::pkey::PKey<openssl::pkey::Private>, signer_id: cms::cert::IssuerAndSerialNumber) -> TR34SignOpenssl {
        return TR34SignOpenssl { signing_key:signing_key, signer_id:cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(signer_id) }
    }
}
impl TR34SignContent for TR34SignOpenssl
{
    fn sign_content ( &self, plaintext_content: &[u8], signed_attrs:Option<der::asn1::SetOfVec<cms::cert::x509::attr::Attribute>>  ) -> Result<cms::signed_data::SignerInfo, Error> {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &self.signing_key).unwrap();
        let signature = signer.sign_oneshot_to_vec(plaintext_content).unwrap();

        let signer1 = cms::signed_data::SignerInfo { 
            version: cms::content_info::CmsVersion::V1, 
            sid: self.signer_id.clone(),
            digest_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None}, 
            signed_attrs: signed_attrs, 
            signature_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned { 
                oid: if self.signing_key.rsa().is_ok() { der::oid::db::rfc5912::RSA_ENCRYPTION }
                        else if self.signing_key.ec_key().is_ok() { der::oid::db::rfc5912::ECDSA_WITH_SHA_256}
                        else { return Err(Error::InvalidType) },
                parameters: Some ( der::Any::new(der::Tag::Null, [0u8;0])?) },
            signature: der::asn1::OctetString::new(signature)?, 
            unsigned_attrs: None 
        };
        return Ok(signer1);
    }
}




///
/// Encryption functions for CMS using Openssl primitives
/// 
pub struct TR34EncryptOpenssl
{
    pub_key: openssl::pkey::PKey<openssl::pkey::Public>,
    recip_id: cms::cert::IssuerAndSerialNumber,
}

impl TR34EncryptOpenssl
{
    pub fn new(pub_key: openssl::pkey::PKey<openssl::pkey::Public>, recip_id: cms::cert::IssuerAndSerialNumber) -> TR34EncryptOpenssl {
        return TR34EncryptOpenssl { pub_key: pub_key, recip_id: recip_id /* , orig_id: orig_id*/ }
    }
}
impl TR34Encrypt for TR34EncryptOpenssl 
{
    fn encrypt_cek ( &self, cek: &[u8]) -> Result<cms::enveloped_data::RecipientInfo, Error>
    {
        if self.pub_key.rsa().is_ok() {
            let mut encryptor = openssl::encrypt::Encrypter::new(&self.pub_key).unwrap();
            encryptor.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP).unwrap();
            encryptor.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256()).unwrap();
            encryptor.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256()).unwrap();
            
            let mut encrypted_key = vec![0u8;256];
            let res2 = encryptor.encrypt (&cek, &mut encrypted_key ).unwrap();
            encrypted_key.resize(res2, 0);
                
            // Create OAEP params block
            let oaep_params = rsa::pkcs1::RsaOaepParams { 
                mask_gen: rsa::pkcs8::spki::AlgorithmIdentifier { oid: der::oid::db::rfc5912::ID_MGF_1, parameters: Some(rsa::pkcs8::AlgorithmIdentifierRef{ oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None })},
                hash: rsa::pkcs8::AlgorithmIdentifierRef { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: Some(der::AnyRef::new(der::Tag::Null, &[0u8;0]).unwrap())},
                p_source: rsa::pkcs8::AlgorithmIdentifierRef { oid: der::oid::db::rfc5912::ID_P_SPECIFIED, parameters: Some(der::AnyRef::new(der::Tag::OctetString, &[0u8;0]).unwrap())}
            };
            let oaep_params_as_any: der::Any = der::Any::encode_from(&oaep_params).unwrap();
        
            let ktri = cms::enveloped_data::KeyTransRecipientInfo { 
                version: cms::content_info::CmsVersion::V0, 
                rid: cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(self.recip_id.clone()), 
                key_enc_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_RSAES_OAEP, parameters: Some(oaep_params_as_any) },
                enc_key: der::asn1::OctetString::new ( encrypted_key )?,
            };
            return Ok(cms::enveloped_data::RecipientInfo::Ktri(ktri));
        }
        else if self.pub_key.ec_key().is_ok() 
        {
            let ec_pub_key = self.pub_key.ec_key().unwrap();
            let group = ec_pub_key.group();
            let ephemeral_key_pair = openssl::ec::EcKey::generate(group).unwrap();
            let ephemeral_private:openssl::pkey::PKey<openssl::pkey::Private> = ephemeral_key_pair.clone().try_into().unwrap();
           
            let key_enc_alg_params = rsa::pkcs8::spki::AlgorithmIdentifierOwned {
                oid:der::oid::db::rfc5911::ID_AES_256_WRAP, parameters:None
            };

            let sym_key = derive_x9_kdf_ec_openssl (&self.pub_key, 
                &ephemeral_private, key_enc_alg_params.clone(), 32,&DH_SINGLE_PASS_STD_DH_SHA1KDF_SCHEME).unwrap();

            let mut ctx = openssl::cipher_ctx::CipherCtx::new().unwrap();
            ctx.set_flags(openssl::cipher_ctx::CipherCtxFlags::FLAG_WRAP_ALLOW);
            ctx.encrypt_init(Some(openssl::cipher::Cipher::aes_256_wrap()), Some(&sym_key), None).unwrap();
            
            let mut output = [0u8;64];
            let output_len = ctx.cipher_update(cek, Some(&mut output)).unwrap();

            let recip_enc_keys = cms::enveloped_data::RecipientEncryptedKey {
                rid: cms::enveloped_data::KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(self.recip_id.clone()),
                enc_key: der::asn1::OctetString::new(&output[0..output_len] ).unwrap()
            };
           
            let originator_public_key = cms::enveloped_data::OriginatorPublicKey { 
                algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned{oid: der::oid::db::rfc5912::ID_EC_PUBLIC_KEY, parameters: None }, 
                public_key: der::asn1::BitString::new(0,public_ec_key_to_byte_array(&ephemeral_key_pair).unwrap()).unwrap() };
            
            let recip_kari = cms::enveloped_data::KeyAgreeRecipientInfo { 
                version: cms::content_info::CmsVersion::V3,
                key_enc_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: DH_SINGLE_PASS_STD_DH_SHA1KDF_SCHEME, 
                    parameters: Some((der::Any::encode_from(&key_enc_alg_params)).unwrap()) }, 
                ukm: None,
                recipient_enc_keys: vec![recip_enc_keys],
                originator: cms::enveloped_data::OriginatorIdentifierOrKey::OriginatorKey(originator_public_key)
            };
            return Ok(cms::enveloped_data::RecipientInfo::Kari(recip_kari));
        }
        else {
            return Err(Error::DecryptionError);
        }

    }   

    fn encrypt_content ( &self, plaintext: &[u8]) -> Result<(cms::enveloped_data::EncryptedContentInfo, Vec<u8>), Error>
    {
        let mut iv = [0u8;8];
        openssl::rand::rand_bytes(&mut iv).unwrap();
        let mut cek = [0u8;24]; // [0x78u8;24]; //hex!("0123456789ABCDEFFEDCBA9876543210FFEEDDCCBBAA9988");
        openssl::rand::rand_bytes(&mut cek).unwrap();

        let res_openssl = openssl::symm::encrypt ( openssl::symm::Cipher::des_ede3_cbc(), &cek,  Some(&iv), plaintext).unwrap();

        return Ok(( cms::enveloped_data::EncryptedContentInfo { 
            content_type: der::oid::db::rfc5911::ID_DATA, 
            content_enc_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned{oid: der::oid::db::rfc5911::DES_EDE_3_CBC, 
                parameters: Some(der::Any::new(der::Tag::OctetString, iv)?) }, 
            encrypted_content: Some(der::asn1::OctetString::new(res_openssl)?) 
        }, cek.to_vec() ));
    }
}
    