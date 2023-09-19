use crate::KeyBlockFields;

use der::{self, Encode, Decode, asn1::SetOfVec};

pub const ID_RANDOM_NONCE: der::asn1::ObjectIdentifier= der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.25.3");




pub trait TR34Decrypt {
    fn decrypt_cek ( &self, recip: &cms::enveloped_data::RecipientInfo ) -> Result<Vec<u8>, Error>;
    fn decrypt_content ( encryted_content: &cms::enveloped_data::EncryptedContentInfo, cek: &[u8] ) -> Result<Vec<u8>,Error>;
}

pub trait TR34Encrypt {
    fn encrypt_content ( &self, plaintext_content: &[u8] ) -> Result<(cms::enveloped_data::EncryptedContentInfo, Vec<u8>),Error>;
    fn encrypt_cek ( &self, cek: &[u8] ) -> Result<cms::enveloped_data::RecipientInfo, Error>;
}
pub trait TR34SignContent {
    fn sign_content ( &self, plaintext_content: &[u8], signed_attrs:Option<der::asn1::SetOfVec<cms::cert::x509::attr::Attribute>> ) -> Result<cms::signed_data::SignerInfo, Error>;
}

pub trait TR34VerifyContent {
    fn verify_content ( &self, content: &[u8], signer_info: &cms::signed_data::SignerInfo  ) -> Result<bool, Error>;
}


pub trait TR34Signed {
    fn get_cms (&self) -> cms::content_info::ContentInfo;

    fn get_signer_id(&self) -> Result<cms::cert::IssuerAndSerialNumber, Error>{
        let signed_data = self.get_signed_data()?;
        if signed_data.signer_infos.as_ref().len() != 1 { 
            return Err (Error::DecryptionError)
        }
        if let Some(signer_info) = signed_data.signer_infos.as_ref().get(0) {
            if let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(signer_id) = signer_info.sid.clone() {
                return Ok(signer_id);
            }
        }
        return Err(Error::NoCompatibleSignerBlockFound);
    }
    fn get_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        let cms = self.get_cms();
        if cms.content_type != der::oid::db::rfc5911::ID_SIGNED_DATA { 
            return Err(Error::InvalidContentType); 
        }
        return Ok(cms.content.decode_as::<cms::signed_data::SignedData>()?);
    }

    fn verify_signature<F: TR34VerifyContent> (&self, verify_func: F) -> bool
    {
        let signed_data: cms::signed_data::SignedData = self.get_cms().content.decode_as().unwrap();

        assert! ( signed_data.digest_algorithms.get(0).unwrap().oid ==der::oid::db::rfc5912::ID_SHA_256);
        
        let mb_econtent = signed_data.encap_content_info.econtent.as_ref().unwrap();

        for signer_info in signed_data.signer_infos.0.iter() {

            if let Some(signed_attrs) = signer_info.signed_attrs.as_ref() {
                for signed_attr in signed_attrs.iter() {
                    if signed_attr.oid == der::oid::db::rfc5911::ID_MESSAGE_DIGEST {
                        assert! ( signed_attr.values.len() == 1);
                        let mut calc_dig = openssl::sha::Sha256::new();
                        calc_dig.update(mb_econtent.value());
                        let calc_dig_out = calc_dig.finish();
                        assert! ( signed_attr.values.get(0).unwrap().decode_as::<der::asn1::OctetString>().unwrap() == der::asn1::OctetString::new(calc_dig_out).unwrap() );
                    }
                }
                // Spec says if there are signed attributes then the hash value is calculated over this signed attributes
                if let Ok(result) = verify_func.verify_content ( signed_attrs.to_der().unwrap().as_ref(), signer_info )  {
                    if result == true { return true };
                }
            }
            else {
                if let Ok(result) = verify_func.verify_content(&mb_econtent.value(), signer_info) {
                    if result == true { return true}
                }
            }
        }                
        
        return false;
    }  

    fn build_and_sign_data<F> (mut signed_attrs: Option<SetOfVec<cms::cert::x509::attr::Attribute>>, encapsulated_content_info: &cms::signed_data::EncapsulatedContentInfo, 
        certificate_set: Option<cms::signed_data::CertificateSet>, crl: Option<cms::revocation::RevocationInfoChoices>, signing_func: F) -> Result<cms::signed_data::SignedData, Error> 
     where F: TR34SignContent 
    {
        let signature_block: cms::signed_data::SignerInfo;
        if signed_attrs.as_ref().is_some() 
        {
            let mut calc_dig = openssl::sha::Sha256::new();
            calc_dig.update(encapsulated_content_info.econtent.as_ref().unwrap().value());
            
            let digest = cms::cert::x509::attr::Attribute { oid: der::oid::db::rfc5911::ID_MESSAGE_DIGEST, 
                        values: SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, calc_dig.finish())?])?} ;

            signed_attrs.as_mut().unwrap().insert (digest)?;
            signature_block = signing_func.sign_content (&signed_attrs.as_ref().unwrap().to_der()?, signed_attrs)?;
        }
        else {
            signature_block = signing_func.sign_content (encapsulated_content_info.econtent.as_ref().unwrap().value(), None)?;
        }
        
        let outer = cms::signed_data::SignedData { 
            version: cms::content_info::CmsVersion::V1, 
            digest_algorithms: SetOfVec::try_from(vec![rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None }])?,
            encap_content_info: encapsulated_content_info.clone(),
            certificates: certificate_set, 
            crls: crl, 
            signer_infos: cms::signed_data::SignerInfos (SetOfVec::try_from(vec![signature_block])?) };

        return Ok(outer);
    }

    
}



pub trait TR34Enveloped {
    fn get_enveloped_data (&self) -> Result <cms::enveloped_data::EnvelopedData, Error>;

    fn decrypt<F> ( &self, decrypt_func: F) -> Result<Vec<u8>,Error>
    where F: TR34Decrypt
    {   
        let envelope = self.get_enveloped_data()?;

        for recip_info in envelope.recip_infos.0.iter() {
            let decryptresult=  decrypt_func.decrypt_cek( recip_info );
                // Spec says if there are signed attributes then the hash value is calculated over this signed attributes
            if decryptresult.is_ok() { 

                let envelope = self.get_enveloped_data()?;
                return <F as TR34Decrypt>::decrypt_content( &envelope.encrypted_content, &decryptresult.unwrap());
               
            }
        }
        return Err(Error::DecryptionError);
    }
}


#[derive(Clone, Debug, Eq, PartialEq, der::Sequence )]
pub struct TR34Block {
    pub version: cms::content_info::CmsVersion,
    pub issuer_and_serial_number: cms::cert::IssuerAndSerialNumber,
    pub clear_key: der::asn1::OctetString,
    //pub attribute_header: OidAndAttributeHeader,
    pub attribute_header: cms::cert::x509::attr::Attribute,
}

#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)] // NOTE: added `Sequence`
#[asn1(tag_mode = "EXPLICIT")]
pub struct UbtCaUnbind {
    pub id_krd: cms::cert::IssuerAndSerialNumber,
    pub id_kdh: cms::cert::IssuerAndSerialNumber,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TR34KeyToken {
    cms: cms::content_info::ContentInfo,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TR34RandomNumberToken {
    attr: cms::cert::x509::attr::Attribute,
}


#[derive(PartialEq,Eq)]
pub struct TR34KdhUnbindToken {
    cms: cms::content_info::ContentInfo,
}
#[derive(Debug,PartialEq,Eq)]
pub struct TR34KdhRebindToken {
    cms: cms::content_info::ContentInfo,
}
#[derive(PartialEq,Eq)]
pub struct TR34CaUnbindToken {
    cms: cms::content_info::ContentInfo,
}
#[derive(PartialEq,Eq)]
pub struct TR34CaRebindToken {
    cms: cms::content_info::ContentInfo,
}

#[derive(Debug)]
pub enum Error {
    InvalidType,
    InvalidContentType,
    NoCompatibleSignerBlockFound,
    DecryptionError,
    MandatoryFieldMissing,
    KeyBlockHeaderInconsistency,
    IssuerSerialInconsistency,
    MissingContent,
    NoCompatibleRecipientFound,
    UnsupportedOption,
    DerError (der::Error),
    Utf8Error ( std::string::FromUtf8Error),
    OpenSsslErrorStack ( openssl::error::ErrorStack),
}
impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        return Error::DerError(e)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        return Error::Utf8Error(e);
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        return Error::OpenSsslErrorStack(e);
    }
}

impl TR34KeyToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34KeyToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        Ok(TR34KeyToken { cms: import/* , verified: false*/ })
    }
    
    pub fn get_outer_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        return Ok(self.cms.content.decode_as()?);
    }
   
    pub fn get_inner_enveloped_data(&self) -> Result<cms::enveloped_data::EnvelopedData, Error> {
        assert! (self.get_outer_signed_data()?.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_ENVELOPED_DATA);
        let mb_econtent = self.get_outer_signed_data()?.encap_content_info.econtent.unwrap().decode_as::<der::asn1::OctetString>()?;
        return Ok(cms::enveloped_data::EnvelopedData::from_der ( mb_econtent.as_bytes())?);
    }
    // From TR-34 2019, section 5.4.9
    pub fn get_random_number (&self) -> Result<Vec<u8>,Error>{
        return get_random_number_from_cms(&self.cms);
    }

    pub fn get_timestamp (&self) -> Result<der::asn1::UtcTime, Error>{
        for signed_attr in get_signed_attrs_from_cms(&self.cms).iter() {
            if signed_attr.oid == der::oid::db::rfc5911::ID_SIGNING_TIME {
                return Ok(signed_attr.values.get(0).unwrap().decode_as::<der::asn1::UtcTime>()?);
            }
        }
        return Err(Error::MandatoryFieldMissing);
    }
    pub fn get_key_block_header (&self) -> Result<Vec<u8>, Error> {
        for signed_attr in get_signed_attrs_from_cms(&self.cms).iter() {
            if signed_attr.oid == der::oid::db::rfc5911::ID_DATA {
                return Ok(signed_attr.values.get(0).unwrap().value().to_vec());
            }
        }
        return Err(Error::MandatoryFieldMissing);
    }
    pub fn get_key_block_header2 (&self) -> Result<KeyBlockFields, Error> {
        let key_block_header = self.get_key_block_header()?;
        let fixed_header: Result<[u8;16],_> = key_block_header[0..16].try_into();

        let option_blocks = 
            if key_block_header.len() > 16 { String::from_utf8(key_block_header[16..].to_vec())? } else {"".to_owned()};

        return Ok(KeyBlockFields{ fixed_header: fixed_header.unwrap(), 
            optional_blocks_str: option_blocks, key: Vec::<u8>::new() }); 
    }

    pub fn get_plaintext_key2<F> (&self, decrypt_func: F) -> Result<Vec<u8>, Error>
    where F: TR34Decrypt
        {
            let plaintext_enveloped_data = self.decrypt (decrypt_func);
            if plaintext_enveloped_data.is_err() { return Err(Error::DecryptionError); }
            let tr34keyblock = TR34Block::from_der ( &plaintext_enveloped_data.unwrap() )?;

            if tr34keyblock.attribute_header.values.get(0).unwrap().value() != self.get_key_block_header().unwrap() { 
                return Err(Error::KeyBlockHeaderInconsistency); }
            if tr34keyblock.issuer_and_serial_number != self.get_signer_id()? { 
                return Err(Error::IssuerSerialInconsistency); }

            return Ok(tr34keyblock.clear_key.into_bytes());
        }

    pub fn get_crl (&self) -> Option<cms::revocation::RevocationInfoChoices> {
        return self.get_outer_signed_data().unwrap().crls;
    }

    pub fn build<Encryptor: TR34Encrypt, Signer: TR34SignContent> ( 
        signer_issuer_and_serial: &cms::cert::IssuerAndSerialNumber, 
        key_block_header: &[u8], 
        cleartext_key: &[u8], 
        random_number: Option<&[u8]>,
        encrypt_func: Encryptor, 
        signing_func: Signer) -> Result<TR34KeyToken, Error>
    {
        let block_to_be_encrypted = TR34Block { 
            version: cms::content_info::CmsVersion::V1, 
            issuer_and_serial_number: signer_issuer_and_serial.clone(), 
            clear_key: der::asn1::OctetString::new ( cleartext_key)?, 
            attribute_header: cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc5911::ID_DATA, 
                values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, key_block_header)?])?},
        };

        let (encrypted_content_info, cek) = encrypt_func.encrypt_content (&block_to_be_encrypted.to_der().unwrap()).unwrap();
        let recip_info = encrypt_func.encrypt_cek (&cek).unwrap();

        let enveloped_data = cms::enveloped_data::EnvelopedData {
            version: cms::content_info::CmsVersion::V1,
            originator_info: None,
            recip_infos: cms::enveloped_data::RecipientInfos ( SetOfVec::try_from(vec![recip_info]).unwrap()),
            encrypted_content: encrypted_content_info,
            unprotected_attrs: None,
        };
        let mut signed_attrs = SetOfVec::new();
        if let Some(random_number) = random_number {
            signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, random_number)?])?})?;
        }
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc5911::ID_DATA, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, key_block_header)?])?})?;

        let encap_content_info =  cms::signed_data::EncapsulatedContentInfo { 
                    econtent_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA, 
                    econtent: Some(der::Any::new(der::Tag::OctetString, enveloped_data.to_der()?)?), 
                };
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), 
            &encap_content_info, None, None, signing_func)?;
        return Ok(TR34KeyToken { cms: cms::content_info::ContentInfo { content_type: der::oid::db::rfc5911::ID_SIGNED_DATA /*PKCS7_SIGNED_DATA_OID*/, 
            content: der::Any::encode_from(&outer)? }/* , verified:false*/});
    }


}

impl TR34Signed for TR34KeyToken  {
    fn get_cms(&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
pub struct AlgorithmIdentifierDave {
    /// Algorithm OID, i.e. the `algorithm` field in the `AlgorithmIdentifier`
    /// ASN.1 schema.
    pub oid: der::oid::ObjectIdentifier,

    /// Algorithm `parameters`.
    pub parameters: Option<der::Any>,
    // Moved the following encrypted_content field from EncryptedContentInfoDave to cope with malformed cms messages
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub encrypted_content: Option<der::asn1::OctetString>,
}

#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
#[allow(missing_docs)]
pub struct EncryptedContentInfoDave {
    pub content_type: der::oid::ObjectIdentifier,
    //pub content_enc_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned,
    pub content_enc_alg: AlgorithmIdentifierDave,
    // #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    // pub encrypted_content: Option<der::asn1::OctetString>,
}

#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
#[allow(missing_docs)]
pub struct EnvelopedDataDave {
    pub version: cms::content_info::CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<cms::enveloped_data::OriginatorInfo>,
    pub recip_infos: cms::enveloped_data::RecipientInfos,
    pub encrypted_content: EncryptedContentInfoDave,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unprotected_attrs: Option<cms::cert::x509::attr::Attributes>,
}

// THe example in TR-34 has an error where the encrypted payload is put into the wrong sequence
// This function attempts to correct this error and return a valid EnvelopedData structure
fn parse_malformed_enveloped_data ( message: &der::Any ) -> Result<cms::enveloped_data::EnvelopedData, Error> {
    // missing sequence, re-add
    let env_mal_any = der::Any::new ( der::Tag::Sequence, message.value())?;
    let env_mal = env_mal_any.decode_as::<EnvelopedDataDave>()?;

    let ecr_con_info = cms::enveloped_data::EncryptedContentInfo {
        content_type: env_mal.encrypted_content.content_type,
        content_enc_alg: rsa::pkcs8::spki::AlgorithmIdentifierOwned {
            oid: env_mal.encrypted_content.content_enc_alg.oid,
            parameters: env_mal.encrypted_content.content_enc_alg.parameters,
        },
        encrypted_content: env_mal.encrypted_content.content_enc_alg.encrypted_content,
    };
    return Ok ( cms::enveloped_data::EnvelopedData {
        version: env_mal.version,
        originator_info: env_mal.originator_info,
        recip_infos: env_mal.recip_infos,
        encrypted_content: ecr_con_info,
        unprotected_attrs: env_mal.unprotected_attrs,
    })

}


impl TR34Enveloped for TR34KeyToken {
    fn get_enveloped_data(&self) -> Result<cms::enveloped_data::EnvelopedData, Error> {
        let outer_signed_data: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
        let econtent = outer_signed_data.encap_content_info.econtent.unwrap();
        let x =  econtent.decode_as::<der::asn1::OctetString>().unwrap();// cms::enveloped_data::EnvelopedData::

        if let Ok(env) = cms::enveloped_data::EnvelopedData::from_der(x.as_bytes()) {
            return Ok(env);
        }
        else if let Ok(cms) = cms::content_info::ContentInfo::from_der(x.as_bytes()) {
            if let Ok (env) = cms.content.decode_as::<cms::enveloped_data::EnvelopedData>() {
                return Ok(env)
            }
            return Err(Error::InvalidType);
        }
        else if let Ok(env) = parse_malformed_enveloped_data(&econtent) {
            return Ok(env)
        }
        else if let Ok(env) = econtent.decode_as::<cms::enveloped_data::EnvelopedData>() {
            return Ok( env);
        }
        
        else {
            return Err(Error::DecryptionError);
        }
    }
}

impl std::fmt::Display for TR34KeyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TR34KeyBlock....")
        //.field("cms", &self.cms)
        .field("random_number", &hex::encode(&get_random_number_from_cms(&self.cms).unwrap()))
        //.field("signed_data", &get_signed_data_from_cms(&self.cms))
        .field("key_block_header", &std::str::from_utf8(&self.get_key_block_header().unwrap()))
        .field("signer_serial_number", &self.get_signer_id().unwrap().serial_number)
        .finish()
    }
}

impl TR34RandomNumberToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34RandomNumberToken, der::Error> {
        let import = cms::cert::x509::attr::Attribute::from_der(input)?;
        return Ok (TR34RandomNumberToken { attr: import });
    }
    pub fn to_der (&self) -> Result<Vec<u8>, der::Error> {
        return self.attr.to_der();
    }
    pub fn build ( input: &[u8]) -> Result<TR34RandomNumberToken, Error> {
        let random_as_any = cms::cert::x509::attr::AttributeValue::new( der::Tag::OctetString, input.to_owned() )?;
        let attr = cms::cert::x509::attr::Attribute { oid: ID_RANDOM_NONCE, values: SetOfVec::try_from(vec![random_as_any])? };
        return Ok(TR34RandomNumberToken { attr });
    }
    pub fn get_random_number (&self) -> Result<&[u8],Error> {
        return Ok(self.attr.values.get(0).unwrap().value());
    }
    
}


impl TR34KdhUnbindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34KdhUnbindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != der::oid::db::rfc5911::ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34KdhUnbindToken { cms: import});
    }

    pub fn get_outer_signed_data(&self) -> cms::signed_data::SignedData {
        return self.cms.content.decode_as().unwrap();
    }

    


    pub fn build<F> ( krd_id: &cms::cert::IssuerAndSerialNumber, crl: &cms::cert::x509::crl::CertificateList,
        random_nonce: &[u8], signing_func: F ) -> Result<TR34KdhUnbindToken, Error> 
        where F: TR34SignContent 
    {
        let encap_content_info = cms::signed_data::EncapsulatedContentInfo { 
            econtent_type: der::oid::db::rfc5911::ID_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, krd_id.to_der()?)?) 
        };
        let mut crl2 = SetOfVec::new();
        crl2.insert (cms::revocation::RevocationInfoChoice::Crl(crl.clone()))?;

        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_DATA.into()])?})?;
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, random_nonce)?])?})?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), 
            &encap_content_info, None, Some(cms::revocation::RevocationInfoChoices(crl2)), signing_func)?;

        return Ok(TR34KdhUnbindToken { cms: cms::content_info::ContentInfo { 
            content_type: der::oid::db::rfc5911::ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

    }
    pub fn get_krd_id(&self) -> Result<cms::cert::IssuerAndSerialNumber, Error> {
        let econtents = self.get_signed_data()?.encap_content_info.econtent.unwrap();
        let krd_id = cms::cert::IssuerAndSerialNumber::from_der(econtents.value())?;
        return Ok(krd_id);
    }
    pub fn get_random_number (&self) -> Result<Vec<u8>, Error>{
        return get_random_number_from_cms (&self.cms);
    }
    pub fn get_crl (&self) {
        // TODO
    }
    
}

impl TR34Signed for TR34KdhUnbindToken {
    fn get_cms (&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}




impl TR34KdhRebindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34KdhRebindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != der::oid::db::rfc5911::ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34KdhRebindToken { cms: import });     
    }
    pub fn get_outer_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        return Ok( self.cms.content.decode_as::<cms::signed_data::SignedData>()?);
    }
    pub fn get_rebind_id(&self) -> Result<cms::cert::IssuerAndSerialNumber,Error> {
        let econtent_as_sequence = der::Any::new(der::Tag::Sequence, self.get_outer_signed_data()?.encap_content_info.econtent.unwrap().value()).unwrap();
        let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
        let unbind_id = cms::cert::IssuerAndSerialNumber::from_der( signed_inner.encap_content_info.econtent.unwrap().value()).unwrap();
        return Ok(unbind_id);
    }
    pub fn get_random_number (&self) -> Result<Vec<u8>, Error>{
        return get_random_number_from_cms (&self.cms);
    }
    // From TR-34:2019 5.5.3
    pub fn get_new_kdh_cred (&self) -> cms::cert::x509::certificate::CertificateInner{
        let inner = get_inner_signed_data (&self.cms);
        match inner.certificates.unwrap().0.get(0).unwrap() {
            cms::cert::CertificateChoices::Certificate(x) => return x.clone(),
            _=> panic!("No certificate"),
        }
    }

    pub fn build<F> ( krd_id: &cms::cert::IssuerAndSerialNumber, new_kdh_cert: cms::cert::x509::Certificate, 
        crl: &cms::cert::x509::crl::CertificateList, random_nonce: &[u8], signing_obj: F ) -> Result<TR34KdhRebindToken, Error> 
       where F: TR34SignContent 
    {
        let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let digest_algorithms = SetOfVec::new ();
        
        let signed_data = cms::signed_data::SignedData { 
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: digest_algorithms,
            encap_content_info: cms::signed_data::EncapsulatedContentInfo {  
                econtent_type: der::oid::db::rfc5911::ID_DATA, 
                econtent: Some(der::Any::new(der::Tag::OctetString, krd_id.to_der()?)?) },
            certificates: Some(cms::signed_data::CertificateSet(cert_set)),
            crls: None,
            signer_infos: cms::signed_data::SignerInfos(SetOfVec::new()),
        };
        let encap_content_info = cms::signed_data::EncapsulatedContentInfo{ econtent_type: der::oid::db::rfc5911::ID_SIGNED_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&signed_data)?.value())?) };
        
        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_SIGNED_DATA.into()])?})?;
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, random_nonce)?])?})?;

        let mut crl2 = SetOfVec::new();
        crl2.insert (cms::revocation::RevocationInfoChoice::Crl(crl.clone()))?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( 
            Some(signed_attrs), 
            &encap_content_info, 
            None, 
            Some(cms::revocation::RevocationInfoChoices(crl2)),
            signing_obj)?;

        return Ok(TR34KdhRebindToken { cms: cms::content_info::ContentInfo { content_type: der::oid::db::rfc5911::ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

    }

}

impl TR34Signed for TR34KdhRebindToken {
    fn get_cms (&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}
impl TR34CaUnbindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34CaUnbindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != der::oid::db::rfc5911::ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34CaUnbindToken { cms: import});  
    }
    pub fn get_outer_signed_data(&self) -> cms::signed_data::SignedData {
        let x: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
        return x;
    }
    pub fn get_unbind_ids(&self) -> UbtCaUnbind {
        // There seems to be a missing SEQUENCE in the stream, decode with a dummy header
        let econtents = self.get_outer_signed_data().encap_content_info.econtent.unwrap();
        let econtent_as_sequence = der::Any::new( der::Tag::Sequence, econtents.value()).unwrap();
        return econtent_as_sequence.decode_as::<UbtCaUnbind>().unwrap();
    }

    pub fn build<F> ( krd_id: &cms::cert::IssuerAndSerialNumber, kdh_id: &cms::cert::IssuerAndSerialNumber, 
        signing_func: F ) -> Result<TR34CaUnbindToken, Error> 
       where F: TR34SignContent 
    {
        let content = UbtCaUnbind{ id_krd: krd_id.clone(), id_kdh: kdh_id.clone() };

        let encap_content_info = cms::signed_data::EncapsulatedContentInfo { 
            econtent_type: der::oid::db::rfc5911::ID_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&content)?.value())?) 
        };
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( None, 
            &encap_content_info, None, None, signing_func)?;

        return Ok(TR34CaUnbindToken { cms: cms::content_info::ContentInfo { content_type: der::oid::db::rfc5911::ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

    }

}
impl TR34Signed for TR34CaUnbindToken {
    fn get_cms (&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}


pub fn get_signed_data_from_cms(cms: &cms::content_info::ContentInfo) -> cms::signed_data::SignedData {
    return cms.content.decode_as().unwrap();
}
pub fn get_inner_signed_data(cms: &cms::content_info::ContentInfo) -> cms::signed_data::SignedData {
    let outer_signed_data = get_signed_data_from_cms(cms);
    assert! ( outer_signed_data.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_SIGNED_DATA);
    let econtent_as_sequence = der::Any::new(der::Tag::Sequence, outer_signed_data.encap_content_info.econtent.unwrap().value()).unwrap();
    let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
    return signed_inner;
}

fn get_signed_attrs_from_cms(cms: &cms::content_info::ContentInfo) -> cms::signed_data::SignedAttributes {
    return get_signed_data_from_cms(cms).signer_infos.as_ref().get(0).as_ref().unwrap().signed_attrs.as_ref().unwrap().clone();
}

fn get_random_number_from_cms (cms: &cms::content_info::ContentInfo) -> Result<Vec<u8>, Error>{
    for signed_attr in get_signed_attrs_from_cms(cms).iter() {
        if signed_attr.oid == ID_RANDOM_NONCE {
            return Ok(signed_attr.values.get(0).unwrap().value().to_vec());
        }
    }
    return Err(Error::MandatoryFieldMissing);
}




// Top of page 34 says parameters for HLA Unbind Token
impl TR34CaRebindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34CaRebindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != der::oid::db::rfc5911::ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34CaRebindToken { cms: import});
    }
    // pub fn to_der(&self ) -> Result<Vec<u8>, der::Error> {
    //     return self.cms.to_der();
    // }
    pub fn get_outer_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        return Ok(self.cms.content.decode_as()?);
    }
    pub fn get_inner_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        let outer_signed_data = self.get_outer_signed_data()?;
        if outer_signed_data.encap_content_info.econtent_type != der::oid::db::rfc5911::ID_SIGNED_DATA { 
            return Err(Error::InvalidContentType);
        }
        if outer_signed_data.encap_content_info.econtent.is_none() {
            return Err(Error::MissingContent);
        }
        let econtent_as_sequence = der::Any::new(der::Tag::Sequence, outer_signed_data.encap_content_info.econtent.unwrap().value())?;
        return Ok(econtent_as_sequence.decode_as::<cms::signed_data::SignedData>()?);
    }

    // Description of the ca rebind token indicates there are two ids - ID_KRD_CRED and ID_KDH_CRED
    pub fn get_rebind_ids(&self) -> Result<UbtCaUnbind, Error> {
        let econtents = self.get_inner_signed_data()?.encap_content_info.econtent.unwrap();
        let econtent_as_sequence = der::Any::new( der::Tag::Sequence, econtents.value())?;
        return Ok(econtent_as_sequence.decode_as::<UbtCaUnbind>()?);
    }  
    // From TR-34:2019 5.5.3
    pub fn get_new_kdh_cred (&self) -> cms::cert::x509::certificate::CertificateInner {
        let signed_inner = self.get_inner_signed_data().unwrap();
        assert! ( signed_inner.certificates.clone().unwrap().0.len() == 1 );
        //let x = signed_inner.certificates.unwrap().0.get(0);
        match signed_inner.certificates.unwrap().as_ref().get(0).unwrap() {
            cms::cert::CertificateChoices::Certificate(c) => return c.clone(),
            _ => panic!("unhandled enum type"),
        }
    }

    

    pub fn build<F> ( krd_id: &cms::cert::IssuerAndSerialNumber, kdh_id: &cms::cert::IssuerAndSerialNumber, new_kdh_cert: cms::cert::x509::Certificate, 
        signing_time: &der::asn1::UtcTime, signing_func: F ) -> Result<TR34CaRebindToken, Error> 
       where F: TR34SignContent
    {
        let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let content = UbtCaUnbind{ id_krd: krd_id.clone(), id_kdh: kdh_id.clone() };
        
        let signed_data = cms::signed_data::SignedData { 
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: SetOfVec::new (),
            encap_content_info: cms::signed_data::EncapsulatedContentInfo {  econtent_type: der::oid::db::rfc5911::ID_DATA, 
                econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&content)?.value())?) },
            certificates: Some(cms::signed_data::CertificateSet(cert_set)),
            crls: None,
            signer_infos: cms::signed_data::SignerInfos(SetOfVec::new()),
        };
        let encap_content_info = cms::signed_data::EncapsulatedContentInfo{ econtent_type: der::oid::db::rfc5911::ID_SIGNED_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&signed_data)?.value())?) };
        
        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_SIGNED_DATA.into()])?})?;
        signed_attrs.insert ( cms::cert::x509::attr::Attribute { oid:der::oid::db::rfc5911::ID_SIGNING_TIME, values:SetOfVec::try_from(vec![der::Any::encode_from(signing_time)?])?})?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), 
            &encap_content_info, None, None, signing_func)?;

        return Ok(TR34CaRebindToken { cms: cms::content_info::ContentInfo { content_type: der::oid::db::rfc5911::ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

    }



}

impl TR34Signed for TR34CaRebindToken {
    fn get_cms (&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}

impl Encode for TR34CaRebindToken {
    /// Compute the length of this value in bytes when encoded as ASN.1 DER.
    fn encoded_len(&self) -> der::Result<der::Length> {
        return self.cms.encoded_len();
    }

    /// Encode this value as ASN.1 DER using the provided [`Writer`].
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        return self.cms.encode(encoder);
    }

}







