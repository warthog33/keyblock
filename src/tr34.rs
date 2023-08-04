use cms::{cert::{x509::{attr::Attribute, certificate::CertificateInner, crl::CertificateList}, IssuerAndSerialNumber}, signed_data::{SignerInfo, SignedData, 
    SignerInfos, EncapsulatedContentInfo}, content_info::CmsVersion, enveloped_data::KeyTransRecipientInfo, revocation::RevocationInfoChoice};
use der::{self, Encode, Decode, oid::{ObjectIdentifier, db::rfc5911::{ID_DATA, ID_SIGNED_DATA}}, asn1::{UtcTime, SetOfVec, OctetString}, Any};
use rsa::pkcs8::spki::AlgorithmIdentifierOwned;

pub const ID_RANDOM_NONCE: der::asn1::ObjectIdentifier= ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.25.3");


#[derive(Clone, Debug, Eq, PartialEq, der::Sequence )]
pub struct TR34Block {
    pub version: CmsVersion,
    pub issuer_and_serial_number: cms::cert::IssuerAndSerialNumber,
    pub clear_key: der::asn1::OctetString,
    //pub attribute_header: OidAndAttributeHeader,
    pub attribute_header: Attribute,
}



#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)] // NOTE: added `Sequence`
#[asn1(tag_mode = "EXPLICIT")]
pub struct UbtCaUnbind {
    pub id_krd: cms::cert::IssuerAndSerialNumber,
    pub id_kdh: cms::cert::IssuerAndSerialNumber,
}

// #[derive(Clone, Debug, Eq, PartialEq, der::Sequence, der::ValueOrd)]
// pub struct OidAndAttributeHeader{
//     pub oid: der::oid::ObjectIdentifier,
//     pub attribute_header: der::asn1::SetOf<der::asn1::OctetString,1>,
// }

pub struct TR34KeyToken {
    cms: cms::content_info::ContentInfo,
    //verified: bool,
}


#[derive(Debug, Eq, PartialEq)]
pub struct TR34RandomNumberToken {
    attr: Attribute,
}

pub trait TR34Signed {
    fn get_cms (&self) -> cms::content_info::ContentInfo;

    fn get_signer_id(&self) -> Result<IssuerAndSerialNumber, Error>{
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
    fn get_signed_data(&self) -> Result<SignedData, Error> {
        let cms = self.get_cms();
        if cms.content_type != ID_SIGNED_DATA { 
            return Err(Error::InvalidContentType); 
        }
        return Ok(cms.content.decode_as::<cms::signed_data::SignedData>()?);
    }

    fn verify_signature<F> (&self, verify_func: F) -> bool     
        where F: Fn(&[u8], &SignerInfo) -> bool 
    {
       //let signed_data = self.get_cms();
       let signed_data: cms::signed_data::SignedData = self.get_cms().content.decode_as().unwrap();
   
        assert! ( signed_data.digest_algorithms.get(0).unwrap().oid ==der::oid::db::rfc5912::ID_SHA_256);
        
        let mb_econtent = signed_data.encap_content_info.econtent.as_ref().unwrap();

        //let x = signed_data.signer_infos.0.iter();

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
                if verify_func ( signed_attrs.to_der().unwrap().as_ref(), signer_info ) == true {
                    return true
                }
            }
            else {
                if  verify_func(&mb_econtent.value(), signer_info) == true {
                    return true;
                }
                //mb_econtent.value()
            }
        }                
        
        return false;
        //let signer_info = signed_data.signer_infos.0.get(0).unwrap();
    //let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &signer_public_key).unwrap();
    //verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).unwrap();
    }    

    fn build_and_sign_data<F> (mut signed_attrs: Option<SetOfVec<Attribute>>, signer_issuer_and_serial: &IssuerAndSerialNumber, encapsulated_content_info: &EncapsulatedContentInfo, 
        certificate_set: Option<cms::signed_data::CertificateSet>, crl: Option<cms::revocation::RevocationInfoChoices>, signing_func: F) -> Result<SignedData, Error> 
     where F: Fn(&[u8]) -> Vec<u8> 
    {
        let signature: Vec<u8>;
        if signed_attrs.as_ref().is_some() 
        {
            let mut calc_dig = openssl::sha::Sha256::new();
            calc_dig.update(encapsulated_content_info.econtent.as_ref().unwrap().value());
            
            let digest = Attribute { oid: der::oid::db::rfc5911::ID_MESSAGE_DIGEST, 
                        values: SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, calc_dig.finish())?])?} ;

            signed_attrs.as_mut().unwrap().insert (digest)?;
            signature = signing_func (&signed_attrs.as_ref().unwrap().to_der()?);
        }
        else {
            signature = signing_func (encapsulated_content_info.econtent.as_ref().unwrap().value());
        }
        
        let signer1 = SignerInfo { 
            version: cms::content_info::CmsVersion::V1, 
            sid: cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(signer_issuer_and_serial.clone()), 
            digest_alg: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None}, 
            signed_attrs: signed_attrs, 
            signature_algorithm: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::RSA_ENCRYPTION, parameters: Some ( Any::new(der::Tag::Null, [0u8;0])?) },
            signature: der::asn1::OctetString::new(signature)?, 
            unsigned_attrs: None 
        };

        let outer = SignedData { 
            version: cms::content_info::CmsVersion::V1, 
            digest_algorithms: SetOfVec::try_from(vec![AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None }])?,
            encap_content_info: encapsulated_content_info.clone(),
            certificates: certificate_set, 
            crls: crl, 
            signer_infos: SignerInfos (SetOfVec::try_from(vec![signer1])?) };

        return Ok(outer);
    }

    
}

// pub struct TR34KeyTokenFactory
// {
//     random_number : Option<Attribute>,
//     key_block_header: Result<Attribute, Error>,
//     //signer_id: Option<cms::signed_data::SignerIdentifier>,
//     signer_issuer_and_serial: Result<IssuerAndSerialNumber, Error>,
//     recipient_issuer_and_serial: Result<IssuerAndSerialNumber, Error>,
//     //signing_func: dyn Fn (&[u8], &cms::signed_data::SignerInfo),
//     key_value: Result<Vec<u8>, Error>,
// }

// impl TR34KeyTokenFactory 
// {
//     pub fn new () -> TR34KeyTokenFactory {
//         return TR34KeyTokenFactory { random_number: None, key_block_header: Err(Error::MandatoryFieldMissing), signer_issuer_and_serial: Err(Error::MandatoryFieldMissing), 
//             recipient_issuer_and_serial: Err(Error::MandatoryFieldMissing), key_value: Err(Error::MandatoryFieldMissing)};
//     }
//     pub fn set_random_number ( &mut self, random_number: &[u8]) {
//         let any = der::Any::new(der::Tag::OctetString, random_number).unwrap();
//         self.random_number = Some(Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::from_iter(vec![any]).unwrap()});
//     }
//     pub fn set_key_block_header ( &mut self, key_block_header: &[u8]) {
//         let any = der::Any::new(der::Tag::OctetString, key_block_header).unwrap();
//         self.key_block_header = Ok(Attribute { oid:PKCS7_DATA_OID, values:SetOfVec::from_iter(vec![any]).unwrap()});
//     }
//     pub fn set_signer_issuer_and_serial ( &mut self, signer_id: IssuerAndSerialNumber ) {
//         self.signer_issuer_and_serial = Ok(signer_id);
//     }
//     pub fn set_recipient_issuer_and_serial ( &mut self, signer_id: IssuerAndSerialNumber ) {
//         self.recipient_issuer_and_serial = Ok(signer_id);
//     }
//     pub fn set_key_value (&mut self, key_value: &[u8]) {
//         self.key_value = Ok(key_value.into());
//     }
//     // pub fn set_signing_func<F> ( &mut self, signing_func: F )
//     //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8]) 
//     // {
//     // }
    
// }



pub trait TR34Enveloped {
    fn get_enveloped_data (&self) -> Result <cms::enveloped_data::EnvelopedData, Error>;

    fn decrypt_enveloped_data<F> ( &self, decrypt_func: F) -> Result<Vec<u8>, Error>
        where F: Fn(&[u8], &[u8], &[u8]) -> Option<Vec<u8>>
    {
        //envelope: &cms::enveloped_data::EnvelopedData;
        let envelope = self.get_enveloped_data()?;

        for recip_info in envelope.recip_infos.0.iter() {
            if let cms::enveloped_data::RecipientInfo::Ktri(id) = recip_info 
            {
                let decryptresult=  decrypt_func(
                        envelope.encrypted_content.encrypted_content.as_ref().unwrap().as_bytes(), 
                        id.enc_key.as_bytes(), 
                        envelope.encrypted_content.content_enc_alg.parameters.as_ref().unwrap().value());
                // Spec says if there are signed attributes then the hash value is calculated over this signed attributes
                //return verifier.verify_oneshot(signer_info.signature.as_bytes(), &signed_attrs.to_der().unwrap()).unwrap(); 
                //if x == true { return true };            
                if decryptresult.is_some() { return Ok(decryptresult.unwrap()); }
            }
        }
        return Err(Error::NoCompatibleRecipientFound);
    }
    fn decrypt_enveloped_data2<F> ( &self, decrypt_func: F) -> bool
        where F: Fn(&cms::enveloped_data::RecipientInfo) -> bool
    {   
        //envelope: &cms::enveloped_data::EnvelopedData;
        let envelope = self.get_enveloped_data().unwrap();

        for recip_info in envelope.recip_infos.0.iter() {
            let decryptresult=  decrypt_func( recip_info );
                // Spec says if there are signed attributes then the hash value is calculated over this signed attributes
                //return verifier.verify_oneshot(signer_info.signature.as_bytes(), &signed_attrs.to_der().unwrap()).unwrap(); 
                //if x == true { return true };            
            if decryptresult == true { return decryptresult; }
        }
        return false;
    }

    fn build_and_encrypt_envelope<E> ( plaintext_data: &[u8], recipient_issuer_and_serial: &IssuerAndSerialNumber, encrypt_func: E)-> Result<cms::enveloped_data::EnvelopedData, Error>
        where E: Fn(&[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) 
    {
        let (encrypted_data, encapsulated_key, iv ) = encrypt_func ( plaintext_data);
                 
        let ktri = KeyTransRecipientInfo { 
            version: cms::content_info::CmsVersion::V0, 
            rid: cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(recipient_issuer_and_serial.clone()), 
            key_enc_alg: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_RSAES_OAEP, parameters: None },
            enc_key: OctetString::new ( encapsulated_key )?,
        };

        let recipient_infos = SetOfVec::try_from ( vec![cms::enveloped_data::RecipientInfo::Ktri(ktri)])?;

        let enveloped_data = cms::enveloped_data::EnvelopedData { 
            version: CmsVersion::V0, 
            originator_info: None, 
            recip_infos: cms::enveloped_data::RecipientInfos(recipient_infos), 
            encrypted_content: cms::enveloped_data::EncryptedContentInfo { 
                content_type: ID_DATA, 
                content_enc_alg: AlgorithmIdentifierOwned{oid: der::oid::db::rfc5911::DES_EDE_3_CBC, parameters: Some(der::Any::new(der::Tag::OctetString, iv)?) }, 
                encrypted_content: Some(OctetString::new(encrypted_data)?) 
            },
            unprotected_attrs: None, 
        }; 
        return Ok(enveloped_data);
    }

}

#[derive(PartialEq,Eq)]
pub struct TR34KdhUnbindToken {
    cms: cms::content_info::ContentInfo,
}
#[derive(PartialEq,Eq)]
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
    DerError (der::Error),
}
impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        return Error::DerError(e)
    }
}

impl TR34KeyToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34KeyToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        Ok(TR34KeyToken { cms: import/* , verified: false*/ })
    }
    // pub fn new () -> TR34KeyToken {
    //     let outer = SignedData { 
    //             version: cms::content_info::CmsVersion::V1, 
    //             digest_algorithms: SetOfVec::new (), 
    //             encap_content_info: EncapsulatedContentInfo { econtent_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA, econtent: None },
    //             certificates: None, 
    //             crls: None, 
    //             signer_infos: SignerInfos ( SetOfVec::new()) };


    //     let signer1 = SignerInfo { 
    //             version: cms::content_info::CmsVersion::V1, 
    //             sid: cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { 
    //                 issuer: cms::cert::x509::name::RdnSequence::, 
    //                 serial_number: cms::cert::x509::serial_number::SerialNumber::new(&[0u8;1]).unwrap() }), 
    //             digest_alg: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None}, 
    //             signed_attrs: None, 
    //             signature_algorithm: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::RSA_ENCRYPTION, parameters: None },
    //             signature: der::asn1::OctetString::new([0u8;0]).unwrap(), 
    //             unsigned_attrs: None };
    //     //let outer_as_any = der::Any::new(der::Tag::OctetString, outer.to_der().unwrap()).unwrap();
    //     let outer_as_any = der::Any::encode_from(&outer).unwrap();
    //     let cms2 =cms::content_info::ContentInfo { content_type: PKCS7_SIGNED_DATA_OID, content: outer_as_any };
    //     return TR34KeyToken { cms: cms2, verified: false }
    // }
    pub fn get_outer_signed_data(&self) -> Result<cms::signed_data::SignedData, Error> {
        return Ok(self.cms.content.decode_as()?);
    }
    // pub fn set_outer_signed_data(&mut self, signed_data: &cms::signed_data::SignedData ) {
    //     self.cms.content = der::Any::new(der::Tag::OctetString, signed_data.to_der().unwrap()).unwrap();
    // }
    // pub fn verify_signature<F>(&self, verify_func:F) -> bool 
    //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8])
    // {
    //     return verify_signature ( &self.get_outer_signed_data(), verify_func);
    // }
    pub fn get_inner_enveloped_data(&self) -> Result<cms::enveloped_data::EnvelopedData, Error> {
        assert! (self.get_outer_signed_data()?.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_ENVELOPED_DATA);
        let mb_econtent = self.get_outer_signed_data()?.encap_content_info.econtent.unwrap().decode_as::<OctetString>()?;
        return Ok(cms::enveloped_data::EnvelopedData::from_der ( mb_econtent.as_bytes())?);
    }
    // From TR-34 2019, section 5.4.9
    pub fn get_random_number (&self) -> Vec<u8>{
        return get_random_number_from_cms(&self.cms);
    }

    // pub fn set_random_number ( &mut self, random_number: &[u8]) {
    //     let mut outer_signed_data = self.get_outer_signed_data();
    //     let mut signer_info = outer_signed_data.signer_infos.0.get(0).unwrap().clone();
    //     set_random_number_from_signer_info (&mut signer_info, random_number);
    //     let mut ve = SetOfVec::new();
    //     ve.insert(signer_info).unwrap();
    //     let si = SignerInfos(ve);
    //     //let ve = ;
    //     outer_signed_data.signer_infos = si;
    //     self.set_outer_signed_data(&outer_signed_data);
    // }
    // pub fn set_key_block_header ( &mut self, key_block_header: &[u8]) {
    //     let mut outer_signed_data = self.get_outer_signed_data();
    //     let mut signer_info = outer_signed_data.signer_infos.0.get(0).unwrap().clone();

    //     let any = der::Any::new(der::Tag::OctetString, key_block_header).unwrap();
    //     let a = Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![any]).unwrap()};
    //     signer_info.signed_attrs.insert(SetOfVec::try_from(vec![a]).unwrap());

    //     let mut ve = SetOfVec::new();
    //     ve.insert(signer_info).unwrap();
    //     let si = SignerInfos(ve);
    //     //let ve = ;
    //     outer_signed_data.signer_infos = si;
    //     self.set_outer_signed_data(&outer_signed_data);
    // }


    pub fn get_timestamp (&self) -> UtcTime{
        for signed_attr in get_signed_attrs_from_cms(&self.cms).iter() {
            if signed_attr.oid == der::oid::db::rfc5911::ID_SIGNING_TIME {
                return signed_attr.values.get(0).unwrap().decode_as::<UtcTime>().unwrap();
            }
        }
        panic! ("Missing key block header attribute");
    }
    pub fn get_key_block_header (&self) -> Vec<u8> {
        for signed_attr in get_signed_attrs_from_cms(&self.cms).iter() {
            if signed_attr.oid == ID_DATA {
                return signed_attr.values.get(0).unwrap().value().to_vec();
            }
        }
        panic! ("Missing key block header attribute");
    }
    

    pub fn get_plaintext_key<F> (&self, decrypt_func: F) -> Result<Vec<u8>, Error>
        where F: Fn(&[u8], &[u8], &[u8]) -> Option<Vec<u8>>
    {
        let plaintext_enveloped_data = self.decrypt_enveloped_data (decrypt_func);
        if plaintext_enveloped_data.is_err() { return Err(Error::DecryptionError); }
        let tr34keyblock = TR34Block::from_der ( &plaintext_enveloped_data.unwrap() )?;

        if tr34keyblock.attribute_header.values.get(0).unwrap().value() != self.get_key_block_header() { return Err(Error::KeyBlockHeaderInconsistency); }
        if tr34keyblock.issuer_and_serial_number != self.get_signer_id()? { return Err(Error::IssuerSerialInconsistency); }

        return Ok(tr34keyblock.clear_key.into_bytes());
    }
    pub fn get_crl (&self) -> Option<cms::revocation::RevocationInfoChoices> {
        return self.get_outer_signed_data().unwrap().crls;
    }

    pub fn build<E,F> ( signer_issuer_and_serial: &IssuerAndSerialNumber, 
            recipient_issuer_and_serial: &IssuerAndSerialNumber,
            key_block_header: &[u8], 
            cleartext_key: &[u8], 
            random_number: Option<&[u8]>,
            encrypt_func: E, signing_func: F) -> Result<TR34KeyToken, Error>
        where E: Fn(&[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>),
             F: Fn(&[u8]) -> Vec<u8> 
    {
        let block_to_be_encrypted = TR34Block { 
            version: cms::content_info::CmsVersion::V1, 
            issuer_and_serial_number: signer_issuer_and_serial.clone(), 
            clear_key: OctetString::new ( cleartext_key)?, 
            attribute_header: Attribute { oid:ID_DATA, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, key_block_header)?])?},
         };

        let enveloped_data = <TR34KeyToken as TR34Enveloped>::build_and_encrypt_envelope ( &block_to_be_encrypted.to_der()?, recipient_issuer_and_serial, encrypt_func )?;
        // let (encrypted_data, encapsulated_key, iv ) = encrypt_func ( &block_to_be_encrypted.to_der()?);
                 
        // let ktri = KeyTransRecipientInfo { 
        //     version: cms::content_info::CmsVersion::V0, 
        //     rid: cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(recipient_issuer_and_serial.clone()), 
        //     key_enc_alg: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_RSAES_OAEP, parameters: None },
        //     enc_key: OctetString::new ( encapsulated_key )?,
        // };

        // let mut recipient_infos = SetOfVec::new();
        // recipient_infos.insert ( cms::enveloped_data::RecipientInfo::Ktri(ktri))?;

        // let enveloped_data = cms::enveloped_data::EnvelopedData { 
        //     version: CmsVersion::V0, 
        //     originator_info: None, 
        //     recip_infos: cms::enveloped_data::RecipientInfos(recipient_infos), 
        //     encrypted_content: cms::enveloped_data::EncryptedContentInfo { 
        //         content_type: PKCS7_DATA_OID, 
        //         content_enc_alg: AlgorithmIdentifierOwned{oid: ID_DES_EDE_3_CBC, parameters: Some(der::Any::new(der::Tag::OctetString, iv)?) }, 
        //         encrypted_content: Some(OctetString::new(encrypted_data)?) 
        //     },
        //     unprotected_attrs: None, 
        // };

        let mut signed_attrs = SetOfVec::new();
        if let Some(random_number) = random_number {
            signed_attrs.insert ( Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, random_number)?])?})?;
        }
        signed_attrs.insert ( Attribute { oid:ID_DATA, values:SetOfVec::try_from(vec![der::Any::new(der::Tag::OctetString, key_block_header)?])?})?;

        let encap_content_info =  EncapsulatedContentInfo { 
                    econtent_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA, 
                    econtent: Some(der::Any::new(der::Tag::OctetString, enveloped_data.to_der()?)?), 
                };
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), signer_issuer_and_serial, 
            &encap_content_info, None, None, signing_func)?;

        // let signature = signing_func (&signed_attrs.to_der()?);
        
        // let signer1 = SignerInfo { 
        //     version: cms::content_info::CmsVersion::V1, 
        //     sid: cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(signer_issuer_and_serial.clone()), 
        //     digest_alg: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None}, 
        //     signed_attrs: Some(signed_attrs), 
        //     signature_algorithm: AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::RSA_ENCRYPTION, parameters: None },
        //     signature: der::asn1::OctetString::new(signature)?, 
        //     unsigned_attrs: None };

        // let mut signer_infos = SetOfVec::new();
        // signer_infos.insert ( signer1)?;

        // let mut digest_algorithms = SetOfVec::new ();
        // digest_algorithms.insert ( AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None })?;

        // let outer = SignedData { 
        //     version: cms::content_info::CmsVersion::V1, 
        //     digest_algorithms: digest_algorithms, 
        //     encap_content_info: EncapsulatedContentInfo { 
        //         econtent_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA, 
        //         econtent: Some(der::Any::new(der::Tag::OctetString, enveloped_data.to_der()?)?) 
        //     },
        //     certificates: None, 
        //     crls: None, 
        //     signer_infos: SignerInfos ( signer_infos) };

        return Ok(TR34KeyToken { cms: cms::content_info::ContentInfo { content_type: der::oid::db::rfc5911::ID_SIGNED_DATA /*PKCS7_SIGNED_DATA_OID*/, 
            content: der::Any::encode_from(&outer)? }/* , verified:false*/});
    }
}

impl TR34Signed for TR34KeyToken  {
    fn get_cms(&self) -> cms::content_info::ContentInfo {
        return self.cms.clone();
    }
}

impl TR34Enveloped for TR34KeyToken {
    fn get_enveloped_data(&self) -> Result<cms::enveloped_data::EnvelopedData, Error> {
        let outer_signed_data: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
        let x =  outer_signed_data.encap_content_info.econtent.unwrap().decode_as::<OctetString>().unwrap();// cms::enveloped_data::EnvelopedData::
        return Ok(cms::enveloped_data::EnvelopedData::from_der(x.as_bytes())?);
    }
}


impl TR34RandomNumberToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34RandomNumberToken, der::Error> {
        let import = Attribute::from_der(input);
        if import.is_ok() {
            Ok(TR34RandomNumberToken { attr: import.unwrap() })
        }
        else {
            return Err(import.err().unwrap());
        }    
    }
    pub fn to_der (&self) -> Result<Vec<u8>, der::Error> {
        return self.attr.to_der();
    }
    pub fn build ( input: &[u8]) -> Result<TR34RandomNumberToken, Error> {
        let random_as_any = cms::cert::x509::attr::AttributeValue::new( der::Tag::OctetString, input.to_owned() )?;
        let attr = Attribute { oid: ID_RANDOM_NONCE, values: SetOfVec::try_from(vec![random_as_any]).unwrap() };
        return Ok(TR34RandomNumberToken { attr: attr });
    }
    pub fn get_random_number (&self) -> &[u8] {
        return self.attr.values.get(0).unwrap().value();
    }
    
}


impl TR34KdhUnbindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34KdhUnbindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34KdhUnbindToken { cms: import});
    }

    pub fn get_outer_signed_data(&self) -> cms::signed_data::SignedData {
        return self.cms.content.decode_as().unwrap();
    }

    pub fn build<F> ( krd_id: &IssuerAndSerialNumber, kdh_id: &IssuerAndSerialNumber, crl: &CertificateList,
        random_nonce: &[u8], signing_func: F ) -> Result<TR34KdhUnbindToken, Error> 
        where F: Fn(&[u8]) -> Vec<u8> 
    {
        let encap_content_info = EncapsulatedContentInfo { 
            econtent_type: der::oid::db::rfc5911::ID_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, krd_id.to_der()?)?) 
        };
        let mut crl2 = SetOfVec::new();
        crl2.insert (RevocationInfoChoice::Crl(crl.clone()))?;

        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_DATA.into()])?})?;
        signed_attrs.insert ( Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![Any::new(der::Tag::OctetString, random_nonce)?])?})?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), kdh_id, 
            &encap_content_info, None, Some(cms::revocation::RevocationInfoChoices(crl2)), signing_func)?;

        return Ok(TR34KdhUnbindToken { cms: cms::content_info::ContentInfo { content_type: ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

    }
    // pub fn get_signed_data(&self) -> cms::signed_data::SignedData {
    //     let x: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
    //     return x;
    // }
    
    // pub fn verify_signature<F>(&self, verify_func:F) -> bool 
    //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8])
    // {
    //     return verify_signature ( &self.get_signed_data(), verify_func);
    // }
    pub fn get_krd_id(&self) -> IssuerAndSerialNumber {
        let econtents = self.get_signed_data().unwrap().encap_content_info.econtent.unwrap();
        let krd_id = cms::cert::IssuerAndSerialNumber::from_der(econtents.value());
        return krd_id.unwrap();
    }
    pub fn get_random_number (&self) -> Vec<u8>{
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
        if import.content_type != ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34KdhRebindToken { cms: import });     
    }
    pub fn get_outer_signed_data(&self) -> cms::signed_data::SignedData {
        let x: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
        return x;
    }
    // pub fn verify_signature<F>(&self, verify_func:F) -> bool 
    //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8])
    // {
    //     return verify_signature ( &self.get_outer_signed_data(), verify_func);
    // }
    pub fn get_rebind_id(&self) -> IssuerAndSerialNumber {
        let econtent_as_sequence = der::Any::new(der::Tag::Sequence, self.get_outer_signed_data().encap_content_info.econtent.unwrap().value()).unwrap();
        let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
        //let as_seq = der::Any::new ( der::Tag::Sequence, signed_inner.encap_content_info.econtent.unwrap().value()).unwrap();
        let unbind_id = cms::cert::IssuerAndSerialNumber::from_der( signed_inner.encap_content_info.econtent.unwrap().value()).unwrap();
        return unbind_id;
    }
    pub fn get_random_number (&self) -> Vec<u8>{
        return get_random_number_from_cms (&self.cms);
    }
    // From TR-34:2019 5.5.3
    pub fn get_new_kdh_cred (&self) -> CertificateInner{
        //let inner = get_signed_data_from_cms(&self.cms);
        let inner = get_inner_signed_data (&self.cms);
        match inner.certificates.unwrap().0.get(0).unwrap() {
            cms::cert::CertificateChoices::Certificate(x) => return x.clone(),
            _=> panic!("No certificate"),
        }
    }

    pub fn build<F> ( krd_id: &IssuerAndSerialNumber, signing_kdh_id: &IssuerAndSerialNumber, new_kdh_cert: cms::cert::x509::Certificate, 
        crl: &CertificateList, random_nonce: &[u8], signing_func: F ) -> Result<TR34KdhRebindToken, Error> 
       where F: Fn(&[u8]) -> Vec<u8> 
    {
        let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let digest_algorithms = SetOfVec::new ();
        
        let signed_data = SignedData { 
            //econtent_type: der::oid::db::rfc5911::ID_DATA, 
            //econtent: Some(der::Any::new(der::Tag::OctetString, content.to_der()?)?) 
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {  econtent_type: der::oid::db::rfc5911::ID_DATA, 
                econtent: Some(der::Any::new(der::Tag::OctetString, krd_id.to_der()?)?) },
            certificates: Some(cms::signed_data::CertificateSet(cert_set)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let encap_content_info = EncapsulatedContentInfo{ econtent_type: ID_SIGNED_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&signed_data)?.value())?) };
        
        
        //let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        //cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_SIGNED_DATA.into()])?})?;
        signed_attrs.insert ( Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![Any::new(der::Tag::OctetString, random_nonce)?])?})?;

        let mut crl2 = SetOfVec::new();
        crl2.insert (RevocationInfoChoice::Crl(crl.clone()))?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( 
            Some(signed_attrs), 
            signing_kdh_id, 
            &encap_content_info, 
            None, //Some(cms::signed_data::CertificateSet(cert_set)), 
            Some(cms::revocation::RevocationInfoChoices(crl2)),
            signing_func)?;

        return Ok(TR34KdhRebindToken { cms: cms::content_info::ContentInfo { content_type: ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

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
        if import.content_type != ID_SIGNED_DATA {
            return Err(Error::InvalidContentType);
        }
        return Ok(TR34CaUnbindToken { cms: import});  
    }
    pub fn get_outer_signed_data(&self) -> cms::signed_data::SignedData {
        let x: cms::signed_data::SignedData = self.cms.content.decode_as().unwrap();
        return x;
    }
    // pub fn verify_signature<F>(&self, verify_func:F) -> bool 
    //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8])
    // {
    //     return verify_signature ( &self.get_outer_signed_data(), verify_func);
    // }
    pub fn get_unbind_ids(&self) -> UbtCaUnbind {
        // let econtent_as_sequence = der::Any::new(der::Tag::Sequence, self.get_outer_signed_data().encap_content_info.econtent.unwrap().value()).unwrap();
        // let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
        // let as_seq = der::Any::new ( der::Tag::Sequence, signed_inner.encap_content_info.econtent.unwrap().value()).unwrap();
        // return as_seq.decode_as::<UbtCaUnbind>().unwrap();
        
        // There seems to be a missing SEQUENCE in the stream, decode with a dummy header
        let econtents = self.get_outer_signed_data().encap_content_info.econtent.unwrap();
        let econtent_as_sequence = der::Any::new( der::Tag::Sequence, econtents.value()).unwrap();
        return econtent_as_sequence.decode_as::<UbtCaUnbind>().unwrap();
    }

    pub fn build<F> ( krd_id: &IssuerAndSerialNumber, kdh_id: &IssuerAndSerialNumber, signer_id: &IssuerAndSerialNumber,
        signing_func: F ) -> Result<TR34CaUnbindToken, Error> 
       where F: Fn(&[u8]) -> Vec<u8> 
    {
        let content = UbtCaUnbind{ id_krd: krd_id.clone(), id_kdh: kdh_id.clone() };

        let encap_content_info = EncapsulatedContentInfo { 
            econtent_type: der::oid::db::rfc5911::ID_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&content)?.value())?) 
        };
        
        //let mut signed_attrs = SetOfVec::new();
        //signed_attrs.insert ( Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::from_iter(vec![der::oid::db::rfc5911::ID_DATA.into()])?})?;
        //signed_attrs.insert ( Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::from_iter(vec![Any::new(der::Tag::OctetString, random_nonce)?])?})?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( None, signer_id, 
            &encap_content_info, None, None, signing_func)?;

        return Ok(TR34CaUnbindToken { cms: cms::content_info::ContentInfo { content_type: ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

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
    assert! ( outer_signed_data.encap_content_info.econtent_type == ID_SIGNED_DATA);
    let econtent_as_sequence = der::Any::new(der::Tag::Sequence, outer_signed_data.encap_content_info.econtent.unwrap().value()).unwrap();
    let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
    return signed_inner;
}

fn get_signed_attrs_from_cms(cms: &cms::content_info::ContentInfo) -> cms::signed_data::SignedAttributes {
    return get_signed_data_from_cms(cms).signer_infos.as_ref().get(0).as_ref().unwrap().signed_attrs.as_ref().unwrap().clone();
}

fn get_random_number_from_cms (cms: &cms::content_info::ContentInfo) -> Vec<u8>{
    for signed_attr in get_signed_attrs_from_cms(cms).iter() {
        if signed_attr.oid == ID_RANDOM_NONCE {
            return signed_attr.values.get(0).unwrap().value().to_vec();
        }
    }
    panic! ("Missing random number attribute");
}
//fn set_random_number_from_cms (cms: &mut cms::content_info::ContentInfo, random_number: Vec<u8>) {
// fn set_random_number_from_signer_info (signer_info: &mut cms::signed_data::SignerInfo, random_number: &[u8]) {
//     let any = der::Any::new(der::Tag::OctetString, random_number).unwrap();
//     let a = Attribute { oid:ID_RANDOM_NONCE, values:SetOfVec::try_from(vec![any]).unwrap()};
//     signer_info.signed_attrs.insert(SetOfVec::try_from(vec![a]).unwrap());
// }



    // let mut signed_data: cms::signed_data::SignedData = cms.content.decode_as().unwrap();
    // let mut signer_infos = &mut signed_data.signer_infos;
    // let mut signer_info2 = signer_infos.as_mut();
    // let mut signer_info3 = signer_info2.as_slice();
    // let mut signer_info4 = signer_info2.get(0);
    
    // for signer_info in signer_info3.iter_mut() {
    //     signer_info.signed_attrs.insert ( SetOfVec::from_iter(vec![a]).unwrap());
    // }

    // if let Some(signer_info) = signer_infos.0.get(0) {
    //     signer_info.signed_attrs = None;
    //     // Have a reference to 
    //     if let Some(signed_attrs) = signer_info.signed_attrs.as_mut() {
    //         for signed_attr in signed_attrs.iter() {
    //             if signed_attr.oid == ID_RANDOM_NONCE {
    //                 let any = der::Any::new(der::Tag::OctetString, random_number).unwrap();
    //                 signed_attr.values = SetOfVec::from_iter (vec![any]).unwrap();
    //                 return;
    //             }
    //         }
    //     }
    // }

//     panic! ("Missing random number attribute");
// }



// Top of page 34 says parameters for HLA Unbind Token
impl TR34CaRebindToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34CaRebindToken, Error> {
        let import = cms::content_info::ContentInfo::from_der(input)?;
        if import.content_type != ID_SIGNED_DATA {
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
        if outer_signed_data.encap_content_info.econtent_type != ID_SIGNED_DATA { 
            return Err(Error::InvalidContentType);
        }
        if outer_signed_data.encap_content_info.econtent.is_none() {
            return Err(Error::MissingContent);
        }
        let econtent_as_sequence = der::Any::new(der::Tag::Sequence, outer_signed_data.encap_content_info.econtent.unwrap().value())?;
        return Ok(econtent_as_sequence.decode_as::<cms::signed_data::SignedData>()?);
    }

    // pub fn verify_signature<F>(&self, verify_func:F) -> bool 
    //     where F: Fn(&[u8], &SignerInfo) -> bool //message: &[u8], signature: &[u8])
    // {
    //     return verify_signature ( &self.get_outer_signed_data(), verify_func);
    // }
    // Description of the ca rebind token indicates there are two ids - ID_KRD_CRED and ID_KDH_CRED
    pub fn get_rebind_ids(&self) -> Result<UbtCaUnbind, Error> {
        let econtents = self.get_inner_signed_data()?.encap_content_info.econtent.unwrap();
        let econtent_as_sequence = der::Any::new( der::Tag::Sequence, econtents.value())?;
        return Ok(econtent_as_sequence.decode_as::<UbtCaUnbind>()?);
    }  
    // From TR-34:2019 5.5.3
    pub fn get_new_kdh_cred (&self) -> CertificateInner {
        let signed_inner = self.get_inner_signed_data().unwrap();
        assert! ( signed_inner.certificates.clone().unwrap().0.len() == 1 );
        //let x = signed_inner.certificates.unwrap().0.get(0);
        match signed_inner.certificates.unwrap().as_ref().get(0).unwrap() {
            cms::cert::CertificateChoices::Certificate(c) => return c.clone(),
            _ => panic!("unhandled enum type"),
        }
    }

    pub fn build<F> ( krd_id: &IssuerAndSerialNumber, kdh_id: &IssuerAndSerialNumber, signer_issuer: &IssuerAndSerialNumber, new_kdh_cert: cms::cert::x509::Certificate, 
        signing_time: &UtcTime, signing_func: F ) -> Result<TR34CaRebindToken, Error> 
       where F: Fn(&[u8]) -> Vec<u8> 
    {
        let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let content = UbtCaUnbind{ id_krd: krd_id.clone(), id_kdh: kdh_id.clone() };
        //let digest_algorithms = 
        //digest_algorithms.insert ( AlgorithmIdentifierOwned { oid: der::oid::db::rfc5912::ID_SHA_256, parameters: None })?;

        let signed_data = SignedData { 
            //econtent_type: der::oid::db::rfc5911::ID_DATA, 
            //econtent: Some(der::Any::new(der::Tag::OctetString, content.to_der()?)?) 
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: SetOfVec::new (),
            encap_content_info: EncapsulatedContentInfo {  econtent_type: der::oid::db::rfc5911::ID_DATA, 
                econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&content)?.value())?) },
            certificates: Some(cms::signed_data::CertificateSet(cert_set)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let encap_content_info = EncapsulatedContentInfo{ econtent_type: ID_SIGNED_DATA, 
            econtent: Some(der::Any::new(der::Tag::OctetString, der::Any::encode_from(&signed_data)?.value())?) };
        

        //let mut cert_set = SetOfVec::<cms::cert::CertificateChoices>::new();
        //cert_set.insert(cms::cert::CertificateChoices::Certificate(new_kdh_cert))?;

        let mut signed_attrs = SetOfVec::new();
        signed_attrs.insert ( Attribute { oid:der::oid::db::rfc6268::ID_CONTENT_TYPE, values:SetOfVec::try_from(vec![der::oid::db::rfc5911::ID_SIGNED_DATA.into()])?})?;
        signed_attrs.insert ( Attribute { oid:der::oid::db::rfc5911::ID_SIGNING_TIME, values:SetOfVec::try_from(vec![der::Any::encode_from(signing_time)?])?})?;
        
        let outer = <TR34KeyToken as TR34Signed>::build_and_sign_data ( Some(signed_attrs), signer_issuer, 
            &encap_content_info, None, None, signing_func)?;

        return Ok(TR34CaRebindToken { cms: cms::content_info::ContentInfo { content_type: ID_SIGNED_DATA, content: der::Any::encode_from(&outer)? } });

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







