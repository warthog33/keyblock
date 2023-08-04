pub mod fromtr34;
use der::oid::db::rfc5911::ID_SIGNED_DATA;
use fromtr34::*;
use openssl::{pkey::Id};


// fn get_certs_openssl () -> openssl::stack::Stack<openssl::x509::X509> {
//     let root_pem = pem::parse(B_2_1_1_SAMPLE_ROOT_KEY_P12).unwrap();
//     let root_key_openssl = openssl::pkcs12::Pkcs12::from_der(root_pem.contents()).unwrap().parse2("TR34").unwrap();
//     let _root_key_openssl2 = openssl::pkcs12::Pkcs12::from_der(root_pem.contents()).unwrap().parse2("TR34").unwrap();

//     let ca_kdh_pem = pem::parse(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12).unwrap();
//     let ca_kdh_openssl = openssl::pkcs12::Pkcs12::from_der(ca_kdh_pem.contents()).unwrap().parse2("TR34").unwrap();

//     //let ca_kdh_crl_pem = pem::parse(B_2_1_3_TR34_SAMPLE_KDH_CRL_P12).unwrap();
//     //let ca_kdh_crl_openssl = openssl::pkcs12::Pkcs12::from_der(ca_kdh_crl_pem.contents()).unwrap().parse2("TR34").unwrap();

    
//     let ca_krd_pem = pem::parse(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12).unwrap();
//     let ca_krd_openssl = openssl::pkcs12::Pkcs12::from_der(ca_krd_pem.contents()).unwrap().parse2("TR34").unwrap();
    
//     let kdh_1_pem = pem::parse(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12).unwrap();
//     let kdh_1_key_openssl = openssl::pkcs12::Pkcs12::from_der(kdh_1_pem.contents()).unwrap().parse2("TR34").unwrap();

//     let kdh_2_pem = pem::parse(B_2_1_6_TR34_SAMPLE_KDH_2_KEY_P12).unwrap();
//     let kdh_2_openssl = openssl::pkcs12::Pkcs12::from_der(kdh_2_pem.contents()).unwrap().parse2("TR34").unwrap();

//     let krd_1_pem = pem::parse(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12).unwrap();
//     let krd_1_openssl = openssl::pkcs12::Pkcs12::from_der(krd_1_pem.contents()).unwrap().parse2("TR34").unwrap();

//     let mut certs = openssl::stack::Stack::new().unwrap();
//     certs.push (root_key_openssl.cert.unwrap() ).unwrap();
//     certs.push ( ca_kdh_openssl.cert.unwrap()).unwrap();
//     certs.push( kdh_1_key_openssl.cert.unwrap() ).unwrap();
    
//     // let mut chain = openssl::stack::Stack::new().unwrap();
//     // chain.push ( root_key_openssl.cert.unwrap());
//     // chain.push ( ca_krd_openssl.cert.unwrap()).unwrap();

//     let mut verify_params = openssl::x509::verify::X509VerifyParam::new().unwrap();
//     //let expected_depth = if cfg!(any(ossl110)) { 1 } else { 2 };
//     let expected_depth = 1;
//     verify_params.set_depth(expected_depth);
    
//     let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
//     store_builder.add_cert(ca_krd_openssl.cert.unwrap()).unwrap();
//     store_builder.set_param(&verify_params).unwrap();

//     //store_builder.add_cert(ca_kdh_openssl.cert.unwrap()).unwrap();
//     let store = store_builder.build();
   

//     // let mut context = openssl::x509::X509StoreContext::new().unwrap();
//     // let _res = context.init(&store, &krd_1_openssl.cert.unwrap(), &chain, |c| c.verify_cert());

//     // let _chn = context.chain();

//     //certs.push ( ca_krd_openssl.cert.unwrap()).unwrap();
//     //certs.push( kdh_2_openssl.cert.unwrap()).unwrap();
//     //certs.push( krd_1_openssl.cert.unwrap()).unwrap();
    
//     certs
// }




#[test]
fn decode_b_2_1_1_ca_openssl() {
    let ca_key_pem = pem::parse(B_2_1_1_SAMPLE_ROOT_KEY_P12).unwrap();
    let ca_key_openssl = openssl::pkcs12::Pkcs12::from_der ( ca_key_pem.contents()).unwrap().parse2("TR34").unwrap();

    let ca_cert = ca_key_openssl.cert.unwrap();
    assert! ( ca_cert.as_ref().serial_number() == openssl::asn1::Asn1Integer::from_bn(&openssl::bn::BigNum::from_dec_str("223338299393").unwrap()).unwrap().as_ref());
    assert! ( format!("{:?}",ca_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample Root\"]" );
    assert! ( format!("{:?}",ca_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample Root\"]" );
    assert! ( ca_cert.as_ref().issuer_name_hash() == 1388095582);

    let priv_key = ca_key_openssl.pkey.unwrap();
    assert! ( priv_key.id() == Id::RSA);
    assert! ( priv_key.rsa().unwrap().size() == 2048 / 8 );

    // No cert chain on the root key
    assert! ( ca_key_openssl.ca.is_none());

    // Root CA key is self signed
    let verified = ca_cert.verify(&ca_cert.as_ref().public_key().unwrap()).unwrap();
    assert! ( verified == true);
}


#[test]
fn decode_b_2_1_2_ca_kdh_openssl() {
    let root_public_key = get_root_pub_key_openssl();

    let kdh_key_pem = pem::parse(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12).unwrap();
    let kdh_key_openssl = openssl::pkcs12::Pkcs12::from_der ( kdh_key_pem.contents()).unwrap().parse2("TR34").unwrap();
    let kdh_cert = kdh_key_openssl.cert.unwrap();

    let verified = kdh_cert.verify(&root_public_key).unwrap();
    assert! ( verified == true);
    assert! ( kdh_cert.as_ref().serial_number() == openssl::asn1::Asn1Integer::from_bn(&openssl::bn::BigNum::from_dec_str("223338299397").unwrap()).unwrap().as_ref());
    assert! ( format!("{:?}",kdh_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample CA KDH\"]" );
    assert! ( format!("{:?}",kdh_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample Root\"]" );
    assert! ( kdh_cert.as_ref().issuer_name_hash() == 1388095582);
}

#[test]
fn decode_b_2_1_4_ca_krd_openssl() {
    let root_public_key = get_root_pub_key_openssl();

    let ca_krd_pem = pem::parse(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12).unwrap();
    let ca_krd_openssl = openssl::pkcs12::Pkcs12::from_der ( ca_krd_pem.contents()).unwrap().parse2("TR34").unwrap();
    let krd_cert = ca_krd_openssl.cert.as_ref().unwrap();
    
    assert! ( krd_cert.verify(&root_public_key).unwrap() == true);
    
    assert! ( krd_cert.as_ref().serial_number().to_bn().unwrap() == openssl::bn::BigNum::from_dec_str("223338299398").unwrap());
    assert! ( format!("{:?}",krd_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample CA KRD\"]" );
    assert! ( format!("{:?}",krd_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample Root\"]" );
    assert! ( krd_cert.as_ref().issuer_name_hash() == 1388095582);
}

#[test]
fn decode_b_2_1_5_kdh_1_openssl() {
    let kdh_1_pem = pem::parse(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12).unwrap();
    let kdh_1_openssl = openssl::pkcs12::Pkcs12::from_der ( kdh_1_pem.contents()).unwrap().parse2("TR34").unwrap();

    let kdh_1_cert = kdh_1_openssl.cert.unwrap();
    assert! ( kdh_1_cert.verify(&get_ca_kdh_openssl()).unwrap() == true);
    assert! ( kdh_1_cert.as_ref().serial_number().to_bn().unwrap() == openssl::bn::BigNum::from_dec_str("223338299398").unwrap());
    assert! ( format!("{:?}",kdh_1_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample KDH 1\"]" );
    assert! ( format!("{:?}",kdh_1_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample CA KDH\"]" );
    assert! ( kdh_1_cert.as_ref().issuer_name_hash() == 918036607);
}

#[test]
fn decode_b_2_1_6_kdh_2_openssl() {
    let kdh_2_pem = pem::parse(B_2_1_6_TR34_SAMPLE_KDH_2_KEY_P12).unwrap();
    let kdh_2_openssl = openssl::pkcs12::Pkcs12::from_der ( kdh_2_pem.contents()).unwrap().parse2("TR34").unwrap();

    let kdh_2_cert = kdh_2_openssl.cert.unwrap();
    assert! ( kdh_2_cert.verify(&get_ca_kdh_openssl()).unwrap() == true);
    assert! ( kdh_2_cert.as_ref().serial_number().to_bn().unwrap() == openssl::bn::BigNum::from_dec_str("223338299399").unwrap());
    assert! ( format!("{:?}",kdh_2_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample KDH 2\"]" );
    assert! ( format!("{:?}",kdh_2_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample CA KDH\"]" );
    assert! ( kdh_2_cert.as_ref().issuer_name_hash() == 918036607);
}

#[test]
fn decode_b_2_1_7_krd_1_openssl() {
    let krd_1_epm = pem::parse(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12).unwrap();
    let krd_1_openssl = openssl::pkcs12::Pkcs12::from_der ( krd_1_epm.contents()).unwrap().parse2("TR34").unwrap();

    let krd_1_cert = krd_1_openssl.cert.unwrap();
    assert! ( krd_1_cert.verify(&get_ca_krd_openssl()).unwrap() == true);
    assert! ( krd_1_cert.as_ref().serial_number().to_bn().unwrap() == openssl::bn::BigNum::from_dec_str("223338299399").unwrap());
    assert! ( format!("{:?}",krd_1_cert.as_ref().subject_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample KRD 1\"]" );
    assert! ( format!("{:?}",krd_1_cert.as_ref().issuer_name()) == "[countryName = \"US\", organizationName = \"TR34 Samples\", commonName = \"TR34 Sample CA KRD\"]" );
    assert! ( krd_1_cert.as_ref().issuer_name_hash() == 3838194345);
}



 #[test]
fn decode_b_2_2_3_1_sample_tdea_enveloped_data_openssl() {
    // Have to add the contentInfo wrapper around the file to make openssl import it
    let enveloped_data = <der::Any as der::Decode>::from_der(pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents()).unwrap();
    let content_info = cms::content_info::ContentInfo { content: enveloped_data,  content_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA};

    let content_info_openssl = openssl::cms::CmsContentInfo::from_der(&der::Encode::to_der(&content_info).unwrap()).unwrap();

    let result = content_info_openssl.decrypt_without_cert_check(&get_krd_1_openssl());

    println! ( "{result:?}");
}


 #[test]
fn decode_b_2_2_3_2_sample_aes_enveloped_data_openssl() {
    // Have to add the contentInfo wrapper around the file to make openssl import it
    let enveloped_data = <der::Any as der::Decode>::from_der(pem::parse(B_2_2_3_2_AES_ENVELOPED_DATA).unwrap().contents()).unwrap();
    let content_info = cms::content_info::ContentInfo { content: enveloped_data,  content_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA};

    let content_info_openssl = openssl::cms::CmsContentInfo::from_der(&der::Encode::to_der(&content_info).unwrap()).unwrap();

    let result = content_info_openssl.decrypt_without_cert_check(&get_krd_1_openssl());

    println! ( "{result:?}");
}


// This file is just the attributes part of a CMS structure, do not think openssl has a dedicated api to read it.
 #[test]
fn decode_b_2_2_5_1_signed_attributes_2_pass () {
    let _pem = pem::parse(B_2_2_5_SAMPLE_AUTHENTICATED_ATTRIBUTES_2_PASS_PEM).unwrap();
 
}



#[test]
fn decode_b_3_root_ca_openssl () {
    let _token_openssl = openssl::cms::CmsContentInfo::from_der(pem::parse(B_3_TR34_SAMPLE_ROOT_P7B).unwrap().contents()).unwrap();
   
    // there are useful certs in the certs field, but there doens't seem to be an API to retreive them!
    // can be done with cmdline openssl cms ... -certsout <filename>
    
}


#[test]
fn decode_b_4_ca_kdh_openssl () {
   
    let _token_openssl_pkcs7 = openssl::pkcs7::Pkcs7::from_der(pem::parse(B_4_CA_KDH_P7B).unwrap().contents()).unwrap();
    let mut _token_openssl_cms = openssl::cms::CmsContentInfo::from_der(pem::parse(B_4_CA_KDH_P7B).unwrap().contents()).unwrap();

    //let certs = openssl::stack::Stack::<X509>::new().unwrap();
    //let x = token_openssl_pkcs7.signers(&certs, openssl::pkcs7::Pkcs7Flags::NOINTERN).unwrap();
 
}

#[test]
fn decode_b_5_ca_krd_openssl () {
    
    let _token_openssl = openssl::cms::CmsContentInfo::from_der(pem::parse(B_5_SAMPLE_CA_KRD_P7B).unwrap().contents()).unwrap();
   
}


#[test]
fn decode_b_6_kdh_credential_token_openssl () {
    // Doesn't decode, not sure why..
    let _token_openssl = openssl::cms::CmsContentInfo::from_der(pem::parse(B_6_KDH_1_W_CRL_PEM).unwrap().contents()).unwrap();
   
}

#[test]
fn decode_b_7_krd_credential_token_openssl () {
    let _token_openssl = openssl::cms::CmsContentInfo::from_der(pem::parse(B_7_KRD_CREDENTIAL_TOKEN_1_P7B).unwrap().contents()).unwrap();

    // This token contains only a certificate, and is not signed...
    // Not sure how to get any of the contents for the purpose of decoding!

    
}

#[test]
fn decode_b_8_kdh_key_token_tdea_openssl() {
    let b_8_pem = pem::parse(B_8_ONE_PASS_KEY_TOKEN).unwrap();
    let mut outer = openssl::cms::CmsContentInfo::from_der(b_8_pem.contents()).unwrap();

    //verify_signature_openssl(outer, &get_kdh_1_pub_key());

    // let mut builder = X509StoreBuilder::new().unwrap();
    // let _ = builder.add_cert(get_cert_openssl(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12));
    // let _ = builder.add_cert(get_cert_openssl(B_2_1_1_SAMPLE_ROOT_KEY_P12));
    // let rootstore = builder.build();

    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12)).unwrap();
    //certs.push (get_cert_openssl(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12)).unwrap();
    //certs.push ( get_cert_openssl(B_2_1_1_SAMPLE_ROOT_KEY_P12)).unwrap();
        

    let mut inner_vec = Vec::<u8>::new();
    // Can't get this to work!! - best I can do is disable to signer cert chain verification!
    let verify_result = outer.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);
    println! ( "verify_result={verify_result:?} {}", inner_vec.len());

    assert! (verify_result.is_ok());
    assert! ( inner_vec == pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents());

    // inner_vec is decoded in decode_b_2_2_3_1_...
    //let outer2 = openssl::pkcs7::Pkcs7::from_der(b_8_pem.contents()).unwrap();

    // This fails... not sure why, maybe the inner object is not a proper cms or maybe openssl doesn't work properly..
    //let _inner = openssl::cms::CmsContentInfo::from_der(&inner_vec).unwrap();

    //println! ("{err:?}");
    
    

    // let kdh_1_pem = pem::parse(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12).unwrap();
    // let kdh_1_key_openssl = openssl::pkcs12::Pkcs12::from_der(kdh_1_pem.contents()).unwrap().parse2("TR34").unwrap();
    // let kdh_1_priv_key_openssl = kdh_1_key_openssl.pkey.unwrap();
    // //let kdh_1_cert_openssl = kdh_1_key_openssl.cert.unwrap();

    // let outerver = outer.decrypt_without_cert_check(&kdh_1_priv_key_openssl);

    // println! ( "outerver={outerver:?} ");
}


#[test]
fn decode_b_9_kdh_key_token_tdea_openssl() {
    let b_9_pem = pem::parse(B_9_TWO_PASS_TOKEN).unwrap();
    let mut outer = openssl::cms::CmsContentInfo::from_der(b_9_pem.contents()).unwrap();

    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12)).unwrap();

    let mut inner_vec = Vec::<u8>::new();
    // Can't get this to work!! - best I can do is disable to signer cert chain verification!
    let verify_result = outer.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);
    
    assert! ( verify_result.is_ok());
    assert! ( inner_vec == pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents());

    // inner_vec is decoded in decode_b_2_2_3_1_...

    //println! ( "inner_vec={:?}", &inner_vec);
   
    //let content_info_inner = cms::content_info::ContentInfo { content: der::Any::new(der::Tag::Sequence, inner_vec).unwrap(), content_type: PKCS7_SIGNED_DATA_OID};
    //let content_info_inner = cms::content_info::ContentInfo { content: <der::Any as der::Decode>::from_der(&inner_vec).unwrap(), 
    //                                                                        content_type: der::oid::db::rfc5911::ID_ENVELOPED_DATA};

    //let _inner = openssl::cms::CmsContentInfo::from_der(&der::Encode::to_der(&content_info_inner).unwrap()).unwrap();

    // Enveloped data has encrypted content...
}


#[test]
fn decode_b_10_rebind_token() {
    let mut rebind_token = openssl::cms::CmsContentInfo::from_der(pem::parse(B_10_TR34_SAMPLE_RBT_CA_UNBIND_PEM).unwrap().contents()).unwrap();
    
    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12)).unwrap();

    let mut inner_vec = Vec::<u8>::new();
    // Can't get full chain verification to work!! - best I can do is disable to signer cert chain verification!
    let verify_result = rebind_token.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);

    assert! ( verify_result.is_ok());
    
    println! ( "inner={verify_result:?} ({}) {:?}", inner_vec.len(), inner_vec);

    // turn into full Content Info der - needs to have a sequence tag added as well as being wrapped in a content info struct
    let content_info_inner = cms::content_info::ContentInfo { content: der::Any::new(der::Tag::Sequence, inner_vec).unwrap(), content_type: ID_SIGNED_DATA};

    let _inner_as_content_info_openssl = openssl::cms::CmsContentInfo::from_der(&der::Encode::to_der(&content_info_inner).unwrap()).unwrap();

    // not sure what to do with this object now, it is not signed nor encrypted... but has a kdh identifier in the payload
   
}    


#[test]
fn decode_b_11_rbt_kdh_openssl() {
    let rebind_token_pem = pem::parse(B_11_SAMPLE_RBT_KDH_PEM).unwrap();
    let mut rebind_token = openssl::cms::CmsContentInfo::from_der(rebind_token_pem.contents()).unwrap();
   
    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12)).unwrap();

    let mut inner_vec = Vec::<u8>::new();
    // Can't get full chain verification to work!! - best I can do is disable to signer cert chain verification!
    let verify_result = rebind_token.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);

    assert! ( verify_result.is_ok());
  
    let content_info_inner = cms::content_info::ContentInfo { content: der::Any::new(der::Tag::Sequence, inner_vec).unwrap(), content_type: ID_SIGNED_DATA};

    // Import the inner structure into openssl, which is parsed and accepted.
    let mut _inner_as_content_info_openssl = openssl::cms::CmsContentInfo::from_der(&der::Encode::to_der(&content_info_inner).unwrap()).unwrap();
    //let mut pkcs7 = openssl::pkcs7::Pkcs7::from_der(&der::Encode::to_der(&content_info_inner).unwrap()).unwrap();

    // Not sure what else to do! Verify doesn't work because there are no signers... there are no functions exposed to retrieve the certs or the payload
    //let mut inner_vec2 = Vec::<u8>::new();
    //let verify_result2 = _inner_as_content_info_openssl.verify(None, None, None, Some(&mut inner_vec2), openssl::cms::CMSOptions::all());
    
    //assert! ( inner_vec == pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents());
    
}

#[test]
fn decode_b_12_openssl () {
    let _rng_token_pem = pem::parse(B_12_KRD_RANDOM_NUMBER_TOKEN).unwrap();
    
    // Not sure what to do with this option, openssl doesn't seem to have custom asn1 parsing functions exposed
}


#[test]
fn decode_b_13_openssl () {
    let rebind_token_pem = pem::parse(B_13_UBT_CA_UNBIND).unwrap();
    let mut rebind_token = openssl::cms::CmsContentInfo::from_der(rebind_token_pem.contents()).unwrap();
   
    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12)).unwrap();

    let mut inner_vec = Vec::<u8>::new();
    // Can't get full chain verification to work!! - best I can do is disable to signer cert chain verification!
    let verify_result = rebind_token.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);

    assert! ( verify_result.is_ok());

    let content = der::Any::new( der::Tag::Sequence, inner_vec).unwrap().decode_as::<keyblock::tr34::UbtCaUnbind>().unwrap();

    // Confirm that main payload has recognised ids
    assert! ( content.id_kdh == <cms::cert::IssuerAndSerialNumber as der::Decode>::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    assert! ( content.id_krd == <cms::cert::IssuerAndSerialNumber as der::Decode>::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
}

#[test]
fn decode_b_14_openssl () {
    
    let mut ubt_kdh_openssl = openssl::cms::CmsContentInfo::from_der(pem::parse(B_14_UBT_KDH_UNBIND).unwrap().contents()).unwrap();

    //let certs = get_certs_openssl();
    let mut certs = openssl::stack::Stack::new().unwrap();
    certs.push (get_cert_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12)).unwrap();

    let mut inner_vec = Vec::<u8>::new();
    let verify_result = ubt_kdh_openssl.verify(Some(&certs), None, None, Some(&mut inner_vec), openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY);

    assert! ( verify_result.is_ok());
    assert! ( inner_vec == pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents());

}