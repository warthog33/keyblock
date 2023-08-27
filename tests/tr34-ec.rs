use keyblock::{tr34::{TR34Signed, TR34Enveloped}, tr34openssl::{TR34DecryptOpenssl, TR34VerifyOpenssl}};


pub mod fromtr34;

fn get_kdh_1_pub_key_ec () -> openssl::pkey::PKey<openssl::pkey::Public>
{
    let cont = std::fs::read_to_string("openssltests/eckey.cert").unwrap();
    let x = openssl::x509::X509::from_pem(cont.as_bytes());
    return x.unwrap().public_key().unwrap();
}

fn get_kdh_1_cert_ec () -> openssl::x509::X509
{
    let cont = std::fs::read_to_string("openssltests/eckey.cert").unwrap();
    let x = openssl::x509::X509::from_pem(cont.as_bytes());
    return x.unwrap();
}
fn get_kdh_1_priv_key_ec() -> openssl::pkey::PKey<openssl::pkey::Private>
{
    let cont = std::fs::read_to_string("openssltests/eckey.pem").unwrap();
    let x = openssl::pkey::PKey::private_key_from_pem(cont.as_bytes());
    return x.unwrap();
}
fn get_kdh_issuer_and_serial() -> cms::cert::IssuerAndSerialNumber {
    let cert = <cms::cert::x509::Certificate as der::Decode>::from_der(&get_kdh_1_cert_ec().to_der().unwrap()).unwrap();
    return cms::cert::IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer, 
        serial_number: cert.tbs_certificate.serial_number};
}
fn get_krd_cert_ec () -> openssl::x509::X509
{
    let cont = std::fs::read_to_string("openssltests/eckeykrd.cert").unwrap();
    let x = openssl::x509::X509::from_pem(cont.as_bytes());
    return x.unwrap();
}
fn get_krd_pub_key_ec () -> openssl::pkey::PKey<openssl::pkey::Public>
{
    let cont = std::fs::read_to_string("openssltests/eckeykrd.cert").unwrap();
    let x = openssl::x509::X509::from_pem(cont.as_bytes());
    return x.unwrap().public_key().unwrap();
}

fn get_krd_priv_key_ec () -> openssl::pkey::PKey<openssl::pkey::Private>
{
    let cont = std::fs::read_to_string("openssltests/eckeykrd.pem").unwrap();
    let x = openssl::pkey::PKey::private_key_from_pem(cont.as_bytes());
    return x.unwrap();
}
fn get_krd_issuer_and_serial() -> cms::cert::IssuerAndSerialNumber {
    let cert = <cms::cert::x509::Certificate as der::Decode>::from_der(&get_krd_cert_ec().to_der().unwrap()).unwrap();
    return cms::cert::IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer, 
        serial_number: cert.tbs_certificate.serial_number};
}

#[test]
fn verify_ec_signed_and_encrypted_command_line () {
    let cont = std::fs::read_to_string("openssltests/signed_and_encrypted.pem").unwrap();
    let pem = pem::parse(cont).unwrap();

    let key_token = keyblock::tr34::TR34KeyToken::from_der(pem.contents()).unwrap();

    let verify_with_kdh_1 = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_kdh_issuer_and_serial()));
        return get_kdh_1_pub_key_ec();
    });
    assert! ( key_token.verify_signature(verify_with_kdh_1) == true);

    let decrypt_with_krd = TR34DecryptOpenssl::new(
        | id| {
            assert! ( id == &get_krd_issuer_and_serial());
            return get_krd_priv_key_ec();
        });
    let x = key_token.decrypt(decrypt_with_krd);

    assert! ( x.is_ok());
}


#[test]
fn create_encrypted_cms_blob () {

    // Create signed and encrypted message
    let message = "Hello World2".as_bytes(); 
    let mut certs = openssl::stack::Stack::<openssl::x509::X509>::new().unwrap();
    certs.push(get_krd_cert_ec()).unwrap();

    let encrypted = openssl::cms::CmsContentInfo::encrypt(&certs, message, 
        openssl::symm::Cipher::aes_256_cbc(), openssl::cms::CMSOptions::BINARY).unwrap();

    let signed = openssl::cms::CmsContentInfo::sign(
        Some(&get_kdh_1_cert_ec()), Some(&get_kdh_1_priv_key_ec()), 
        None, Some( &encrypted.to_der().unwrap() ), openssl::cms::CMSOptions::CMS_NOCERTS|openssl::cms::CMSOptions::BINARY);



    let key_token = keyblock::tr34::TR34KeyToken::from_der(&signed.unwrap().to_der().unwrap()).unwrap();

    
    let verify_kdh_1_openssl = TR34VerifyOpenssl::new ( 
            | id| {
                assert! ( id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_kdh_issuer_and_serial()));
                return get_kdh_1_pub_key_ec();
            }
        );

    assert! ( key_token.verify_signature(verify_kdh_1_openssl) == true);

    let qw = key_token.decrypt(TR34DecryptOpenssl::new ( 
        | id| {
        assert! ( id == &get_krd_issuer_and_serial());
        return get_krd_priv_key_ec();
    }));

    assert! ( &qw.unwrap() == message );

    
}


#[test]
fn build_and_verify() {
     
    let signer_using_kdh_openssl = keyblock::tr34openssl::TR34SignOpenssl::new ( 
        get_kdh_1_priv_key_ec(), get_kdh_issuer_and_serial() );
    let encrypt_using_krd_openssl = keyblock::tr34openssl::TR34EncryptOpenssl::new ( 
            get_krd_pub_key_ec(), get_krd_issuer_and_serial() );
        
    let built2 = keyblock::tr34::TR34KeyToken::build (
            &get_kdh_issuer_and_serial(), 
            "A02560000000".as_bytes(), 
            &[4u8;16], 
            Some(&[7u8;10]),
            encrypt_using_krd_openssl, 
            signer_using_kdh_openssl).unwrap();
    
    assert! ( built2.get_random_number().unwrap() == [7u8;10]);

    let verify_kdh_1_openssl = TR34VerifyOpenssl::new ( 
        | id| {
            let signer_issuer_and_serial_number = match id {
                cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(v) => v,
                _ => panic!("unhandled enum type"),
            };
            let kdrd_cert = <cms::cert::x509::Certificate as der::Decode>::from_der(&get_kdh_1_cert_ec().to_der().unwrap()).unwrap();
            assert! ( signer_issuer_and_serial_number.issuer == kdrd_cert.tbs_certificate.issuer);
            assert! ( signer_issuer_and_serial_number.serial_number == kdrd_cert.tbs_certificate.serial_number);

            return get_kdh_1_pub_key_ec();
        }
    );

    assert! ( built2.verify_signature(verify_kdh_1_openssl) == true);


    let decrypt_using_krd = TR34DecryptOpenssl::new ( 
        | id| {
        assert! ( id == &get_krd_issuer_and_serial());
        return get_krd_priv_key_ec();
    });

    let de = built2.decrypt(decrypt_using_krd);
    assert! ( de.is_ok() );

}

