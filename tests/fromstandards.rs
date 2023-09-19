
//use crate::keyblock::{self}; 
//use aead::KeyInit;
use hex_literal::hex;
use keyblock::*;

#[test]
///
/// Example from ANSI X9.143:2021 8.6 ECC Key Block Example with CT Certificate Chain Optional Block
/// 8.5 RSA Key Block Example with CT Optional Block
/// Same as ISO 20038:2023 - 8.4 ECC Key Block Example with CT Certificate Chain Optional Block
/// 
fn test_x9_143_2021_ecc_keyblock_8_6 () {
    //let mut key_block_factory_8 =  KeyBlockFactory::<aes::Aes256,  flavours::KeyBlockFlavor2<aes::Aes256>>::new(&hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6").into());
    let mut key_block_factory =  KeyBlockDAes256::new(&hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6").into());
    
    key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("4142434445")); return 1;});
        

    let cert1 =  "02\
                        00\
                        02F0\
                        MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVB\
                        AMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIxMDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZX\
                        JjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM4\
                        9AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeSstGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/\
                        gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDV\
                        R0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOWF+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MD\
                        kwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TYW1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwI\
                        DSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDo\
                        TkvKYQ==\
                        00\
                        02C4\
                        MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EAwIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVB\
                        AMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMjEwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscG\
                        hhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji\
                        +3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePHxwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMB\
                        Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwF\
                        oAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leG\
                        FtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZ\
                        THxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2LlUqpN/069y5s=";

    let mut key_block =  KeyBlockFields::new();
    key_block
        //.set_version( KeyBlockVersion('D'))
        .set_secret (&hex!("307702010104202d493257a45b34c11b6526a03db4d8ae16ee87a0c16bdf1be23c2dd8b164a2d3a00a06082a8648c
                            e3d030107a14403420004423f48bac7e9f21303dcba6370677aea13ff9f841d27a9671098792b2d1a5976b15be648
                            36565926cdea587915bff36a0ac38e343f819b5620e4dfdb02f5bd21"))
        //.set_usage ( KeyUsage::from("S0"))
        .set_usage ( KeyUsage("S0"))
        .set_algorithm (  KeyAlgorithm::ECC)
        .set_keyversion("00")
        .set_mode (  KeyMode::S_SIGNATURE_ONLY)
        .add_optional_block("CT", cert1)
        .add_optional_block("KP","012331550BC9")
        .add_optional_block("TS", "20200818004100Z")
        .set_exportability( KeyExportability::N_NON_EXPORTABLE);
        
    let wrapped_key8 = key_block_factory.wrap (&mut key_block).unwrap();
    let expected_result8 = "D1840S0ES00N0400CT000405CC020002F0MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1U\
                                    ECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVBAMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIx\
                                    MDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZXJjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA\
                                    1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeS\
                                    stGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4A\
                                    wEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOW\
                                    F+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TY\
                                    W1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR\
                                    4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDoTkvKYQ==0002C4MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EA\
                                    wIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVBAMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMj\
                                    EwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIEN\
                                    BMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji+3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePH\
                                    xwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVH\
                                    Q4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwFoAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPT\
                                    A7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leGFtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0\
                                    EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZTHxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2Ll\
                                    UqpN/069y5s=KP10012331550BC9TS1320200818004100ZPB11000000000000023806274FDDE312047FA37117320D\
                                    914DD1CF20705A140E39FF88DF107110F26DDFDB20AD909B4C67987C76907C6518B63C8BB7969A52BA3EE6218C9B2\
                                    9F02C243D23E5DF5F87D4CBC0E587DD619F1F228D3F605316DC39DDD6E9D13BAB633D13A97BE7EF67DBEECADA32FA\
                                    968E57BDF87EE5AEAA47CDCF427154AE66508B99EF6186011C7BE905F875B24C5D05EA14E";

    assert_eq!( &wrapped_key8, expected_result8);

    let unwrapped_block = key_block_factory.unwrap(&wrapped_key8).unwrap();

    assert! ( unwrapped_block.get_usage() == KeyUsage("S0"));
    assert! ( unwrapped_block.get_certificate().unwrap() == CertificateOption::Chain ( vec![
        CertificateOption::X509(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert1[8..760]).unwrap()),
        CertificateOption::X509(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert1[766..]).unwrap())]));
    assert! ( unwrapped_block.get_optional_block_by_id(&OptionalKeyBlockId::KP_KEY_CHECK_VALUE).unwrap() == "012331550BC9");
    assert! ( unwrapped_block.get_key_check_value().unwrap() == KeyCheckValue::CmacKCV(hex!("2331550BC9").to_vec()));
    //assert! ( unwrapped_block.get_optional_block_by_id(&OptionalKeyBlockId::TS_TIME_STAMP).unwrap() == "20200818004100Z");
    assert! ( unwrapped_block.get_time_stamp().unwrap() == chrono::NaiveDateTime::parse_from_str("20200818004100Z", "%Y%m%d%H%M%SZ").unwrap().and_utc())

}

///
/// Example from ANSI X9.143:2021 8.5 RSA Key Block Example with CT Optional Block
/// Same as ISO 20038:20038 8.3 RSA Key Block Example with CT Optional Block

#[test]
fn test_x9_143_2021_rsa_keyblock_8_5 ()  
{
    // Example for RSA
    //let mut key_block_factory =  KeyBloc kFactory::<aes::Aes128,  flavours::KeyBlockFlavor2<aes::Aes128>>::new(&hex!("FA36E44278DB3AB5 F298F9F7DA8F1F88").into());
    let mut key_block_factory =  KeyBlockDAes128::new(&hex!("FA36E44278DB3AB5 F298F9F7DA8F1F88").into());
    
    key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("414243444546")); return 1;});
        
    let cert = "00MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQB\
                        gNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcm\
                        NoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhki\
                        G9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8\
                        YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87\
                        /rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7\
                        nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQI\
                        DAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR8\
                        37QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwh\
                        i5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6J\
                        usIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9ao\
                        VA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC\
                        8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA\
                        /cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7Z";
                 
    let mut key_block =  KeyBlockFields::new();
    key_block
        //.set_version( KeyBlockVersion::D_AES_CBC)
        //.set_kbpk (&hex!("FA36E44278DB3AB5 F298F9F7DA8F1F88").into(),  KPBKAlgorithm::Aes128)
        //.set_kbpk (&hex!("FA36E44278DB3AB5 F298F9F7DA8F1F88").into() )
        .set_secret (&hex!("308204a40201000282010100d6c460fb012e8dedf2d78574b451e9bf1c69
            63f7f2ae5741d2745cb410e7e00be405fc89b832c6e7dbea9065d577c27c
            610770107649ad5abeec1f2b8ed33a3cca321ffed00196400bbb70ef8d0f
            e1c7de9f522bcae6d956f895f50529fa01d3a1e9597ebd6b7c8b2e106873
            a3a521c18ef49244bceffad81c255ab616448cc9af50811da738343d9dbe
            1de83a0f7e4e43bd08fa7a7e06c1107fbd59afe77688aa95184779d25f2d
            6e7e16dc0e2b3b250444f4da002c12f6bbdd17b9e5993a92239c9b37a966
            9b7edaef587bee7e8ce7869ac362a4258595a3ed6cb544f2155b2ffd806c
            f5aca56c11d0398aa9fd4dad0744f1339f10606cf2696bcda9b173390203
            01000102820101009a6193ed1ace624bf7d2a1266130b8bc1e2a4c284214
            bcb89e15f345a519695e62cd42d9a4c52b62241d9b2af8a61bf1d8b5c602
            af650aee3e6bf184182912a5fc1ac8111d68e69ea75058407ac03de6b4cb
            060060dc4cc34df24dad269d868ea0c6e3044e1963ef906f4f06414e44d3
            a4757e67570192e9a261dfb12094aa36476582272edab0f56f816d9fa695
            80b3ab053237135bd1dddb42af77e11e1629f5a11b22c5e3e2db3e8767a9
            0b94414898dccbb47efe619f0620ac29c389fb464ce9c5e243963e13b6da
            38efae1330aefb54c0d5e2e59b6d7fbe4b3a22ee483f74e74d4a4a25978c
            65f4ac5829c34260930c85ecea1fb24db52a438d4eb2cf6102818100ed00
            3deeb8013af4e4ebe172fe474b23fe20128805840c2d277e3e308d5b4452
            7f1ed33c07af350d5b22b27e082cd101dd2de54dc8df8f91d4ba5768eb9e
            c5f27db5d358ea5e0dee08a535677cb3f765789c9dae56b7421b9e54525e
            f928ab2885bf098e837999ad0ca3ca6ac642ea9ad1331856b0ccee5df01f
            ed1b2f63c3a502818100e7fbda0a71c926dd51f037206d901a297554a39b
            bc9239794421f1f54d29766e50e016ca5701bda79aec543f5066b3730e05
            3ea4b5872d25c29673ca8457b07390d11af23f2247a1133fc2522b96cb02
            da77d927fee6661066058d1a4d85fe3c1d3418542f24b3982b4ddfb4192e
            512eda1baaaa59955b50945dd083e26e4d0502818002d4e0e88c3c3f8713
            8119f574c2474c8bc9b84ef5b9e92754f4762bc05499d15e8170c6a3d4dd
            0e66cb5854972669ecdac6a499b44faf786f91366023888716e9979589d7
            6afe419ccad4838302e76ec7ed1f1929221161211822cfcdac45b73b39d8
            1462cfbe1d4a2c5ecbbdc8a8e2e6a2f4a47c82464acb06a69f8f86629d02
            81804e98a99af84a2a7cb992255b3b43a3598083189b5f1c3b94b65cb9d9
            5e373a04ce29de0ed7c3a339f1e737f3eb8da026cf0d3fd81618a25734c2
            3ca0d48dd11e9666023728e4b857fe698fb0bf4beba41fd8931e55e2419a
            34b694c3e0981136d4be1db007f8eb5016fbdf5ae95d23ec37c13fe54f4c
            a70f79f4fefc6feee6f1028181008321c2f1e8914c0ae09c418acfebb8a7
            b86a1e7144182f5145fba90af104de3bc7604d86a831ac2f38da356c99bc
            60bea80e26ec8b7faf8bb84a8661ef564bdc65da0519f5e3ce81ff491cc7
            1da0813960048b225e61c56684d3ce01ae28a212c9acce946e2aab80add5
            1b00093029c5d52e9af6c8a3eb861641b00e23636a68"))
        .set_usage (  KeyUsage::S0_ASYMMETRIC_KEY_PAIR_FOR_DIGITAL_SIGNATURE)
        .set_algorithm (  KeyAlgorithm::RSA)
        .set_keyversion("00")
        .set_mode (  KeyMode::S_SIGNATURE_ONLY)
        .add_optional_block("CT", cert)
        .add_optional_block("KP","01D77F007724")
        .add_optional_block("TS", "20200818221218Z")
        .set_exportability( KeyExportability::N_NON_EXPORTABLE);
        
    let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
    let expected_result = "D3776S0RS00N0400CT0004050000MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UEC\
                                    gwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME\
                                    8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAo\
                                    xMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRc\
                                    tBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHTo\
                                    elZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l\
                                    8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYq\
                                    p/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG\
                                    CCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQ\
                                    QbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA\
                                    0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe\
                                    4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX\
                                    /bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrT\
                                    Nahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7ZKP1001\
                                    D77F007724TS1320200818221218ZPB0D000000000A7C9F8FA80A4BA3555CA071503CE1A6133649BB18A5A9130492\
                                    172CA4E7360C060379738A28503230BDB04EED4E9B209643867613F5090A0E0392C21EB74747795B397315AB5D1F4\
                                    9A33693533E73AC0BEDA172FF530BE986F5EC1C25F481F05A69DF8B33624E621AF35FFAEC06C2005F37872923EEBF\
                                    F38182FB290BFBA2A9FF88AD36278625868FA38A0DC9A53E0202C4D1DEF3B9DACFD249DA85DE3CCF92A8E6C0F8CDF\
                                    8DE5FD17331BE5D580F210CE4EA1B01F1A0BFD6EFF410A71661234AD363D4B60885F00358729900FF95D7C87D3DE6\
                                    FB4C83B24C8C7BB5A2E3763E9CBA50A0E3A8C1AF908699952BCB6B038FEA9D13FDE08801DC0573E55B842219DBF6D\
                                    5DA5F028C73793AA718D01DE93D85AE06E7E08DC94ADB4EAA51B6DDAEA3750D0B77467D2982AC96F3EB28889715CB\
                                    B81C71E97A60E58D44977C1D8220A422E98E17ACEBF72A8A18D4E7FC1695F442860E6063E8BB6BFF2184F77E635C2\
                                    F5A02DADE4897A3B1374145C3AD6DF06C0D556F5DE9454CF40C4FC8922DFE245F868E668F1DA5BE0079F9D1D1861C\
                                    A4B5E6C782F296098C07CB43784D64D8B8557410E5BAFF59333A791FF030EB0661C0590A665B50A3A727217100C45\
                                    50B2AD9C96C658D6731C09B55DFAE665952E2913A4E090F45DCEB45D6683C3FC15E3A4CA49C7F2E684B3580DB47A5\
                                    3E5BDB228FAD250C584548D5DEDBB45004B5E0E75C37ACE8167CC6D9574A74876718D2F42996622B8EC0B895FF7A6\
                                    739E4CF64B7F03FABDFBC0A565CB3455736D2B4E2B64D6EC175A569F78DB7ACB331B00804279677F4BFD0C35CBF0A\
                                    38D646AA9051961123E16075A06B6331A9A30601AF3FD6A89AD9924AE1D9EC2FE0FF3B3A1B3E3E13D09B08B80D91F\
                                    9EDF51B2E6D8DABD0FEB6C5C1085A11FA6A98CE8CC09E36C8A24D981A74E140EF30912E8CDBBE2A0CBD52B40C72D1\
                                    958F4BB2F49BCBABBD80116FEF21BC91D219EEAEDA4DC11692C624B0836C3137A3BEE4549DEAB750A9DD5ACA7E3F8\
                                    22084783CDFEEB765EBEB9E3CFF053E8B8D5A1F1854B8AFF6325F10B81C7627D0DA895B1D19FEEF0AE3F3E138E87C\
                                    4ADDF0BA53CA40ED0D1452044600FF4838D710F6D03474C317AC306DD7DA169B6C918E999E3A50DA1A34DDFCA3899\
                                    F4469B9E969C0BD144F04B2621AB9E9E18455D526844155309565DA9D1726CD3A7ACC5FEDEF30DED078547CED31CE\
                                    F84A31A810FA966F303CB950ACC324AE54BFAB9A04FAD93C38CD6239D7FAD2C59A9B71171F5676DA8ED3A3FFB5287\
                                    DF141C1F5CE972CA26857AD3039B82B625960A7859F19EF0E94F8C4680A33189870942139DDFA64D5095FA46EB490\
                                    85DB99EFC9C6A3F3A290DB9592F8B76B017113F7D1FEFE52E70FE26574467257CFEEA6D3F2BBD1BAEDDDCE3468827\
                                    568A78536DE78E7AC872247BDB120A55DDE16A3D0CFBB7D097AD7AD0FA2671390D8D532A3915F5B3163FF1EE23553\
                                    D83A1109980859C420F754BC74ECD1449B9A60EA252D3F035D715BCBD491485261C51238926E290BD7F0617E90BD6\
                                    AB8B46443B05C28D61F8BB897417926623AF91B499C661629795165EF56460850F1D4F9CE199C2B9E21F1884A4D14\
                                    644DAE5FB963B880EC2FFF70021772D524289D068A24F0283C42F0B4779996D2CF60EE6E45C364E2547DB92361B3D\
                                    BCEDBAA96B9F10A1AAA1AB23CDE1B75F3299D4544787A07F6A9F7127";

    assert_eq!( &wrapped_key, expected_result);

    let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
    assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
    assert_eq! ( recovered_block.get_version(), key_block.get_version());
    assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
    assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
    assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), key_block.get_optional_block_by_index(0).unwrap());
    assert_eq! ( recovered_block.get_optional_block_by_index(1).unwrap(), key_block.get_optional_block_by_index(1).unwrap());
    assert_eq! ( recovered_block.get_optional_block_by_index(2).unwrap(), key_block.get_optional_block_by_index(2).unwrap());

    //assert_eq! ( recovered_block.get_optional_block_by_id(&OptionalKeyBlockId::KP_KEY_CHECK_VALUE).unwrap(), "01D77F007724");
    assert_eq! ( recovered_block.get_key_check_value().unwrap(), KeyCheckValue::CmacKCV(hex!("D77F007724").to_vec()));
    //assert_eq! ( recovered_block.get_optional_block_by_id(&OptionalKeyBlockId::TS_TIME_STAMP).unwrap(), "20200818221218Z");
    assert! ( recovered_block.get_time_stamp().unwrap() == chrono::NaiveDateTime::parse_from_str("20200818221218Z", "%Y%m%d%H%M%SZ").unwrap().and_utc());
    //assert_eq! ( recovered_block.get_optional_block_by_id(&OptionalKeyBlockId::CT_PUBLIC_KEY_CERTIFICATE).unwrap(), cert);
    assert_eq! ( recovered_block.get_certificate().unwrap(), CertificateOption::X509(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert[2..]).unwrap()));
        //cert[2..].as_bytes().to_vec()));

    //.add_optional_block("CT", cert)
    
}

///
#[test]
fn test_x9_143_2021_aes_keyblock_8_1 () 
{
    // Example from X9.143:2021, 8.1 Key Block Example
    // Same from X9.143:2022, 8.1 Key Block Example
    // Same as ISO 20038:2017, Sample B1
    // Same as ISO 20038:2023, 8.1 AES Key Block Example
    let mut key_block_factory =  KeyBlockDAes256::new(&hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6").into());
    
    key_block_factory.set_rng (| buf: &mut [u8]| -> i32 { buf.copy_from_slice( &hex!("1A87BBFA2CFe78D383e5f4c6aa83473c 1c2965473CE206bb855b01533782")); return 1; } );
    
   
    let mut key_block =  KeyBlockFields::new();
    key_block
        .set_usage( KeyUsage::P0_PIN_ENCRYPTION_KEY)
        .set_algorithm (  KeyAlgorithm::AES)
        .set_mode(  KeyMode::E_ENCRYPT_WRAP_ONLY)
        .set_exportability (  KeyExportability::E_EXPORTABLE)
        .set_context (  KeyContext::STORAGE_OR_EXCHANGE_0)
        .set_secret ( &hex!("3F419E1CB7079442 AA37474C2EFBF8B8"));
        
    let wrapped_key = key_block_factory.wrap ( &mut key_block ).unwrap();
    let expected_result = concat!("D0144P0AE00E0000","2C77FA3F4A553BED","6E88AE5C172A4166","E3D4ACA8E2AC71C1","58A476FAC12C13C3","829DE55D3AB54C48","F4C4FEF7AC75E90F","C47F1B77E7B19A73","ED46E64410082557");
    assert_eq!( &wrapped_key, expected_result);

    let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
    assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
    assert_eq! ( recovered_block.get_version(), key_block.get_version());
    assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
    assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
    assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    
}

#[test]
fn test_x9_143_2021_aes_keyblock_8_2 () 
{
    // Second example from ANSI X9.143:2021, 8.2 AES Key Block with Optional Blocks
    // Same as ISO 20038:2023 8.2 Key Block with Optional Blocks
    let mut key_block_factory =  KeyBlockDAes256::new(&hex!("E38331FBACE33F0B 8694ABA5DC611CA2 0831949FEB898810 2147291578F704E1").into());
    
    key_block_factory.set_rng (|buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("1a87bbfa2cfe78d383e5f4c6aa83")); return 1;});
        
    let mut key_block =  KeyBlockFields::new();
    key_block
        .set_secret ( &hex!("8C326037F8910BBF DBC267E5101DFBF9 480433028D5E67B3 4673440F8ACEC972"))
        .set_usage (  KeyUsage::C0_CARD_VERIFICATION_KEY)
        .set_exportability( KeyExportability::N_NON_EXPORTABLE)
        .set_mode( KeyMode::V_VERIFY_ONLY)
        .set_keyversion("A1")
        .set_algorithm( KeyAlgorithm::AES)
        .add_optional_block("KS", "VM9A")
        .add_optional_block("TS", "2018-06-18T20:42:39.22");

    let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
    let expected_result = concat!("D0192C0AVA1N0300KS08VM9ATS1A2018-06-18T20:42:39.22PB0E0000000000","5FDAFA00A1E84F599C2EB51A1F7A767D5E42314F0E84A3FC1A7B84C1DE81114659E6306AD544208F68F1","5602BD3E12DA","0C7F9FC551F1C8E6385FAFC1F7B499F5");
    
    assert_eq!( &wrapped_key, expected_result);

    let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
    assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
    assert_eq! ( recovered_block.get_version(), key_block.get_version());
    assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
    assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
    assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), key_block.get_optional_block_by_index(0).unwrap());
    assert_eq! ( recovered_block.get_optional_block_by_index(1).unwrap(), key_block.get_optional_block_by_index(1).unwrap());
    
    assert! ( recovered_block.get_time_stamp().unwrap() == chrono::NaiveDateTime::parse_from_str("2018-06-18T20:42:39.22", "%Y-%m-%dT%H:%M:%S%.f").unwrap().and_utc());
    
    assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), ("KS", "VM9A"));
}



    
    //////////////////////////////////////////////////////
    /// 
    /// TDES key block examples from X9.143
    /// 
    /// 
    #[test]
    fn test_x9_143_2021_example_1a() {
        // Third example from ANSI X9.143:2021 8.3.2.1 Example 1a: Using Key Variant Binding Method
        // Exactly the same as ANSI X9.143:2022 8.3.2.1 Example 1a: Using Key Variant Binding Method
        // Seems to use KBPK directly KBEK, not sure how MAC is calculated!

        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor1<des::TdesEde2>>::new(&hex!("89E88CF7931444F3 34BD7547FC3F380C").into());
        let mut key_block_factory = KeyBlockATdes2::new ( &hex!("89E88CF7931444F3 34BD7547FC3F380C" ).into());
    
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("249f30A2B39A7D6B 720DF563BB07")); return 1;});
            

        let mut key_block = KeyBlockFields::new();
        key_block
            .set_secret (&hex!("F039121BEC83D26B 169BDCD5B22AAF8F"))
            .set_usage ( KeyUsage::P0_PIN_ENCRYPTION_KEY)
            .set_algorithm ( KeyAlgorithm::TDES)
            .set_mode ( KeyMode::E_ENCRYPT_WRAP_ONLY)
            .set_exportability(KeyExportability::E_EXPORTABLE);
            
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        
        // The value below is from ANSI X9_143:2021, but it seems to have a mistake. It includes the key length obfuscation padding but 
        // messes up the overall length and key encrytion, ignore for the moment.
        //let expected_result = concat!("A0072P0TE00E0000", "A8974C06DBFD58D197101A28DEC1A6C7C23F00A3B18EC6D538DE4A5B5F49A542", "D61A8A8B");
        // This is the value as correct as far as the author can see.
        let expected_result = "A0088P0TE00E00007DD4DD9566DC0E2F956DCAC0FDE915318973835AEC2D731C2AD2E7B6151EB4CA6E3552DB";
        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        
    }

   


    #[test]
    fn test_x9_143_2022_example_1b() {
     // ANSI X9.143:2022 8.3.2.2 Example 1b: Using Key Derivation Binding Method
     // (THere is a similar example in X9.143:2021, but it produces a different result - believe this is the correct answer)
        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor2<des::TdesEde2>>::new(&hex!("DD7515F2BFC17F85 CE48F3CA25CB21F6").into());
        let mut key_block_factory = KeyBlockBTdes2::new ( &hex!("DD7515F2BFC17F85 CE48F3CA25CB21F6" ).into());
            
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("7CB920D261E9F3AA 1C2965473CE2")); return 1;});

        let mut key_block = KeyBlockFields::new();
        key_block
            //.set_version(KeyBlockVersion::B_TDES_DERIVATION)
            //.set_kbpk (&hex!("DD7515F2BFC17F85 CE48F3CA25CB21F6").into(),  KPBKAlgorithm::TDES_2_KEY)
            .set_secret (&hex!("3F419E1CB7079442 AA37474C2EFBF8B8"))
            .set_usage ( KeyUsage::P0_PIN_ENCRYPTION_KEY)
            .set_algorithm ( KeyAlgorithm::TDES)
            .set_mode ( KeyMode::E_ENCRYPT_WRAP_ONLY)
            .set_exportability(KeyExportability::E_EXPORTABLE);
        
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        let expected_result = concat!("B0096P0TE00E0000D7ED9E189BC6F715125B265B149DF8FE218A396785608923D6197378386A3759308FC49A2AA891BA");
   
        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());

    }

    /// ANSI X9.143:2022 8.4.1 Example 2a: Using Key Variant Binding Method
    /// Mistake in length field.... version field ('A' vs 'C') and key usage 0x42 vs 0x4b ?
    #[test]
    fn test_x9_143_2022_example_2a() {

        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor1<des::TdesEde2>>::new(&hex!("B8ED59E0A279A295 E9F5ED7944FD06B9").into());
        let mut key_block_factory = KeyBlockCTdes2::new ( &hex!("B8ED59E0A279A295 E9F5ED7944FD06B9" ).into());

        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("7CB920D261E9F3AA 8546A8ED98D1")); return 1;});

        let mut key_block = KeyBlockFields::new();
            key_block
            //.set_version(KeyBlockVersion::C_TDES_BINDING)
            //.set_version( KeyBlockVersion::A_KEY_VARIANT)
            //.set_kbpk (&hex!("B8ED59E0A279A295 E9F5ED7944FD06B9").into(),  KPBKAlgorithm::TDES_2_KEY)
            .set_secret (&hex!("EDB380DD340BC2620247D445F5B8D678"))
            .set_usage ( KeyUsage::B0_BDK)
            //.set_usage (  KeyUsage('K', '0'))
            .set_algorithm ( KeyAlgorithm::TDES)
            .set_keyversion("12")
            .set_mode ( KeyMode::X_KEY_DERIVATION_KEY)
            .add_optional_block("KS", "00604B120F9292800000")
            .set_exportability(KeyExportability::S_EXPORTABLE_UNDER_ANY_KEY);
            
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        //let expected_result5 = concat!("C0096B0TX12S0100KS1800604B120F9292800000","42B758A2400AB598","AE37782823DAF0BA","4BDB0DAFF3491534","5CA169AE1F976A42","9EB139E5"); // this is what is in the standard
        let expected_result = concat!("C0112B0TX12S0100KS1800604B120F9292800000","42B758A2400AB598","AE37782823DAF0BA","4BDB0DAFF3491534","5CA169AE1F976A42","9EB139E5"); // this is what matches
    
        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), key_block.get_optional_block_by_index(0).unwrap());
    }


    /// ANSI X9.143:2022 8.4.2 Example 2b: Using Key Derivation Binding Method
    #[test]
    fn test_x9_143_2022_example_2b() {
    //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor2<des::TdesEde2>>::new(&hex!("1D22BF32387C600A D97F9B97A51311AC").into());
    let mut key_block_factory = KeyBlockBTdes2::new ( &hex!("1D22BF32387C600A D97F9B97A51311AC" ).into());

    key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("7CB920D261E9F3AA 30111D18CC4C")); return 1;});

    let mut key_block = KeyBlockFields::new();
    key_block
        //.set_version(KeyBlockVersion::B_TDES_DERIVATION)
        //.set_kbpk (&hex!("1D22BF32387C600A D97F9B97A51311AC").into(),  KPBKAlgorithm::TDES_2_KEY)
        .set_secret (&hex!("E8BC63E5479455E2 6577F715D587FE68"))
        .set_usage ( KeyUsage::B0_BDK)
        .set_algorithm ( KeyAlgorithm::TDES)
        .set_keyversion("12")
        .set_mode ( KeyMode::X_KEY_DERIVATION_KEY)
        
        .add_optional_block("KS", "00604B120F9292800000")
        .set_exportability(KeyExportability::S_EXPORTABLE_UNDER_ANY_KEY);
        
    let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
    let expected_result = concat!("B0120B0TX12S0100KS1800604B120F9292800000","15CEB14B76D551F2","1EC43A75390FA118","A98C6CB049E3B9E8","64A5F4A8B9A5108A","6DB5635C95B042D7");

        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), key_block.get_optional_block_by_index(0).unwrap());

    }




    //////////////////////////////////////////////////////////////////
    ///
    /// Samples extracted from ASC TR-31:2018
    /// None have key length obfuscation
    /// 
    /// 
    /// 
    /// 
    /// 
     #[test]
    fn test_tr_31_example_1a() {
        // ASC TR-31:2018 Example 1a: Using Key Variant Binding Method
        
        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor1<des::TdesEde2>>::new(&hex!("89E88CF7931444F3 34BD7547FC3F380C").into());
        let mut key_block_factory =  KeyBlockATdes2::new ( &hex!("89E88CF7931444F3 34BD7547FC3F380C" ).into());

        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("720DF563BB07")); return 1;});
        key_block_factory.set_key_length_obfuscation(false);
            
            
        let mut key_block =  KeyBlockFields::new();
        key_block
            //.set_version( KeyBlockVersion::A_KEY_VARIANT)
            //.set_kbpk (&hex!("89E88CF7931444F3 34BD7547FC3F380C").into())
            .set_secret (&hex!("F039121BEC83D26B 169BDCD5B22AAF8F"))
            .set_usage (  KeyUsage::P0_PIN_ENCRYPTION_KEY)
            .set_algorithm (  KeyAlgorithm::TDES)
            .set_mode (  KeyMode::E_ENCRYPT_WRAP_ONLY)
            .set_exportability( KeyExportability::E_EXPORTABLE);
            
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        let expected_result = concat!("A0072P0T","E00E0000","F5161ED9","02807AF2","6F1D6226","3644BD24","192FDB31","93C73030","1CEE8701");
        
        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    }

    #[test]
    fn test_tr_31_example_1b() {
        // Example from ASC X9 TR-31:2018 A.7.2.2 Example 1b: Using Key Variant Binding Method ???
        
        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor2<des::TdesEde2>>::new(&hex!("DD7515F2BFC17F85 CE48F3CA25CB21F6").into());
        let mut key_block_factory =  KeyBlockBTdes2::new ( &hex!("DD7515F2BFC17F85 CE48F3CA25CB21F6" ).into());
        
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("1C2965473CE2")); return 1;});
        key_block_factory.set_key_length_obfuscation(false);
        
        let mut key_block =  KeyBlockFields::new();
        key_block
            //.set_version( KeyBlockVersion::B_TDES_DERIVATION)
            .set_secret (&hex!("3F419E1CB7079442 AA37474C2EFBF8B8"))
            .set_usage (  KeyUsage::P0_PIN_ENCRYPTION_KEY)
            .set_algorithm (  KeyAlgorithm::TDES)
            .set_mode (  KeyMode::E_ENCRYPT_WRAP_ONLY)
            .set_exportability( KeyExportability::E_EXPORTABLE);
            
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        let expected_result = concat!("B0080P0T","E00E0000","94B42007","9CC80BA3","461F86FE","26EFC4A3","B8E4FA4C","5F534117","6EED7B72","7B8A248E");
        assert_eq!( &wrapped_key, expected_result);


        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    }

    /// ASC TR-31:2018 A.7.3.1 Example 2a: Using Key Variant Binding Method
    #[test]
    fn test_tr_31_example_2a () {

        //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor1<des::TdesEde2>>::new(&hex!("B8ED59E0A279A295 E9F5ED7944FD06B9").into());
        let mut key_block_factory =  KeyBlockCTdes2::new ( &hex!("B8ED59E0A279A295 E9F5ED7944FD06B9" ).into());

        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("8546A8ED98D1")); return 1;});
        key_block_factory.set_key_length_obfuscation(false);
        
        let mut key_block =  KeyBlockFields::new();
        key_block
        //.set_version( KeyBlockVersion::C_TDES_BINDING  )
        .set_secret (&hex!("EDB380DD340BC2620247D445F5B8D678"))
        .set_usage (  KeyUsage::B0_BDK)
        .set_algorithm (  KeyAlgorithm::TDES)
        .set_keyversion("12")
        .set_mode (  KeyMode::X_KEY_DERIVATION_KEY)
        .add_optional_block("KS", "00604B120F9292800000")
        .set_exportability( KeyExportability::S_EXPORTABLE_UNDER_ANY_KEY);
        
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        let expected_result = concat!("C0096B0TX12S0100KS1800604B120F9292800000","BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D6098901","5D02155C" );
        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), key_block.get_optional_block_by_index(0).unwrap());

    }


    /// ASC TR-31:2018 A.7.3.2 Example 2b: Using Key Derivation Binding Method
    #[test]
    fn test_tr_31_example_2b () {

      //let mut key_block_factory =  KeyBlockFactory::<des::TdesEde2,  flavours::KeyBlockFlavor2<des::TdesEde2>>::new(&hex!("1D22BF32387C600A D97F9B97A51311AC").into());
        let mut key_block_factory =  KeyBlockBTdes2::new ( &hex!("1D22BF32387C600A D97F9B97A51311AC" ).into());
        
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("30111D18CC4C")); return 1;});
        key_block_factory.set_key_length_obfuscation(false);
        

        let mut key_block =  KeyBlockFields::new();
        key_block
        //.set_version( KeyBlockVersion::B_TDES_DERIVATION)
        .set_secret (&hex!("E8BC63E5479455E2 6577F715D587FE68"))
        .set_usage (  KeyUsage::B0_BDK)
        .set_algorithm (  KeyAlgorithm::TDES)
        .set_keyversion("12")
        .set_mode (  KeyMode::X_KEY_DERIVATION_KEY)
        .add_optional_block("KS", "00604B120F9292800000")
        .set_exportability( KeyExportability::S_EXPORTABLE_UNDER_ANY_KEY);
        
        let wrapped_key = key_block_factory.wrap (&mut key_block).unwrap();
        let expected_result5 = concat!("B0104B0TX12S0100KS1800604B120F9292800000","BB68BE8680A400D9191AD4ECE45B6E6C0D21C4738A52190E","248719E24B433627" );
        assert_eq!( &wrapped_key, expected_result5);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        assert_eq! ( recovered_block.get_optional_block_by_index(0).unwrap(), ("KS", "00604B120F9292800000"));

    }


    /// ASC TR-31:2018 Example 3: AES Key Block without Optional Blocks
    #[test]
    fn test_tr_31_example_3 () 
    {
        // Example from X9.143:2021, 8.1 Key Block Example
        //let mut key_block_factory =  KeyBlockFactory::<aes::Aes256,  flavours::KeyBlockFlavor2<aes::Aes256>>::new(&hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6").into());
        let mut key_block_factory =  KeyBlockDAes256::new ( &hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6" ).into());
      
        key_block_factory.set_rng (| buf: &mut [u8]| -> i32 { buf.copy_from_slice( &hex!("1c2965473CE206bb855b01533782")); return 1; } );
        key_block_factory.set_key_length_obfuscation(false);
        
        let mut key_block =  KeyBlockFields::new();
        key_block
            //.set_version( KeyBlockVersion::D_AES_CBC)
            .set_usage( KeyUsage::P0_PIN_ENCRYPTION_KEY)
            .set_algorithm (  KeyAlgorithm::AES)
            .set_mode(  KeyMode::E_ENCRYPT_WRAP_ONLY)
            .set_exportability (  KeyExportability::E_EXPORTABLE)
            .set_context (  KeyContext::STORAGE_OR_EXCHANGE_0)
            .set_secret ( &hex!("3F419E1CB7079442 AA37474C2EFBF8B8"));
            
        let wrapped_key = key_block_factory.wrap ( &mut key_block ).unwrap();
        let expected_result = concat!("D0112P0AE00E0000","B82679114F470F54","0165EDFBF7E250FC","EA43F810D215F8D2","07E2E417C07156A2","7E8E31DA05F74255","09593D03A457DC34");

        assert_eq!( &wrapped_key, expected_result);

        let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());

    }
    

/// ASC TR-31:2018 Example 3: AES Key Block without Optional Blocks
#[test]
fn test_x9_143_2021_examples_from_options () 
{
    // Example from X9.143:2021, 6.3....
    let mut key_block_factory =  KeyBlockDAes256::new ( &hex!("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6" ).into());
  
    key_block_factory.set_rng (| buf: &mut [u8]| -> i32 { buf.copy_from_slice( &hex!("1c2965473CE206bb855b01533782")); return 1; } );
    key_block_factory.set_key_length_obfuscation(false);
    
    let mut key_block =  KeyBlockFields::new();
    key_block
        //.set_version( KeyBlockVersion::D_AES_CBC)
        .set_usage( KeyUsage::P0_PIN_ENCRYPTION_KEY)
        .set_algorithm (  KeyAlgorithm::AES)
        .set_mode(  KeyMode::E_ENCRYPT_WRAP_ONLY)
        .set_exportability (  KeyExportability::E_EXPORTABLE)
        .set_context (  KeyContext::STORAGE_OR_EXCHANGE_0)
        .set_secret ( &hex!("3F419E1CB7079442 AA37474C2EFBF8B8"))
        .add_optional_block("DA", "01P0TENM0TGN")
        .add_optional_block("HM", "21")
        .add_optional_block("KS", "12345678901234600000")
        .add_optional_block("IK", "1234567812345678")
        //.add_optional_block("KS", "0112345678")
        .add_optional_block("WP", "001")
        .add_optional_block("BI", "001234567812");

            
    let wrapped_key = key_block_factory.wrap ( &mut key_block ).unwrap();
    
    let mut recovered_block = key_block_factory.unwrap(&wrapped_key).unwrap();
    assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
    assert_eq! ( recovered_block.get_version(), key_block.get_version());
    assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
    assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
    assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    assert! ( recovered_block.get_derivation_allowed().unwrap() == vec![
        DerivationAllowed::new ( KeyUsage::P0_PIN_ENCRYPTION_KEY, KeyAlgorithm::TDES, KeyMode::E_ENCRYPT_WRAP_ONLY, KeyExportability::N_NON_EXPORTABLE ),
        DerivationAllowed::new ( KeyUsage::M0_MAC_KEY_ISO_16609_MAC_ALG_1, KeyAlgorithm::TDES, KeyMode::G_GENERATE_ONLY, KeyExportability::N_NON_EXPORTABLE )]);
    assert! ( recovered_block.get_hmac_hash().unwrap() == HmacHashType::SHA_256);
    assert! ( recovered_block.get_tdes_dukpt_ksn().unwrap() == TdesKeySerialNumber { bdk_or_ks_id: hex!("1234567890"), device_id: hex!("1234600000") });
    assert! ( recovered_block.get_aes_dukpt_ksn().unwrap() == AesKeySerialNumber { bdk_or_ks_id: hex!("12345678"), device_id: hex!("12345678") });
    assert! ( recovered_block.get_base_derivation_key_id().unwrap() == BaseDerivationKeyId::TdesKsi(hex!("1234567812")));
    assert! ( recovered_block.get_wrapping_pedigree().unwrap() == WrappingPedigree::WP_1_LESSER);

}


    
    /////////////////////////////////////////////////////////
    //
    // ISO 20038:2017 B.2 CTR mode without padding, 
    // Same as ISO 20038:2023 8.5 CTR mode without padding
    //
    ///

    #[test]
    fn test_iso_20038_b2 () 
    {
        //let mut key_block_factory =  KeyBlockFactory::<aes::Aes256,  flavours::KeyBlockFlavor3<aes::Aes256>>::new(&hex!("3235362d 62697420 41455320 77726170 70696e67 20284953 4f203230 30333829").into());
        let mut key_block_factory =  KeyBlockEAes256::new ( &hex!("3235362d 62697420 41455320 77726170 70696e67 20284953 4f203230 30333829" ).into());
      
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("76e58387 0c9910328912920d593c")); return 1;});
        key_block_factory.set_key_length_obfuscation(false);
        
                
        let mut key_block =  KeyBlockFields::new();
        key_block
            //.set_version( KeyBlockVersion::E_AES_CTR)
            .set_secret (&hex!("77726170 70656420 33444553 206b6579"))
            .set_usage (  KeyUsage::B0_BDK)
            .set_algorithm (  KeyAlgorithm::TDES)
            .set_keyversion("16")
            .set_mode (  KeyMode::V_VERIFY_ONLY)
            .set_exportability( KeyExportability::N_NON_EXPORTABLE);
            
        let wrapped_key10 = key_block_factory.wrap (&mut key_block);
        let expected_result10 = concat!("E0084B0TV16N0000\
                                                B2AE5E26\
                                                BBA7F246\
                                                E84D5EA2\
                                                4167E208\
                                                A6B6\
                                                6EF2E27E\
                                                55A52DB5\
                                                2F0AEACB\
                                                94C57547");

        assert_eq!( &wrapped_key10.unwrap(), expected_result10);

        let mut recovered_block = key_block_factory.unwrap(expected_result10).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
    }
   
    #[test]
    fn test_iso_20038_b3 () 
    {
        // ISO 20038:2017 B.3 CBC mode with CBC mode with padding
        // Mistake in key to be encrypted, it is different between initial and part of mac calculation
        //let mut key_block_factory_10 =  KeyBlockFactory::<aes::Aes256,  flavours::KeyBlockFlavor2<aes::Aes256>>::new(&hex!("3235362d 62697420 41455320 77726170 70696e67 20284953 4f203230 30333829").into());
        let mut key_block_factory =  KeyBlockDAes256::new ( &hex!("3235362d 62697420 41455320 77726170 70696e67 20284953 4f203230 30333829" ).into());
      
        key_block_factory.set_rng ( |buf: &mut[u8]|->i32 { buf.copy_from_slice(&hex!("76e58387 0c9910328912920d593c")); return 1;});
                
        let mut key_block =  KeyBlockFields::new();
        key_block
            //.set_version( KeyBlockVersion::D_AES_CBC)
            .set_secret (&hex!("76736170 70646420 32454552 206B6479"))
            .set_usage (  KeyUsage::M3_MAC_KEY_ISO_9797_1_MAC_ALG_3)
            .set_algorithm (  KeyAlgorithm::TDES)
            .set_keyversion("16")
            .set_mode (  KeyMode::V_VERIFY_ONLY)
            .set_exportability( KeyExportability::N_NON_EXPORTABLE);
            
        let wrapped_key = key_block_factory.wrap (&mut key_block);
        let expected_result = concat!("D0112M3TV16N0000", "18462FA5903B8D2B","82FEE26B29713C0B","E7ED81601087F122","52093D06FC0A012C","1CF769AD0E3E9E4877166AB013FC22B4");

        assert_eq!( &wrapped_key.unwrap(), expected_result);

        let mut recovered_block = key_block_factory.unwrap(expected_result).unwrap();
        assert_eq! ( recovered_block.get_secret(), key_block.get_secret());
        assert_eq! ( recovered_block.get_version(), key_block.get_version());
        assert_eq! ( recovered_block.get_usage(), key_block.get_usage());
        assert_eq! ( recovered_block.get_mode(), key_block.get_mode());
        assert_eq! ( recovered_block.get_exportability(), key_block.get_exportability());
        

    }


    //
    // Atalla key block
    // Byte 0 - Version number of the format
    // Byte 1 - Key Usage - ATM Master key, CVV, Data encryption, IV, key encryption, MAC, manuf defined, PIN encryption, Refeence PIN block, SIgnature....
    // Byte 2 - Algorithm - Manuf defined, SHA-1, RC2/MD2, IBM3624, ANSI, Atalla, DES/3DES, EMV Key Derivation, AES ...
    // Byte 3 - Mode of use - Encrypt, Decrypt,Generate, Verify, no restriction
    // Byte 4 - Exportability
    // Byte 5 - Padding flag
    // Byte 6 - Special handling information
    // Byte 7 - Other information
    // 
    // The 8 byte header is used as the IV to encrypt the key field
