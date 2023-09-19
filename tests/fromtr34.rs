//use std::io::Read;
use keyblock::{tr34::{self, TR34RandomNumberToken, TR34KdhRebindToken, TR34KeyToken, TR34CaUnbindToken, TR34CaRebindToken, TR34Signed, TR34Enveloped}, tr34openssl::{TR34VerifyOpenssl, TR34DecryptOpenssl, TR34SignOpenssl}};


use hex_literal::hex;

use der::{asn1::{ObjectIdentifier, OctetString, UtcTime}, Encode, Decode, Sequence, Any, EncodeValue, Length, oid::db::{rfc5911::{ID_MESSAGE_DIGEST, ID_CONTENT_TYPE, ID_AES_128_CBC, ID_DATA, ID_SIGNED_DATA}, rfc5912::{ID_SHA_1, ID_RSAES_OAEP, ID_MGF_1, ID_P_SPECIFIED, ID_SHA_256}, rfc6268::{ID_ENCRYPTED_DATA, ID_ENVELOPED_DATA}, rfc4519::COUNTRY_NAME}};


/* Root key sample from TR-34 2019, B.2.1.1 */
pub const B_2_1_1_SAMPLE_ROOT_KEY_P12:&str = "-----BEGIN TR34_Sample_Root.p12-----\
        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\
        -----END TR34_Sample_Root.p12-----";

pub const B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12:&str = "-----BEGIN TR34_Sample_CA_KDH.p12-----\
        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\
        -----END TR34_Sample_CA_KDH.p12-----";

pub const B_2_1_3_TR34_SAMPLE_KDH_CRL:&str = "-----BEGIN TR34 Sample CA KDH CRL -----\
        MIIB1DCBvQIBATANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJVUzEVMBMGA1UE\
        ChMMVFIzNCBTYW1wbGVzMRswGQYDVQQDExJUUjM0IFNhbXBsZSBDQSBLREgXDTEw\
        MTEwMjE3MzMzMFoXDTEwMTIwMjE3MzMzMFowSDAWAgU0AAAACBcNMTAxMTAyMTcy\
        ODEzWjAWAgU0AAAAChcNMTAxMTAyMTczMTQ2WjAWAgU0AAAACxcNMTAxMTAyMTcz\
        MzI1WjANBgkqhkiG9w0BAQsFAAOCAQEANvBqPIisvPqfjjsIUO7gmpz3tbKRiG5R\
        DTSf5fBcG9t9nznk6mUIgo8u0+55Y8hYdFJ5XDlGKwYNW5csmnte+JChk8VyJdHI\
        jVbu0dA/fpp1hw1gTRXgEv/XuFBupLoU57UQGMFtjZ77asXFFWhrE04WsdZ/Hov0\
        PI/JpguWFK3M6a9pwnqUU9QmNE9rFEUO5YOCFHQeq/f4fxUqkxn62e07SBoRPAM2\
        PSmt0C4wMTopOvwYe3JSmPsUxdmXlnhaJswZzwfCvJojuPb27hmgB5BPS/Yy3P3n\
        8oJfMS/mKOPQxxzVC7CO5ATipfARoLWrTyphJ14lAJ2uAGYO/zLWww==\
        -----END TR34 Sample CA KDH CRL -----";

pub const B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12:&str = "-----BEGIN TR34_Sample_CA_KRD.p12-----\
        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\
        -----END TR34_Sample_CA_KRD.p12-----";

pub const B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12:&str = "-----BEGIN TR34_Sample_KDH_1.p12-----\
        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\
        qmcECIviRsKaEokn\
        -----END TR34_Sample_KDH_1.p12-----";


pub const B_2_1_6_TR34_SAMPLE_KDH_2_KEY_P12:&str = "-----BEGIN TR34_Sample_KDH_2.p12-----\
        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\
        -----END TR34_Sample_KDH_2.p12-----";

pub const B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12:&str = "-----BEGIN TR34_Sample_KRD_1.p12-----\
        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\
        -----END TR34_Sample_KRD_1.p12-----";


const B_2_2_1_1_ROOT_ISSUER_AND_SERIAL_NUMBER:&str = "-----BEGIN TR34 Sample Root IssuerAndSerialNumber PEM File-----\
        MEgwPzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UE\
        AxMQVFIzNCBTYW1wbGUgUm9vdAIFNAAAAAE=\
        -----END TR34 Sample Root IssuerAndSerialNumber PEM File-----";

const B_2_2_1_2_CA_KDH_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN TR34 Sample CA KDH IssuerAndSerialNumber PEM File-----\
        MEgwPzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UE\
        AxMQVFIzNCBTYW1wbGUgUm9vdAIFNAAAAAU=\
        -----END TR34 Sample CA KDH IssuerAndSerialNumber PEM File-----";

const B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN TR34 Sample CA KRD IssuerAndSerialNumber PEM File-----\
        MEgwPzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UE\
        AxMQVFIzNCBTYW1wbGUgUm9vdAIFNAAAAAY=\
        -----END TR34 Sample CA KRD IssuerAndSerialNumber PEM File-----";

pub const B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN TR34 Sample KDH 1 IssuerAndSerialNumber PEM File-----\
        MEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UE\
        AxMSVFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABg==\
        -----END TR34 Sample KDH 1 IssuerAndSerialNumber PEM File-----";

const B_2_2_1_5_KDH_2_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN TR34 Sample KDH 2 IssuerAndSerialNumber PEM File-----\
        MEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UE\
        AxMSVFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABw==\
        -----END TR34 Sample KDH 2 IssuerAndSerialNumber PEM File-----";

pub const B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN TR34 Sample KRD 1 IssuerAndSerialNumber PEM File-----\
        MEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UE\
        AxMSVFIzNCBTYW1wbGUgQ0EgS1JEAgU0AAAABw==\
        -----END TR34 Sample KRD 1 IssuerAndSerialNumber PEM File-----";

const B_2_2_2_1_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_FILE: &str = "-----BEGIN TR34 Sample EncryptedContent PEM File-----\
        MIGCAgEBMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEb\
        MBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABgQQASNFZ4mrze/+3LqY\
        dlQyEDAfBgkqhkiG9w0BBwExEgQQQTAyNTZLMFRCMDBFMDAwMA==\
        -----END TR34 Sample EncryptedContent PEM File-----";

const B_2_2_2_3_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_PEM: &str = "-----BEGIN TR34 Sample EncryptedContent PEM File-----\
        MIGCAgEBMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEb\
        MBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABgQQASNFZ4mrze/+3LqY\
        dlQyEDAfBgkqhkiG9w0BBwExEgQQQTAyNTZLMFRCMDBFMDAwMA==\
        -----END TR34 Sample EncryptedContent PEM File-----";

const B_2_2_2_4_SAMPLE_AES_KEY_BLOCK_USING_ISSUER_AND_SERIAL_NUMBER: &str = "-----BEGIN clear_aes_key_block.der-----\
        MIGCAgEBMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEb\
        MBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABgQQASNFZ4mrze/+3LqY\
        dlQyEDAfBgkqhkiG9w0BBwExEgQQRDAyNTZLMEFCMDBFMDAwMA==\
        -----END clear_aes_key_block.der-----";


const B_2_2_3_1_TDEA_ENVELOPED_DATA_BROKEN: &str = "-----BEGIN TR34 Sample EnvelopedData PEM File-----\
        MIICVQIBADGCAZ4wggGaAgEAMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRS\
        MzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS1JEAgU0AAAABzBF\
        BgkqhkiG9w0BAQcwODANBglghkgBZQMEAgEFADAYBgkqhkiG9w0BAQgwCwYJYIZI\
        AWUDBAIBMA0GCSqGSIb3DQEBCQQABIIBACy9CG3HIyhtl6phfB6UmA5Tmui/Uakm\
        xV/khYvkgIVlBvCPAJMn4urIE9d8eySgrlIyXFZFL3UEZs1Xge8ctLVzpgckEG0S\
        UvGMJ0IpWZt4h7o3nFCBeCGY3JoJRJPTicqD1vCNWNiOlUgG97AKYgsgymB5BnRy\
        fHnXS3ngOcmF4vEHvsMKf8guXNQmihos1Xn8gizDZqVy3GmVJqGxzAzj9oMK5/6q\
        K+FGTxv7SBTZePYAdkZAfyJLdYQPlhEn7w4jRyajajZWSjLSx0YFpQhJyb+fk/cn\
        0axo/tcg3u7SrQoGSzCsAdK+6zzNA9RjFdQPH/1tJg3G9lN9cOAoGKcwga0GCSqG\
        SIb3DQEHATCBnwYIKoZIhvcNAwcECAEjRWeJq83vgIGIUzKh+EUh3i07I+vjyy1n\
        SxYRTsWYIUECw97hdcKmaUAOsDkTbmMuSjIUCqtVRqxHh5n3t6AlM19FzKPNGJQx\
        T/UT4+Alc621E134sdsyd9neJz3GqLXnnSFfY7k6UhN9uvvlzD/0cpGdhtJAl2I3\
        D6gKd67Rg+HtWXv5v9ydKGk0x8Hh6NAD+w==\
        -----END TR34 Sample EnvelopedData PEM File-----";

/* From Errata */
pub const B_2_2_3_1_TDEA_ENVELOPED_DATA: &str = "-----BEGIN TR34 Sample EnvelopedData----- 
        MIICVAIBADGCAZ4wggGaAgEAMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRS\
        MzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS1JEAgU0AAAABzBF\
        BgkqhkiG9w0BAQcwODANBglghkgBZQMEAgEFADAYBgkqhkiG9w0BAQgwCwYJYIZI\
        AWUDBAIBMA0GCSqGSIb3DQEBCQQABIIBACy9CG3HIyhtl6phfB6UmA5Tmui/Uakm\
        xV/khYvkgIVlBvCPAJMn4urIE9d8eySgrlIyXFZFL3UEZs1Xge8ctLVzpgckEG0S\
        UvGMJ0IpWZt4h7o3nFCBeCGY3JoJRJPTicqD1vCNWNiOlUgG97AKYgsgymB5BnRy\
        fHnXS3ngOcmF4vEHvsMKf8guXNQmihos1Xn8gizDZqVy3GmVJqGxzAzj9oMK5/6q\
        K+FGTxv7SBTZePYAdkZAfyJLdYQPlhEn7w4jRyajajZWSjLSx0YFpQhJyb+fk/cn\
        0axo/tcg3u7SrQoGSzCsAdK+6zzNA9RjFdQPH/1tJg3G9lN9cOAoGKcwgawGCSqG\
        SIb3DQEHATAUBggqhkiG9w0DBwQIASNFZ4mrze+AgYhTMqH4RSHeLTsj6+PLLWdL\
        FhFOxZghQQLD3uF1wqZpQA6wORNuYy5KMhQKq1VGrEeHmfe3oCUzX0XMo80YlDFP\
        9RPj4CVzrbUTXfix2zJ32d4nPcaoteedIV9juTpSE326++XMP/RykZ2G0kCXYjcP\
        qAp3rtGD4e1Ze/m/3J0oaTTHweHo0AP7\
        -----END TR34 Sample EnvelopedData-----";

const B_2_2_3_2_AES_ENVELOPED_DATA_BROKEN: &str = "-----BEGIN TR34 AES Sample EnvelopedData.bin-----\
        MIICXgIBADGCAZ4wggGaAgEAMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRS\
        MzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS1JEAgU0AAAABzBF\
        BgkqhkiG9w0BAQcwODANBglghkgBZQMEAgEFADAYBgkqhkiG9w0BAQgwCwYJYIZI\
        AWUDBAIBMA0GCSqGSIb3DQEBCQQABIIBAFwQW/LUvMCx3L4Xrj4j6K4x+zu/FQ1/\
        bGSHeukPFGXX9C5Ou489870/RJkCI0fAJ/AynbYnTt2oMCAtcjurYhmujK3yCpp3\
        dn5Jk2U4W3pjuPg5hSv7/YUPD85W8U2EkCB93ZXc3ulMhB7QSb+wAiRy88h0Wdwr\
        yPZBtlBh39cR81grYMQ6uBApXDJ5T6GdoH6tW4J+tWS2SgvN3J7wlU6W/x8fuw0F\
        02R+83Udu6UneLeSjTNrO34I85hwuG3RWx+p4rPOrNrbzY6VB8fnyrXcSRHsDJO5\
        BSXKn4h6/H/FYKFih3vp+QybzJWnSgwk5mAwKAkP9mcou9L4HEXX2QgwgbYGCSqG\
        SIb3DQEHATCBqAYJYIZIAWUDBAECBAgBI0VniavN74CBkA3ekx0oHeuLzKr4AZRN\
        9aiz1gVrZ7O15kMZ2wKYbl0qO6eHHVCfjsNsJpo++TxTwKh1ONt4HC0NwKZ9Tlpn\
        l+lna5TNb2PmEEGLdDeX/TfcqkX7icynUHo4dR4C6r9DIUO5pgYw9FPC5zb+zdSf\
        TmJj9ilNQIwa1KdVtpfnUkWPfBcQO0IKS7UrnN6oaH0nhA==\
        -----END TR34 AES Sample EnvelopedData.bin-----";

/* From Errata */
pub const B_2_2_3_2_AES_ENVELOPED_DATA: &str = "-----BEGIN TR34 AES Sample EnvelopedData-----\
        MIICXQIBADGCAZ4wggGaAgEAMEowQTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRS\
        MzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUgQ0EgS1JEAgU0AAAABzBF\
        BgkqhkiG9w0BAQcwODANBglghkgBZQMEAgEFADAYBgkqhkiG9w0BAQgwCwYJYIZI\
        AWUDBAIBMA0GCSqGSIb3DQEBCQQABIIBAFwQW/LUvMCx3L4Xrj4j6K4x+zu/FQ1/\
        bGSHeukPFGXX9C5Ou489870/RJkCI0fAJ/AynbYnTt2oMCAtcjurYhmujK3yCpp3\
        dn5Jk2U4W3pjuPg5hSv7/YUPD85W8U2EkCB93ZXc3ulMhB7QSb+wAiRy88h0Wdwr\
        yPZBtlBh39cR81grYMQ6uBApXDJ5T6GdoH6tW4J+tWS2SgvN3J7wlU6W/x8fuw0F\
        02R+83Udu6UneLeSjTNrO34I85hwuG3RWx+p4rPOrNrbzY6VB8fnyrXcSRHsDJO5\
        BSXKn4h6/H/FYKFih3vp+QybzJWnSgwk5mAwKAkP9mcou9L4HEXX2QgwgbUGCSqG\
        SIb3DQEHATAVBglghkgBZQMEAQIECAEjRWeJq83vgIGQDd6THSgd64vMqvgBlE31\
        qLPWBWtns7XmQxnbAphuXSo7p4cdUJ+Ow2wmmj75PFPAqHU423gcLQ3Apn1OWmeX\
        6WdrlM1vY+YQQYt0N5f9N9yqRfuJzKdQejh1HgLqv0MhQ7mmBjD0U8LnNv7N1J9O\
        YmP2KU1AjBrUp1W2l+dSRY98FxA7QgpLtSuc3qhofSeE\
        -----END TR34 AES Sample EnvelopedData-----";

#[allow(dead_code)]
const B_2_2_4_1_SAMPLE_SIGNED_ATTRIBUTES_1_PASS_DER_BROKEN: &str = "\
        -----BEGIN TR34 Sample Authenticated Attributes 1Pass PEM File-----\
        oIGKMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwMwHAYJKoZIhvcNAQkFMQ8XDTEy\
        MDIwMzE2MTgwNlowHwYJKoZIhvcNAQcBMRIEEEEwMjU2SzBUQjAwRTAwMDAwLwYJ\
        KoZIhvcNAQkEMSIEIF2YFF4i/Lf2dRsaRTowxSSH+SS8de9G23l0x6psS8ct\
        -----END TR34 Sample Authenticated Attributes 1Pass PEM File-----";

const B_2_2_4_SAMPLE_SIGNED_ATTRIBUTES_1_PASS_DER: &str = "-----BEGIN TR34 Sample Signed Attributes 1 Pass.der-----\
        oIGKMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwMwHAYJKoZIhvcNAQkFMQ8XDTIw\
        MDIxMDE5MTM1M1owHwYJKoZIhvcNAQcBMRIEEEEwMjU2SzBUQjAwRTAwMDAwLwYJ\
        KoZIhvcNAQkEMSIEIGPF2d7jM8bnkhSn9ID9cdMLQnvKfN6fVptudMMQOwid\
        -----END TR34 Sample Signed Attributes 1 Pass.der-----";

#[allow(dead_code)]
const B_2_2_5_1_SAMPLE_AUTHENTICATED_ATTRIBUTES_2_PASS_PEM_BROKEN: &str = "-----BEGIN TR34 Sample Authenticated Attributes 2Pass PEM File-----
        oIGOMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwMwIAYKKoZIhvcNAQkZAzESBBAW\
        frDnJ4HklAESIzRFVmd4MB8GCSqGSIb3DQEHATESBBBBMDI1NkswVEIwMEUwMDAw\
        MC8GCSqGSIb3DQEJBDEiBCBdmBReIvy39nUbGkU6MMUkh/kkvHXvRtt5dMeqbEvH\
        LQ==\
        -----END TR34 Sample Authenticated Attributes 2Pass PEM File-----";

pub const B_2_2_5_SAMPLE_AUTHENTICATED_ATTRIBUTES_2_PASS_PEM: &str = "-----BEGIN TR34 Sample Signed Attributes 2 Pass-----\
        MYGOMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwMwIAYKKoZIhvcNAQkZAzESBBAW\
        frDnJ4HklAESIzRFVmd4MB8GCSqGSIb3DQEHATESBBBBMDI1NkswVEIwMEUwMDAw\
        MC8GCSqGSIb3DQEJBDEiBCBjxdne4zPG55IUp/SA/XHTC0J7ynzen1abbnTDEDsI\
        nQ==\
        -----END TR34 Sample Signed Attributes 2 Pass-----";


pub const B_3_TR34_SAMPLE_ROOT_P7B: &str = "-----BEGIN TR34_Sample_Root.p7b----- 
        MIIDbwYJKoZIhvcNAQcCoIIDYDCCA1wCAQExADAPBgkqhkiG9w0BBwGgAgQAoIID\
        QDCCAzwwggIkoAMCAQICBTQAAAABMA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNVBAYT\
        AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGTAXBgNVBAMTEFRSMzQgU2FtcGxl\
        IFJvb3QwHhcNMTAxMTAyMDAwMDAwWhcNMzAxMDI3MjM1OTU5WjA/MQswCQYDVQQG\
        EwJVUzEVMBMGA1UEChMMVFIzNCBTYW1wbGVzMRkwFwYDVQQDExBUUjM0IFNhbXBs\
        ZSBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3mddLsBixkFi\
        OABvgmylJxglg/Kt0v6MHYHmrV7B6Fs5vq+XCJTbK08idzl5VBwSI9UagrYf9UGM\
        Hl82eSfJuqrDLz4WIFXQd27DkkIlw99CwiOP+aqqPopHKHFSrOPMqRR9X4IgvnNI\
        Swje10P3pD7m65hhmdERRQtqFfBQerTgct242xaWyAAf15lnfoNfOWpyaercLXrC\
        Cr2qHdiN1IVv8RoXanw5QLx9YJrMyfPFHdABfD/t2ce9C/3q+gsJFh+ccekq5zrx\
        da2xU8vvziw6D83qOUxEIwo3+C7cRI65sGafyC6UNeaZqa4xka1O6l3NHSzcO+bH\
        UQeObBOGnwIDAQABoz8wPTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSCgxyG\
        pzrgtvQuTM73ycOiT0rJ7DALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEB\
        AMz9j7S4NHj0jsVgeO6Ch5qx1GgQGmgtUSmM3BMsk18DnUdTbh9LAe2eUotpxSYL\
        L3hbtoYsUC54blxj+IEzj/zLuSn+TuMItQ9scxreiVUCClv/3gYI3lHfhs0YhzD7\
        zEwG9Q1X9Q0EUN+5IiWOhZacQQaJZhc8JmZD6edL7t24I0rNZwJxv/z1F6tN8KqI\
        4UaqdUPTLRhqTpwr/5hcsN4UdehKoPWFYE1oN8Kvh++CWYlq0wat95E/TTGH9YyD\
        KANXscT+QbyWkwRNsHBD1QAHc45nqBalI1mRqAX3/IU9iqg6NNUguOgGus9W0GVo\
        TpAhE2ITwTKfCPXEQWUEtv4xAA==\
        -----END TR34_Sample_Root.p7b-----";

pub const B_4_CA_KDH_P7B: &str = "-----BEGIN TR34_Sample_CA_KDH.p7b----- 
        MIIDcQYJKoZIhvcNAQcCoIIDYjCCA14CAQExADAPBgkqhkiG9w0BBwGgAgQAoIID\
        QjCCAz4wggImoAMCAQICBTQAAAAFMA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNVBAYT\
        AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGTAXBgNVBAMTEFRSMzQgU2FtcGxl\
        IFJvb3QwHhcNMTAxMTAyMDAwMDAwWhcNMjUxMDI4MjM1OTU5WjBBMQswCQYDVQQG\
        EwJVUzEVMBMGA1UEChMMVFIzNCBTYW1wbGVzMRswGQYDVQQDExJUUjM0IFNhbXBs\
        ZSBDQSBLREgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu+h1zlsPb\
        pJnlXXqlBxSsXnXBJx2QAOru0qAHq2RmcFFfQyEsiiC8Mstnsc1dcS9md293bVi8\
        X4FzDFOWNiIrRCjIqvz80Ay86ElwcGbBlG0Or7IzE7amrb8j6SL1ldHuV6bEvgFN\
        amTl2cRUKckgQQ4fEsJeVQAGXUl6R3jPA1YN6BGGztflt0dKHUcD6q+UQGo8cxRN\
        +Mlx+HnPM66OmEjeUFG0YCmmLJSXvOhq8VJGCzlDriTP+c6I9aUEhdoUs9Md08ad\
        8kEF0lJiU+o4if4cb9gzqBOvQ/7EDED4gtreTuv+WAFEjdy9neT7tp1WoIEOCCtz\
        KjXqKhZwcob/AgMBAAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLgq\
        WAoNefZKB8dYq8OTZWNfN8oYMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOC\
        AQEAm/sj4Zb3KBzwDQHyFeg1cXewqD8y4obs+FYxNuDkGfC7yGuZfvn5ng95sKJy\
        jglQLtcwTtas4LgD9Z8myJj3qBT6TBlKtAPh6ZmNHBYVFuR3GKxaeFJ1Mj6jrZil\
        QO5K9luajD6DHLgzu+/LzUFzQ8nrJATovizH3VctThSFuzkvi/caeS9pOJKDAso7\
        HuubFJfO2DHvhDqlWFgiJhZoI4pZwJ9rhd3J/QYXhF7Lccjye0TcSxTzar+5RUJI\
        Jknyk6r3xGIq6qwIp2QVafblOmThBPgvOKSgl2Q63LkH/BFSSvRy19DQkHMXw99j\
        lOzd9mJxp/sq4wz41YF8g1bfgzEA\
        -----END TR34_Sample_CA_KDH.p7b-----";

pub const B_5_SAMPLE_CA_KRD_P7B: &str = "-----BEGIN TR34_Sample_CA_KRD.p7b-----\
        MIIDcQYJKoZIhvcNAQcCoIIDYjCCA14CAQExADAPBgkqhkiG9w0BBwGgAgQAoIID\
        QjCCAz4wggImoAMCAQICBTQAAAAGMA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNVBAYT\
        AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGTAXBgNVBAMTEFRSMzQgU2FtcGxl\
        IFJvb3QwHhcNMTAxMTAyMDAwMDAwWhcNMjUxMDI4MjM1OTU5WjBBMQswCQYDVQQG\
        EwJVUzEVMBMGA1UEChMMVFIzNCBTYW1wbGVzMRswGQYDVQQDExJUUjM0IFNhbXBs\
        ZSBDQSBLUkQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD79+R/P7Ox\
        9NQVfsmKX8WFTDQpX8a4h29AWw437Z0+WkzplhwTpEcw5OiXqpJ2vSAw80UjuplX\
        8FZ7oFOpNOyVkj6zkF764ZygA5F4ycHwhGg+JScKc1YW5LoUpV38k7+shAh6Irwp\
        BxgwM0i+F6LGAVlF/ZoUcF18Q7qUgNdiP7tGjSS2EgRm+fCH49eJuCopHOF4uciv\
        4wGEp8uHaWIPTsxtIStFOPRumheKssvnrK7PHZEWTtDvWTNARH54UP99eT3EhRKI\
        TiDgneqACQljhHY1vtPpIXTfqYI4QdDviRLcInujDGgTM2hG2UEkjcDU8OLSWWWC\
        WO0aAhhHKeLbAgMBAAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFBI4\
        bs+2pm7a2/8Jb2W71bBQ+cwNMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOC\
        AQEAayNCRdcgDRQYHWB6xs5zWNl10j2jA/IfVLjeuvemiMtc5QUiMkrdktC4EzF6\
        vZYa1B0QdXY5qMjWGF3MyN8GPgtdSQayH65BFhyRN1MaicsRmPch5VekqnqijJ6G\
        mYPwbGlDE0ygJTkoaDreEzZOv8Ikqn4dvCC9h5Fu778A2iAvD0bebvxheOONLJrD\
        b8mLffrBQLI5YprFYeKE9W0JrhqHjukAfhBZl8XXTRrH+XA8eCskJRjxczCbuboA\
        qHekeCL8hZ4ePWFfVdEKDFmIRz+lhIZnNj+upKdhKVZasHmNft4aGLpUtgApbM42\
        MyKEQH/1tzSYfWJcMh5AAE9l4TEA\
        -----END TR34_Sample_CA_KRD.p7b-----";

pub const B_6_KDH_1_W_CRL_PEM: &str = "-----BEGIN TR34_Sample_KDH_1_w_CRL PEM File-----\
        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\
        -----END TR34_Sample_KDH_1_w_CRL PEM File-----";

pub const B_7_KRD_CREDENTIAL_TOKEN_1_P7B: &str = "-----BEGIN TR34_Sample_KRD_1.p7b-----
        MIIDbAYJKoZIhvcNAQcCoIIDXTCCA1kCAQExADAPBgkqhkiG9w0BBwGgAgQAoIID\
        PTCCAzkwggIhoAMCAQICBTQAAAAHMA0GCSqGSIb3DQEBCwUAMEExCzAJBgNVBAYT\
        AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGzAZBgNVBAMTElRSMzQgU2FtcGxl\
        IENBIEtSRDAeFw0xMDExMDIwMDAwMDBaFw0yMDEwMjkyMzU5NTlaMEAxCzAJBgNV\
        BAYTAlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGjAYBgNVBAMTEVRSMzQgU2Ft\
        cGxlIEtSRCAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Fwwy2+7\
        HTlM5ah7SdttzxQ0sPpOCqNx+FDui65/LcPFSNUcvaPdAfDWVTv7eYUecxVDmEsi\
        42K0/B3T1t6CN30gEyzGOWXdCtLdaJ6YUpFhNUDzDnWlWPkVsunkDdQhysa9t0WQ\
        9EKKtGhOy0KU07rSEvZmIgDu993DATFvumdrcSD7kYk8K6MRqE9zryFjtWBEBf12\
        C7FSaJz1IE8gy72XYjtduWzPa6OCasOHkNPCxmzX6/1cnx5wy8d/VY+VUBqanLSr\
        Pf2iZdAQpJq3AqABXfD24I0M42MwZBxNx16o/n3V6ms3vWQyhXf4VQ0/AVqlbxq1\
        8l5V9ZNAr1P5VQIDAQABozkwNzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQNcgU8qYLi\
        wYnORyBQ000EWppZ0zALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAA2e\
        05yX0uF78HE020C6GkrO1yrWj9UZ3j4i+bjLalGAW1/NQ48ccwl+aZnwXMBvvHvy\
        P8sSQRKOCnnXk1FgBoUY0YplMPtIYzfJfwytcYyh3CSB8hwffeA+xWsSzqgryB69\
        9JRCdW/z2pktKMFEV0erECHxwU/+Q9CFKOZo4EBt/1ANVV2CO58LUcS720fG8Xsw\
        J0ebXIvkSEJ27Qtxza3BwklGttGGRoyFdOO40eoVH9iUIhvb9MLnPJQF15Xnt/3i\
        GZrjMXbTrnKtqA2VECBPDIcFd7f3UtxHmynVASE5HM/KgXjIaxqtdptYTmgX4WKw\
        WjEZMPik8d3XUnQg17ExAA==\
        -----END TR34_Sample_KRD_1.p7b-----";

/* From Errata */
pub const B_8_ONE_PASS_KEY_TOKEN: &str = "-----BEGIN CMS-----\
        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\
        PU0KIBeKDHL97YA0pLVheQet6H1GbEmy\
        -----END CMS-----";

#[allow(dead_code)]
/* From TR34-2019, replaced by errata */            
pub const B_8_KTKDH_1_PASS_BROKEN: &str = "-----BEGIN KTKDH_1Pass PEM File-----\
        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\
        lM0lIQ+khVtc2Ghijha8DJZTX10XzV3yFg==\
        -----END KTKDH_1Pass PEM File-----";
        
/* From Errata */
pub const B_9_TWO_PASS_TOKEN :&str = "-----BEGIN CMS-----\
        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\
        pq6XOnKRgInmOQJfF1Sxp2X70hBorCNs3Zjj0A==\
        -----END CMS-----";

#[allow(dead_code)]
/* From TR-34 2019, before being amended */
const B_9_KTKDH_TWO_PASS_PEM_BROKEN: &str ="-----BEGIN KTKDH_2Pass PEM File-----\
        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\
        EoexwHn7aU71w31HgSGR0FS0vnlG5vaCf43xFww=\
        -----END KTKDH_2Pass PEM File-----";

pub const B_10_TR34_SAMPLE_RBT_CA_UNBIND_PEM: &str = "-----BEGIN TR34_Sample_RBT_CA_Unbind PEM File-----\
        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\
        T0HC9prOsi7Dj6cYDT+e9aYMoho=\
        -----END TR34_Sample_RBT_CA_Unbind PEM File-----";

pub const B_11_SAMPLE_RBT_KDH_PEM: &str = "-----BEGIN TR34_Sample_RBT_KDH PEM File-----\
        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\
        -----END TR34_Sample_RBT_KDH PEM File-----";

pub const B_12_KRD_RANDOM_NUMBER_TOKEN:&str = "-----BEGIN RKRD.der-----\
        MCAGCiqGSIb3DQEJGQMxEgQQFn6w5yeB5JQBEiM0RVZneA==\
        -----END RKRD.der-----";

pub const B_13_UBT_CA_UNBIND:&str = "-----BEGIN TR34_Sample_UBT_CA_Unbind PEM File-----\
        MIICRgYJKoZIhvcNAQcCoIICNzCCAjMCAQExDTALBglghkgBZQMEAgEwgakGCSqG\
        SIb3DQEHAaCBmwSBmDBKMEExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxUUjM0IFNh\
        bXBsZXMxGzAZBgNVBAMTElRSMzQgU2FtcGxlIENBIEtSRAIFNAAAAAcwSjBBMQsw\
        CQYDVQQGEwJVUzEVMBMGA1UEChMMVFIzNCBTYW1wbGVzMRswGQYDVQQDExJUUjM0\
        IFNhbXBsZSBDQSBLREgCBTQAAAAGMYIBcTCCAW0CAQEwSDA/MQswCQYDVQQGEwJV\
        UzEVMBMGA1UEChMMVFIzNCBTYW1wbGVzMRkwFwYDVQQDExBUUjM0IFNhbXBsZSBS\
        b290AgU0AAAABjALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEA3R4yEtKZ\
        TmpcHCZBzIlT4oTzClIjMp82g8OTmqMNSCWM9HlVF/1G6D+W02bDuYJC58IBdup/\
        9kLnpNVDwXRXVLiGFvCI2BqSkwUwx3hmTVxu0Q+xU+bv4DTNDHq3TNhAwlQBRzE5\
        D6udzqMX6kZP6QBVwgYwuX5Y7WQCRQmsRahvwdGhMOGQGgz9VWbI7fZdHFkd6zqX\
        wZqMxSmokqzHOb/yGUA6or0IUP1WkK77KIpnvvnz2s18xpxmbrzLbbY3RdKzGiV3\
        bzDuFXuJ84T3ZuHhzZoxMoijsDK/AlVPXs3KgQOjFObfhTyyMYGYptiEuxWscg9B\
        70ZcQ5s35GGOpg==\
        -----END TR34_Sample_UBT_CA_Unbind PEM File-----";

pub const B_14_UBT_KDH_UNBIND:&str = "-----BEGIN TR34_Sample_UBT_KDH PEM File-----\
         MIIEPAYJKoZIhvcNAQcCoIIELTCCBCkCAQExDTALBglghkgBZQMEAgEwWwYJKoZI\
         hvcNAQcBoE4ETDBKMEExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBs\
         ZXMxGzAZBgNVBAMTElRSMzQgU2FtcGxlIENBIEtSRAIFNAAAAAehggHYMIIB1DCB\
         vQIBATANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVFIz\
         NCBTYW1wbGVzMRswGQYDVQQDExJUUjM0IFNhbXBsZSBDQSBLREgXDTEwMTEwMjE3\
         MzMzMFoXDTEwMTIwMjE3MzMzMFowSDAWAgU0AAAACBcNMTAxMTAyMTcyODEzWjAW\
         AgU0AAAAChcNMTAxMTAyMTczMTQ2WjAWAgU0AAAACxcNMTAxMTAyMTczMzI1WjAN\
         BgkqhkiG9w0BAQsFAAOCAQEANvBqPIisvPqfjjsIUO7gmpz3tbKRiG5RDTSf5fBc\
         G9t9nznk6mUIgo8u0+55Y8hYdFJ5XDlGKwYNW5csmnte+JChk8VyJdHIjVbu0dA/\
         fpp1hw1gTRXgEv/XuFBupLoU57UQGMFtjZ77asXFFWhrE04WsdZ/Hov0PI/JpguW\
         FK3M6a9pwnqUU9QmNE9rFEUO5YOCFHQeq/f4fxUqkxn62e07SBoRPAM2PSmt0C4w\
         MTopOvwYe3JSmPsUxdmXlnhaJswZzwfCvJojuPb27hmgB5BPS/Yy3P3n8oJfMS/m\
         KOPQxxzVC7CO5ATipfARoLWrTyphJ14lAJ2uAGYO/zLWwzGCAdowggHWAgEBMEow\
         QTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UEAxMS\
         VFIzNCBTYW1wbGUgQ0EgS0RIAgU0AAAABjALBglghkgBZQMEAgGgZTAYBgkqhkiG\
         9w0BCQMxCwYJKoZIhvcNAQcBMBgGCiqGSIb3DQEJGQMxCgQIfeocAIlOJGowLwYJ\
         KoZIhvcNAQkEMSIEIIeYFo5vfzEY7ehSK2M237Vs/fldtwY8tyMO8AtNZm0aMA0G\
         CSqGSIb3DQEBAQUABIIBAE80v8n2d8D3kBFwR7HqYM/TMltuf10kfDrB8LYMqLLp\
         JXOhQctjYBetCTDQ0kK75szZyaapV1cjmowsmfwejK6IrS1qtueiVsjFLmqROECz\
         QiqSdSZ/iPZ82Brdkwd//jD20n2XYIpdmBUhSL7XD65DPz963KcSYARf9bPkK1wK\
         FB9ozwsW4YeuT2Rv0QpwCBJEKspvIpKM8D8pJQHT+3cEMGurGVQtvXaG396YuOJs\
         qg4mLN+92YRSBY61rRrlFxX4ARwtn6a9RuHW8P+dOTYkT9t0msZByYdJrk8V2oyQ\
         VtM8wqN6incGM24kRrcZvoU5lsEz9brY6Uz/wvC+JB0=\
        -----END TR34_Sample_UBT_KDH PEM File-----";


 #[derive(Clone, Debug, Eq, PartialEq, der::Sequence )]
pub struct TR34Block2 {
    pub version: cms::content_info::CmsVersion /*u8*/,
    pub issuer_and_serial_number: der::Any, //IssuerAndSerialNumber,
    pub clear_key: der::asn1::OctetString,
    //pub attribute_header: OidAndAttributeHeader,
    pub attribute_header: cms::cert::x509::attr::Attribute,
}

/// Implementation of PFX container from PKCS#12
#[derive(Clone, Debug, Eq, PartialEq, Sequence)] // NOTE: added `Sequence`
struct PFX {
    version: u8,
    //authsafe: PKCSData,
    authsafe: cms::content_info::ContentInfo,
    mac_data: MacData,
    //rr: Box<dyn AnyObject>,
    //modulus: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)] // NOTE: added `Sequence`
struct MacData {
    mac: DigestInfo,
    mac_salt: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)] // NOTE: added `Sequence`
struct DigestInfo {
    digest_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned, //AlgorithmIdentifier2, //ObjectIdentifier,
    digest: OctetString,
}








#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AuthenticatedSafe {
    f1: cms::content_info::ContentInfo,
    f2: cms::content_info::ContentInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SafeContents {
    b1: SafeBag
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SafeBag {
    bag_id: ObjectIdentifier,
    bag_value: Any,
    bag_attributes: Any,
}





/// Same as cms::EnvelopedData except the encryptedContentInfo.content_enc_alg
#[derive(Clone, Debug, Eq, PartialEq, Sequence )]
pub struct EnvelopedData2 {
    pub version: cms::content_info::CmsVersion,
    pub originator_info: Option<cms::enveloped_data::OriginatorInfo>,
    pub recip_infos: cms::enveloped_data::RecipientInfos,
    pub encrypted_content: EncryptedContentInfo2,
    pub unprotected_attrs: Option<cms::cert::x509::attr::Attributes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedContentInfo2 {
    pub content_type: ObjectIdentifier,
    pub content_enc_alg: AlgorithmIdentifier2,
    
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub encrypted_content: Option<OctetString>,
}


#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct AlgorithmIdentifier2 {
    /// Algorithm OID, i.e. the `algorithm` field in the `AlgorithmIdentifier`
    /// ASN.1 schema.
    pub oid: ObjectIdentifier,

    /// Algorithm `parameters`.
    pub parameters: Option<Any>,
    // The TR-34 examples have an extra field, which is either extra parameters or the actual encrypted data
    pub parameters2: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct RsaOaepParams {
    hash_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned,
    mask_gen_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned,
    p_source_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct Mgf1Params {
    hash_algorithm: ObjectIdentifier,
}


/// Modification of SignedData to allow decoding of b.6 - signer_infos and crls were reversed!
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct 
SignedData2 {
    pub version: cms::content_info::CmsVersion,
    pub digest_algorithms: cms::signed_data::DigestAlgorithmIdentifiers,
    pub encap_content_info: cms::signed_data::EncapsulatedContentInfo,
    //todo consider defer decoding certs and CRLs
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<cms::signed_data::CertificateSet>,

    pub signer_infos: cms::signed_data::SignerInfos,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<cms::revocation::RevocationInfoChoices>,
}

pub struct TR34EnvelopedToken {
    env: cms::enveloped_data::EnvelopedData,
}

impl TR34EnvelopedToken {
    pub fn from_der ( input: &[u8]) -> Result<TR34EnvelopedToken, keyblock::tr34::Error> {
        let import = cms::enveloped_data::EnvelopedData::from_der(input)?;
        Ok(TR34EnvelopedToken { env: import/* , verified: false*/ })
    }
}

impl TR34Enveloped for TR34EnvelopedToken {
    fn get_enveloped_data(&self) -> Result<cms::enveloped_data::EnvelopedData, keyblock::tr34::Error> {
        return Ok(self.env.clone());
    }
}


pub fn get_cert_openssl(pem_contents: &str ) -> openssl::x509::X509 {
    let key_pem = pem::parse(pem_contents).unwrap();
    let key_openssl = openssl::pkcs12::Pkcs12::from_der (key_pem.contents()).unwrap().parse2("TR34").unwrap();
    return key_openssl.cert.unwrap();
}

fn get_pub_key_openssl(pem_contents: &str ) -> openssl::pkey::PKey<openssl::pkey::Public> {
    let cert = get_cert_openssl(pem_contents);
    return cert.public_key().unwrap();
}
fn get_priv_key_openssl(pem_contents: &str ) -> openssl::pkey::PKey<openssl::pkey::Private> {
    let key_pem = pem::parse(pem_contents).unwrap();
    let key_openssl = openssl::pkcs12::Pkcs12::from_der (key_pem.contents()).unwrap().parse2("TR34").unwrap();
    return key_openssl.pkey.unwrap();
}

pub fn get_root_pub_key_openssl() -> openssl::pkey::PKey<openssl::pkey::Public> {
    return get_pub_key_openssl(B_2_1_1_SAMPLE_ROOT_KEY_P12);
}
pub fn get_ca_kdh_openssl() -> openssl::pkey::PKey<openssl::pkey::Public> {
    return get_pub_key_openssl(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12);
}
pub fn get_ca_krd_openssl() -> openssl::pkey::PKey<openssl::pkey::Public> {
    return get_pub_key_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12);
}

fn get_kdh_1_pub_key() -> openssl::pkey::PKey<openssl::pkey::Public> {
    return get_pub_key_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12);
}

fn get_cert_from_p12(pem_contents: &str) -> cms::cert::x509::Certificate {
    let openssl_cert = get_cert_openssl(pem_contents);
    let der = openssl_cert.to_der().unwrap();
    return cms::cert::x509::Certificate::from_der(&der).unwrap();
}
fn get_cert_from_p7(pem_contents: &str) -> cms::cert::x509::Certificate {
    let der = pem::parse(pem_contents).unwrap();
    let cms = cms::content_info::ContentInfo::from_der(&der.contents()).unwrap();
    let signed_data: cms::signed_data::SignedData = cms.content.decode_as().unwrap();
    if let cms::cert::CertificateChoices::Certificate(cert) = signed_data.certificates.unwrap().0.get(0).unwrap() {
        return cert.clone();
    }
    else {
        panic! ("No certificates in file");
    }
}


fn get_ca_root_cert () -> cms::cert::x509::Certificate {
    return get_cert_from_p7(B_3_TR34_SAMPLE_ROOT_P7B);
}
fn get_ca_kdh_cert() -> cms::cert::x509::Certificate {
    return get_cert_from_p12(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12);
}
fn get_ca_krd_cert() -> cms::cert::x509::Certificate {
    return get_cert_from_p12(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12);
}

fn get_kdh_1_cert() -> cms::cert::x509::Certificate {
    return get_cert_from_p12(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12);
}
fn get_kdh_2_cert() -> cms::cert::x509::Certificate {
    return get_cert_from_p12(B_2_1_6_TR34_SAMPLE_KDH_2_KEY_P12);
}
fn get_krd_1_cert() -> cms::cert::x509::Certificate {
    return get_cert_from_p12(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
}
pub fn get_krd_1_openssl() -> openssl::pkey::PKey<openssl::pkey::Private> {
    return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
}

pub fn get_krd_1_pub_openssl() -> openssl::pkey::PKey<openssl::pkey::Public> {
    return get_pub_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
}








#[test]
fn decode_b_2_1_2_ca_kdh() {
    let kdh_key_pem = pem::parse(B_2_1_2_TR34_SAMPLE_CA_KDH_KEY_P12).unwrap();

    let kdh_key_cms = PFX::from_der ( kdh_key_pem.contents()).unwrap();

    assert! ( kdh_key_cms.version == 3);
    assert! ( kdh_key_cms.mac_data.mac.digest_algorithm.oid == ID_SHA_1);
    assert! ( kdh_key_cms.mac_data.mac.digest == OctetString::new(hex!("4FC97705BDC61724FAC6019C78DF1F210B7D30CE")).unwrap());
    assert! ( kdh_key_cms.mac_data.mac_salt == OctetString::new(hex!("7D3C960C6C470C05")).unwrap());

    assert! ( kdh_key_cms.authsafe.content_type == der::oid::db::rfc5911::ID_DATA );
    //let content = kdh_key_cms.authsafe.content.decode_as::<cms::enveloped_data::EnvelopedData>();

    //let contents = kdh_key_cms.authsafe.content;
    let contents2 = AuthenticatedSafe::from_der(kdh_key_cms.authsafe.content.value()).unwrap();

    assert! ( contents2.f1.content_type == ID_ENCRYPTED_DATA);
    //let encrypted_data = cms::encrypted_data::EncryptedData::from_der(contents2.f1.content.value());
   
    assert! ( contents2.f2.content_type == der::oid::db::rfc5911::ID_DATA);
    let data = SafeContents::from_der(contents2.f2.content.value()).unwrap();
    assert!(data.b1.bag_id == ID_PKCS8_SHROUDED_KEY_BAG);
}

#[test]
fn decode_b_2_2_1_1 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_1_ROOT_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();

    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample Root", 223338299393);
}

#[test]
fn decode_b_2_2_1_2 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_2_CA_KDH_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();

    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample Root", 223338299397);
}

#[test]
fn decode_b_2_2_1_3 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    
    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample Root", 223338299398);
}

#[test]
fn decode_b_2_2_1_4 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    
    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample CA KDH", 223338299398);
}

#[test]
fn decode_b_2_2_1_5 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_5_KDH_2_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    
    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample CA KDH", 223338299399);
}
#[test]
fn decode_b_2_2_1_6 (){
    let issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    
    decode_ca_kdh_issuer_and_serial_number ( &issuer_and_serial_number, "TR34 Sample CA KRD", 223338299399);
}

#[test]
fn decode_b_2_1_3_crl() {
    let crl_pem = pem::parse(B_2_1_3_TR34_SAMPLE_KDH_CRL).unwrap();

    let crl = cms::cert::x509::crl::CertificateList::from_der ( crl_pem.contents()).unwrap();

    assert! ( crl.tbs_cert_list.version == cms::cert::x509::Version::V2);
    assert! ( crl.tbs_cert_list.signature.oid == ID_SHA_256_WITH_RSA_ENCRYPTION2);
    assert! ( crl.tbs_cert_list.signature.parameters.unwrap() == Any::new(der::Tag::Null, [0u8;0]).unwrap());

    //assert! ( crl.tbs_cert_list.issuer == get_b_2_2_1_4_kdh_1_id().issuer);
    assert! ( crl.tbs_cert_list.issuer == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap().issuer);
    assert! ( crl.tbs_cert_list.this_update.to_date_time() == der::DateTime::new ( 2010, 11, 2, 17, 33, 30).unwrap());
    assert! ( crl.tbs_cert_list.next_update.unwrap().to_date_time() == der::DateTime::new ( 2010, 12, 2, 17, 33, 30).unwrap());
    assert! ( crl.tbs_cert_list.crl_extensions.is_none() );

    let revoked_cert1 = crl.tbs_cert_list.revoked_certificates.as_ref().unwrap().get(0).unwrap();
    assert! ( revoked_cert1.crl_entry_extensions.is_none());
    assert! ( revoked_cert1.revocation_date.to_date_time() == der::DateTime::new ( 2010, 11, 2, 17, 28, 13).unwrap());
    assert! ( revoked_cert1.serial_number.as_bytes() == &223338299400i64.to_be_bytes()[3..]);
}

#[test]
fn decode_b_2_2_2_1_tdea_key_block() {
    let keyblock = keyblock::tr34::TR34Block::from_der(pem::parse(B_2_2_2_1_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_FILE).unwrap().contents()).unwrap();

    assert! ( keyblock.issuer_and_serial_number == get_b_2_2_1_4_kdh_1_id());
    assert! ( keyblock.version == cms::content_info::CmsVersion::V1);
    assert! ( keyblock.clear_key.as_bytes() == hex!("0123456789ABCDEFFEDCBA9876543210"));
    assert! ( keyblock.attribute_header.values.get(0).unwrap().value() == hex!("41 30 32 35 36 4B 30 54 42 30 30 45 30 30 30 30"));
    assert! ( keyblock.attribute_header.values.get(0).unwrap().value() == "A0256K0TB00E0000".as_bytes());
}

// Not sure how this is different to the one above!
#[test]
fn decode_b_2_2_2_3_tdea_key_block() {
    let keyblock = keyblock::tr34::TR34Block::from_der(pem::parse(B_2_2_2_3_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_PEM).unwrap().contents()).unwrap();

    assert! ( keyblock.issuer_and_serial_number == get_b_2_2_1_4_kdh_1_id());
    assert! ( keyblock.version == cms::content_info::CmsVersion::V1);
    assert! ( keyblock.clear_key.as_bytes() == hex!("0123456789ABCDEFFEDCBA9876543210"));
    assert! ( keyblock.attribute_header.values.get(0).unwrap().value() == hex!("41 30 32 35 36 4B 30 54 42 30 30 45 30 30 30 30"));
    assert! ( keyblock.attribute_header.values.get(0).unwrap().value() == "A0256K0TB00E0000".as_bytes());

    assert! ( B_2_2_2_1_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_FILE == B_2_2_2_3_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_PEM )
}
#[test]
fn decode_b_2_2_2_4_aes_key_block() {
    let keyblock = keyblock::tr34::TR34Block::from_der(pem::parse(B_2_2_2_4_SAMPLE_AES_KEY_BLOCK_USING_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();

    assert! ( keyblock.issuer_and_serial_number == get_b_2_2_1_4_kdh_1_id());
    assert! ( keyblock.version == cms::content_info::CmsVersion::V1);
    assert! ( keyblock.clear_key.as_bytes() == hex!("0123456789ABCDEFFEDCBA9876543210"));
    // Key block header from example is missing a 'B'
    assert! ( keyblock.attribute_header.oid == der::oid::db::rfc5911::ID_DATA);
    assert! ( keyblock.attribute_header.values.get(0).unwrap().value() == "D0256K0AB00E0000".as_bytes());

    assert! ( keyblock.to_der().unwrap() == pem::parse(B_2_2_2_4_SAMPLE_AES_KEY_BLOCK_USING_ISSUER_AND_SERIAL_NUMBER).unwrap().contents());
}


#[test]
fn decode_b_2_2_3_1_sample_tdea_enveloped_data() {
    let mb_enveloped_data = cms::enveloped_data::EnvelopedData::from_der(pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents()).unwrap();
    let mb_enveloped_data_broken2 = EnvelopedData2::from_der(pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA_BROKEN).unwrap().contents()).unwrap();
    let token = TR34EnvelopedToken::from_der( pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents()).unwrap();
    assert! ( mb_enveloped_data.encrypted_content.encrypted_content.as_ref().unwrap().as_bytes() == mb_enveloped_data_broken2.encrypted_content.content_enc_alg.parameters2.as_ref().unwrap().value()) ;
    
    assert! ( mb_enveloped_data.version == cms::content_info::CmsVersion::V0);
    assert! ( mb_enveloped_data.originator_info.is_none() );
    assert! ( mb_enveloped_data.unprotected_attrs.is_none());
    assert! ( mb_enveloped_data.recip_infos.0.is_empty()== false);
    assert! ( mb_enveloped_data.recip_infos.0.len() == 1);
    
    let recip_info = mb_enveloped_data.recip_infos.0.get(0).unwrap();
    let recip_ktri = match recip_info {
        cms::enveloped_data::RecipientInfo::Ktri ( v ) => v,
        _ => panic!("unhandled enum type"),
    };

    assert! ( recip_ktri.version == cms::content_info::CmsVersion::V0 );
    assert! ( recip_ktri.key_enc_alg.oid == ID_RSAES_OAEP);
    let expected_recipient = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    assert! ( recip_ktri.rid == cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(expected_recipient));
    assert! ( recip_ktri.key_enc_alg.parameters.is_some());

    assert! ( recip_ktri.enc_key.len() == Length::new(256) );

    let enc_alg_params = recip_ktri.key_enc_alg.parameters.as_ref().unwrap().decode_as::<RsaOaepParams>().unwrap();
    assert! ( enc_alg_params.hash_algorithm.oid == ID_SHA_256 );
    assert! ( enc_alg_params.hash_algorithm.parameters.unwrap() == Any::new(der::Tag::Null, [0u8;0]).unwrap());
   
    assert! ( enc_alg_params.mask_gen_algorithm.oid == ID_MGF_1);
    let mgf_1_params = enc_alg_params.mask_gen_algorithm.parameters.unwrap().decode_as::<Mgf1Params>().unwrap();
    assert! ( mgf_1_params.hash_algorithm == ID_SHA_256 );
    
    assert! ( enc_alg_params.p_source_algorithm.oid == ID_P_SPECIFIED);
    assert! ( enc_alg_params.p_source_algorithm.parameters.as_ref().unwrap() == &Any::new(der::Tag::OctetString, [0u8;0]).unwrap()); // empty
    
    let mb_encrypted_content_info = mb_enveloped_data.encrypted_content.clone();
    assert! ( mb_encrypted_content_info.content_type ==ID_DATA);
    assert! ( mb_encrypted_content_info.content_enc_alg.oid == der::oid::db::rfc5911::DES_EDE_3_CBC);
    assert! ( mb_encrypted_content_info.content_enc_alg.parameters.as_ref().unwrap().value() == hex!("0123456789ABCDEF"));
    
    let decryption_object = TR34DecryptOpenssl::new(
            |id| {
                assert! ( id == &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
                return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
            });
    let decrypted_content = token.decrypt(decryption_object);
    assert! ( decrypted_content.unwrap() == pem::parse(B_2_2_2_1_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_FILE).unwrap().contents());

}


#[test]
fn decode_b_2_2_3_2_sample_aes_enveloped_data() {
    
    let mb_enveloped_data = cms::enveloped_data::EnvelopedData::from_der(pem::parse(B_2_2_3_2_AES_ENVELOPED_DATA).unwrap().contents()).unwrap();
    let token = TR34EnvelopedToken::from_der(pem::parse(B_2_2_3_2_AES_ENVELOPED_DATA).unwrap().contents()).unwrap();

    let mb_enveloped_data_broken = pem::parse(B_2_2_3_2_AES_ENVELOPED_DATA_BROKEN).unwrap();
    let mb_enveloped_data_broken2 = EnvelopedData2::from_der(mb_enveloped_data_broken.contents()).unwrap();

    assert! ( mb_enveloped_data.encrypted_content.encrypted_content.as_ref().unwrap().as_bytes() == mb_enveloped_data_broken2.encrypted_content.content_enc_alg.parameters2.as_ref().unwrap().value()) ;
    
    assert! ( mb_enveloped_data.version == cms::content_info::CmsVersion::V0);
    assert! ( mb_enveloped_data.originator_info.is_none() );
    assert! ( mb_enveloped_data.originator_info.is_none());
    assert! ( mb_enveloped_data.unprotected_attrs.is_none());
    
    assert! ( mb_enveloped_data.recip_infos.0.is_empty()== false);
    assert! ( mb_enveloped_data.recip_infos.0.len() == 1);
    
    let recip_info = mb_enveloped_data.recip_infos.0.get(0).unwrap();
    let recip_ktri = match recip_info {
        cms::enveloped_data::RecipientInfo::Ktri ( v ) => v,
        _ => panic!("unhandled enum type"),
    };

    assert! ( recip_ktri.version == cms::content_info::CmsVersion::V0 );
    assert! ( recip_ktri.key_enc_alg.oid == ID_RSAES_OAEP);
    let expected_recipient = cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap();
    assert! ( recip_ktri.rid == cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(expected_recipient));
    assert! ( recip_ktri.key_enc_alg.parameters.is_some());

    let enc_alg_params = recip_ktri.key_enc_alg.parameters.as_ref().unwrap().decode_as::<RsaOaepParams>().unwrap();

    assert! ( enc_alg_params.hash_algorithm.oid == ID_SHA_256 );
    assert! ( enc_alg_params.hash_algorithm.parameters.unwrap() == Any::new(der::Tag::Null, [0u8;0]).unwrap());
    assert! ( enc_alg_params.mask_gen_algorithm.oid == ID_MGF_1);
    assert! ( enc_alg_params.mask_gen_algorithm.parameters.unwrap().decode_as::<Mgf1Params>().unwrap().hash_algorithm == ID_SHA_256 );
    assert! ( enc_alg_params.p_source_algorithm.oid == ID_P_SPECIFIED);
    assert! ( enc_alg_params.p_source_algorithm.parameters.as_ref().unwrap() == &Any::new(der::Tag::OctetString, [0u8;0]).unwrap()); // empty
   
    let mb_encrypted_content_info = mb_enveloped_data.encrypted_content;
    
    assert! ( mb_encrypted_content_info.content_type ==ID_DATA);
    assert! ( mb_encrypted_content_info.content_enc_alg.oid == ID_AES_128_CBC);
    assert! ( mb_encrypted_content_info.content_enc_alg.parameters.as_ref().unwrap().value() == hex!("0123456789ABCDEF"));
    
    // Has a mistake in AES decryption, see patches in TR34DecryptCEKOpenssl.decrypt_content
    let decryption_object = TR34DecryptOpenssl::new(|id| {
        assert!(id == &get_b_2_2_1_6_krd_1_id());
        return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
    });
    let decrypted_content = token.decrypt(decryption_object).unwrap();
    println! ( "Faulty sample, the decrypted content should use TR34Block, not the modified TRBlock2");
    let parsedblock2 = TR34Block2::from_der(&decrypted_content).unwrap();
    println! ( "Faulty sample, the issuer and serial number field does not parse and is different to the expected value");
    assert! ( parsedblock2.issuer_and_serial_number != Any::from_der(&get_b_2_2_1_4_kdh_1_id().to_der().unwrap()).unwrap());
    assert! ( parsedblock2.version == cms::content_info::CmsVersion::V1);
    assert! ( parsedblock2.clear_key.as_bytes() == hex!("0123456789ABCDEFFEDCBA9876543210"));
    assert! ( parsedblock2.attribute_header.oid == der::oid::db::rfc5911::ID_DATA);

    println! ( "Faulty sample, the reference in the following assertion D0256K0AB00E0000");
    assert! ( parsedblock2.attribute_header.values.get(0).unwrap().value() == "A0256K0TB00E0000".as_bytes());

    println! ( "Faulty sample, the inequality in the following assertion should be an equality");
    assert! ( decrypted_content != pem::parse(B_2_2_2_4_SAMPLE_AES_KEY_BLOCK_USING_ISSUER_AND_SERIAL_NUMBER).unwrap().contents());

}



#[test]
fn test_b_2_2_4_1_signed_attributes () {
    let pem = pem::parse(B_2_2_4_SAMPLE_SIGNED_ATTRIBUTES_1_PASS_DER).unwrap();
    // Need to use a reader so can call decode_implicit, otherwise decode explicit is called
    let mut reader = der::SliceReader::new(&pem.contents()).unwrap();
    let ctx = der::asn1::ContextSpecific::<cms::signed_data::SignedAttributes>::decode_implicit(&mut reader, der::TagNumber::new(0));
    let signed_attrs = ctx.unwrap().unwrap().value;

    assert! ( signed_attrs.len() == 4);

    let signed_attr_1 = signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.len() == 1);
    assert! ( signed_attr_1.values.get(0).unwrap().decode_as::<ObjectIdentifier>().unwrap() == ID_ENVELOPED_DATA );

    let signed_attr_2 = signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == der::oid::db::rfc5911::ID_SIGNING_TIME);
    assert! ( signed_attr_2.values.len() == 1);
    let time = UtcTime::from_unix_duration(std::time::Duration::from_secs(1581362033));
    assert! ( signed_attr_2.values.get(0).unwrap().decode_as::<UtcTime>().unwrap() == time.unwrap());

    let signed_attr_3 = signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == ID_DATA);
    assert! ( signed_attr_3.values.len() == 1);
    assert! ( signed_attr_3.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, "A0256K0TB00E0000".as_bytes()).unwrap() );
    
    let signed_attr_4 = signed_attrs.get(3).unwrap();
    assert! ( signed_attr_4.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_4.values.len() == 1);
    
}


#[test]
fn test_b_2_2_5_1_signed_attributes_2_pass () {
    let signed_attrs = cms::signed_data::SignedAttributes::from_der ( pem::parse(B_2_2_5_SAMPLE_AUTHENTICATED_ATTRIBUTES_2_PASS_PEM).unwrap().contents()).unwrap();
    
    assert! ( signed_attrs.len() == 4);

    let signed_attr_1 = signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.len() == 1);
    assert! ( signed_attr_1.values.get(0).unwrap().decode_as::<ObjectIdentifier>().unwrap() == ID_ENVELOPED_DATA );

    // TR-31 header!
    let signed_attr_2 = signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == ID_DATA);
    assert! ( signed_attr_2.values.len() == 1);
    assert! ( signed_attr_2.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, "A0256K0TB00E0000".as_bytes()).unwrap() );

    let signed_attr_3 = signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == tr34::ID_RANDOM_NONCE);
    assert! ( signed_attr_3.values.len() == 1);
    assert! ( signed_attr_3.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, hex!("167EB0E72781E4940112233445566778")).unwrap());

    let signed_attr_4 = signed_attrs.get(3).unwrap();
    assert! ( signed_attr_4.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_4.values.len() == 1);
    
}
/// 
/// 


#[test]
fn decode_b_3 () {
    let mb_content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_3_TR34_SAMPLE_ROOT_P7B).unwrap().contents()).unwrap();

    assert! ( mb_content_info.content_type == der::oid::db::rfc5911::ID_SIGNED_DATA);

    let signed_data: cms::signed_data::SignedData = mb_content_info.content.decode_as().unwrap();
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.digest_algorithms.len()==0);
    assert! ( signed_data.crls.is_none());
    assert! ( signed_data.signer_infos.0.is_empty());
    assert! ( signed_data.encap_content_info.econtent_type == ID_DATA);
    assert! ( signed_data.encap_content_info.econtent.unwrap() == Any::new(der::Tag::OctetString, [0u8;0]).unwrap());
    assert! ( signed_data.certificates.is_some());
    assert! ( signed_data.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_ca_root_cert())] );
}

#[test]
fn decode_b_4 () {
    let mb_content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_4_CA_KDH_P7B).unwrap().contents()).unwrap();

    assert! ( mb_content_info.content_type == der::oid::db::rfc5911::ID_SIGNED_DATA);

    let signed_data: cms::signed_data::SignedData = mb_content_info.content.decode_as().unwrap();
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.digest_algorithms.len()==0);
    assert! ( signed_data.crls.is_none());
    assert! ( signed_data.signer_infos.0.is_empty());
    assert! ( signed_data.encap_content_info.econtent_type == ID_DATA);
    assert! ( signed_data.encap_content_info.econtent.unwrap() == Any::new(der::Tag::OctetString, [0u8;0]).unwrap());
    assert! ( signed_data.certificates.is_some());
    assert! ( signed_data.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_ca_kdh_cert())] );
}

#[test]
fn decode_b_5 () {
    let mb_content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_5_SAMPLE_CA_KRD_P7B).unwrap().contents()).unwrap();

    assert! ( mb_content_info.content_type == der::oid::db::rfc5911::ID_SIGNED_DATA);

    let signed_data: cms::signed_data::SignedData = mb_content_info.content.decode_as().unwrap();
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.digest_algorithms.len()==0);
    assert! ( signed_data.crls.is_none());
    assert! ( signed_data.signer_infos.0.is_empty());
    assert! ( signed_data.encap_content_info.econtent_type == ID_DATA);
    assert! ( signed_data.encap_content_info.econtent.unwrap() == Any::new(der::Tag::OctetString, [0u8;0]).unwrap());
    assert! ( signed_data.certificates.is_some());
    assert! ( signed_data.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_ca_krd_cert())] );
}


#[test]
fn decode_b_6_kdh_credential_token () {
    let token = cms::content_info::ContentInfo::from_der(pem::parse(B_6_KDH_1_W_CRL_PEM).unwrap().contents()).unwrap();
    assert! (token.content_type == der::oid::db::rfc5911::ID_SIGNED_DATA);

    let signed_data_broken = token.content.decode_as::<cms::signed_data::SignedData>(); // not sure why this pem isnt valid....
    assert! ( signed_data_broken.is_err());

    // Use our own dodgy SignedData2 structure to decode 
    println! ( "Broken sample, b.6 has malformed SignedData");
    let signed_data = token.content.decode_as::<SignedData2>().unwrap();
    
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.certificates.is_some());
    assert! ( signed_data.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_kdh_1_cert())]);
 
    assert! ( signed_data.crls.is_some());
    assert! ( signed_data.crls.unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(get_ca_kdh_crl())]);
    assert! ( signed_data.signer_infos.0.is_empty());
    assert! ( signed_data.digest_algorithms.is_empty());

    let encap_content = signed_data.encap_content_info;
    assert! ( encap_content.econtent_type == der::oid::db::rfc5911::ID_DATA);
}

#[test]
fn decode_b_7_krd_credential_token () {
    let token = cms::content_info::ContentInfo::from_der(pem::parse(B_7_KRD_CREDENTIAL_TOKEN_1_P7B).unwrap().contents()).unwrap();
    assert! (token.content_type == ID_SIGNED_DATA);

    let signed_data = token.content.decode_as::<cms::signed_data::SignedData>().unwrap();
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_krd_1_cert())]);
    assert! ( signed_data.crls.is_none());
    assert! ( signed_data.signer_infos.0.is_empty());
    assert! ( signed_data.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_DATA);
    assert! ( signed_data.encap_content_info.econtent.unwrap() == Any::new(der::Tag::OctetString, [0u8;0]).unwrap());
}





#[test]
fn decode_b_8_ktkdh_1_pass() {
    let mb_content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_8_ONE_PASS_KEY_TOKEN).unwrap().contents()).unwrap();
     
    assert! ( mb_content_info.content_type == ID_SIGNED_DATA);

    let mb_signed_data: cms::signed_data::SignedData = mb_content_info.content.decode_as().unwrap();
    let key_token = TR34KeyToken::from_der(pem::parse(B_8_ONE_PASS_KEY_TOKEN).unwrap().contents()).unwrap();
    let mb_signed_data2 = key_token.get_outer_signed_data().unwrap();
   
    assert! ( mb_signed_data == mb_signed_data2);

    assert! ( mb_signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( mb_signed_data.digest_algorithms.as_ref().to_vec() == vec![rsa::pkcs8::spki::AlgorithmIdentifierOwned{oid:ID_SHA_256,parameters: None }]);
    assert! ( mb_signed_data.certificates.is_none());
    assert! ( mb_signed_data.crls.clone().unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(cms::cert::x509::crl::CertificateList::from_der ( pem::parse(B_2_1_3_TR34_SAMPLE_KDH_CRL).unwrap().contents()).unwrap())]);
    
    assert! ( key_token.get_crl().unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(cms::cert::x509::crl::CertificateList::from_der ( pem::parse(B_2_1_3_TR34_SAMPLE_KDH_CRL).unwrap().contents()).unwrap())]);
        
    assert! ( mb_signed_data.signer_infos.0.len() == 1);
    let signer_info = mb_signed_data.signer_infos.0.get(0).unwrap();
    assert! ( signer_info.version == cms::content_info::CmsVersion::V1);
    assert! ( signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
    assert! ( signer_info.digest_alg.oid == ID_SHA_256);
    assert! ( signer_info.digest_alg.parameters.is_none());
    assert! ( signer_info.signature_algorithm.oid == der::oid::db::rfc5912::RSA_ENCRYPTION); // ID_SHA_256_WITH_RSA_ENCRYPTION);
    assert! ( signer_info.signature_algorithm.parameters.as_ref().unwrap() == &Any::new(der::Tag::Null, [0u8;0]).unwrap());
    assert! ( signer_info.signed_attrs.as_ref().unwrap() == &get_b_2_2_4_signed_attr_1_pass());
    assert! ( signer_info.unsigned_attrs.is_none() );

    
    assert! ( key_token.get_timestamp().unwrap() == UtcTime::from_unix_duration(std::time::Duration::from_secs(1581362033)).unwrap());
    key_token.get_cms();
    
    let verify_with_kdh_1_openssl = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        return get_kdh_1_pub_key();
    });
    assert! ( key_token.verify_signature(verify_with_kdh_1_openssl) == true);
    assert! ( key_token.get_inner_enveloped_data().unwrap() == cms::enveloped_data::EnvelopedData::from_der(pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents()).unwrap());

    let decrypt_using_krd_openssl = keyblock::tr34openssl::TR34DecryptOpenssl::new ( 
        | id| {
        assert! ( id == &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
        return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
        //return get_priv_key_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12);
    });

    let decryped_payload: Result<Vec<u8>, tr34::Error> = key_token.decrypt(decrypt_using_krd_openssl);
    assert! ( decryped_payload.is_ok());
    assert! ( decryped_payload.unwrap() == pem::parse(B_2_2_2_3_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_PEM).unwrap().contents());

    assert! ( key_token.get_key_block_header().unwrap() == "A0256K0TB00E0000".as_bytes());

    let key_block_header = key_token.get_key_block_header2().unwrap();
    assert! ( key_block_header.get_version() == keyblock::KeyBlockVersion::A_KEY_VARIANT);
    assert! ( key_block_header.get_usage() == keyblock::KeyUsage("K0"));
    assert! ( key_block_header.get_algorithm() == keyblock::KeyAlgorithm::TDES);
    assert! ( key_block_header.get_mode() == keyblock::KeyMode::B_ENCRYPT_WRAP_DECRYPT_UNWRAP);
    assert! ( key_block_header.get_exportability() == keyblock::KeyExportability::E_EXPORTABLE);
    
        
}




#[test]
fn decode_b_9_ktkdh_2_pass() {
    let key_token = TR34KeyToken::from_der( pem::parse(B_9_TWO_PASS_TOKEN).unwrap().contents()).unwrap();

    let signed_data = key_token.get_outer_signed_data().unwrap();
    
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_data.digest_algorithms.len()==1);
    assert! ( signed_data.digest_algorithms.get(0).unwrap().oid ==ID_SHA_256);
    assert! ( signed_data.digest_algorithms.get(0).unwrap().parameters.is_none());
    assert! ( signed_data.certificates.is_none());
    assert! ( signed_data.crls.clone().unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(get_ca_kdh_crl())]);
            
    let signer_info = signed_data.signer_infos.0.get(0).unwrap();
    
    assert! ( signer_info.version == cms::content_info::CmsVersion::V1);
    assert! ( signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
    assert! ( signer_info.digest_alg.oid == ID_SHA_256);
    assert! ( signer_info.digest_alg.parameters.is_none());
    assert! ( signer_info.signature_algorithm.oid == der::oid::db::rfc5912::RSA_ENCRYPTION); // ID_SHA_256_WITH_RSA_ENCRYPTION);
    assert! ( signer_info.signature_algorithm.parameters.as_ref().unwrap() == &Any::new(der::Tag::Null, [0u8;0]).unwrap());
    assert! ( signer_info.unsigned_attrs.is_none() );

    let signed_attrs = signer_info.signed_attrs.as_ref().unwrap();
    assert! ( signed_attrs.len() == 4);

    let signed_attr_1 = signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.len() == 1);
    assert! ( signed_attr_1.values.get(0).unwrap().decode_as::<ObjectIdentifier>().unwrap() == ID_ENVELOPED_DATA );
    
    // TR-31 header!
    let signed_attr_2 = signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == ID_DATA);
    assert! ( signed_attr_2.values.len() == 1);
    assert! ( signed_attr_2.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, "A0256K0TB00E0000".as_bytes()).unwrap());

    assert! ( key_token.get_key_block_header().unwrap() == "A0256K0TB00E0000".as_bytes());
                                                   
    let signed_attr_3 = signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == tr34::ID_RANDOM_NONCE);
    assert! ( signed_attr_3.values.len() == 1);
    assert! ( signed_attr_3.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, [22,126,176,231,39,129,228,148,1,18,35,52,69,86,103,120]).unwrap() );

    assert! ( key_token.get_random_number().unwrap() == [22,126,176,231,39,129,228,148,1,18,35,52,69,86,103,120]);

    let signed_attr_4 = signed_attrs.get(3).unwrap();
    assert! ( signed_attr_4.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_4.values.len() == 1);

    let verify_with_kdh_1 = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        return get_kdh_1_pub_key();
    });
    assert! ( key_token.verify_signature(verify_with_kdh_1) == false);

    assert! (signed_data.encap_content_info.econtent_type == ID_ENVELOPED_DATA);
    assert! (signed_data.encap_content_info.econtent.as_ref().unwrap().header().unwrap().tag == der::Tag::OctetString);
    
    let mb_enveloped_data = cms::enveloped_data::EnvelopedData::from_der ( signed_data.encap_content_info.econtent.unwrap().value()).unwrap();
    assert! ( mb_enveloped_data == cms::enveloped_data::EnvelopedData::from_der ( pem::parse(B_2_2_3_1_TDEA_ENVELOPED_DATA).unwrap().contents()).unwrap());

    let decrypt_with_krd = TR34DecryptOpenssl::new (
        | id | {
            assert! ( id == &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
            return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12)
        } );

    let decrypted_payload = key_token.decrypt(decrypt_with_krd).unwrap();
    assert! ( decrypted_payload == pem::parse(B_2_2_2_3_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_PEM).unwrap().contents());


}





#[test]
fn decode_b_10_ca_rebind_token() {
    let rbt_content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_10_TR34_SAMPLE_RBT_CA_UNBIND_PEM).unwrap().contents()).unwrap();
    let rebind_token = TR34CaRebindToken::from_der( pem::parse(B_10_TR34_SAMPLE_RBT_CA_UNBIND_PEM).unwrap().contents()).unwrap();
    
    assert! ( rbt_content_info.content_type == ID_SIGNED_DATA);

    let rbt_signed_outer : cms::signed_data::SignedData = rbt_content_info.content.decode_as().unwrap();
    
    assert! ( rbt_signed_outer.digest_algorithms.clone().into_vec() == vec![rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: ID_SHA_256, parameters: None}]);
    assert! ( rbt_signed_outer.certificates.is_none());
    assert! ( rbt_signed_outer.crls.is_none());

    assert! ( rbt_signed_outer.signer_infos.0.len() == 1);

    let outer_signer_info = rbt_signed_outer.signer_infos.0.get(0).unwrap();
    assert! ( outer_signer_info.digest_alg.oid == ID_SHA_256);
    assert! ( outer_signer_info.digest_alg.parameters.is_none());
    assert! ( outer_signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_3_ca_krd_id()));
    
    let outer_signed_attrs = outer_signer_info.signed_attrs.as_ref().unwrap();

    let signed_attr_1 = outer_signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.len() == 1);
    assert! ( signed_attr_1.values.get(0).unwrap().decode_as::<ObjectIdentifier>().unwrap() == ID_SIGNED_DATA );
    
    let signed_attr_2 = outer_signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == der::oid::db::rfc5911::ID_SIGNING_TIME);
    assert! ( signed_attr_2.values.len() == 1);
    let expected_time = UtcTime::from_unix_duration(std::time::Duration::from_secs(1328016134));
    assert! ( signed_attr_2.values.get(0).unwrap().decode_as::<UtcTime>().unwrap() == expected_time.unwrap());

    let signed_attr_3 = outer_signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_3.values.len() == 1);
    
    let verify_with_ca_krd = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_3_ca_krd_id()));
        return get_ca_krd_openssl();
    });
    assert! ( rebind_token.verify_signature(verify_with_ca_krd) == true);
    

    assert! ( rbt_signed_outer.encap_content_info.econtent_type == ID_SIGNED_DATA);
    let econtent_as_sequence = Any::new(der::Tag::Sequence, rbt_signed_outer.encap_content_info.econtent.unwrap().value()).unwrap();
    let signed_inner = econtent_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();

    assert! ( signed_inner.version == cms::content_info::CmsVersion::V1);
    assert! ( signed_inner.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_kdh_2_cert())] );
    assert! ( signed_inner.crls.is_none());
    assert! ( signed_inner.digest_algorithms.is_empty());
    assert! ( signed_inner.signer_infos.0.is_empty());
    
    assert! ( signed_inner.encap_content_info.econtent_type == ID_DATA);

    // Different to TR-34, which says there is a single sequence with on issuer... have to a dodgty to parse the two blocks
    println! ( "Faulty Sample: Missing a sequence tag in the esigned content");
    let as_seq = Any::new ( der::Tag::Sequence, signed_inner.encap_content_info.econtent.unwrap().value()).unwrap();
    let unbind_id = as_seq.decode_as::<tr34::UbtCaUnbind>().unwrap();

    assert! ( unbind_id.id_krd == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let unbind_id2 = rebind_token.get_rebind_ids().unwrap();
    assert! ( unbind_id2.id_krd == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    assert! ( unbind_id2.id_kdh == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    assert! ( rebind_token.get_new_kdh_cred() == get_kdh_2_cert());

    let signer_with_ca_krd = TR34SignOpenssl::new (
        get_priv_key_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12),
        cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let built_ca_rebind_token2 = TR34CaRebindToken::build (
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        get_kdh_2_cert(),
        &UtcTime::from_unix_duration(std::time::Duration::from_secs(1328016134)).unwrap(),
        signer_with_ca_krd
    ).unwrap();

    assert! ( built_ca_rebind_token2 == rebind_token);

 }
    



#[test]
fn decode_b_11_kdh_rebind() {
    let content_info = cms::content_info::ContentInfo::from_der(pem::parse(B_11_SAMPLE_RBT_KDH_PEM).unwrap().contents()).unwrap();
    let rebind_token = TR34KdhRebindToken::from_der(pem::parse(B_11_SAMPLE_RBT_KDH_PEM).unwrap().contents()).unwrap();
 
    assert! ( content_info.content_type == ID_SIGNED_DATA);

    let signed_outer : cms::signed_data::SignedData = content_info.content.decode_as().unwrap();

    let verify_with_kdh_1_openssl = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        return get_kdh_1_pub_key();
    });
    assert! ( rebind_token.verify_signature(verify_with_kdh_1_openssl) == true);
    
    assert! ( signed_outer.digest_algorithms.into_vec() == vec![rsa::pkcs8::spki::AlgorithmIdentifierOwned { oid: ID_SHA_256, parameters: None}]);
    assert! ( signed_outer.certificates.is_none());
    assert! ( signed_outer.crls.as_ref().is_some());
    assert! ( signed_outer.crls.unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(get_ca_kdh_crl())]);
    assert! ( signed_outer.signer_infos.0.len() == 1);
    assert! ( signed_outer.version == cms::content_info::CmsVersion::V1);

    let outer_signer_info = signed_outer.signer_infos.0.get(0).unwrap();
    assert! ( outer_signer_info.digest_alg.oid == ID_SHA_256);
    assert! ( outer_signer_info.digest_alg.parameters.is_none());
    assert! ( outer_signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));

    let outer_signed_attrs = outer_signer_info.signed_attrs.as_ref().unwrap();
    
    let signed_attr_1 = outer_signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.len() == 1);
    assert! ( signed_attr_1.values.get(0).unwrap().decode_as::<ObjectIdentifier>().unwrap() == ID_SIGNED_DATA );
    
    let signed_attr_2 = outer_signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == tr34::ID_RANDOM_NONCE);
    assert! ( signed_attr_2.values.len() == 1);
    assert! ( signed_attr_2.values.get(0).unwrap().decode_as::<OctetString>().unwrap() == OctetString::new([125,234,28,0,137,78,36,106]).unwrap() );

    let signed_attr_3 = outer_signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_3.values.len() == 1);
    
    assert! ( signed_outer.encap_content_info.econtent_type == ID_SIGNED_DATA);
    
    // There seems to be a missing SEQUENCE in the stream, decode with a dummy header
    let inner_as_sequence = Any::new( der::Tag::Sequence, signed_outer.encap_content_info.econtent.unwrap().value()).unwrap();
    let inner = inner_as_sequence.decode_as::<cms::signed_data::SignedData>().unwrap();
     
    assert! ( inner.certificates.unwrap().0.into_vec() == vec![cms::cert::CertificateChoices::Certificate(get_kdh_2_cert())] );
    assert! ( inner.crls.is_none());
    assert! ( inner.digest_algorithms.is_empty());
    assert! ( inner.signer_infos.0.is_empty());
    assert! ( inner.version == cms::content_info::CmsVersion::V1);
    
    assert! ( inner.encap_content_info.econtent_type == ID_DATA);

    // ignore OctetString header and parse value as der
    let unbind_id = cms::cert::IssuerAndSerialNumber::from_der( inner.encap_content_info.econtent.unwrap().value()).unwrap();
    assert! ( unbind_id == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    
    assert! ( rebind_token.get_rebind_id().unwrap() == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    assert! ( rebind_token.get_new_kdh_cred() == get_kdh_2_cert());
    assert! ( rebind_token.get_random_number().unwrap() == hex!("7D EA 1C 00 89 4E 24 6A"));

    let signer_with_kdh_1 = TR34SignOpenssl::new (
        get_priv_key_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12),
        cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
  
    let built_kdh_rebind_token = TR34KdhRebindToken::build(
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        get_kdh_2_cert(),
        &get_ca_kdh_crl(),
        &hex!("7D EA 1C 00 89 4E 24 6A"),
        signer_with_kdh_1
    ).unwrap();

    assert! ( built_kdh_rebind_token == rebind_token );

}

#[test]
fn decode_b_12 () {
    let rngtoken = cms::cert::x509::attr::Attribute::from_der(pem::parse(B_12_KRD_RANDOM_NUMBER_TOKEN).unwrap().contents()).unwrap();
    let rngtoken2 = TR34RandomNumberToken::from_der(pem::parse(B_12_KRD_RANDOM_NUMBER_TOKEN).unwrap().contents()).unwrap();
    assert! ( rngtoken.oid == tr34::ID_RANDOM_NONCE);
    assert! ( rngtoken.values.into_vec() == vec![Any::new(der::Tag::OctetString, hex!("167EB0E72781E4940112233445566778")).unwrap()]);
    assert! ( rngtoken2.get_random_number().unwrap() == hex!("167EB0E72781E4940112233445566778"));

    let built_token = TR34RandomNumberToken::build ( &hex!("167EB0E72781E4940112233445566778") ).unwrap();
    assert! ( built_token == rngtoken2);
}


#[test]
fn decode_b_13_ca_unbind () {
    let cms_content = cms::content_info::ContentInfo::from_der(pem::parse(B_13_UBT_CA_UNBIND).unwrap().contents()).unwrap();
    let parsed_unbind_token = TR34CaUnbindToken::from_der(pem::parse(B_13_UBT_CA_UNBIND).unwrap().contents()).unwrap();
    
    assert! (cms_content.content_type == ID_SIGNED_DATA);
    let signed_data: cms::signed_data::SignedData = cms_content.content.decode_as().unwrap();

    assert! ( signed_data.version == cms::content_info::CmsVersion::V1 );  // Is V3 according to TR-34
    assert! ( signed_data.digest_algorithms.get(0).unwrap().oid == ID_SHA_256);
    assert! ( signed_data.certificates.is_none());
    assert! ( signed_data.crls.is_none());

    assert! ( signed_data.signer_infos.0.len() == 1 );
    let signer_info = signed_data.signer_infos.0.get(0).unwrap();
    assert! ( signer_info.version == cms::content_info::CmsVersion::V1 );
    assert! ( signer_info.signed_attrs.is_none());
    assert! ( signer_info.digest_alg.oid == ID_SHA_256 );
    assert! ( signer_info.signature_algorithm.oid == der::oid::db::rfc5912::RSA_ENCRYPTION /*ID_SHA_256_WITH_RSA_ENCRYPTION*/);
    assert! ( signer_info.unsigned_attrs.is_none());
    assert! ( signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_3_ca_krd_id()));

    let verify_with_ca_krd = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_3_ca_krd_id()));
        return get_ca_krd_openssl();
    });
    assert! ( parsed_unbind_token.verify_signature(verify_with_ca_krd) == true);
    
    assert! ( signed_data.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_DATA );
    let econtents_as_octet_string = signed_data.encap_content_info.econtent.as_ref().unwrap().decode_as::<OctetString>().unwrap();
   
    // There seems to be a missing SEQUENCE in the stream, decode with a dummy header
    let econtent_as_sequence = Any::new( der::Tag::Sequence, econtents_as_octet_string.as_bytes()).unwrap();
    let content = econtent_as_sequence.decode_as::<tr34::UbtCaUnbind>().unwrap();

    // Confirm that main payload has recognised ids
    assert! ( content.id_kdh == get_b_2_2_1_4_kdh_1_id());
    assert! ( content.id_kdh == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    assert! ( content.id_krd == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let unbind_id2 = parsed_unbind_token.get_unbind_ids();
    assert! ( unbind_id2.id_krd == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    assert! ( unbind_id2.id_kdh == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let signer_with_ca_krd = TR34SignOpenssl::new (
        get_priv_key_openssl(B_2_1_4_TR34_SAMPLE_CA_KRD_KEY_P12),
        cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    
    let built_ca_rebind_token2 = TR34CaUnbindToken::build(
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        signer_with_ca_krd
    ).unwrap();

    assert! ( built_ca_rebind_token2 == parsed_unbind_token );


}


#[test]
fn decode_b_14_kdh_unbind () {
    let pem = pem::parse(B_14_UBT_KDH_UNBIND).unwrap();
    let cms_content = cms::content_info::ContentInfo::from_der(pem.contents()).unwrap();
    let unbind_token = tr34::TR34KdhUnbindToken::from_der(pem.contents()).unwrap();
    assert! (cms_content.content_type == ID_SIGNED_DATA);

    let signed_data: cms::signed_data::SignedData = cms_content.content.decode_as().unwrap();
    assert! ( signed_data.version == cms::content_info::CmsVersion::V1 );  // Is V3 according to TR-34
    assert! ( signed_data.digest_algorithms.as_ref().get(0).unwrap().oid == ID_SHA_256);
    assert! ( signed_data.certificates.is_none());
    assert! ( signed_data.crls.is_some());
    assert! ( signed_data.crls.clone().unwrap().0.into_vec() == vec![cms::revocation::RevocationInfoChoice::Crl(get_ca_kdh_crl())]);
    
    assert! ( signed_data.signer_infos.0.len() == 1 );
    let signer_info = signed_data.signer_infos.as_ref().get(0).unwrap();
    assert! ( signer_info.version == cms::content_info::CmsVersion::V1 );
    assert! ( signer_info.signed_attrs.is_some());
    assert! ( signer_info.digest_alg.oid == ID_SHA_256 );
    assert! ( signer_info.signature_algorithm.oid == der::oid::db::rfc5912::RSA_ENCRYPTION /*ID_SHA_256_WITH_RSA_ENCRYPTION*/);
    assert! ( signer_info.unsigned_attrs.is_none());
    assert! ( signer_info.sid == cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()) );
    
    let signed_attrs = signer_info.signed_attrs.as_ref().unwrap();
    assert! (signed_attrs.len() == 3);

    let signed_attr_1 = signed_attrs.get(0).unwrap();
    assert! ( signed_attr_1.oid == ID_CONTENT_TYPE);
    assert! ( signed_attr_1.values.get(0).unwrap() == &der::oid::db::rfc5911::ID_DATA.into());
        
    let signed_attr_2 = signed_attrs.get(1).unwrap();
    assert! ( signed_attr_2.oid == tr34::ID_RANDOM_NONCE);
    assert! ( signed_attr_2.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, hex!("7DEA1C00894E246A")).unwrap());

    assert! ( unbind_token.get_random_number().unwrap() == hex!("7DEA1C00894E246A"));
    
    let signed_attr_3 = signed_attrs.get(2).unwrap();
    assert! ( signed_attr_3.oid == ID_MESSAGE_DIGEST);
    assert! ( signed_attr_3.values.get(0).unwrap() == &Any::new(der::Tag::OctetString, hex!("8798168E6F7F3118EDE8522B6336DFB56CFDF95DB7063CB7230EF00B4D666D1A")).unwrap());
    
    let verify_with_kdh_1 = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        return get_kdh_1_pub_key();
    });
    assert! ( unbind_token.verify_signature(verify_with_kdh_1) == true);
    

    assert! ( signed_data.encap_content_info.econtent_type == der::oid::db::rfc5911::ID_DATA );
    
    // Content contains a single KRDidentifier
    let econtents = signed_data.encap_content_info.econtent.unwrap().decode_as::<OctetString>().unwrap();
    let krd_id = cms::cert::IssuerAndSerialNumber::from_der(econtents.as_bytes());
    //let krd_id = econtents.decode_as::<cms::cert::IssuerAndSerialNumber>();
    
    assert! (krd_id.unwrap() == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let krd_id2 = unbind_token.get_krd_id();
    assert! (krd_id2.unwrap() == cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());

    let signer_with_kdh_1 = TR34SignOpenssl::new (
        get_priv_key_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12),
        cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap());
    
    let built_kdh_unbind_token2 = tr34::TR34KdhUnbindToken::build(
        &cms::cert::IssuerAndSerialNumber::from_der(pem::parse(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).unwrap().contents()).unwrap(),
        &get_ca_kdh_crl(),
        &hex!("7DEA1C00894E246A"),
        signer_with_kdh_1
    ).unwrap();

    assert! ( built_kdh_unbind_token2 == unbind_token );
    
}





fn decode_ca_kdh_issuer_and_serial_number (issuer_and_serial_number: &cms::cert::IssuerAndSerialNumber, issuer_name:&str, expected_serial_number: u64) {
     
    assert! ( issuer_and_serial_number.issuer.0.len() == 3);
    let signer_issuer_1 = issuer_and_serial_number.issuer.0.get(0).unwrap();
    let signer_issuer_2 = issuer_and_serial_number.issuer.0.get(1).unwrap();
    let signer_issuer_3 = issuer_and_serial_number.issuer.0.get(2).unwrap();

    let signer_issuer_1_attribute_1 = signer_issuer_1.0.get(0).unwrap();
    assert! ( signer_issuer_1_attribute_1.oid == COUNTRY_NAME );
    assert! ( signer_issuer_1_attribute_1.value.decode_as::<der::asn1::PrintableString>().unwrap().to_string() == "US" );

    let signer_issuer_2_attribute_1 = signer_issuer_2.0.get(0).unwrap();
    assert! ( signer_issuer_2_attribute_1.oid == der::oid::db::rfc4519::ORGANIZATION_NAME);
    assert! ( signer_issuer_2_attribute_1.value.decode_as::<der::asn1::PrintableString>() == der::asn1::PrintableString::new("TR34 Samples") );

    let signer_issuer_3_attribute_1 = signer_issuer_3.0.get(0).unwrap();
    assert! ( signer_issuer_3_attribute_1.oid == der::oid::db::rfc4519::COMMON_NAME);
    assert! ( signer_issuer_3_attribute_1.value.decode_as::<der::asn1::PrintableString>() == der::asn1::PrintableString::new(issuer_name));

    assert! ( issuer_and_serial_number.serial_number.as_bytes().len() == 5);
    let mut serial_number_as_8_byte_array = [0u8; 8];
    serial_number_as_8_byte_array[3..].clone_from_slice(issuer_and_serial_number.serial_number.as_bytes());
    let serial_number_as_u64 = u64::from_be_bytes(serial_number_as_8_byte_array);

    assert! ( expected_serial_number == serial_number_as_u64);
   
}



fn get_ca_kdh_crl() -> cms::cert::x509::crl::CertificateList {
    return decode_from_pem(B_2_1_3_TR34_SAMPLE_KDH_CRL).decode_as().unwrap();
}



fn get_b_2_2_1_3_ca_krd_id() -> cms::cert::IssuerAndSerialNumber {
    // let pem2 = pem::parse(B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER).unwrap();
    // let ca_krd_issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem2.contents()).unwrap();
    // ca_krd_issuer_and_serial_number
    return decode_from_pem(B_2_2_1_3_CA_KRD_ISSUER_AND_SERIAL_NUMBER).decode_as::<cms::cert::IssuerAndSerialNumber>().unwrap();
}
fn get_b_2_2_1_4_kdh_1_id() -> cms::cert::IssuerAndSerialNumber {
    //let pem3 = pem::parse(B_2_2_1_4_KDH_1_ISUER_AND_SERIAL_NUMBER).unwrap();
    //let kdh_1_issuer_and_serial_number = cms::cert::IssuerAndSerialNumber::from_der(pem3.contents()).unwrap();
    //kdh_1_issuer_and_serial_number
    return decode_from_pem(B_2_2_1_4_KDH_1_ISSUER_AND_SERIAL_NUMBER).decode_as::<cms::cert::IssuerAndSerialNumber>().unwrap();
}
fn get_b_2_2_1_6_krd_1_id() -> cms::cert::IssuerAndSerialNumber {
    return decode_from_pem(B_2_2_1_6_KRD_1_ISSUER_AND_SERIAL_NUMBER).decode_as().unwrap();
}

// fn get_b_2_2_2_1_tdea_content_file() -> keyblock::tr34::TR34Block {
//     return decode_from_pem(B_2_2_2_1_TR34_SAMPLE_TDEA_ENCRYPTED_CONTENT_FILE).decode_as().unwrap();
// }
fn get_b_2_2_4_signed_attr_1_pass() -> cms::signed_data::SignedAttributes {
    let context_specific = decode_from_pem(B_2_2_4_SAMPLE_SIGNED_ATTRIBUTES_1_PASS_DER);
    return Any::new( der::Tag::Set, context_specific.value()).unwrap().decode_as::<cms::signed_data::SignedAttributes>().unwrap();
}




fn decode_from_pem ( pem_contents: &str ) -> Any{
    let pem = pem::parse(pem_contents).unwrap();
    return Any::from_der(pem.contents()).unwrap();
}



const ID_SHA_256_WITH_RSA_ENCRYPTION2: der::asn1::ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ID_PKCS8_SHROUDED_KEY_BAG: der::asn1::ObjectIdentifier= ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");


#[test]
fn test_encode_random () {

    let random_number = vec! [ 0, 1, 2, 3, 4, 5, 6, 7 ];
    let createdtoken = TR34RandomNumberToken::build(&random_number).unwrap();
    let token_as_der = createdtoken.to_der().unwrap();
    let parsedtoken = TR34RandomNumberToken::from_der ( &token_as_der ).unwrap();
    assert! ( parsedtoken.get_random_number().unwrap() == random_number);
}



#[test]
fn test_encode_1_pass_key_token () {
    let random_number = vec! [ 0, 1, 2, 3, 4, 5, 6, 7 ];
    let key_to_transport = [3u8; 24];
    
    let encrypt_with_krd = keyblock::tr34openssl::TR34EncryptOpenssl::new (
        get_pub_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12),
        get_b_2_2_1_6_krd_1_id());
    let sign_with_kdh = TR34SignOpenssl::new(
         get_priv_key_openssl(B_2_1_5_TR34_SAMPLE_KDH_1_KEY_P12),
         get_b_2_2_1_4_kdh_1_id());

    let token = TR34KeyToken::build ( 
        &get_b_2_2_1_4_kdh_1_id(), /*&get_b_2_2_1_6_krd_1_id(),*/ 
        "ABCDEF".as_bytes(), &key_to_transport, Some(&random_number),
        encrypt_with_krd, sign_with_kdh).unwrap();

    assert! ( token.get_random_number().unwrap() == random_number);
    assert! ( token.get_key_block_header().unwrap() == "ABCDEF".as_bytes());

    let verify_with_kdh_1 = TR34VerifyOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(get_b_2_2_1_4_kdh_1_id()));
        return get_kdh_1_pub_key();
    });
    assert! ( token.verify_signature(verify_with_kdh_1) == true);
        
    let decrypt_with_krd = TR34DecryptOpenssl::new(|issuer_id| {
        assert! ( issuer_id == &get_b_2_2_1_6_krd_1_id());
        return get_priv_key_openssl(B_2_1_7_TR34_SAMPLE_KRD_1_KEY_P12);
    });
    let recovered_key2 = token.get_plaintext_key2(decrypt_with_krd);
    assert! ( recovered_key2.unwrap() == key_to_transport );

   

}





