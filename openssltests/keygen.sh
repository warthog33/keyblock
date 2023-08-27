#!/bin/sh -x
#openssl genpkey -algorithm EC -out key.pem -outform pem -cipher AES 
#-pkeyopt ec_paramgen_curve:P-256 ec_param_enc:named_curve -text
               -pkeyopt ec_paramgen_curve:P-384 \
               -pkeyopt ec_param_enc:named_curve

#openssl genpkey -algorithm EC -out eckeykrd.pem -pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve
openssl genpkey -algorithm RSA -out eckeykrd.pem 

openssl x509 -new -subj '/countryName=AU/organizationName=TR34 EC Samples/commonName=TR34 EC Sample Root/' -key eckey.pem -out eckey.cert
openssl x509 -new -subj '/countryName=AU/organizationName=TR34 EC Samples/commonName=TR34 EC Sample KRD/' -key eckeykrd.pem -out eckeykrd.cert

cat eckey.pem eckey.cert > eckey.pair
cat eckeykrd.pem eckeykrd.cert > eckeykrd.pair


openssl cms -encrypt -in helloworld.txt -inform der -recip eckeykrd.cert -out encrypted.der -outform der -aes192 -keyopt rsa_padding_mode:oaep -aes192-wrap   -keyopt rsa_oaep_md:sha1 -keyopt rsa_mgf1_md:sha1
#openssl cms -encrypt -in helloworld.txt -inform der -recip eckeykrd.cert -out encrypted.der -outform der -aes192 -aes128-wrap -keyopt ecdh_kdf_md:sha256
openssl cms -sign -in encrypted.der -inform der -signer eckey.pair -out signed_and_encrypted.pem -outform pem -nodetach -nocerts -binary 

#openssl cms -cmsout -print -in signed.pem -inform pem

openssl cms -verify -in signed_and_encrypted.pem -inform pem -certfile eckey.cert -CAfile eckey.cert -nointern -nosigs -out verified.der -outform der
diff encrypted.der verified.der
ls -l encrypted.der verified.der


#openssl cms -cmsout -print -in verified.der -inform der 
#openssl cms -decrypt -in verified.der -inform der -originator eckey.cert -recip eckeykrd.pair -out decrypted.txt -keyopt ecdh_kdf_md:sha256
openssl cms -decrypt -in verified.der -inform der -originator eckey.cert -recip eckeykrd.pair -out decrypted.txt 

