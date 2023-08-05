#!/bin/sh -x
#openssl cms -sign -signer b.2.1.5.kdh1.pem -in helloworld.txt -nodetach -outform der -out helloworld.signed.der -nocerts -outform der 
openssl cms -encrypt -recip b.2.1.5.kdh1.pem -in helloworld.txt -inform der -out helloworld.encrypted.der -nocerts -outform der 
openssl pkcs7 -sign -signer b.2.1.5.kdh1.pem -in helloworld.encrypted.der -inform der -nodetach -outform der -out helloworld.encrypted.signed.der -nocerts
#openssl cms -encrypt -recip b.2.1.5.kdh1.pem -in helloworld.txt -inform der  -nocerts -outform der | openssl cms -sign -signer b.2.1.5.kdh1.pem -nodetach -outform der -out helloworld.encrypted.signed.der -nocerts 
