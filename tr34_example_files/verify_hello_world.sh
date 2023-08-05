#!/bin/sh -x
openssl cms -verify -in helloworld.encrypted.signed.der -inform der -certfile b.2.1.5.kdh1.pem -noverify -out helloworld.unsigned.der
openssl cms -decrypt -in helloworld.unsigned.der -inform der -recip b.2.1.5.kdh1.pem
