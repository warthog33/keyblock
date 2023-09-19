#!/bin/sh -x
openssl asn1parse -in b.8.keytoken.pem -inform pem -out b.8.keytoken.der -noout
openssl cms -cmsout -in b.8.keytoken.der -inform der -noverify -print 
openssl cms -verify -in b.8.keytoken.der -inform der -certfile b.2.1.5.kdh1.pem -noverify -out b.8.keytoken.inner.der
openssl asn1parse -in b.8.keytoken.inner.der -inform der
openssl cms -cmsout -in b.8.keytoken.inner.der -inform der -noverify -print
