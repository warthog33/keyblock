#!/bin/sh -x
openssl asn1parse -in b.14.kdhunbind.pem -inform pem -out b.14.kdhunbind.der
openssl cms -cmsout -in b.14.kdhunbind.der -inform der -noverify -print 
openssl cms -verify -in b.14.kdhunbind.der -inform der -certfile b.2.1.5.kdh1.pem -noverify -out b.14.kdhunbind.inner.der
