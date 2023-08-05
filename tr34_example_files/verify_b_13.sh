#!/bin/sh -x
openssl asn1parse -in b.13.caunbind.pem -inform pem -out b.13.caunbind.der
openssl cms -cmsout -in b.13.caunbind.der -inform der -noverify -print 
openssl cms -verify -in b.13.caunbind.der -inform der -certfile b.2.1.4.cakrh.pem -noverify -out b.13.caunbind.inner.der
