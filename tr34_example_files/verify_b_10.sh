#!/bin/sh -x
openssl cms -cmsout -in b.10.caunbind.pem -inform pem -noverify -print 
openssl cms -verify -in b.10.caunbind.pem -inform pem -certfile b.2.1.2.cakdh.pem -noverify -out b.10.caunbind.inner.der
