#!/bin/sh -x
openssl cms -cmsout -in b.9.2passtoken.pem -inform pem -noverify -print 
openssl cms -verify -in b.9.2passtoken.pem -inform pem -certfile b.2.1.5.kdh1.pem -noverify -out b.9.2passtoken.inner.der
