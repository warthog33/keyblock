#/bin/sh
openssl cms -verify -in b.8.pem -inform pem -certfile b.2.1.5.kdh1.pem -noverify -out b.8.inner.der
