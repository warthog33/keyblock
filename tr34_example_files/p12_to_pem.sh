#!/bin/sh -x

openssl asn1parse -in b.2.1.1.root.p12 -inform pem -out b.2.1.1.root.p12.der -noout
openssl pkcs12 -in b.2.1.1.root.p12.der -info -legacy -out b.2.1.1.root.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.2.cakdh.p12 -inform pem -out b.2.1.2.cakdh.p12.der -noout
openssl pkcs12 -in b.2.1.2.cakdh.p12.der -info -legacy -out b.2.1.2.cakdh.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.4.cakrd.p12 -out b.2.1.4.cakrd.der > /dev/null
openssl pkcs12 -in b.2.1.4.cakrd.der  -info -legacy -out b.2.1.4.cakrd.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.5.kdh1.p12 -out b.2.1.5.kdh1.der > /dev/null
openssl pkcs12 -in b.2.1.5.kdh1.der -info -legacy -out b.2.1.5.kdh1.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.6.kdh2.p12 -out b.2.1.6.kdh2.der > /dev/null
openssl pkcs12 -in b.2.1.6.kdh2.der -info -legacy -out b.2.1.6.kdh2.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.7.krd1.p12 -out b.2.1.7.krd1.der > /dev/null
openssl pkcs12 -in b.2.1.7.krd1.der -info -legacy -out b.2.1.7.krd1.pem -password pass:TR34 -nomacver -passout pass:TR34
openssl x509 -in b.2.1.7.krd1.pem -key b.2.1.7.krd1.pem -out b.2.1.7.krd1.selfsigned.crt -password pass:TR34
base64 < b.2.1.7.krd1.selfsigned.crt > b.2.1.7.krd1.selfsigned.json
openssl x509 -in b.2.1.7.krd1.selfsigned.pem -CA b.2.1.4.cakrd.pem -out b.2.1.7.krd1.resigned.crt -password pass:TR34
base64 < b.2.1.7.krd1.resigned.crt > b.2.1.7.krd1.resigned.json
