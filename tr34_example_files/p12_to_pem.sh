#!/bin/sh -x

openssl asn1parse -in b.2.1.1.root.p12 -inform pem -out b.2.1.1.root.p12.der -noout
openssl pkcs12 -in b.2.1.1.root.p12.der -info -legacy -out b.2.1.1.root.pem -password pass:TR34 -nomacver -passout pass:TR34

openssl asn1parse -in b.2.1.2.cakdh.p12 -inform pem -out b.2.1.2.cakdh.p12.der -noout
openssl pkcs12 -in b.2.1.2.cakdh.p12.der -info -legacy -out b.2.1.2.cakdh.pem -password pass:TR34 -nomacver -passout pass:TR34
#openssl pkcs12 -in b.2.1.2.root.p12 -info -legacy -out b.2.1.2.root.pem -password pass:TR34 -nomacver
openssl asn1parse -in b.2.1.4.cakrd.p12 -out b.2.1.4.cakrd.der > /dev/null
openssl pkcs12 -in b.2.1.4.cakrd.der  -info -legacy -out b.2.1.4.cakrd.pem -password pass:TR34 -nomacver -passout pass:TR34
openssl pkcs12 -in b.2.1.5.kdh1.p12.q -info -legacy -out b.2.1.5.kdh1.pem -password pass:TR34 -nomacver -passout pass:TR34
