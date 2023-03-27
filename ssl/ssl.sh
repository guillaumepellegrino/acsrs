#!/bin/bash

##################################################
# Generate default certificates
# for secure connection with ACSRS
##################################################

CN="*"

gen_ca_conf()
{
    cat > ca.conf <<- EOM
[req]
default_bits = 4096
prompt = no
default_md = sha256
x509_extensions= v3_ca
distinguished_name = dn

[dn]
OU=ACS Management Server
CN=ACSRS Root CA

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
EOM
}

genrootca()
{
    echo "Generate root CA"

    # Generate 4096 bits CA Private Key using RSA
    openssl genrsa -out ca-key.pem 4096

    # Generate a Certificate Signing Request
    gen_ca_conf
    openssl req -new -key ca-key.pem -out ca.csr -config ca.conf

    # Self sign the root CA
    openssl req -x509  -days $((20*365)) -in ca.csr -sha256 -nodes -new -key ca-key.pem -out ca.pem -config ca.conf

    # CSR can be removed
    rm -f ca.csr
}

gencert()
{
    echo "Generate certificates for $CN"

    # Generate a 4096 bits Private Key using RSA
    openssl genrsa -out key.pem 4096

    # Generate a Certificate Signing Request
    openssl req -new -key key.pem -out cert.csr -subj "/CN=$CN"

    # Sign the CSR
    openssl x509 -req -days $((20*365)) -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -CAcreateserial -CAserial ca.srl

    # Generate PKCS12 certificate
    openssl pkcs12 -export -inkey key.pem -in cert.pem -CAfile ca.pem -out identity.p12 -passout pass:ACSRS
    # CSR can be removed
    rm -f cert.csr
}

verifycert()
{
    echo "Verify certificate"
    openssl verify -CAfile ca.pem cert.pem
}

clean()
{
    rm -f *.pem *.p12 *.0
}

case "$1" in
    all|"")
        genrootca
        gencert
        verifycert
        ;;
    genrootca)
        genrootca
        ;;
    gencert)
        gencert
        verifycert
        ;;
    verify)
        verifycert
        ;;
    clean)
        clean
        ;;
    *)
        echo "Unknown command '$1'"
        echo "$0 (all|genrootca|gencert|verify|clean)"
        ;;
esac
