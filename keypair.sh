openssl req -newkey rsa:4096 -keyout $2.key -out $2.csr -config openssl.cnf -days 3650
openssl rsa -in $2.key -out $2.key.insecure
mv $2.key.insecure $2.key
openssl ca -in $2.csr -config openssl.cnf
mv CA/certs/*.pem $1/certs/$2.cert
mv $2.csr $1/csr/
mv $2.key $1/private/
