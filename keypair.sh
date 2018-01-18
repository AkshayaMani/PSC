sudo openssl req -newkey rsa:4096 -keyout $2.key -out $2.csr -config openssl.cnf -days 3650
openssl rsa -in $2.key -out $2.key.insecure
sudo mv $2.key.insecure $2.key
sudo openssl ca -in $2.csr -config openssl.cnf
sudo mv $1/certs/*.pem $1/certs/$2.cert
sudo mv $2.csr $1/csr/
sudo mv $2.key $1/private/
