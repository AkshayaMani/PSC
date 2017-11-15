sudo openssl req -newkey rsa:4096 -keyout DC$1.key -out DC$1.csr -config openssl.cnf -days 3650
openssl rsa -in DC$1.key -out DC$1.key.insecure
sudo mv DC$1.key.insecure DC$1.key
sudo openssl ca -in DC$1.csr -config openssl.cnf
sudo mv DC/certs/$2.pem DC/certs/DC$1.cert
sudo mv DC$1.csr DC/csr/
sudo mv DC$1.key DC/private/
