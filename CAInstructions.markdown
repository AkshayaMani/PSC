# CA Key generation (OpenSSL 1.0.2g)

The CA needs a few files to operate: one to keep track of the last serial number used by the CA (each certificate must have a unique serial number) and another file to record which certificates have been issued:

```
    sudo sh -c "echo '01' > PSC/CA/serial"
    sudo touch PSC/CA/index.txt
```

The third file is a CA configuration file (refer PSC/openssl.cnf). Though not strictly necessary, it is very convenient when issuing multiple certificates. Edit openssl.cnf, and change the following fields: Here, directory usr must be directory TS, CP, or DP depending on the keys you want to generate.

```
    [ CA_default ]
    dir             = ./                 		# Where everything is kept
    database        = $dir/CA/index.txt     		# database index file.
    new_certs_dir   = $dir/<usr>/certs        		# default place for new certs.
    certificate     = $dir/CA/certs/<ca_name>.cert	# The CA certificate
    serial          = $dir/CA/serial        		# The current serial number
    private_key     = $dir/CA/private/<ca_name>.key# The private key
    default_days    = 3650                  		# how long to certify for
    default_bits    = 4096
```

Also, add default values for country, province, organization, etc.:

```
    [ req_distinguished_name ]              
    countryName                     = Country Name (2 letter code)
    countryName_default             = US
    countryName_min                 = 2
    countryName_max                 = 2
    stateOrProvinceName             = State or Province Name (full name)
    stateOrProvinceName_default     = Washington DC
    localityName                    = Locality Name (eg, city)
    localityName_default            = Georgetown
    0.organizationName              = Organization Name (eg, company)
    0.organizationName_default      = Georgetown University
    1.organizationName              = Second Organization Name (eg, company)
    1.organizationName_default      = Computer Science Department
    organizationalUnitName          = Organizational Unit Name (eg, section)
    organizationalUnitName_default  = Private Set-Union Cardinality
    commonName                      = Common Name (eg, YOUR name)
    commonName_max                  = 64
    emailAddress                    = Email Address
    emailAddress_max                = 40
```

Generate the root CA key: (Use a random passphrase)

```
    sudo openssl genrsa -aes256 -out <ca_name>.key 4096
```

Create the insecure key, the one without a passphrase, and shuffle the key names:

```
    openssl rsa -in <ca_name>.key -out <ca_name>.key.insecure
    sudo mv <ca_name>.key.insecure <ca_name>.key
```

Next, create the self-signed root certificate:

```
    sudo openssl req -new -x509 -days 3650 -key <ca_name>.key -out <ca_name>.cert -config <openssl_configuration_file>
```

Add the root certificate and key to the destined folders:

```
    sudo mv <ca_name>.key PSC/CA/private/
    sudo mv <ca_name>.cert PSC/CA/certs/
```

Next create a user key and a certificate signing request in one step: (Use a random passphrase)

```
    sudo openssl req -newkey rsa:4096 -keyout <usr_common_name>.key -out <usr_common_name>.csr -config openssl.cnf -days 3650
```

Create the insecure key, the one without a passphrase, and interchange the key names:

```
    openssl rsa -in <usr_common_name>.key -out <usr_common_name>.key.insecure
    sudo mv <usr_common_name>.key.insecure <usr_common_name>.key
```

Using the CSR, generate a certificate signed by the CA:

```
    sudo openssl ca -in <usr_common_name>.csr -config openssl.cnf
```
 
Rename certificate file:

```
    sudo mv PSC/<usr>/certs/<index>.pem PSC/<usr>/certs/<usr_common_name>.cert
```

Add the user certificate and key in the destined folders:

```
    sudo mv <usr_common_name>.csr PSC/<usr>/csr/
    sudo mv <usr_common_name>.key PSC/<usr>/private/
```
