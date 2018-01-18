# CA Key generation

The CA needs a few files to operate, one to keep track of the last serial number used by the CA, each certificate must have a unique serial number, and another file to record which certificates have been issued:

```
    sudo sh -c "echo '01' > CA/serial"
    sudo touch CA/index.txt
    sudo cp /etc/ssl/openssl.cnf openssl.cnf
```

The third file is a CA configuration file. Though not strictly necessary, it is very convenient when issuing multiple certificates. Edit openssl.cnf, and change the following fields: Here, directory usr must be directory TS, CP, or DP depending on the keys you want to generate.

```
    [ CA_default ]
    dir             = ./                 # Where everything is kept
    database        = $dir/CA/index.txt     # database index file.
    new_certs_dir   = $dir/<usr>/certs        # default place for new certs.
    certificate     = $dir/CA/certs/ca.cert # The CA certificate
    serial          = $dir/CA/serial        # The current serial number
    private_key     = $dir/CA/private/ca.key# The private key
    default_days    = 3650                  # how long to certify for
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
    organizationalUnitName_default  = Differential Tor Project
    commonName                      = Common Name (eg, YOUR name)
    commonName_max                  = 64
    emailAddress                    = Email Address
    emailAddress_max                = 40
```

Generate the root CA key: (Use a random <passphrase>)

```
    sudo openssl genrsa -aes256 -out ca.key 4096
```

Create the insecure key, the one without a passphrase, and shuffle the key names:

```
    openssl rsa -in ca.key -out ca.key.insecure
    sudo mv ca.key.insecure ca.key
```

Next, create the self-signed root certificate:

```
    sudo openssl req -new -x509 -days 3650 -key ca.key -out ca.cert -config openssl.cnf
```

Add the root certificate and key to the destined folders:

```
    sudo mv ca.key PSC/CA/private/
    sudo mv ca.cert PSC/CA/certs/
```

Next create a user key and a certificate signing request in one step: (Use a random <passphrase>)

```
    sudo openssl req -newkey rsa:4096 -keyout <DP_common_name>.key -out <DP_common_name>.csr -config openssl.cnf -days 3650
```

Create the insecure key, the one without a passphrase, and interchange the key names:

```
    openssl rsa -in <DP_common_name>.key -out <DP_common_name>.key.insecure
    sudo mv <DP_common_name>.key.insecure <DP_common_name>.key
```

Using the CSR, generate a certificate signed by the CA:

```
    sudo openssl ca -in <DP_common_name>.csr -config openssl.cnf
```
 
Rename certificate file:

```
    sudo mv PSC/<usr>/certs/<index>.pem <usr>/certs/<DP_common_name>.cert
```

Add the user certificate and key in the destined folders:

```
    sudo mv <DP_common_name>.csr <usr>/csr/
    sudo mv <DP_common_name>.key <usr>/private/
```
