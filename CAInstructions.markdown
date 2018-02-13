# CA Instructions (OpenSSL 1.0.2g)

## CA files

### Serial file

Create a file that keeps track of the last serial number used by the CA (each certificate must have a unique serial number):

```
    echo '01' > PSC/CA/serial
```

### Index file

Create an index file that keeps record of all certificates issued:

```
    touch PSC/CA/index.txt
```

### Configuration file

Create a CA configuration file (refer PSC/openssl.cnf). This is optional, but is very convenient while issuing multiple certificates. 

Edit openssl.cnf, and change the following fields: (Here, directory \<usr\> must be directory TS, CP, or DP depending on the keys you want to generate.)

```
    [ CA_default ]
    dir             = ./                 		    # Where everything is kept
    database        = $dir/CA/index.txt     		# database index file.
    new_certs_dir   = $dir/CA/certs        		    # default place for new certs.
    certificate     = $dir/CA/certs/<ca_name>.cert	# The CA certificate
    serial          = $dir/CA/serial        		# The current serial number
    private_key     = $dir/CA/private/<ca_name>.key # The private key
    default_days    = 3650                  		# how long to certify for
    default_bits    = 4096
    default_md      = sha256
    policy          = policy_match
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
    commonName                      = Common Name (i.e. <usr_common_name>)
    commonName_max                  = 64
    emailAddress                    = Email Address
    emailAddress_max                = 40
```

## CA key

Generate the CA key: (Use a random passphrase)

```
    openssl genrsa -aes256 -out <ca_name>.key 4096
```

Create the insecure key, the one without a passphrase, and interchange the key names:

```
    openssl rsa -in <ca_name>.key -out <ca_name>.key.insecure
    mv <ca_name>.key.insecure <ca_name>.key
```

Next, create the self-signed root certificate:

```
    openssl req -new -x509 -days 3650 -key <ca_name>.key -out <ca_name>.cert -config <openssl_configuration_file>
```

Add the root certificate and key to the destined folders:

```
    mv <ca_name>.key PSC/CA/private/
    mv <ca_name>.cert PSC/CA/certs/
```

## CP/DP/TS key

Use ./keypair.sh and the instructions in DEPLOY.markdown to create these keys.
