This folder contains certificate-related files needed only for testing purposes.
Certificates are valid for 20 years.

The following blog post was used this to generate the certificates and CRL:
https://www.golinuxcloud.com/revoke-certificate-generate-crl-openssl/#Step-1_Revoke_certificate_using_OpenSSL

Step-by-step guide to generate the certificates and CRL:

### Prepare the folder structure and files
```bash
# Init test-crl
mkdir cert-with-crl && cd cert-with-crl
mkdir certs private crl
touch index.txt serial
touch crlnumber
echo 01 > serial
echo 1000 > crlnumber
```
- Add committed oppenssl.cnf in test-crl folder.  
- Add committed ext_template.cnf in test-crl folder.  
- Check the `crlDistributionPoints` config in `ext_template.cnf` & `openssl.cnf`. 
And adapt it to target the right URL (classpath for testing) that will be used by the policy to download the CRL. 
In our example, the CRL will be available at `classpath:io/gravitee/policy/jws/cert-with-crl/crl/rootca.crl`. 


### Generate root CA private key and certificate
```bash
# Generates a new private RSA key with a length of 4096 bits.
openssl genrsa -out private/cakey.pem 4096

# Creates a new self-signed X.509 certificate that will be valid for the next 7300 days (or roughly 20 years).
openssl req -new -x509 -days 7300  -config openssl.cnf  -key private/cakey.pem -out certs/cacert.pem
# Only fill the Common Name (e.g. server FQDN or YOUR name) []:RootCA

# Print the details of the previously created certificate
openssl x509 -noout -text -in certs/cacert.pem
```

### Generate server private key and Certificate Signing Request (CSR)
```bash
# Generates a new private RSA key with a length of 4096 bits.
openssl genrsa -out certs/server.key.pem 4096

# Generates a CSR (Certificate Signing Request) using the private generated previously. This CSR can then be sent to a Certificate Authority (CA), who will issue an SSL certificate for your server. The CA uses the information in the CSR (including the public key) to create the SSL certificate.
openssl req -new -key certs/server.key.pem -out certs/server.csr
# Only fill the Common Name (e.g. server FQDN or YOUR name) []:server

# Takes the CSR and signs it using the CA setup specified in the main configuration file (openssl.cnf), while overriding or adding configuration with an extension file (ext_template.cnf), creating a certificate (certs/server.crt)
openssl ca -config openssl.cnf -notext -batch -in certs/server.csr -out certs/server.crt -extfile ext_template.cnf

# Extracts the public key contained in the certs/server.crt and outputs it to a file
openssl x509 -pubkey -in certs/server.crt -noout > certs/server.x509-key.pub

# Convert the public key to an OpenSSH public key
ssh-keygen -i -m pkcs8 -f certs/server.x509-key.pub > certs/server.SSH-pub-key.pub
# Used to configure the policy (policy.jws.kid.*) into gravitee.yml file

# Generates CSRs as on line L46
openssl req -new -key certs/server.key.pem -out certs/server-valid.csr
# Only fill the Common Name (e.g. server FQDN or YOUR name) []:server-valid
openssl req -new -key certs/server.key.pem -out certs/server-revoked.csr
# Only fill the Common Name (e.g. server FQDN or YOUR name) []:server-revoked
openssl req -new -key certs/server.key.pem -out certs/server-expired.csr
# Only fill the Common Name (e.g. server FQDN or YOUR name) []:server-expired


# Generate and sign the server certificate using rootca certificate
openssl ca -config openssl.cnf -notext -batch -in certs/server-valid.csr -out certs/server-valid.crt -extfile ext_template.cnf
openssl ca -config openssl.cnf -notext -batch -in certs/server-revoked.csr -out certs/server-revoked.crt -extfile ext_template.cnf
openssl ca -config openssl.cnf -notext -batch -in certs/server-expired.csr -out certs/server-expired.crt -extfile ext_template.cnf -startdate 20200101010000Z -enddate 20210101010000Z
```

### Revoke server certificate

```bash
# Revokes the certificate found in 'certs/server-revoked.crt' using the Certificate Authority function of OpenSSL as configured in 'openssl.cnf'.
openssl ca -config openssl.cnf -revoke certs/server-revoked.crt

# Verify the server certificate status
# server-revoked line should start with R
cat index.txt
```

### Generate CRL
```bash
# Generates a CRL using the OpenSSL's CA utility and its configurations mentioned in 'openssl.cnf'. This CRL can be distributed to parties that need to check whether an issued certificate has been revoked.
openssl ca -config openssl.cnf -gencrl -out crl/rootca.crl
```

### Create JWT to test the policy

Go to https://jwt.io/ and create a JWT with the following information:
- Add public key (`certs/server-valid.crt`) and private key (`certs/server.pem`)
- Add payload:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
- Add Header:
```json
{
  "kid": "MAIN",
  "x5c": ["<public key content without line break>"],
  "alg": "RS256"
}
```

### Useful links
- Tool to check cert https://www.sslchecker.com/certdecoder



