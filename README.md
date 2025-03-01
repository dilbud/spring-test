# spring-test

- openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
- openssl rsa -pubout -in private_key.pem -out public_key.pem
- openssl req -new -key private_key.pem -out certificate.csr
- openssl req -x509 -key private_key.pem -in certificate.csr -out certificate.pem -days 365