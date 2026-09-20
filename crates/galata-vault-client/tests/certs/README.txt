TEST-ONLY certificates for crates/galata-vault-client/tests/http.rs (the private-CA
test). They protect nothing: the private key is committed on purpose.

  ca.der          a self-signed CA, "galata-vault-client test CA" (P-256, 100 years)
  server.der      CN=localhost, SAN DNS:localhost + IP:127.0.0.1, signed by
                  the CA, serverAuth (P-256, 100 years)
  server.key.der  the server's private key, PKCS#8 DER

Made once with the openssl CLI:

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout ca.key -out ca.pem -days 36500 -subj "/CN=galata-vault-client test CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout server.key -out server.csr -subj "/CN=localhost"
  printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > ext.cnf
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out server.pem -days 36500 -extfile ext.cnf
  openssl x509 -in ca.pem -outform DER -out ca.der
  openssl x509 -in server.pem -outform DER -out server.der
  openssl pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server.key.der
