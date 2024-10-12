## STIR/SHAKEN

### generate keypair & certs
```sh
#gen CA privkey
openssl ecparam -noout -name prime256v1 -genkey -out ca-key.pem
#gen CA cert
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 1825 -out ca-cert.pem
#gen cert privkey
openssl ecparam -noout -name prime256v1 -genkey -out sp-key.pem
#convert cert privkey pkcs1 -> pkcs8
openssl pkcs8 -topk8 -nocrypt -in sp-key.pem -out sp-key-p8.pem

#gen cert extension data
cat >TNAuthList.conf << EOF
      asn1=SEQUENCE:tn_auth_list

      [tn_auth_list]
      spc=EXP:0,IA5:1001
      range=EXP:1,SEQUENCE:TelephoneNumberRange
      one=EXP:2,IA5:333

      [TelephoneNumberRange]
      start1=IA5:111
      count1=INT:128
      start2=IA5:222
      count2=INT:256
EOF
openssl asn1parse -genconf TNAuthList.conf -out TNAuthList.der

#gen cfg for cert
cat >openssl.conf << EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
commonName = "SHAKEN"
[ v3_req ]
EOF
od -An -t x1 -w TNAuthList.der | sed -e 's/ /:/g' -e 's/^/1.3.6.1.5.5.7.1.26=DER/' >> openssl.conf

#gen cert req
openssl req -new -nodes -key sp-key.pem -keyform PEM -subj '/C=US/ST=VA/L=IQNT/O=YOURCOMPANYNAME, Inc./OU=VOIP/CN=SHAKEN'  -sha256 -config openssl.conf  -out sp-csr.pem

#sign cert
openssl x509 -req -in sp-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial  -days 825 -sha256 -extfile openssl.conf -extensions v3_req -out sp-cert.pem
```

### sems-jwt-tool examples
```sh
# gen&decode STIR/SHAKEN JWT token
sems-jwt-tool encode --key sp-key-p8.pem --x5u=https://invalid.domain/sp-cert.pem --orig_tn=1111 --dest_tn=2222 | sems-jwt-tool decode -i -

# gen&verify STIR/SHAKEN JWT token
sems-jwt-tool encode --key sp-key-p8.pem --x5u=https://invalid.domain/sp-cert.pem --orig_tn=1111 --dest_tn=2222 | sems-jwt-tool verify -i - --cert sp-cert.pem
```

## raw JWT

### generate keypair
```sh
#gen privkey
openssl ecparam -noout -name prime256v1 -genkey -out key_pkcs1.pem
#convert privkey pkcs1 -> pkcs8
openssl pkcs8 -topk8 -nocrypt -in key_pkcs1.pem -out key.pem
#gen pubkey
openssl ec -in key.pem -pubout -out pub.pem
```

### sems-jwt-tool examples
```sh
#gen JWT token
sems-jwt-tool encode --key key.pem --raw --claim=id:1/i --claim=iat:$(date +%s)/i --claim=exp:$(($(date +%s) + 38400))/i

#gen&decode JWT token
sems-jwt-tool encode --key key.pem --raw --claim=id:1/i --claim=iat:$(date +%s)/i --claim=exp:$(($(date +%s) + 38400))/i | sems-jwt-tool decode -i - --raw

#gen&verify JWT token
sems-jwt-tool encode --key key.pem --raw --claim=id:1/i --claim=iat:$(date +%s)/i --claim=exp:$(($(date +%s) + 38400))/i | sems-jwt-tool decode -i - --raw --key pub.pem
```
