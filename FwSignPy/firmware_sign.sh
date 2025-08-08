#!/bin/sh


gen_post()
{
    cli_name=$1

    $(which openssl) x509 -in ${cli_name}.cert -outform der -out ${cli_name}.der
}

gen_fw_certificate()
{
    cert_name=$1

    $(which openssl) ecparam -name prime256v1 -genkey -noout -out ${cert_name}.key


    # Create the self-sign  certificate
    $(which openssl) req -x509 -days 3650 -key ${cert_name}.key -out ${cert_name}.cert -subj \
        "/C=KR/ST=Seoul/L=Seoul/O=SBC/OU=${cert_name}/CN=www.spi.im"
}

gen_sign_by_ca()
{
    ca_name=$1
    cli_name=$2

    $(which openssl) x509 req -days 3650 -in ${cli_name}.cert \
        -CA ${ca_name}.crt -CAkey ${ca_name}.key -CAcreateserial \
        -out ${cli_name}.crt

    gen_post $cli_name
}


image_sign_using_certificate()
{
    cert_name=$1
    file_name=$1

    $(which openssl) dgst -sha256 -sign ${cert_name}.key -out ${file_name}.sig ${file_name}.efi

    echo "Verify signature"

    $(which openssl) dgst -sha256 -verify ${cert_name}.crt -signature ${file_name}.sig ${file_name}.efi


}




#gen_fw_certificate  $2
#gen_sign_by_ca $1 $2

# 1-1. ECC 개인키(root_ca.key) 생성
# -name 옵션으로 사용할 곡선(curve)을 지정합니다. prime256v1은 널리 사용되는 곡선입니다.
openssl ecparam -name prime256v1 -genkey -noout -out root_ca.key

# 1-2. ROOT CA 자체 서명 인증서(root_ca.crt) 생성
# -key 옵션으로 위에서 생성한 ECC 개인키를 사용합니다.
openssl req -x509 -new -sha256 -nodes -key root_ca.key -days 3650 -out root_ca.crt \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=My ECC Root CA/CN=My ECC Root CA"


# 2-1. 서명할 인증서의 ECC 개인키(server.key) 생성
openssl ecparam -name prime256v1 -genkey -noout -out server.key

# 2-2. 서명 요청(CSR) 파일(server.csr) 생성
openssl req -new -sha256 -key server.key -out server.csr \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=My ECC Server/CN=server.example.com"


# 작업 디렉터리 및 파일 준비 (openssl.cnf 설정에 필요)
mkdir -p ca_db
touch ca_db/index.txt
echo 1000 > ca_db/serial

# 서버 인증서에 확장 속성 추가 (서버 인증서 용도를 명시)
echo "extendedKeyUsage=serverAuth" > v3.ext

# ROOT CA로 server.csr 서명
openssl x509 -req -in server.csr -CA root_ca.crt -CAkey root_ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile v3.ext

# openssl verify -CAfile [루트 CA 인증서].crt [서명된 인증서].crt
openssl verify -CAfile root_ca.crt server.crt

echo "done ..."
#gen_sign_by_ca "root_ca_ecc" "FSBL"

#image_sign_using_certificate "FSBL" "FSBL"
