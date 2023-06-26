openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf
openssl genrsa -des3 -out server.key 2048
openssl genrsa -des3 -out client.key 2048
openssl req -new -key server.key -out server.csr -config openssl.cnf
openssl req -new -key client.key -out client.csr -config openssl.cnf
openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
openssl ca -in client.csr -out client.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
docker cp client.crt HostU:/cert/client.crt
docker cp client.key HostU:/cert/client.key
cd ../
./server
