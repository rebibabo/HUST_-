执行下面命令可以创建extranet Internet网络和Intranet局域网络

```shell
docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet
docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet
```

然后创建两个虚拟docker HostV和HostU

```shell
 docker run -it --name=HostU --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash
 docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
 docker run -it --name=HostU --hostname=HostU --privileged "zhouyang996/codebert-attack:v1" /bin/bash
```

下面是脚本generate.sh，在VM的cert目录上生成证书，并将客户端证书拷贝到了HostU中

```shell
openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf
openssl genrsa -des3 -out server.key 2048
openssl genrsa -des3 -out client.key 2048
openssl req -new -key server.key -out server.csr -config openssl.cnf
openssl req -new -key client.key -out client.csr -config openssl.cnf
openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
openssl ca -in client.csr -out client.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
docker cp client.crt HostU:/cert/client.crt
docker cp client.key HostU:/cert/client.key
```

编译server.c和client.c的命令

```shell
gcc -o client client.c -lssl -lcrypto -lpthread -lcrypt
gcc -o server server.c -lssl -lcrypto -lpthread -lcrypt
```

编写了下面的脚本run.sh放在了copy文件夹的上一级目录，copy是tls-2023的拷贝

```shell
while getopts ":vuscdai" opt do
    case $opt in
        u)
	    	sudo docker start HostU
            sudo docker exec -it HostU /bin/bash
            ;;
        v) 	
            sudo docker start HostV
            sudo docker exec -it HostV /bin/bash
            ;;
		a)
            sudo docker cp copy/cert/client.crt HostU2:/cert/client.crt
            sudo docker cp copy/cert/client.key HostU2:/cert/client.key
            sudo docker cp copy/client HostU2:/client
            sudo docker start HostU2
            sudo docker exec -it HostU2 /bin/bash
            ;;
        s)
            sudo docker commit $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p") seedubuntu
            ;;
        c)
            sudo docker cp $2 $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p"):$3
            sudo docker commit $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p") seedubuntu
            ;;
        d)
            for i in `docker ps -a | grep $2 | awk '{print $1}'`
            do
            	sudo docker rm $i
            done
            sudo docker rmi $2
            ;;
        ?)
            echo "there is unrecognized parameter."
            exit 1
            ;;
    esac
done
```

下面是脚本的解释

```shell
./run.sh -u							# 运行HostU
./run.sh -v 						# 运行HostV
./run.sh -s							# 保存最近一次的docker
./run.sh -c	[VM路径] [docker路径]	 # 将主机文件拷贝到docker
./run.sh -d [imageID]				# 删除ID对应的镜像
```

在HostU中编写run.sh如下

```shell
if ! cat /etc/hosts | grep 10.0.2.8
then
    echo "10.0.2.8        yuanzhongsheng" >> /etc/hosts
fi
./client yuanzhongsheng 4433
```

在HostV中编写run.sh如下

```shell
service openbsd-inetd start
route add -net 192.168.53.0/24 gateway 192.168.60.1 eth0
```

然后在VM、HostU、HostV中依次运行下面的指令，就可以运行VPN server和client

```shell
VM	 : sudo ./server	
HostU: ./run.sh				
HostV: ./run.sh
```