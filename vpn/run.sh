while getopts ":vuscdai" opt
do
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
        i) 
        	sudo 2copy/server
        	sudo ifconfig tun0 192.168.53.1/24 up
        	sudo iptables -F
        	sudo sysctl net.ipv4.ip_forward=1
        	;;
        ?)
            echo "there is unrecognized parameter."
            exit 1
            ;;
    esac
done
