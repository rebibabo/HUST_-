while getopts ":vuscd" opt
do
        case $opt in
                u)
                        docker run -it --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash
                        ;;
                v) 	
                	docker run -it --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
                	;;
                s)
                        docker commit $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p") handsonsecurity/seed-ubuntu:large
                        ;;
                c)
                	docker cp $2 $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p"):$3
			docker commit $(printf "%s\n" $(docker ps -a | sed -n "2p") | sed -n "1p") handsonsecurity/seed-ubuntu:large
                	;;
                d)
                	for i in `docker ps -a | grep $2 | awk '{print $1}'`
			do
			    docker rm $i
			done
			docker rmi $2
			;;
                ?)
                        echo "there is unrecognized parameter."
                        exit 1
                        ;;
        esac
done
