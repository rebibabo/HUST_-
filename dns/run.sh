while getopts ":rscd" opt
do
        case $opt in
                r)
                        docker run -it -hostname=dns "handsonsecurity/seed-ubuntu:large" /bin/bash
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
