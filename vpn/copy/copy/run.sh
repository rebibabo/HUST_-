rm error.txt
gcc -o client client.c -lssl -lcrypto -lpthread -lcrypt 2> error.txt
gcc -o server server.c -lssl -lcrypto -lpthread -lcrypt 2>> error.txt
if cat error.txt | grep error;
then 
	echo "no"
else
	docker cp client HostU:/client
	sudo ./server
fi

