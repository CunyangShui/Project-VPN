# run as client
all:
	gcc -o simpletun ../simpletun.c
run:
	bash init_client.sh &
	sudo ./simpletun -i tun0 -c 10.211.55.6
