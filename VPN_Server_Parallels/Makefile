#run as server
all:
	gcc -o simpletun ../simpletun.c
run:
	bash init_server.sh &
	sudo ./simpletun -i tun0 -s 