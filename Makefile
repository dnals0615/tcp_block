all : tcp_block

send_arp : main.o
	gcc -o tcp_block main.o -lpcap

main.o : main.c
	gcc -c -o main.o main.c

clean : 
	rm *.o tcp_block
