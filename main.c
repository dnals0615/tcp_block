#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>


void get_mac_address(u_int8_t *mac_address, u_int8_t *interface)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
}

void get_ip_address(u_int8_t *ip_address, u_int8_t *interface) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	memcpy(ip_address, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	close(fd);
}


int main(int argc, char *argv[])
{
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_int8_t errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t *interface = argv[1];
	u_int8_t attacker_mac[6];
	u_int8_t attacker_ip[4];
	u_int8_t target_mac[6];
        u_int8_t target_ip[4];
        u_int8_t sender_ip[4];
	u_int8_t tmp[6] = {0,};
	
	const u_int8_t *packet_get;

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

	while(1)
	{
		pcap_next_ex(handle, &header, &packet_get);
		// check if TCP packet
		if( (packet_get[12] == 0x08) && (packet_get[13] == 0x00) && (packet_get[23] == 0x06) ) 
		{
			int ip_len = (packet_get[14] & 0x0f) * 4;
			int tcp_len = (packet_get[14+ip_len+12]>>4) * 4;
			int hi = 14+ip_len+tcp_len; //http index
			int len = 14+ip_len+tcp_len;
			u_int8_t packet[len];
			
			//forward RST
			for(int i = 0;i<len;i++)
			{
				packet[i] = packet_get[i];
			}	
			packet[14+ip_len+13] = packet[14+ip_len+13] | 0x14 ;//ack, rst
			pcap_sendpacket(handle, packet, len);


			//backward RST, FIN
			for(int i = 0;i<len;i++)
			{
				packet[i] = packet_get[i];
			}
			// check if HTTP.request
			if( ((packet_get[hi]=="G")&&(packet_get[hi+1]=="E")&&(packet_get[hi+2]=="T")) || 
			((packet_get[hi]=="P")&&(packet_get[hi+1]=="U")&&(packet_get[hi+2]=="T")) ||
			((packet_get[hi]=="P")&&(packet_get[hi+1]=="O")&&(packet_get[hi+2]=="S")&&(packet_get[hi+3]=="T")) || 
			((packet_get[hi]=="H")&&(packet_get[hi+1]=="E")&&(packet_get[hi+2]=="A")&&(packet_get[hi+3]=="D")) ||
			((packet_get[hi]=="O")&&(packet_get[hi+1]=="P")&&(packet_get[hi+2]=="T")&&(packet_get[hi+3]=="I")&&(packet_get[hi+4]=="O")&&
			(packet_get[hi+5]=="N")&&(packet_get[hi+6]=="S")) ) 
			{	//backward FIN
				//mac change	
				for(int i=0;i<6;i++){tmp[i] = packet[i];}
				for(int i=0;i<6;i++){packet[i] = packet[i+6];}
				for(int i=0;i<6;i++){packet[i+6] = tmp[i];}
				//ip change
				for(int i=0;i<4;i++){tmp[i] = packet[26+i];}
				for(int i=0;i<4;i++){packet[26+i] = packet[30+i];}
				for(int i=0;i<4;i++){packet[30+i] = tmp[i];}
				//port change
				for(int i=0;i<2;i++){tmp[i] = packet[14+ip_len+i];}
				for(int i=0;i<2;i++){packet[14+ip_len+i] = packet[14+ip_len+i+2];}
				for(int i=0;i<2;i++){packet[14+ip_len+i+2] = tmp[i];}	
				//flag change
				packet[14+ip_len+13] = packet[14+ip_len+13] | 0x11; // fin,ack

				pcap_sendpacket(handle, packet, len);	
			}
			else
			{	//backward RST
				//mac change	
				for(int i=0;i<6;i++){tmp[i] = packet[i];}
				for(int i=0;i<6;i++){packet[i] = packet[i+6];}
				for(int i=0;i<6;i++){packet[i+6] = tmp[i];}
				//ip change
				for(int i=0;i<4;i++){tmp[i] = packet[26+i];}
				for(int i=0;i<4;i++){packet[26+i] = packet[30+i];}
				for(int i=0;i<4;i++){packet[30+i] = tmp[i];}
				//port change
				for(int i=0;i<2;i++){tmp[i] = packet[14+ip_len+i];}
				for(int i=0;i<2;i++){packet[14+ip_len+i] = packet[14+ip_len+i+2];}
				for(int i=0;i<2;i++){packet[14+ip_len+i+2] = tmp[i];}
				//flag change	
				packet[14+ip_len+13] = packet[14+ip_len+13] | 0x14; // ack, rst

				pcap_sendpacket(handle, packet, len);
			}
		} 
	}

	
	return 0;
}















