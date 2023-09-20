#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader {
	unsigned char iph_ihl:4, iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3, iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;


	struct in_addr iph_sourceip;
	struct in_addr iph_destip;

};

struct tcpheader{
	u_short tcp_sport;
	u_short tcp_dport;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char tcp_offx2;
	u_char tcp_flags;
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
	char payload[1500];
};


void print_payload(const char *payload, int length){
	printf("	");
	for (int i = 0; i < length; i++){
		if(payload[i] == '\0'){
			break;
		}
		printf("%c", payload[i]);
	}
	printf("\n");
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("\nGot a packet");
	struct ethheader *eth = (struct ethheader *)packet;

	if (ntohs(eth->ether_type) == 0x0800) {
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
		
		printf("\n	src MAC: ");
		for (int i=0; i<6;i++){
			printf("%02x", eth->ether_shost[i]);
			if(i<5) printf("-");
		}
		printf("\n");
		printf("\n	dst MAC: ");
		for (int i = 0; i<6; i++){
			printf("%02x",eth->ether_dhost[i]);
			if(i<5) printf("-");
		}
		printf("\n");
		printf("\n       From: %s\n", inet_ntoa(ip->iph_sourceip));   
   		printf("\n         To: %s\n", inet_ntoa(ip->iph_destip));
		printf("\n	src PORT: %d", ntohs(tcp->tcp_sport));
		printf("\n	dst PORT: %d\n", ntohs(tcp->tcp_dport));
		
		printf("\n And the message is...\n\n");
		print_payload(tcp->payload, sizeof(tcp->payload));
	}

}


int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	if(pcap_setfilter(handle,&fp) != 0){
		pcap_perror(handle, "Error: ");
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);


	return 0;

}
