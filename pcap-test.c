#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void pcap_test(const u_char* packet, int32_t caplen){
	struct libnet_ethernet_hdr *ethernet;
        struct libnet_ipv4_hdr *ipv4;
        struct libnet_tcp_hdr *tcp;
        
        ethernet = (struct libnet_ethernet_hdr*)packet;
	
	printf("Ethernet Header\n");
	printf("\asrc mac\n");
	int i = 0;
	for(i=0; i < ETHER_ADDR_LEN-1; i++){
		printf("%02X:",ethernet->ether_shost[ETHER_ADDR_LEN-i-1]);
	}
	printf("%02X\n", ethernet->ether_shost[ETHER_ADDR_LEN-1]);
	printf("\adst mac\n");
	for(i=0; i<ETHER_ADDR_LEN-1; i++){
		printf("%02X:",ethernet->ether_dhost[ETHER_ADDR_LEN-i-1]);
	}
	printf("%02X\n", ethernet->ether_dhost[ETHER_ADDR_LEN-1]);
	printf("\n");
	
	if(ethernet->ether_type != 8){
		printf("%d ,no ip", ethernet->ether_type);
		return;
	}
	ipv4 = (struct libnet_ipv4_hdr*)(packet+sizeof(*ethernet));
	printf("Ip Header\n");
	uint32_t src_ip = ntohl(ipv4->ip_src.s_addr);
        uint32_t dst_ip = ntohl(ipv4->ip_dst.s_addr);
        
        printf("\asrc Ip\n");
        for(int i=3; i>=0; i--){
        	printf("%d", (src_ip >> (8*i)) & 0x000000ff);
        	if(i == 0){
        		printf("\n");
        	}
        	else{
        		printf(".");
        	}
        }
        
        printf("\adst Ip\n");
        for(int i=3; i>=0; i--){
        	printf("%d", (dst_ip >> (8*i)) & 0x000000ff);
        	if(i == 0){
        		printf("\n\n");
        	}
        	else{
        		printf(".");
        	}
        }
        if(ipv4->ip_p !=6){
        	printf("no tcp\n");
        	return;
        }
        
        printf("TCP Header\n");
                tcp = (struct libnet_tcp_hdr*)(packet+sizeof(*ethernet)+sizeof(*ipv4));
        printf("\asrc port\n");
        printf("%d\n",ntohs(tcp->th_sport));
        printf("\adst port\n");
        printf("%d\n\n",ntohs(tcp->th_dport));
        uint32_t hsize = 14+(ipv4->ip_hl)*4+(tcp->th_off)*4;
        printf("Data\n");
        int cnt = 0;
        for(int i=hsize; i<hsize+8 && i<caplen; i++) {
            printf("0x%02X ",packet[i]);
        }
        
        printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		pcap_test(packet, header->caplen);
	}

	pcap_close(pcap);
}

