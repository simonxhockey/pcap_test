#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void dump(const u_char* p, int len){
	
	struct ether_header *header = (struct ether_header *)p;  //ethernet struct
	
	/*mac address from ethernet header*/
	u_int8_t *destmac = header->ether_dhost;
	u_int8_t *srcmac = header->ether_shost;
	
	printf("source mac=>%02x:%02x:%02x:%02x:%02x:%02x\n", srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]);
	printf("dest mac=>%02x:%02x:%02x:%02x:%02x:%02x\n\n", destmac[0], destmac[1], destmac[2], destmac[3], destmac[4], destmac[5]);
	

	/*if type field is not 0x0800(ip)*/
	if (ntohs(header->ether_type) != 0x0800){
		printf("it is not IP\n");
		return;
	}
	
	printf("it is IP\n");
	
	struct ip* ipheader = (struct ip *)p;  //ip header struct
	ipheader = (ip*)(p+sizeof(struct ether_header));  //ip header is 14byte away from packet
	
	u_int iph_len = ipheader->ip_hl*4;  //ip header length
	/*ip address from ip header*/
	printf("source ip=>%s\n", inet_ntoa(ipheader->ip_src));
	printf("dest ip=>%s\n\n", inet_ntoa(ipheader->ip_dst));
	

	/*if protocol field is not 0x06(tcp)*/
	if (ipheader->ip_p != 0x06){
		printf("it is not TCP\n");
		return;
	}

	printf("it is TCP\n");

	struct tcphdr* tcpheader = (struct tcphdr *)p;  //tcp header struct
	tcpheader = (tcphdr*)(p+sizeof(struct ether_header)+iph_len);  //tcp header is ip header-length away from ip header	
	
	/*tcp port from tcp header*/
	printf("source port=>%d\n", tcpheader->th_sport);
	printf("dest port=>%d\n\n", tcpheader->th_dport);
	
	u_int data_length;  //data(segment) length of tcp
	data_length = ipheader->ip_len - iph_len - tcpheader->th_off*4;  //ip_length - ip_header_length - tcp_header_length
	
	if (data_length == 0){
		printf("it has no data\n");
	}
	else if (data_length > 0 && data_length <= 32){
		printf("Data=>");
		for(int i=0;i<data_length;i++){
			printf("%02x ", p[sizeof(struct ether_header) + iph_len + tcpheader->th_off*4 + i]);
		}
		printf("\n");
	}
	else {
		printf("Data=>");
		for(int i=0;i<32;i++)
			printf("%02x ", p[sizeof(struct ether_header) + iph_len + tcpheader->th_off*4 + i]);
		printf("\n");
	}	

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test ens33\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
	int count = 0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n********************************************************************\n");
    printf("\n%u bytes captured\n", header->caplen);
	dump(packet, header->caplen);
	count+=1;
	if (count == 10) break;
  }

  pcap_close(handle);
  return 0;
}


