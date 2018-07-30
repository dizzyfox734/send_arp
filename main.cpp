#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	unsigned int sp=0;
	unsigned int dp=0;
	unsigned int type=0;
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

  while (true) {
    struct pcap_pkthdr* header;
    struct ip* iph; // add struct
	const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int j, data=0;
	if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
	
	iph = (ip*)packet+14;	// ipheader

	printf("dst MAC : %02x %02x %02x %02x %02x %02x \n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
	printf("src MAC : %02x %02x %02x %02x %02x %02x \n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
	type = packet[12]<<8 | packet[13];
	
	if( type!=0x0800){
		printf("Not IP!\n");
		continue;
	}
	printf("dst IP : %d.%d.%d.%d \n", packet[26], packet[27], packet[28], packet[29]);
	printf("src IP : %d.%d.%d.%d \n", packet[30], packet[31], packet[32], packet[33]);
	
	if(packet[23]!=0x06){
		printf("Not TCP!\n");
		continue;
	}
	sp = packet[34]<<8 | packet[35];
	dp = packet[36]<<8 | packet[37];
	printf("dst port# : %d\n", dp);
	printf("src port# : %d\n", sp);

	data = iph->ip_len - iph->ip_hl;
	if( !data ){
		continue;
	}
	else{
		if( data > 15 ){
			printf("Data : %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x \n", packet[56], packet[57], packet[58], packet[59], packet[60], packet[61], packet[62], packet[63], packet[64], packet[65], packet[66], packet[67], packet[68], packet[69], packet[70], packet[71]);
		}
		else{
			for (j=0; j<data; j++){
				printf("%x ", packet[56+j]);
			}
			printf("\n");
		}
	}



  }



  pcap_close(handle);
  return 0;
}
