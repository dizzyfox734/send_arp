#include <stdio.h>
#include <pcap.h>

void ck_dev(char* input){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if( (dev=pcap_lookupdev(errbuf))==NULL ){
        printf("%s\n", errbuf);
        exit(1);
    }
    
    //check
    if ( *dev!=*input ){
        printf("Wrong input\nTry dev : %s\n", dev);
        exit(1);
    }
}

int main(int argc, char** argv[]){
    ck_dev(argv[1]);
    reuturn 0;
}
