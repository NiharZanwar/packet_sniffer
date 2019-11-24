#include<stdio.h>
#include<stdlib.h>	
#include<string.h>	
#include<netinet/ip_icmp.h>	
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>
#include<netinet/igmp.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<netdb.h>

#define PATH "logfile.txt"
#define MAX_PACKET_SIZE 65536


void perror2(char *str);
void handle_ipv4(char *buff);
void print_tcp(char *buff);
void print_udp(char *buff);
void print_icmp(char *buff);
void print_igmp(char *buff);

int raw_sockfd;
FILE *logfile;
int tcp,udp,igmp,icmp,others;
struct sockaddr_in src,dst;



int main(int argc, char *argv[]){

    int len,bytes_read;
    struct sockaddr addr;
    struct in_addr inaddr;
    char buff[MAX_PACKET_SIZE];
    
    tcp=0;
    udp=0;
    igmp=0;
    icmp=0;
    others=0;

    logfile = fopen(PATH,"w");
    if(logfile == NULL)
        perror2("logfile open");

    raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_sockfd < 0)
        perror2("socket()");

    len = sizeof(addr);

    while(1){


        bytes_read = recvfrom(raw_sockfd,buff, MAX_PACKET_SIZE, 0, &addr,(socklen_t *)&len);
        if(bytes_read<0)
            perror2("recvfrom()");

        struct ethhdr *eth = (struct ethhdr *) buff;

        printf("\n\nETHERNET HEADER:\n");
        printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
        printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
        printf("\t|-Protocol : 0x%X\t",ntohs(eth->h_proto));
        
        switch (ntohs(eth->h_proto)){

            case 2048: printf("\tIPv4 Protocol\n"); 
                       handle_ipv4(buff);
                       break;
            //case 34525: handle_ipv6(buff);
            //case 2054: handle_arp(buff);
            default: printf("\tUnknown Protocol\n");
        

       
        }
        printf("\n--------------------------------------------------------------------------------------------------\n");
    }
}



void perror2(char *str){
    perror(str);
    exit(0);
}

void handle_ipv4(char *buff){

    int iphdrlen;
    struct sockaddr_in source, dest;
    struct protoent *prt = (struct protoent *) malloc(sizeof(struct protoent));

    struct iphdr *myiphdr = (struct iphdr *) (buff + sizeof(struct ethhdr));
    iphdrlen = myiphdr->ihl << 2; 
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = myiphdr->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = myiphdr->daddr;

    prt = getprotobynumber((int)myiphdr->protocol);
    

    printf("\n\tIPv4 HEADER:\n\n");
    printf("\t|-Version : %d\n",(unsigned int)myiphdr->version);
    printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)myiphdr->ihl,((unsigned int)(myiphdr->ihl))*4);
    printf("\t|-Type Of Service : %d\n",(unsigned int)myiphdr->tos);
    printf("\t|-Total Length : %d Bytes\n",ntohs(myiphdr->tot_len));
    printf("\t|-Identification : %d\n",ntohs(myiphdr->id));
    printf("\t|-Time To Live : %d\n",(unsigned int)myiphdr->ttl); 
    printf("\t|-Protocol : %d Protocol name : %s\n",(unsigned int)myiphdr->protocol,prt->p_name);
    printf("\t|-Header Checksum : %d\n",ntohs(myiphdr->check));
    printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
    printf("\t|-Destination IP : %s\n",inet_ntoa(dest.sin_addr));



    switch (myiphdr->protocol){

        case  6: print_tcp(buff + sizeof(struct ethhdr) + iphdrlen);
                 tcp++;
                 break;
        case 17: print_udp(buff + sizeof(struct ethhdr) + iphdrlen);
                 udp++;
                 break;
        case  1: print_icmp(buff + sizeof(struct ethhdr) + iphdrlen);
                 icmp++;
                 break;
        case  2: print_igmp(buff + sizeof(struct ethhdr) + iphdrlen);
                 igmp++;
                 break;
        
        default: break;
    }

    return;
}

void print_tcp(char *buff){

    struct tcphdr *tcph = (struct tcphdr *) malloc(sizeof(struct tcphdr));
    tcph = (struct tcphdr *) buff;

	printf("\n\tTCP Header: \n\n");
	printf("\t\t |-Source Port      : %u\n",ntohs(tcph->source));
	printf("\t\t |-Destination Port : %u\n",ntohs(tcph->dest));
	printf("\t\t |-Sequence Number    : %u\n",ntohl(tcph->seq));
	printf("\t\t |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	printf("\t\t |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	printf("\t\t |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	printf("\t\t |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	printf("\t\t |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	printf("\t\t |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	printf("\t\t |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	printf("\t\t |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	printf("\t\t |-Window         : %d\n",ntohs(tcph->window));
	printf("\t\t |-Checksum       : %d\n",ntohs(tcph->check));
	printf("\t\t |-Urgent Pointer : %d\n",tcph->urg_ptr);
	printf("\n");
	
    //printf("\t\t                      DATA Dump                         \n");


    return;
}


void print_udp(char *buff){

    struct udphdr *udph = (struct udphdr *) malloc(sizeof(struct udphdr));
    udph = (struct udphdr *) buff;

    printf("\n\tUDP HEADER: \n\n");
	printf("\t\t   |-Source Port      : %d\n" , ntohs(udph->source));
	printf("\t\t   |-Destination Port : %d\n" , ntohs(udph->dest));
	printf("\t\t   |-UDP Length       : %d\n" , ntohs(udph->len));
	printf("\t\t   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	printf("\n");


    return;

}

void print_icmp(char *buff){

    struct icmp *icmp = (struct icmp *) buff;

    printf("\n\tICMP HEADER: \n\n");

    printf("\t\tICMP Seq No. : %u \t\tICMP Type : %d \t\tICMP Code : %d \t\tICMP ID : %d\n\n",icmp->icmp_seq, icmp->icmp_type, icmp->icmp_code, icmp->icmp_id);

    return;
}

void print_igmp(char *buff){

    struct igmp *igmph = (struct igmp *) malloc(sizeof(struct igmp));
    igmph = (struct igmp *) buff;

    printf("\n\tIGMP HEADER: \n\n");

    printf("\t\tIGMP Type : %d \t\tIGMP Code : %d \t\tIGMP Checksum : %u\n\n",igmph->igmp_type, igmph->igmp_code, igmph->igmp_cksum);

    return;
}