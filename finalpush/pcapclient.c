#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


int sockfd;
struct sockaddr_in server_addr;

FILE *dnsFile;
FILE *dnsReportFp;

unsigned int record_num=1;
// Ref : https://wiki.wireshark.org/Development/LibpcapFileFormat#overview
//https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html

/*

In pcap header we have the following content at the beginning of the file.
Magic number is used to verify whether the opened file in pcap file or not, using magic number.

*/

/*
pcap file structure:
    24 bytes pcap header 
    16 bytes record header
    incl_len bytes record or packet (Can be for any type)
    16 bytes record header
    incl_len bytes record or packet
    16 bytes record header
    incl_len bytes record or packet.
    ...
    
*/

// 24 Bytes for PCAP Header
typedef struct pcap_hdr_s {
    
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    uint32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */

} pcap_hdr_t;

/*
record header structure:
    This is a 16byte header before every record in the PCAP file.
    Third entry of this header gives information about the length of incl_len
    While forth entry gives the original length of the packet, in case cropped
*/

// Ref : https://wiki.wireshark.org/Development/LibpcapFileFormat#overview
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


/*

Record/Packet structure
    14 byte : Ethernet Header
    IPv4 Header ( > 24 bytes)
    8 bytes : UDP Header / xx : TCP Header / Or any other protocol type header
    12 bytes : DNS Header / FTP or other protocol type header
    DNS Data / or any other data in packet
*/

//' Ethernet header structure
typedef struct ethernet_header_s{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;


/*
Length of the header struct could be a variable value.
*/

// IPv4 header structure
typedef struct ipv4_header_s {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_frag_offset;
    uint8_t ttl;
    uint8_t protocol; //protocol of the entry
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} ipv4_header_t;


// UDP header structure
typedef struct udp_header_s {
    uint16_t src_port;
    uint16_t dest_port; //this should be 53 for DNS.
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

/*

DNS header
    12 bytes

*/

typedef struct dns_header_s {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
} dns_header_t;

/*
Custom header
    This is the custom header we have defined to append the additional information before DNS header, which would be sent to the server to fetch the IP address based on the predefined rules.
    8 bytes
*/
typedef struct dns_custeum_header_s {
    uint16_t hour;
    uint16_t min;
    uint16_t sec;
    uint16_t seq_no;
} dns_custom_header_t;

void print_global_header(pcap_hdr_t *hdr) { //for debugging
    printf("Magic Number   : 0x%x\n", hdr->magic_number);
    printf("Version        : %d.%d\n", hdr->version_major, hdr->version_minor);
    printf("Time Zone      : %d\n", hdr->thiszone);
    printf("Timestamp accuracy: %u\n", hdr->sigfigs);
    printf("Snapshot length: %u\n", hdr->snaplen);
    printf("Link-layer type: %u\n", hdr->network);
}

int create_dns_client_socket()
{

/*
    socket is a systems call. Here AF_INET is a macro with value 2 which is tells that the underlying protocol would be UDP or TCP.
    SOCK_DGRAM tells that we would be using the socket for datagram-oriented socket and also implies the use of UDP protocol
    
*/
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket failed");
        return (-1);
    }

    // 2. Server info
/*
memset is passed with address of that struct along with sizes. For every byte, mmset set all the values to zeroes.
Basically we pass on the starting address and the limit address. In that range we assign every value to be zero.
*/

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; //this is a standard practice to assign the value '2' for UDP and TCP
    server_addr.sin_port = htons(12345); // Server port -> Ethernet is Big Endian and if the machine is little Endian, it converts the format for compativility
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IP -> This is a special IP address, which is the self IP address, as server is also hosted on the same machine for this assignment .
    return(1);

}


int send_dns_msg_to_server(unsigned char *buf,int len)
{
    int bytesSent=0;

    //sendto is a system call(2) which sends the data to the specified port and server in server_addr
    bytesSent=sendto(sockfd, buf, len, 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (bytesSent < 0) {
        printf("sendto failed");
        return (-1);
    }

    return(bytesSent);
}

#define BUFFER_SIZE 1024

int receive_dns_msg_from_server(unsigned char *buffer)
{
    socklen_t addr_len = sizeof(server_addr);
    //recvfrom is a system call(2) which receives the data to the specified port and server in server_addr of max size BUFFER_SIZE and stores to the array buffer.
    int n = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                     (struct sockaddr *)&server_addr, &addr_len);
    if (n < 0) {
        perror("recvfrom failed"); return -1;
    } else {
        buffer[n] = '\0'; // Null-terminate the received data (Not sure if server has added)
        printf("Reply from server: %s\n", buffer);
        fprintf(dnsFile,"\n Reply from server: %s\n", buffer);
    }
    //buf=buffer;
    return 1;
}


int read_pcap_packet(FILE *fp,unsigned char **record_packet)
{
    pcaprec_hdr_t record_hdr;
    // Read the next record header

    int len = fread(&record_hdr, 1, sizeof(record_hdr), fp);
    if(len < 1){
        printf("End of file\n");
        return(0);
    } 
    
    if (len != sizeof(record_hdr)) {
        printf("Failed to read record header %d\n",len);
        return (-1);
    }

    // Print the record header fields
    //printf("Timestamp: %u.%06u seconds\n", record_hdr.ts_sec, record_hdr.ts_usec);
    //printf("Captured Length: %u bytes\n", record_hdr.incl_len);
    //printf("Original Length: %u bytes\n", record_hdr.orig_len);

/*

incl_len: Field type in the record header struct
Allocation of char array with size being incl_len + 10 bytes extra

*/

    *record_packet=malloc(sizeof(char)*record_hdr.incl_len+10); //allocated 10 bytes extra
    if( *record_packet== NULL){
        printf("Memory allocaiton failed for record_packet\n");
        return(-1);
    }

/*

len stores the length of the packet
    if len == 0:
        end of file
    else if len != incl_len:
        error
    else :
        packet read correctly and size is returned

*/
    
    len =fread(*record_packet, 1, record_hdr.incl_len, fp);
    if(len < 1){
        printf("End of file\n");
        return(0);
    }  
    if (len != record_hdr.incl_len) {
        printf("Failed to read record packet readd %d  expected %d\n",len,record_hdr.incl_len);
        return(-1);
    } 

    return(record_hdr.incl_len);

}

int parse_pcap_packet(unsigned char *pcap_packet,int pcap_packet_len)
{
    // Parse Ethernet header
    //printf("Parsing\n");
    int eth_len=14;
    int ipv4_min_len=20;
    int udp_len=8;

    if (pcap_packet_len < eth_len) {
        printf("Packet Ethernet header short pcap_packet_len %d\n\n",pcap_packet_len);
        return (-1);
    }
    ethernet_header_t *eth=(ethernet_header_t *)pcap_packet; //this is typecasting from pcap_packet to map all the data to all the fields in ethernet_header_t
    //printf("ethernet type %x\n",eth->ethertype);

    // ntohs is critical to ensure endian type 
    if (ntohs(eth->ethertype) != 0x0800) { //0x0800: as our processor is little Endian; it indicates IPv4 packet type
        printf("Not an IPv4 packet\n\n");
        return (-1);
    }

    if ( pcap_packet_len < (eth_len+ipv4_min_len) ) {
        printf("IPV4 Header Short Length (min 34) pcap_packet_len %d \n\n",pcap_packet_len);
        return (-1);
    }

    //Typecasting the next part of the packet to IpV4 header.
    ipv4_header_t *ipv4=(ipv4_header_t *)(pcap_packet+eth_len);
    //printf("IPV4 protocol %d\n",ipv4->protocol);
    if (ipv4->protocol != 17) { // UDP Protocol
        printf("Not UDP protocol %d \n\n",ipv4->protocol);
        return (-1);
    }//UDP protocol

    // Implication: it is udp protocol for DNS
    int ipv4_header_len = (ipv4->version_ihl & 0x0F) * 4;
    if (pcap_packet_len < (eth_len + ipv4_header_len + udp_len)) {
        printf("UDP Header Short Length  pcap_packet_len %d \n\n",pcap_packet_len);
        return (-1);
    
    }

    //typecasting next part of the packet to upd header structure.
    udp_header_t *udp=(udp_header_t*)(pcap_packet+ eth_len + ipv4_header_len);
    
    printf("UDP port %d %d\n",(int)ntohs(udp->src_port),ntohs(udp->dest_port));

    //fprintf(dnsFile,"Packet No %d ",record_num);
    //fprintf(dnsFile,"UDP port %d %d\n",(int)ntohs(udp->src_port),ntohs(udp->dest_port));
    
    //for (uint32_t i = 0; i < 12; i++) {
    //    printf("%02x ", *(pcap_packet+14+20+i));
    // }
    //printf("\n");
    if ((int)ntohs(udp->dest_port) != 53) {
           // printf("Not a DNS packet\n\n");
            return(-1);
    }
    fprintf(dnsFile,"Packet No %d ",record_num);
    fprintf(dnsFile,"DNS %d\n",(int)ntohs(udp->dest_port));
    
    printf("DNS Packet 53");
    
    //offset is the sum of length of all the headers before the DNS header and data
    int dns_packet_offset=eth_len + ipv4_header_len+udp_len;

    //typecasting to the dns header struct.
    dns_header_t *dns=(dns_header_t*)(pcap_packet+ dns_packet_offset);

    //checks if the protocol is for DNS.
    uint16_t dns_flags=ntohs(dns->flags);
    fprintf(dnsFile,"DNS Transaciton ID %x\n",ntohs(dns->transaction_id));
    fprintf(dnsFile,"DNS FLAGS %x\n",ntohs(dns->flags));

     if ((dns_flags & 0x8000) == 0) { //to check the dns header
        printf("DNS Query\n");
        return(dns_packet_offset);
    } 
    return(-1);
}

uint16_t dns_header_custom_sequence=0;
uint16_t fixed_hours[]={14,4,8,12,10,21,0,15,12,2,18,9,4,5};

void make_DNS_header(unsigned char *buf){
    time_t now = time(NULL); 
    struct tm *tm_info = localtime(&now); //getting ther local time 
    // Store hour, minute, second as 2-byte integers 
    uint16_t hour = tm_info->tm_hour;
    uint16_t minute = tm_info->tm_min;
    uint16_t second = tm_info->tm_sec;
    memcpy(buf,&hour,2);
    // memcpy(buf,(fixed_hours+dns_header_custom_sequence),2); //for testing difference in hours
    memcpy((buf+2),&minute,2);
    memcpy((buf+4),&second,2);
    memcpy((buf+6),&dns_header_custom_sequence,2);
    dns_header_custom_sequence++;
}
void make_custom_packet(unsigned char **custom_dns_packet,unsigned char *org_dns_packet,int dns_packet_size)
{
    *custom_dns_packet=malloc(sizeof(char)*dns_packet_size+8);
    make_DNS_header(*custom_dns_packet);
    memcpy(*custom_dns_packet+8,org_dns_packet,dns_packet_size);
}
void dns_name(unsigned char *input, unsigned char *output) 
{
   int in=0;
   int out=0;
   int length=input[in];

   while (length != 0) {
        in++;  // ignore first byte
        
        for (int i = 0; i < length; i++) {
            output[out++] = input[in++];
        }

        length = input[in]; 
        if (length != 0) {
            output[out++] = '.'; 
        }
    }
    output[out]='\0';
}

int main(int argc, char *argv[]) {
    
   // if (argc != 2) {
   //     printf("Usage: %s <pcap file>\n", argv[0]);
   //     return 1;
   // }

    printf("PCAP Client\n");
    //char *filename = argv[1];
    //char *filename = "./p.pcap";

    // Set the pcap file to be processed
    char *filename = "./6.pcap"; 
    
    //file which would be used to anayze the DNS packets
    char *dnsFileName="./dns.txt";

    dnsFile = fopen(dnsFileName, "w");
    
    dnsReportFp = fopen("./dnsReport.txt", "w");

    
    if (!dnsReportFp) {
        printf("Failed to open file\n");
        return -1;
    }

/*
    Opening the pcap file in the binary format which is stored in the little Endian format in the memory.
*/
    FILE *fp = fopen(filename, "rb");

    if (!fp) {
        printf("Failed to open file\n");
        return -1;
    }


    create_dns_client_socket(); //we initialize the client socket and configures the server_address 

    pcap_hdr_t header; //will store the header of the pcap file

/*
pcap file opened in binary format
fread : C library call to read the binary data.
It copies the first sizeof(header) amount of content to the structure.
This structure is the header of the pcap file
*/

    size_t read_bytes = fread(&header, 1, sizeof(header), fp);
    if (read_bytes != sizeof(header)) {
        printf("Failed to read pcap header\n");
        fclose(fp);
        return -1;
    }

    //printing the header of the pcap file
    print_global_header(&header);

/*

Magic number is used to validate the type of the file.
Magic number : 0xa1b2c3d4 confirms pcap file
*/    

    if(header.magic_number != 0xa1b2c3d4){
        printf("%s is not valid pcap file\n",argv[1]);
        exit(-1);
    }

    unsigned char *record_packet1;
    unsigned char *custom_dns_packet;
    record_num=1;
    uint32_t len=1;
    int dns_offset;
    int dns_packet_size;
    int dns_custom_packet_size;
    unsigned char dn_query_name[1024];
    unsigned char dns_reply_ip[1024];

/*
    fprintf: call to write header in the dnsreport.txt
*/

    fprintf(dnsReportFp,"\tCustomHeaderFile\tDomainname\t\tResolved IP Address\n");
    fprintf(dnsReportFp,"\t  (HHMMSSID)\n\n");

    //while loop to iterate through all the packets stored in the pcap file 
    
    while(len > 0){
        record_packet1=NULL; //will store the packet
        printf("packet no %d\n",record_num++);

/*

read_pcap_packet is called, which fetches the length of the packet.
Importantly it also allocates memory to the packet read and record_packet1 points to the array where packet is stored.

*/

        len=read_pcap_packet(fp,&record_packet1);


        if(len == 0 ){
            printf("end of file\n");
            break;
        }

        if(len == -1){
            printf("Error in the reading the packet\n");
            printf("Breaking the loop\n");
            break;
        }

        //printf("address %p",(void *)record_packet1);
        //printf("Packet data (first 32 bytes or less):\n");
        //for (uint32_t i = 0; i < 32; i++) {
        //      printf("%02x ", *(record_packet1+i));
        //}
        //printf("\n");
        //ethernet_header_t *eth=(ethernet_header_t *)record_packet1;
        //printf("ethernet type %x\n",eth->ethertype);
        //if (ntohs(eth->ethertype) != 0x0800) {
        //    printf("Not an IPv4 packet\n\n");
        //    return (-1);
        //}

    
    /*
    
    Once the packet has been extracted and stored into an array, parse_pcap_packet finds the location in that array where the dns data starts
    
    */

        dns_offset=parse_pcap_packet(record_packet1,len);
        dns_packet_size=len-dns_offset;
        dns_custom_packet_size= dns_packet_size+8; //stores the size for the custom data added and the original DNS packet content


        if(dns_offset > 0) // Meaning DNS packet
        {
            //printf("DNS packet\n");
            //fprintf(dnsFile,"DNS offset %d %d\n",dns_offset,len);
            //for(int i=0;i< (dns_packet_size);i++)
            //    fprintf(dnsFile,"%02x ", *(record_packet1+i+dns_offset));

            dns_name((record_packet1+dns_offset+12),dn_query_name); //this copies only the DNS data content from the data packet to the newer array
            
            fprintf(dnsFile,"\n Total Bytes %d : %s",dns_custom_packet_size,dn_query_name);

            make_custom_packet(&custom_dns_packet,(record_packet1+dns_offset),dns_packet_size); //final packet is generated and stored in  custom_dns_packet

            //data is sent to the server using syscall inside the following invoked function
            int bytesSent=send_dns_msg_to_server(custom_dns_packet,dns_custom_packet_size);
            fprintf(dnsFile,"\n  Bytes Sent %d : ",bytesSent);
            for(int i=0;i< (dns_packet_size+8);i++)
                fprintf(dnsFile,"%02x ", *(custom_dns_packet+i));
            //free(custom_dns_packet);
            //usleep(100000);

            //Resolved IPv4 is received in the dns_reply_ip
            receive_dns_msg_from_server(dns_reply_ip);

            dns_custom_header_t *dns_ch=(dns_custom_header_t*)(custom_dns_packet); //to stored the custom data.
            fprintf(dnsReportFp,"\t%02d%02d%02d%02d\t\t%s\t\t%s\n",
                            (int)dns_ch->hour,
                            (int)dns_ch->min,
                            (int)dns_ch->sec,
                            (int)dns_ch->seq_no,
                            dn_query_name,
                            dns_reply_ip

                            );
            free(custom_dns_packet);    //memory is freed.       
        }
        //printf("packet no %d\n",record_num++);
        if(record_packet1 != NULL)
            free(record_packet1);
    }

    fclose(fp);
    fclose(dnsFile);
    return 0;
}

