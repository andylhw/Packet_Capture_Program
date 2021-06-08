/*
    작성자 :      홍의성 (gowoonsori)

    공통 수집 :   Ehternet header
    

    기본 start :  TCP / UDP / ICMP 3종류의 tcp/ip프로토콜만 수집

    필터 입력 가능 정보 :  port와 ip로만 추출 가능
                        -port :
                            HTTP(80)
                            DNS (53)
                         두 종류의 프로토콜만 추출 가능
                        -ip
*/
#include <arpa/inet.h>         //network 정보 변환
#include <ctype.h>             //isdigit
#include <netinet/if_ether.h>  //etherrnet 구조체
#include <netinet/ip.h>        //ip header 구조체
#include <netinet/ip_icmp.h>   //icmp header 구조체
#include <netinet/tcp.h>       //tcp header 구조체
#include <netinet/udp.h>       //udp header 구조체
#include <pthread.h>           //thread
#include <stdio.h>             //basic
#include <stdlib.h>            //malloc 동적할당
#include <string.h>            //strlen, strcmp, strcpy
#include <sys/socket.h>        //소켓의 주소 설정 (sockaddr 구조체)
#include <sys/timeb.h>         //msec
#include <time.h>              //저장한 file 이름을 현재 날짜로 하기 위해

#define BUFFER_SIZE 65536  // buffer 사이즈 2^16 크기만큼 생성

typedef enum { false, true } bool;  // bool 자료형 선언

enum port { dns = 53, http = 80, https = 443 };  //캡쳐할 port번호

enum CaptureOptions {
    A = 1,  // ascii
    X,      // hex
    S,      // summary (no detail)
    F       // file
};          // capture option
typedef struct arpheader { 

    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
    
    char *strhType;      //hType to String.
    char *strpType;    //pType to String
    char *strOp;    //Operation Code to String
    
}arphdr_t; 
void *PacketCapture_thread(void *arg);  //캡쳐 스레드
void ARP_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size);
void Arp_header_print(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size);
void Capture_helper(FILE *captureFile, unsigned char *, int);                                       //캡쳐한 패킷 프로토콜 분류
void Ethernet_header_fprint(FILE *captureFile, struct iphdr *);                                     // Ethernet 헤더 정보 fprint
void Ip_header_fprint(FILE *captureFile, struct iphdr *, struct sockaddr_in, struct sockaddr_in);   // ip 헤더 정보 fprint
void Tcp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int);  // tcp 헤더 정보 capture
void Tcp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct tcphdr *, struct sockaddr_in, struct sockaddr_in,
                       int);                                                                        // tcp 헤더 정보 fprint
void Udp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int);  // udp 헤더 정보 capture
void Udp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct udphdr *, struct sockaddr_in, struct sockaddr_in,
                       int);  // udp 헤더 정보 fprint
void Dns_header_frpint();
                                          // icmp 헤더 정보 fprint
void Change_hex_to_ascii(FILE *captureFile, unsigned char *, int, int);  // payload값 hex/ascii/file option에 맞게 출력

void MenuBoard();           // menu board
void Menu_helper();         // menu board exception handling
void StartMenuBoard();      // start menu board
bool start_helper(char *);  // start menu exception handling
bool IsPort(char *);        //포트 형식 검사 | 맞으면 true
bool IsIpAddress(char *);   // ip 형식 검사 | 맞으면 true
bool IsDigit();             // string 이 숫자인지 검사 | 맞으면 true
void buffer_flush();        //입력 버퍼 지우기
void http_header_capture(FILE *captureData, unsigned char *response, int Size);
void https_header_capture(FILE *captureData, unsigned char *httpsHeader, int Size);
void https_header_print(FILE *captureData, unsigned char *httpsHeader, int Size);
void https_handshake_capture(FILE *captureData, unsigned char *httpsHeader, int idx);
void https_ccs_capture(FILE *captureData, unsigned char *httpsHeader, int idx);
void https_appdata_capture(FILE *captureData, unsigned char *httpsHeader, int idx);
void https_encalert_capture(FILE *captureData, unsigned char *httpsHeader, int idx);

void dhcp_header_fprint(FILE *captureData, unsigned char *dhcpHeader, int Size);
bool captureStart = false;                                                   //캡쳐 스레드 시작flag 변수
int total = 0, filter = 0, drop = 0;                                         //캡쳐한 패킷 갯수
int arpMode = 0, dnsMode = 0, httpMode = 0, httpsMode = 0, dhcpMode = 0;     //각각의 Mode값에 따라서, 캡쳐하는게 달라질꺼임.
char protocolOption[128], portOption[128], ipOption[128], printOption[128];  // filter option 변수
int main() {
    Menu_helper();

    return 0;
}
void *PacketCapture_thread(void *arg) {
    int rawSocket = *(int *)arg;                                   // raw socket 전달 받기
    int dataSize;                                                  //받은 데이터 정보 크기
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);  // buffer 공간 할당

    char filename[40];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(filename, "captureFile(%d-%d-%dT%d:%d:%d).txt", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    FILE *captureData = fopen(filename, "a+");  //파일 이어서 작성
    if (captureData == NULL) {
        printf("  !! 파일 열기 실패 하여 종료됩니다.\n");  //에러 처리
        exit(1);
    }

    //캡쳐 시작
    while (captureStart) {
        if ((dataSize = recvfrom(rawSocket, buffer, BUFFER_SIZE, 0, NULL, NULL)) == -1)  //패킷 recv
        {
            drop++;
            printf("packet 받기 실패\n");  // packet drop시
            continue;
        }
        Capture_helper(captureData, buffer, dataSize);  //받은 패킷을 프로토콜 종류에따라 처리
    }

    free(buffer);         //버퍼 공간 해제
    fclose(captureData);  // file close
}
void Capture_helper(FILE *captureData, unsigned char *buffer, int size) {
    struct ethhdr *etherHeader = (struct ethhdr *)buffer;          //버퍼에서 이더넷 정보 get
    struct iphdr *ipHeader = (struct iphdr *)(buffer + ETH_HLEN);  //받은 패킷의 ip header 부분 get
    struct arpheader *arpHeader = (struct arpheader *)(buffer + ETH_HLEN);
    
    total++;                                                       // recv한 모든 패킷 수 증가
	
    /*IPv4의 모든 프로토콜 (ETH_P_IP == 0800)*/
    char *Ptr = (char*)&etherHeader->h_proto;
    //ARP DETECTION. ARP == 0806 
    if (*Ptr == 8 && *(Ptr+1)==6){
    	printf("ARP HEADER DETECTED\n\n");\
    	ARP_header_capture(captureData, etherHeader, arpHeader, buffer, size);
    }
    else if (etherHeader->h_proto == 8) {
        /* all 프로토콜 선택시*/
        if (!strcmp(protocolOption, "*")) {
            if (ipHeader->protocol == 1) {
            } else if (ipHeader->protocol == 6) {
                Tcp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
            } else if (ipHeader->protocol == 17) {
                Udp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
            }
        } else if (!strcmp(protocolOption, "tcp") && (ipHeader->protocol == 6))  // tcp
        {
            Tcp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
        } else if (!strcmp(protocolOption, "udp") && (ipHeader->protocol == 17))  // udp
        {
            Udp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
        }
    }
}
void Ethrenet_header_fprint(FILE *captureData, struct ethhdr *etherHeader) {
    filter++;  // filter 거쳐 캡쳐한 패킷은 이 함수는 무조건 한번씩 거치기 때문에 filter 패킷 값 증가
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                     Ethernet Header                    |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "               Ethernet Type         |      0x%02X00\n",
            etherHeader->h_proto);  // L3 패킷 타입 IPv4 : 0x0800  | ARP 패킷 : 0x0806 | VLAN Tag : 0x8100
    fprintf(captureData, "               Src MAC Addr          |      [%02x:%02x:%02x:%02x:%02x:%02x]\n",  // 6 byte for src
            etherHeader->h_source[0], etherHeader->h_source[1], etherHeader->h_source[2], etherHeader->h_source[3],
            etherHeader->h_source[4], etherHeader->h_source[5]);
    fprintf(captureData, "               Dst MAC Addr          |      [%02x:%02x:%02x:%02x:%02x:%02x]\n",  // 6 byte for dest
            etherHeader->h_dest[0], etherHeader->h_dest[1], etherHeader->h_dest[2], etherHeader->h_dest[3], etherHeader->h_dest[4],
            etherHeader->h_dest[5]);
    fprintf(captureData, "           --------------------------------------------------------\n\n");
}

void Ip_header_fprint(FILE *captureData, struct iphdr *ipHeader, struct sockaddr_in source, struct sockaddr_in dest) {
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       IP Header                        |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                IP Version           |    IPv%d\n", (unsigned int)ipHeader->version);
    fprintf(captureData, "                IP Header Length     |    %d DWORDS ( %d Bytes )\n", (unsigned int)ipHeader->ihl,
            ((unsigned int)(ipHeader->ihl)) * 4);
    fprintf(captureData, "                Type Of Service      |    %d\n", (unsigned int)ipHeader->tos);
    fprintf(captureData, "                IP Total Length      |    %d Bytes\n", ntohs(ipHeader->tot_len));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Identification       |    %d\n", ntohs(ipHeader->id));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Time To Live (TTL)   |    %d\n", (unsigned int)ipHeader->ttl);
    fprintf(captureData, "                Protocol             |    %d\n", (unsigned int)ipHeader->protocol);
    fprintf(captureData, "                Checksum             |    0x%04X\n", ntohs(ipHeader->check));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Src IP Addr          |    %s\n", inet_ntoa(source.sin_addr));
    fprintf(captureData, "                Dst IP Addr          |    %s\n", inet_ntoa(dest.sin_addr));
    fprintf(captureData, "           --------------------------------------------------------\n\n");
}

void ARP_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size){
	u_int8_t sourceMAC[6];
	u_int8_t destMAC[6];
	struct sockaddr_in source, dest;
	printf("ARP PACKET\n");
	printf("HARDWARE IDENTIFIER: [");
	
	switch(ntohs(arpHeader->htype))
	{
		case ARPHRD_NETROM:
			printf("NET/ROM pseud]\n");
			arpHeader->strhType="NET/ROM pseud";
			break;
		case ARPHRD_ETHER:
			printf("Ethernet 100Mbps/1Gbps]\n");
			arpHeader->strhType="Ethernet 100Mbps/1Gbps";
			break;
		case ARPHRD_EETHER:
			printf("Experimental Ethernet]\n");
			arpHeader->strhType="Experimental Ethernet";
			break;
		case ARPHRD_AX25:
			printf("AX.25 Level 2]\n");
			arpHeader->strhType="AX.25 Level 2";
			break;
		case ARPHRD_IEEE802:
			printf("IEEE 802.2 Ethernet/TR/TB]\n");
			arpHeader->strhType="IEEE 802.2 Ethernet/TR/TB";
			break;
		default:
			printf("Other type...]\n");
			arpHeader->strhType="Unknown Type";
			break;
	}
	if(arpHeader->ptype==8){
		printf("Format of protocol type: IPv4\n");
		arpHeader->strpType="IPv4";
	}
	
	printf("Length of hardware address: %d\n", arpHeader->hlen);
	printf("Length of protocol address: %d\n", arpHeader->plen);
	printf("ARP Command: [");
	switch(ntohs(arpHeader->oper)){
		case ARPOP_REQUEST:
			printf("ARP Request]\n");
			arpHeader->strOp = "ARP Request";	
			break;
		case ARPOP_REPLY:
			printf("ARP Reply]\n");
			arpHeader->strOp = "ARP Reply";
			break;
		case ARPOP_RREQUEST:
			printf("RARP Request]\n");
			arpHeader->strOp = "RARP Request";
			break;
		case ARPOP_RREPLY:
			printf("RARP Reply]\n");
			arpHeader->strOp = "RARP Reply";
			break;
		case ARPOP_InREQUEST:
			printf("InARP Request]\n");	
			arpHeader->strOp = "InARP Request";
			break;
		case ARPOP_InREPLY:
			printf("InARP Reply]\n");
			arpHeader->strOp = "InARP Reply";
			break;	
		case ARPOP_NAK:
			printf("(ATM)ARP NAK]\n");
			arpHeader->strOp = "(ATM)ARP NAK";
			break;
		default:
			printf("Unknown Type]\n");
			arpHeader->strOp = "Unknown Type";
			break;
	}
	printf("MAC: [%02X:%02X:%02X:%02X:%02X:%02X]-> ", arpHeader->sha[0],arpHeader->sha[1],arpHeader->sha[2],arpHeader->sha[3],arpHeader->sha[4],arpHeader->sha[5]);
	printf("MAC: [%02X:%02X:%02X:%02X:%02X:%02X]\n",arpHeader->tha[0], arpHeader->tha[1], arpHeader->tha[2], arpHeader->tha[3], arpHeader->tha[4], arpHeader->tha[5]);
	printf("IP: [%d.%d.%d.%d] -> ", arpHeader->spa[0], arpHeader->spa[1], arpHeader->spa[2], arpHeader->spa[3]);
	printf("[%d.%d.%d.%d]\n", arpHeader->tpa[0],arpHeader->tpa[1],arpHeader->tpa[2],arpHeader->tpa[3]);
	Arp_header_print(captureData, etherHeader, arpHeader, Buffer, Size);
}
void Arp_header_print(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size){
fprintf(captureData, "\n############################## ARP Packet #####################################\n");
	Ethrenet_header_fprint(captureData, etherHeader);
	fprintf(captureData, "\n           --------------------------------------------------------\n");
    	fprintf(captureData, "          |                       ARP Packet                       |\n");
	fprintf(captureData, "           --------------------------------------------------------\n");
	fprintf(captureData, "                  Hardware ID        |   %s\n", arpHeader->strhType);
	fprintf(captureData, "             Format of Protocol Type |   %s\n", arpHeader->strpType);
	fprintf(captureData, "           Length of hardware address|   %d\n", arpHeader->hlen);
	fprintf(captureData, "           Length of Protocol Address|   %d\n", arpHeader->plen);
	fprintf(captureData, "           --------------------------------------------------------\n");
	fprintf(captureData, "                  ARP Command        |   %s\n", arpHeader->strOp);
	fprintf(captureData, "               Source MAC Address    |   [%02X:%02X:%02X:%02X:%02X:%02X]\n", arpHeader->sha[0], arpHeader->sha[1], arpHeader->sha[2], arpHeader->sha[3], arpHeader->sha[4], arpHeader->sha[5]);
	fprintf(captureData, "               Dest MAC Address      |   [%02X:%02X:%02X:%02X:%02X:%02X]\n", arpHeader->tha[0], arpHeader->tha[1], arpHeader->tha[2], arpHeader->tha[3], arpHeader->tha[4], arpHeader->tha[5]);
	fprintf(captureData, "               Source IP Address     |   [%u.%u.%u.%u]\n", arpHeader->spa[0], arpHeader->spa[1], arpHeader->spa[2], arpHeader->spa[3] );
	fprintf(captureData, "               Dest IP Address       |   [%u.%u.%u.%u]\n", arpHeader->tpa[0], arpHeader->tpa[1], arpHeader->tpa[2], arpHeader->tpa[3] );
	fprintf(captureData, "           --------------------------------------------------------\n");
	//Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + , F,  (Size - ETH_HLEN));
}
void Tcp_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct iphdr *ipHeader, unsigned char *Buffer, int Size) {
    struct tcphdr *tcpHeader = (struct tcphdr *)(Buffer + (ipHeader->ihl * 4) + ETH_HLEN);  //버퍼에서 tcp 헤더 정보 get
    struct sockaddr_in source, dest;  //출발, 목적지 주소 정보 저장할 변수
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // filter ip 검사
    if (!strcmp(ipOption, "*") || !strcmp(inet_ntoa(source.sin_addr), ipOption) ||
        !strcmp(inet_ntoa(dest.sin_addr), ipOption)) {
        // filter port번호 검사
        if (!strcmp(portOption, "*") || (atoi(portOption) == (int)ntohs(tcpHeader->source)) ||
            (atoi(portOption) == (int)ntohs(tcpHeader->dest))) {
            /*현재 시간 get*/
            struct timeb itb;
            ftime(&itb);
            struct tm *tm = localtime(&itb.time);
            fprintf(stdout, "\n%02d:%02d:%02d:%03d IPv", tm->tm_hour, tm->tm_min, tm->tm_sec, itb.millitm);
            if (ntohs(tcpHeader->source) == http) {
                fprintf(stdout, "[%s]:%u(http) > ",  inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "[%s]:%u = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            } else if (ntohs(tcpHeader->dest) == http) {
                fprintf(stdout, "[%s]:%u > ",  inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "[%s]:%u(http) = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            } else if (ntohs(tcpHeader->source) == https){
            	fprintf(stdout, "[%s]:%u(https) > ", inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "[%s]:%u = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            } else if (ntohs(tcpHeader->dest) == https){
            	fprintf(stdout, "[%s]:%u > ", inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "[%s]:%u(https) = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            }
            
           	else {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "%s:%u = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            }
            if ((unsigned int)tcpHeader->urg == 1) fprintf(stdout, "U.");
            if ((unsigned int)tcpHeader->ack == 1) fprintf(stdout, "A.");
            if ((unsigned int)tcpHeader->psh == 1) fprintf(stdout, "P.");
            if ((unsigned int)tcpHeader->rst == 1) fprintf(stdout, "R.");
            if ((unsigned int)tcpHeader->syn == 1) fprintf(stdout, "S.");
            if ((unsigned int)tcpHeader->fin == 1) fprintf(stdout, "F.");
            fprintf(stdout, "], seq %u, ack %u, win %d, length %d", ntohl(tcpHeader->seq), ntohl(tcpHeader->ack_seq),
                    ntohs(tcpHeader->window), Size);

            /*print option에 따라 payload 부분 다르게 출력*/
            /*
            ascill 출력
            if (!strcmp(printOption, "a")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, A, ETH_HLEN);  // ethernet
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, A, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mtcp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), A, sizeof tcpHeader);  // tcp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof tcpHeader, A,
                                    (Size - sizeof tcpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            hex 출력
            else if (!strcmp(printOption, "x")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, X, ETH_HLEN);  // ethernet
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, X, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mtcp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), X, sizeof tcpHeader);  // tcp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof tcpHeader, X,
                                    (Size - sizeof tcpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            */
            //http 출력.
            
            Tcp_header_fprint(captureData, Buffer, etherHeader, ipHeader, tcpHeader, source, dest, Size);
            if(ntohs(tcpHeader->source) == http || ntohs(tcpHeader->dest) == http){
            	printf("\nHTTP DETECTED\n");
            	http_header_capture(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + 20, Size);
            }
            //https 출력
            if(ntohs(tcpHeader->source) == https || ntohs(tcpHeader->dest) == https){
            	printf("\nHTTPS DETECTED\n");
            	https_header_print(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + 20, Size);
            }
            /*file 출력*/
            
        }
    }
}
void Tcp_header_fprint(FILE *captureData, unsigned char *Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader, struct tcphdr *tcpHeader, struct sockaddr_in source, struct sockaddr_in dest, int Size) {
    fprintf(captureData, "\n############################## TCP Packet #####################################\n");
    Ethrenet_header_fprint(captureData, etherHeader);       // ethernet 정보 fprint
    Ip_header_fprint(captureData, ipHeader, source, dest);  // ip 정보 fprint

    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       TCP Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Source Port             |   %u\n", ntohs(tcpHeader->source));
    fprintf(captureData, "             Dest Port               |   %u\n", ntohs(tcpHeader->dest));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Sequence Number         |   %u\n", ntohl(tcpHeader->seq));
    fprintf(captureData, "             Acknowledge Number      |   %u\n", ntohl(tcpHeader->ack_seq));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             OFFSET(Header Length)   |   %d DWORDS (%d BYTES)\n", (unsigned int)tcpHeader->doff,
            (unsigned int)tcpHeader->doff * 4);
    fprintf(captureData, "           -- FLAGS -----------------------------------------------\n");
    fprintf(captureData, "              |-Urgent Flag          |   %d\n", (unsigned int)tcpHeader->urg);
    fprintf(captureData, "              |-Ack Flag             |   %d\n", (unsigned int)tcpHeader->ack);
    fprintf(captureData, "              |-Push Flag            |   %d\n", (unsigned int)tcpHeader->psh);
    fprintf(captureData, "              |-Reset Flag           |   %d\n", (unsigned int)tcpHeader->rst);
    fprintf(captureData, "              |-Synchronise Flag     |   %d\n", (unsigned int)tcpHeader->syn);
    fprintf(captureData, "              |-Finish Flag          |   %d\n", (unsigned int)tcpHeader->fin);
    fprintf(captureData, "             Window Size (rwnd)      |   %d\n", ntohs(tcpHeader->window));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Checksum                |   0x%04x\n", ntohs(tcpHeader->check));
    fprintf(captureData, "             Urgent Pointer          |   %d\n", tcpHeader->urg_ptr);
    fprintf(captureData, "           --------------------------------------------------------\n");

    /* 패킷 정보(payload) Hex dump 와 ASCII 변환 데이터 파일에 출력 */
    Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + tcpHeader->doff * 4, F, (Size - tcpHeader->doff * 4 - (ipHeader->ihl * 4) - ETH_HLEN));
    //fprintf(captureData, "\n===============================================================================\n");
}
#define RESPONSE_SIZE 32768

void http_header_capture(FILE *captureData, unsigned char *response, int Size){
    /*http 위치찾기.
    for(int i=0;i<30;i++){
    	printf("%02x ", *(response+i));
    }
    */
    int getMode = 0;
    //if GET -> Response가 필요없음.
    if(*response==0x47 && *(response+1)==0x45 && *(response+2) == 0x54){
            	getMode = 1;
    }	
    char *p = response, *q = 0;
    char *end = response + RESPONSE_SIZE;
    char *body = 0;
    enum {length, chunked, connection};
    int encoding = 0;
    int remaining = 0;
    while(1){
    	    
            if (!body && (body = strstr(response, "\r\n\r\n"))) {
                *body = 0;
                body += 4;
		fprintf(captureData, "\nReceived Headers:\n%s\n", response);
                printf("\nReceived Headers:\n%s\n", response);
		
                q = strstr(response, "\nContent-Length: ");
                if (q) {
                    encoding = length;
                    q = strchr(q, ' ');
                    q += 1;
                    remaining = strtol(q, 0, 10);

                } else {
                    q = strstr(response, "\nTransfer-Encoding: chunked");
                    if (q) {
                        encoding = chunked;
                        remaining = 0;
                    } else {
                        encoding = connection;
                    }
                }
                if(getMode != 1){
                
                fprintf(captureData, "\nReceived Body:\n");
                printf("\nReceived Body:\n");
                }
            }else{
            //if not GET -> Get은 요청이니까 제외
	    		if(getMode != 1){
            			printf("%s", body);
            		}
            		break;
            }
            
            	if (body) {
	                if (encoding == length) {
	                    if (p - body >= remaining && *body>=0x21 && *body<=0x7e) {
	                        fprintf(captureData, "%.*s", remaining, body);
	                        printf("%.*s", remaining, body);
                        	break;
	                    }
                	} else if (encoding == chunked) {
	                    do {
	                        if (remaining == 0) {
	                            if ((q = strstr(body, "\r\n"))) {
	                                remaining = strtol(body, 0, 16);
	                                if (!remaining) goto finish;
	                                body = q + 2;
	                            } else {
	                                break;
	                            }
	                        }
                        	if (remaining && p - body >= remaining && *body>=0x21 && *body<=0x7e) {
	                            fprintf(captureData, "%.*s", remaining, body);
	                            printf("%.*s", remaining, body);
	                            body += remaining + 2;
	                            remaining = 0;
	                        }
	                    } while (!remaining);
	                }
	            } //if (body)
	            else{
	            	break;
	      }
          
    }
    finish:
    	printf("\n");
}
void https_header_print(FILE *captureData, unsigned char *httpsHeader, int Size){
	fprintf(captureData, "\n           --------------------------------------------------------\n");
    	fprintf(captureData, "          |                      HTTPS Header                      |\n");
    	fprintf(captureData, "           --------------------------------------------------------\n");
    	https_header_capture(captureData, httpsHeader, Size);
}
void https_header_capture(FILE *captureData, unsigned char *httpsHeader, int Size){
	int idx = 0;
	for(int i=0;i<10;i++){
		printf("%02X ", httpsHeader[i]);
	}
	printf("\n");
	//Content Type: Handshake(22), ChangeCipherSpec(20), ApplicationData(23), Encrypted Alert(21)
	if(httpsHeader[idx]==20){
		https_ccs_capture(captureData, httpsHeader, idx);
		return;
	}
	if(httpsHeader[idx]==21){
		https_encalert_capture(captureData, httpsHeader, idx);
		return;
	}
	if(httpsHeader[idx]==22){
		https_handshake_capture(captureData, httpsHeader, idx);
		return;
	}
	if(httpsHeader[idx]==23){
		https_appdata_capture(captureData, httpsHeader, idx);
		return;
	}
}
void https_encalert_capture(FILE *captureData, unsigned char *httpsHeader, int idx){
	fprintf(captureData, "             Content Type            |   Encrypted Alert(21)\n");
	idx++;
	int alertLen = httpsHeader[idx];
	
	fprintf(captureData, "             Version                 |   TLS 1.2\n");
	fprintf(captureData, "             Length                  |   %d\n", alertLen);
	idx++;
	fprintf(captureData, "             Alert Message           |   Encrypted Alert\n");
	for(int i=0;i<alertLen;i++){
		idx++;
	}
	return;
}
void https_appdata_capture(FILE *captureData, unsigned char *httpsHeader, int idx){
	fprintf(stdout, "Content Type: Application Data\n");
	fprintf(captureData, "             Content Type            |   Application Data(23)\n");
	idx+=2;
	int appLength=0;
	if(httpsHeader[idx]==1){
		fprintf(stdout, "Version: TLS 1.0\n");
		fprintf(captureData, "             Version                 |   TLS 1.0\n");

	}
	if(httpsHeader[idx]==2){
		fprintf(stdout, "Version: TLS 1.1\n");
		fprintf(captureData, "             Version                 |   TLS 1.1\n");
	}
	if(httpsHeader[idx]==3){
		fprintf(captureData, "             Version                 |   TLS 1.2\n");
		fprintf(stdout, "Version: TLS 1.2\n");
	}
	idx++;
	appLength += httpsHeader[idx]*16*16;
	idx++;
	appLength+=httpsHeader[idx];
	fprintf(captureData, "             Length                  |   %d\n", appLength);
	idx++;
	fprintf(captureData, "             First Ten Enc  AppData  |   ");
	fprintf(stdout, "Length: %d\n", appLength);
	fprintf(stdout, "First Ten Encrypted Application Data: ");
	if(appLength>10){
		for(int i=0;i<10;i++){
			fprintf(stdout, "%02x", httpsHeader[idx]);
			fprintf(captureData, "%02x", httpsHeader[idx]);
			idx++;
		}
		for(int i=0;i<appLength-10;i++){
			idx++;
		}
	}
	if(appLength<10){
		for(int i=0;i<appLength;i++){
			fprintf(stdout, "%02x", httpsHeader[idx]);
			fprintf(captureData, "%02x", httpsHeader[idx]);
			idx++;
		}
	}
	fprintf(stdout, "\n");
	fprintf(captureData, "\n");
	
	//DEBUG
	//fprintf(stdout, "Next: %02x\n", httpsHeader[idx]);
	
	if(httpsHeader[idx]==23 || httpsHeader[idx]==22 || httpsHeader[idx]==20){ 
		https_header_capture(captureData, httpsHeader+idx, idx);
		return;
	}else{
		return;
	}
	
	
	
}
void https_ccs_capture(FILE *captureData, unsigned char *httpsHeader, int idx){	
	fprintf(stdout, "Content Type: ChangeCipherSpec(20)\n");
	fprintf(captureData, "             Content Type            |   ChangeCipherSpec(20)\n");
	idx+=2;
	if(httpsHeader[idx]==1){
		fprintf(stdout, "Version: TLS 1.0\n");
		fprintf(captureData, "             Version                 |   TLS 1.0\n");

	}
	if(httpsHeader[idx]==2){
		fprintf(stdout, "Version: TLS 1.1\n");
		fprintf(captureData, "             Version                 |   TLS 1.1\n");
	}
	if(httpsHeader[idx]==3){
		fprintf(captureData, "             Version                 |   TLS 1.2\n");
		fprintf(stdout, "Version: TLS 1.2\n");
	}
	idx++;
	int length = httpsHeader[idx]*16*16;
	//printf("first length: %d", length);
	idx++;
	length+=httpsHeader[idx];
	fprintf(stdout, "Length: %d\n", length);
	idx++;
	fprintf(stdout, "Change Cipher Spec Message\n");
	idx++;
	fprintf(stdout, "next: %02x\n", httpsHeader[idx]);
	if(httpsHeader[idx]==23 || httpsHeader[idx]==22 || httpsHeader[idx]==20){ 
		https_header_capture(captureData, httpsHeader+idx, idx);
		return;
	}else{
		return;
	}
	
}
void https_handshake_capture(FILE *captureData, unsigned char *httpsHeader, int idx){
	//Server(1) Client(0)
	int server = 0;
	if(!(httpsHeader[idx]==22 && httpsHeader[idx+1]==3)){
		return;
	}
	
	fprintf(stdout, "Content Type: Handshake(22)\n");
	fprintf(captureData, "             Content Type            |   Handshake(22)\n");
	idx+=2;
	if(httpsHeader[idx]==1){
		fprintf(stdout, "Version: TLS 1.0\n");
		fprintf(captureData, "             Version                 |   TLS 1.0\n");

	}
	if(httpsHeader[idx]==2){
		fprintf(stdout, "Version: TLS 1.1\n");
		fprintf(captureData, "             Version                 |   TLS 1.1\n");
	}
	if(httpsHeader[idx]==3){
		fprintf(captureData, "             Version                 |   TLS 1.2\n");
		fprintf(stdout, "Version: TLS 1.2\n");
	}
	idx++;
	int length = httpsHeader[idx]*16*16;
	//printf("first length: %d", length);
	idx++;
	
	length+=httpsHeader[idx];
	fprintf(stdout, "Length: %d\n", length);
	fprintf(captureData, "             Length                  |   %d\n", length);
	idx++;
	//printf("Test value: %d\n", httpsHeader[idx]);
	if(httpsHeader[idx]> 5){
		return;
	}
	if(httpsHeader[idx]==1){
		fprintf(stdout, "\nHandshake Protocol: Client Hello\n");
		fprintf(stdout, "Handshake Type: Client Hello\n");

		fprintf(captureData, "             Handshake Protocol      |   Client Hello\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Client Hello\n");
	}
	if(httpsHeader[idx]==2){
		server=1;
		fprintf(stdout, "Handshake Protocol: Server Hello\n");
		fprintf(stdout, "Handshake Type: Server Hello\n");
		fprintf(captureData, "             Handshake Protocol      |   Server Hello\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Server Hello\n");
	}
	if(httpsHeader[idx]==4){
		fprintf(stdout, "Handshake Protocol: New Session Ticket\n");
		fprintf(captureData, "             Handshake Protocol      |   New Session Ticket\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		idx+=2;
		int ticketT = httpsHeader[idx]*256;
		idx++;
		ticketT +=httpsHeader[idx];
		fprintf(stdout, "Session Ticket Lifecycle Hint: %d\n", ticketT);
		fprintf(captureData, "       Session Ticket Lifecycle Hint |   %d\n", ticketT);

		idx++;
		int ticketLen = httpsHeader[idx]*256;
		idx++;
		ticketLen += httpsHeader[idx];
		fprintf(stdout, "Session Ticket Length: %d\n", ticketLen);
		fprintf(captureData, "             Session Ticket Length   |   %d\n", ticketLen);
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Server Hello\n");
		idx++;
		fprintf(stdout, "First Ten Session Ticket: ");
		fprintf(captureData, "             First Ten Session Ticket|   ");
		if(ticketLen>10){
			for(int i=0;i<10;i++){
				fprintf(stdout, "%02x", httpsHeader[idx]);
				fprintf(captureData, "%02x", httpsHeader[idx]);
				idx++;
			}
			for(int i=0;i<ticketLen-10;i++){
				idx++;
			}
		}
		if(ticketLen<10){
			for(int i=0;i<ticketLen;i++){
				fprintf(stdout, "%02x", httpsHeader[idx]);
				fprintf(captureData, "%02x", httpsHeader[idx]);
				idx++;
			}
		}
		fprintf(stdout, "\n");
		fprintf(captureData, "\n");
		
		//DEBUG
		//fprintf(stdout, "Next: %02x\n", httpsHeader[idx]);
		if(httpsHeader[idx]==23 || httpsHeader[idx]==22 || httpsHeader[idx]==20){ 
			https_header_capture(captureData, httpsHeader+idx, idx);
			return;
		}else{
			return;
		}
		
		return;
	}
	if(httpsHeader[idx]==11){
		fprintf(stdout, "Handshake Protocol: Certificate\n");
		fprintf(stdout, "Handshake Type: Certificate\n");
		fprintf(captureData, "             Handshake Protocol      |   Certificate\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Certificate\n");
		idx+=2;
		int cerLen = httpsHeader[idx]*256;
		idx++;
		cerLen += httpsHeader[idx];
		fprintf(stdout, "Certificate Length: %d\n", cerLen);
		fprintf(captureData, "             Certificate Length      |   %d\n", cerLen);
		idx+=cerLen+1;
		if(httpsHeader[idx]==23 || httpsHeader[idx]==22 || httpsHeader[idx]==20){ 
			https_header_capture(captureData, httpsHeader+idx, idx);
			return;
		}else{
			return;
		}		
		return;		
	}
	if(httpsHeader[idx]==14){
		fprintf(stdout, "Handshake Protocol: Server Hello Done\n");
		fprintf(stdout, "Handshake Type: Server Hello Done\n");
		fprintf(captureData, "             Handshake Protocol      |   Server Hello Done\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Server Hello Done\n");
		fprintf(stdout, "Length: 0\n");
		fprintf(captureData, "             Length                  |   0\n");
		return;		
	}
	
	
	if(httpsHeader[idx]==16){
		fprintf(captureData, "             Handshake Protocol      |   Client Key Exchange\n");
		fprintf(captureData, "           --------------------------------------------------------\n");
		fprintf(captureData, "             Handshake Type          |   Client Key Exchange\n");
		fprintf(stdout, "Handshake Protocol: Client Key Exchange\n");
		idx+=3;
		fprintf(stdout, "Length: %d\n", httpsHeader[idx]);
		fprintf(captureData, "             Length                  |   %d\n", httpsHeader[idx]);		
		int ckLen=httpsHeader[idx];
		idx++;
		
		fprintf(captureData, "             Params                  |   EC Diffie-Hellman Client \n");
		fprintf(captureData, "           --------------------------------------------------------\n");		
		fprintf(stdout, "EC Diffie-Hellman Client Params\n");
		fprintf(stdout, "PubKey Length: %d\n", ckLen-1);
		fprintf(captureData, "             PubKey Length           |   %d\n", ckLen-1);
		fprintf(captureData, "             PubKey(10)              |   ");
		for(int i=0;i<10;i++){
			fprintf(captureData, "%02x", httpsHeader[idx+i]);
		}
		for(int i=0;i<ckLen-1;i++){
			fprintf(stdout, "%02x", httpsHeader[idx]);
			idx++;
		}
		if(httpsHeader[idx]==23 || httpsHeader[idx]==22 || httpsHeader[idx]==20){ 
			https_header_capture(captureData, httpsHeader+idx, idx);
			return;
		}else{
			return;
		}
	}
	idx++;
	int hSLength = httpsHeader[idx]*16*16*16*16;
	int extLength;
	idx++;
	hSLength += httpsHeader[idx]*16*16;
	idx++;
	hSLength += httpsHeader[idx];
	fprintf(stdout, "Handshake Length: %d\n", hSLength);
	idx+=2;
	if(httpsHeader[idx]==1){
		fprintf(stdout, "Version: TLS 1.0\n");
	}
	if(httpsHeader[idx]==2){
		fprintf(stdout, "Version: TLS 1.1\n");		
	}
	if(httpsHeader[idx]==3){
		fprintf(stdout, "Version: TLS 1.2\n");
	}
	idx++;
	fprintf(stdout, "Random value: ");
	for(int i=0;i<32;i++){
		fprintf(stdout, "%02x", httpsHeader[idx+i]);
	}
	fprintf(stdout, "\n");
	idx+=32;
	fprintf(stdout, "Session Length: %d\n", httpsHeader[idx]);
	int sesLength = httpsHeader[idx];
	idx++;
	if(sesLength>0){
		fprintf(stdout, "Session ID: ");
		for(int i=0;i<sesLength;i++){
			fprintf(stdout, "%02x", httpsHeader[idx]);
			idx++;
		}
		fprintf(stdout, "\n");
	}
	//sleep(1);
	if(server == 1){
		if(httpsHeader[idx] == 0x13 && httpsHeader[idx+1] == 0x01){
			fprintf(stdout, "Cipher Suite: TLS_AES_128_GCM_SHA256\n");
		}
		if(httpsHeader[idx] == 0x13 && httpsHeader[idx+1] == 0x02){
			fprintf(stdout, "Cipher Suite: TLS_AES_256_GCM_SHA384\n");
		}
		idx+=2;
		if(httpsHeader[idx] != 0){
			printf("Compression Method: %d\n", httpsHeader[idx]);
		}
		if(httpsHeader[idx] == 0){
			printf("Compression Method: (null)\n");
		}
		idx++;
		extLength = httpsHeader[idx]*16*16;
		idx++;
		extLength+=httpsHeader[idx];
		fprintf(stdout, "Extensions Length: %d\n", extLength);
			
		/*
		idx+=6;
		if(httpsHeader[idx]==4){
			fprintf(stdout,"Extension: supported version\n");
			fprintf(stdout,"Type: supported version (43)\n");
			fprintf(stdout,"Length: 2\n");
			fprintf(stdout,"Supported Version: TLS 1.3\n");
		}
		*/
		idx+=2;
		if(httpsHeader[idx]==51){
			fprintf(stdout,"Type: Key share\n");
		}
		idx++;
		int klen=httpsHeader[idx]*16*16;
		idx++;
		klen+=httpsHeader[idx];
		fprintf(stdout, "Length: %d\n", klen);
		idx+=2;
		if(httpsHeader[idx]==0x1d){
			fprintf(stdout, "Group: x25519\n");
		}
		idx++;
		int keLen = httpsHeader[idx]*16*16;
		idx++;
		keLen += httpsHeader[idx];
		fprintf(stdout, "Key Exchange Length: %d\n", keLen);
		idx++;
		fprintf(stdout, "Key Exchange: ");
		for(int i=0;i<32;i++){
			fprintf(stdout, "%02x", httpsHeader[idx+i]);
		}
		fprintf(stdout, "\n");
		idx++;
	}
	if(server == 0){
		int csLen = httpsHeader[idx]*16*16;
		idx++;
		csLen += httpsHeader[idx];
		fprintf(stdout, "Cipher Suite Length: %d\n", csLen);
		idx+=csLen;
		idx++;
		fprintf(stdout, "Compression Methods Length: %d\n", httpsHeader[idx]);
		idx++;
		fprintf(stdout, "Compression Methods: %d\n", httpsHeader[idx]);
		idx++;
		int extLen = httpsHeader[idx]*16*16;
		idx++;
		extLen+=httpsHeader[idx];
		fprintf(stdout, "Extension Length: %d\n", extLen);
		idx+=2;
		if(httpsHeader[idx]==0){
			fprintf(stdout, "Type: server_name\n");
		}
		idx++;
		int extLen2 = httpsHeader[idx]*16*16;
		idx++;
		extLen2+=httpsHeader[idx];
		fprintf(stdout, "Length: %d\n", extLen2);
		idx++;
		fprintf(stdout, "Server Name: ");
		for(int k=0;k<extLen2;k++){
			fprintf(stdout, "%c", httpsHeader[idx]);
			idx++;
		}
		
		
		
	}
}
void Udp_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct iphdr *ipHeader, unsigned char *Buffer, int Size) {
    struct udphdr *udpHeader = (struct udphdr *)(Buffer + ipHeader->ihl * 4 + ETH_HLEN);  //버퍼에서 udp 헤더 정보 get
    struct sockaddr_in source, dest;                                                      //출발, 목적지 주소 정보 저장할 변수
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // ip filter 검사
    if (!strcmp(ipOption, "*") || !strcmp(inet_ntoa(source.sin_addr), ipOption) ||
        !strcmp(inet_ntoa(dest.sin_addr), ipOption)) {  // port 번호 filter 검사
        if (!strcmp(portOption, "*") || (atoi(portOption) == (int)ntohs(udpHeader->source)) ||
            (atoi(portOption) == (int)ntohs(udpHeader->dest))) {
            /*현재 시간 get*/
            struct timeb itb;
            ftime(&itb);
            struct tm *tm = localtime(&itb.time);
            fprintf(stdout, "\n%02d:%02d:%02d:%03d IPv", tm->tm_hour, tm->tm_min, tm->tm_sec, itb.millitm);
            if (ntohs(udpHeader->source) == dns) {
            
            	Udp_header_fprint(captureData, Buffer, etherHeader, ipHeader, udpHeader, source, dest, Size);
                fprintf(stdout, "%d %s:dns > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr));
                fprintf(stdout, "%s:%u = UDP ", inet_ntoa(dest.sin_addr), ntohs(udpHeader->dest));
                Dns_header_frpint(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            } else if (ntohs(udpHeader->dest) == dns) {
            
            	Udp_header_fprint(captureData, Buffer, etherHeader, ipHeader, udpHeader, source, dest, Size);
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(udpHeader->source));
                fprintf(stdout, "%s:dns = UDP ", inet_ntoa(dest.sin_addr));
                Dns_header_frpint(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            }
            //if Port Number is DHCP(67)
            else if(ntohs(udpHeader->source) == 67){
            	fprintf(stdout, "%d %s:dns > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr));
                fprintf(stdout, "%s:%u = UDP ", inet_ntoa(dest.sin_addr), ntohs(udpHeader->dest));
                dhcp_header_fprint(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            }
            else if(ntohs(udpHeader->dest) == 67){
            	fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(udpHeader->source));
                fprintf(stdout, "%s:DHCP = UDP ", inet_ntoa(dest.sin_addr));
                dhcp_header_fprint(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            }
            else {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(udpHeader->source));
                fprintf(stdout, "%s:%u = UDP ", inet_ntoa(dest.sin_addr), ntohs(udpHeader->dest));
            }
            fprintf(stdout, "( length %d )\n", Size);

            /*ascii 출력
            if (!strcmp(printOption, "a")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, A, ETH_HLEN);  // ethernert
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, A, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mudp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), A, sizeof udpHeader);  // udp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, A,
                                    (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            hex 출력
            else if (!strcmp(printOption, "x")) {
                fprintf(stdout, "\n\033[101methernet\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer, X, ETH_HLEN);  // ethernert
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, X, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mudp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), X, sizeof udpHeader);  // udp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, X,
                                    (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            */

            /*file 출력*/
        }
    }
}
void Udp_header_fprint(FILE *captureData, unsigned char *Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader,
                       struct udphdr *udpHeader, struct sockaddr_in source, struct sockaddr_in dest, int Size) {
    fprintf(captureData, "\n############################## UDP Packet #####################################\n");
    Ethrenet_header_fprint(captureData, etherHeader);       // ethernet 정보 print
    Ip_header_fprint(captureData, ipHeader, source, dest);  // ip 정보 print
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       UDP Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Source Port          |   %u\n", ntohs(udpHeader->source));
    fprintf(captureData, "                Destination Port     |   %u\n", ntohs(udpHeader->dest));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                UDP Length           |   %d\n", ntohs(udpHeader->len));
    fprintf(captureData, "                UDP Checksum         |   0x%04x\n", ntohs(udpHeader->check));
    fprintf(captureData, "           --------------------------------------------------------\n");

    /* 패킷 정보(payload) Hex dump 와 ASCII 변환 데이터 출력 */
    Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, F,
                        (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));
}
void dhcp_header_fprint(FILE *captureData, unsigned char *dhcpHeader, int Size){
	int idx = 0;
	fprintf(stdout, "\n");
	fprintf(captureData, "\n           --------------------------------------------------------\n");
	fprintf(captureData, "           |                    DHCP Header                       |\n");
	fprintf(captureData, "           --------------------------------------------------------\n");
	fprintf(stdout, "Message Type: ");
    	
	if(dhcpHeader[idx] == 1){
		fprintf(captureData, "Boot Request (%d)\n", dhcpHeader[idx]);
		fprintf(stdout, "Boot Request (%d)\n", dhcpHeader[idx]);
	}
	if(dhcpHeader[idx] == 2){
		fprintf(captureData, "Boot Reply (%d)\n", dhcpHeader[idx]);
		fprintf(stdout, "Boot Reply (%d)\n", dhcpHeader[idx]);
	}
	idx++;
	if(dhcpHeader[idx] == 1){
		fprintf(captureData, "Hardware Type: Ethernet(0x%02x)\n", dhcpHeader[idx]);
		fprintf(stdout, "Hardware Type: Ethernet (0x%02x)\n", dhcpHeader[idx]);
	}
	idx++;
	fprintf(captureData, "            Hardware address length  |   %d\n", dhcpHeader[idx]);
	fprintf(stdout, "Hardware address length: %d\n", dhcpHeader[idx]);
	idx++;
	fprintf(captureData, "                    Hops             |   %d\n", dhcpHeader[idx]);
	fprintf(stdout, "Hops: %d\n", dhcpHeader[idx]);
	idx++;
	fprintf(captureData, "               Transaction ID        |   %02x%02x%02x%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	fprintf(stdout, "Transaction ID: %02x%02x%02x%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	idx+=4;
	int secelap = dhcpHeader[idx]*256;
	idx++;
	secelap+=dhcpHeader[idx];
	fprintf(captureData, "               Second elapsed        |   %d\n", dhcpHeader[idx]);
	fprintf(stdout, "Seconds elapsed: %d\n", dhcpHeader[idx]);
	idx++;
	if(dhcpHeader[idx]==0 &&dhcpHeader[idx+1] ==0){
		fprintf(captureData, "                 Bootp flags         |   0x0000 (Unicast)\n");
		fprintf(stdout, "Bootp flags: 0x0000 (Unicast)\n");
	}
	idx+=2;
	fprintf(captureData, "              Client IP Address      |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	fprintf(stdout, "Client IP address: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	
	idx+=4;
	fprintf(captureData, "               Your IP Address       |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	fprintf(stdout, "Your (client) IP address: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	idx+=4;
	fprintf(captureData, "            Next Server IP Address   |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	fprintf(stdout, "Next server IP address: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	idx+=4;
	fprintf(captureData, "            Relay agent IP Address   |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	
	fprintf(stdout, "Relay agent IP address: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
	idx+=4;
	if(dhcpHeader[idx+3]==0x69 && dhcpHeader[idx+4]==0x5e && dhcpHeader[idx+5]==0xd5){
		fprintf(captureData, "             Client MAC Address      |   %02x:%02x:%02x:%02x:%02x:%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
		fprintf(stdout, "Client MAC address: Apple_69:5e:d5 (%02x:%02x:%02x:%02x:%02x:%02x)\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
		
		idx+=6;
	}else{
		fprintf(captureData, "             Client MAC Address      |   %02x:%02x:%02x:%02x:%02x:%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
		fprintf(stdout, "Client MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
		idx+=6;
	}
	fprintf(captureData, "          Client HW address padding  |   00000000000000000000\n");
	fprintf(stdout, "Client hardware address padding: ");
	for(int i=0;i<10;i++){
		fprintf(stdout, "00");
		idx++;
	}
	fprintf(stdout, "\n");
	fprintf(captureData, "               Server host name      |   ");
	if(dhcpHeader[idx]==0 && dhcpHeader[idx+1]==0 && dhcpHeader[idx+2]==0){
		fprintf(stdout, "Server host name not given\n");
		
		fprintf(captureData, "not given\n");
		idx+=64;
	}else{
		fprintf(stdout, "Server host name: ");
		for(int i=0;i<64;i++){
			if(dhcpHeader[idx]>=0x20 && dhcpHeader[idx]<=0x7e){
				fprintf(stdout, "%c", dhcpHeader[idx]);
				fprintf(captureData, "%c", dhcpHeader[idx]);
			}
			idx++;
		}
		fprintf(captureData, "\n");
		fprintf(stdout, "\n");
	}
	
	fprintf(captureData, "                Boot file name       |   ");	
	if(dhcpHeader[idx]==0 && dhcpHeader[idx+1]==0 && dhcpHeader[idx+2]==0){
		fprintf(stdout, "Boot file name not given\n");
		fprintf(captureData, "Not given\n");
		idx+=128;
	}else{
		fprintf(stdout, "Boot file name: ");
		for(int i=0;i<128;i++){
			if(dhcpHeader[idx]>=0x20 && dhcpHeader[idx]<=0x7e){
				fprintf(stdout, "%c", dhcpHeader[idx]);	
				fprintf(captureData, "%c", dhcpHeader[idx]);			
			}
			idx++;
		}	
		fprintf(stdout, "\n");
		fprintf(captureData, "\n");
	}
	if(dhcpHeader[idx] == 0x63 && dhcpHeader[idx+1] == 0x82 && dhcpHeader[idx+2] == 0x53 && dhcpHeader[idx+3]==0x63){
		fprintf(stdout, "Magic cookie: DHCP\n");
		fprintf(captureData, "                 Magic cookie        |   DHCP\n");
		
		idx+=4;
	}
	int done = 1;
	int errCount=0;
	while(done){
	//DEBUG
	/*
	fprintf(stdout, "Number: %d\n", dhcpHeader[idx]);
	for(int i=0;i<10;i++){
		fprintf(stdout, "%02x ", dhcpHeader[idx+i]);
	}
	*/
	fprintf(captureData, "           --------------------------------------------------------\n");
	fprintf(stdout, "\n");
	fprintf(captureData, "                   Option            |   ");
	
		//if DHCP Message Type
		if(dhcpHeader[idx]==53){
			if(dhcpHeader[idx+2] == 1){
				fprintf(stdout, "Option: (%d) DHCP Message Type (Discover)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (Discover)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 2){
				fprintf(stdout, "Option: (%d) DHCP Message Type (Offer)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (Offer)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 3){
				fprintf(stdout, "Option: (%d) DHCP Message Type (Request)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (Request)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 4){
				fprintf(stdout, "Option: (%d) DHCP Message Type (Decline)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (Decline)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 5){
				fprintf(stdout, "Option: (%d) DHCP Message Type (ACK)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (ACK)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 6){
				fprintf(stdout, "Option: (%d) DHCP Message Type (NAK)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (NAK)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx+2] == 7){
				fprintf(stdout, "Option: (%d) DHCP Message Type (Release)\n", dhcpHeader[idx]);
				fprintf(captureData, "(%d) DHCP Message Type (Release)\n", dhcpHeader[idx]);
			}
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length = %d\n", dhcpHeader[idx]);
			idx++;
			
    			fprintf(captureData, "                    DHCP             |   ");
			if(dhcpHeader[idx] == 1){
				fprintf(stdout, "DHCP: Discover (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "Discover (%d)\n", dhcpHeader[idx]);
				
			}
			if(dhcpHeader[idx] == 2){
				fprintf(stdout, "DHCP: Offer (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "Offer (%d)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx] == 3){
				fprintf(stdout, "DHCP: Request (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "Request (%d)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx] == 4){
				fprintf(stdout, "DHCP: Decline (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "Decline (%d)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx] == 5){
				fprintf(stdout, "DHCP: ACK (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "ACK (%d)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx] == 6){
				fprintf(stdout, "DHCP: NAK (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "NAK (%d)\n", dhcpHeader[idx]);
			}
			if(dhcpHeader[idx] == 7){
				fprintf(stdout, "DHCP: Release (%d)\n", dhcpHeader[idx]);
				fprintf(captureData, "Release (%d)\n", dhcpHeader[idx]);
			}
			idx++;
		}
		//Parameter Request List
		else if(dhcpHeader[idx]==55){
			fprintf(captureData, "(%d) Parameter Request List\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (55) Parameter Request List\n");
			idx++;
			int prLength = dhcpHeader[idx];
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", prLength);
			idx++;
			for(int i=0;i<prLength;i++){
				fprintf(captureData, "         Parameter Request List item |   ");
				if(dhcpHeader[idx]==1){
					fprintf(captureData, "(%d) Subnet Mask\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Subnet Mask\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==121){
					fprintf(captureData, "(%d) Classless Static Route\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Classless Static Route\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==3){
					fprintf(captureData, "(%d) Router\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Router\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==6){
					fprintf(captureData, "(%d) Domain Name Server\n", dhcpHeader[idx]);	
					fprintf(stdout, "Parameter Request List Item: (%d) Domain Name Server\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==15){
					fprintf(captureData, "(%d) Domain Name\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Domain Name\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==114){
					fprintf(captureData, "(%d) URL [T0D0:RFC3679]\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) URL [T0D0:RFC3679]\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==119){
					fprintf(captureData, "(%d) Domain Search\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Domain Search\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==252){
					fprintf(captureData, "(%d) Private/Proxy autodiscovery\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Private/Proxy autodiscovery\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==95){
					fprintf(captureData, "(%d) LDAP [T0D0:RFC3679]\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) LDAP [T0D0:RFC3679]\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==44){
					fprintf(captureData, "(%d) NetBIOS over TCP/IP Name Server\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) NetBIOS over TCP/IP Name Server\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==46){
					fprintf(captureData, "(%d) NetBIOS over TCP/IP Node Type\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) NetBIOS over TCP/IP Node Type\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==2){
					fprintf(captureData, "(%d) Time offset\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Time offset\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==12){
					fprintf(captureData, "(%d) Host Name\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Host name\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==26){
					fprintf(captureData, "(%d) Interface MTU\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Interface MTU\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==28){
					fprintf(captureData, "(%d) Broadcast Address\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Broadcast Address\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==33){
					fprintf(captureData, "(%d) Static Route\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Static Route\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==40){
					fprintf(captureData, "(%d) Network Interface Service Domain\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Network Interface Service Domain\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==41){
					fprintf(captureData, "(%d) Network Information Service Servers\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Network Information Service Servers\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==42){
					fprintf(captureData, "(%d) Network Time Protocol Servers\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Network Time Protocol Servers\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==249){
					fprintf(captureData, "(%d) Private/Classless Static Route(Microsoft)\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Private/Classless Static Route(Microsoft)\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==252){
					fprintf(captureData, "(%d) Private/Proxy autodiscovery\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Private/Proxy autodiscovery\n", dhcpHeader[idx]);
				}else if(dhcpHeader[idx]==17){
					fprintf(captureData, "(%d) Root Path\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Root Path\n", dhcpHeader[idx]);
				}else{
					fprintf(captureData, "(%d) Unknown - Not Set\n", dhcpHeader[idx]);
					fprintf(stdout, "Parameter Request List Item: (%d) Unknown - Not set\n", dhcpHeader[idx]);
				}
				
				idx++;
			}
		}
		else if(dhcpHeader[idx]==57){
			fprintf(captureData, "(%d) Maximum DHCP Message Size\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Maximum DHCP Message Size\n", dhcpHeader[idx]);
			idx++;
			
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			int mdmLen = dhcpHeader[idx]*256;
			idx++;
			mdmLen+=dhcpHeader[idx];
			fprintf(captureData, "         Maximum DHCP Message Size   |   %d\n", mdmLen);
			fprintf(stdout, "Maximum DHCP Message Size: %d\n", mdmLen);
			idx++;			
		}
		else if(dhcpHeader[idx]==61){
			fprintf(captureData, "(%d) Client identifier\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Client identifier\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			if(dhcpHeader[idx]==1){
				fprintf(captureData, "                Hardware Type        |   Ethernet(0x%02x)\n", dhcpHeader[idx]);
				fprintf(stdout, "Hardware Type: Ethernet(0x%02x)\n", dhcpHeader[idx]);
			}
			idx++;
			if(dhcpHeader[idx+3]==0x69 && dhcpHeader[idx+4]==0x5e && dhcpHeader[idx+5]==0xd5){
				fprintf(captureData, "             Client MAC Address      |   Apple_69:5e:d5 (%02x:%02x:%02x:%02x:%02x:%02x)\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
				fprintf(stdout, "Client MAC address: Apple_69:5e:d5 (%02x:%02x:%02x:%02x:%02x:%02x)\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
				idx+=6;
			}else{
				fprintf(captureData, "             Client MAC Address      |   %02x:%02x:%02x:%02x:%02x:%02x\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
				fprintf(stdout, "Client MAC address: %02x:%02x:%02x:%02x:%02x:%02x", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3], dhcpHeader[idx+4], dhcpHeader[idx+5]);
				idx+=6;
			}
		}
		else if(dhcpHeader[idx]==50){
			fprintf(captureData, "(%d) Requested IP Address\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Requested IP Address\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "             Requested IP Address    |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			fprintf(stdout, "Requested IP Address: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			idx+=4;
		}
		else if(dhcpHeader[idx]==54){
			fprintf(captureData, "(%d) DHCP Server Identifier\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) DHCP Server Identifier\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "            DHCP Server Identifier   |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			fprintf(stdout, "DHCP Server Identifier: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			idx+=4;
		}
		else if(dhcpHeader[idx]==12){
			fprintf(captureData, "(%d) Host Name\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Host Name\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			int hnLen = dhcpHeader[idx];
			idx++;
			fprintf(stdout, "Host Name: ");
			fprintf(captureData, "                  Host Name          |   ");
			for(int i=0;i<hnLen;i++){
				fprintf(stdout, "%c", dhcpHeader[idx]);
				fprintf(captureData, "%c", dhcpHeader[idx]);
				idx++;
			}
			fprintf(captureData, "\n");
			fprintf(stdout, "\n");
		}
		else if(dhcpHeader[idx]==60){
			fprintf(captureData, "(%d) Vender class identifier\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Vender class identifier\n", dhcpHeader[idx]);
			idx++;
			int vciLen = dhcpHeader[idx];
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "            Vendor class identifier  |   ");
			fprintf(stdout, "Vendor class identifier: ");
			for(int i=0;i<vciLen;i++){
				fprintf(captureData, "%c", dhcpHeader[idx]);
				fprintf(stdout, "%c", dhcpHeader[idx]);
				idx++;
			}
			fprintf(captureData, "\n");
			fprintf(stdout, "\n");
		}else if(dhcpHeader[idx]==255){
			fprintf(captureData, "(%d) End\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) End\n", dhcpHeader[idx]);
			done=0;
		}else if(dhcpHeader[idx]==1){
			fprintf(captureData, "(%d) Subnet Mask\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Subnet Mask\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                  Subnet Mask        |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			fprintf(stdout, "Subnet Mask: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			idx+=4;
		}else if(dhcpHeader[idx]==3){
			fprintf(captureData, "(%d) Router\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Router\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                     Router          |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			fprintf(stdout, "Router: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
			idx+=4;
		}else if(dhcpHeader[idx]==6){
			fprintf(captureData, "(%d) Domain Name Server\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Domain Name Server\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			int dnsLen = dhcpHeader[idx];
			idx++;
			for(int i=0;i<dnsLen/4;i++){
				fprintf(captureData, "               Domain Name Server    |   %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
				fprintf(stdout, "Domain Name Server: %d.%d.%d.%d\n", dhcpHeader[idx], dhcpHeader[idx+1], dhcpHeader[idx+2], dhcpHeader[idx+3]);
				idx+=4;
			}
		}else if(dhcpHeader[idx]==15){
			fprintf(captureData, "(%d) Domain Name\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Domain Name\n", dhcpHeader[idx]);
			idx++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			int dnLength = dhcpHeader[idx];
			idx++;
			fprintf(captureData, "                  Domain Name        |   ");
			fprintf(stdout, "Domain Name: ");
			for(int i=0;i<dnLength;i++){
				fprintf(captureData, "%c", dhcpHeader[idx]);
				fprintf(stdout, "%c", dhcpHeader[idx]);
				idx++;
			}
			fprintf(captureData, "\n");
			fprintf(stdout, "\n");
			
		}else{
			fprintf(captureData, "(%d) Not Pre-coded type\n", dhcpHeader[idx]);
			fprintf(stdout, "Option: (%d) Not Pre-coded type\n", dhcpHeader[idx]);
			idx++;
			errCount++;
			fprintf(captureData, "                   Length            |   %d\n", dhcpHeader[idx]);
			fprintf(stdout, "Length: %d\n", dhcpHeader[idx]);
			int unknownLen = dhcpHeader[idx];
			for(int i=0;i<unknownLen;i++){
				idx++;
			}
			idx++;
		}
		if(errCount==10){
			break;
		}
	}
		
	
}
void Dns_header_fprint(FILE *captureData, unsigned char* Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader, struct tcphdr *tcpHeader, struct sockaddr_in source, struct sockaddr_in dest, int size){
	
	
}
void Dns_header_frpint(FILE *captureData, unsigned char *dnsHeader, int Size) {
    int idx = 0;
    char q = ' ';
    
    
    printf("\nDNS HEADER:\n");
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       DNS Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");


    // Transactoin Id
    printf("Transaction ID: ");
    fprintf(captureData, "                Transaction ID       |   0x%02X%02X\n", dnsHeader[idx], dnsHeader[idx+1]);
    fprintf(stdout, " 0x");
    for (idx = 0; idx < 2; idx++) {
        fprintf(stdout, "%02X", (unsigned char)dnsHeader[idx]);
    }
    printf("\n");

    // Flags (질의인지 응답인지만 구별) idx=2;
    int flags = (unsigned char)dnsHeader[idx];
    int flags2 = (unsigned char)dnsHeader[idx+1];
    int reply = 0;
    printf("DNS FLAGS: ");
    
    if(flags == 0x81 && flags2 == 0x80){
    fprintf(captureData, "                   DNS FLAGS         |   %s\n", "Standard query response"); 
    	printf("Standard query response\n");
    	reply = 1;
    }
    else if(flags == 0x01 && flags2 == 0){
     	printf("Standard query\n");
     	fprintf(captureData, "                   DNS FLAGS         |   %s\n", "Standard query");
    }
    
    /*
    if(flags & 0b1000!=0){
    	printf("OR: Response\n");
    }else{
    	printf("OR: Query\n");
    }
    printf("Opcode: ");
    switch(flags & 0b0111){
    	case 0:
    		printf("Query\n");
    		break;
	case 1:
		printf("Inverse Query\n");
		break;
	case 2:
		printf("Status\n");
		break;
	case 3:
		printf("Unassigned\n");
		break;
	case 4:
		printf("Notify\n");
		break;
	case 5:
		printf("Update\n");
		break;
	default:
		printf("Unassigned\n");
		break;
    }idx+=1;
    */
    idx += 3;
    int dnsQuestion = (unsigned char)dnsHeader[idx];
    printf("Questions: %d\n", dnsQuestion);
    fprintf(captureData, "                DNS Questions        |   %d\n", dnsQuestion);
    idx += 2;
    // answer RRs
    int answerRR = (unsigned char)dnsHeader[idx];
    printf("Answer RRs: %d\n", answerRR);
    fprintf(captureData, "                  Answer RRs         |   %d\n", answerRR);
    idx += 2;
    int nsCount = (unsigned char)dnsHeader[idx];
    printf("Authority RRs: %d\n", nsCount);
    fprintf(captureData, "                Authority RRs        |   %d\n", nsCount);
    idx += 2;
    int arCount = (unsigned char)dnsHeader[idx];
    printf("Additional RRs: %d\n", arCount);
    fprintf(captureData, "               Additional RRs        |   %d\n", arCount);
    idx += 2;
    
    int websiteCount = 0;
    char domains[50];
    // Query
    fprintf(captureData, "                  DNS Query          |   ");
    printf("DNS Query: ");
    while (1) {
        if (dnsHeader[idx] == 0) break;
        if (dnsHeader[idx] >= 32 && dnsHeader[idx] < 128){
            fprintf(stdout, "%c", (unsigned char)dnsHeader[idx]);  // data가 ascii라면 출력
            fprintf(captureData, "%c", (unsigned char)dnsHeader[idx]);
            domains[websiteCount] = (unsigned char)dnsHeader[idx];
        }
        else{
            domains[websiteCount] = '.';
            fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
            fprintf(captureData, ".");
        }
        if(websiteCount == 49){
        	break;
        }
        websiteCount++;
        idx++;
    }
    printf("\n");
    fprintf(captureData, "\n");
    idx += 2;

    //질의 type
    int type = (unsigned char)dnsHeader[idx];
    printf("Type: ");
    fprintf(captureData, "                     Type            |   ");
    if (type == 1){
        fprintf(stdout, " A %c\n", q);
        fprintf(captureData, "A %c\n", q);
        }
    else if (type == 28){
        fprintf(stdout, " AAAA %c\n", q);
        fprintf(captureData, "AAAA %c\n", q);
        }
    else if (type == 12){
        fprintf(stdout, " PTR %c\n", q);
        fprintf(captureData, "PTR %c\n", q);
    }
    idx += 2;
    int classQ = dnsHeader[idx];
    if(dnsHeader[idx] == 1){
    	printf("CLASS: IN\n\n");
	fprintf(captureData, "                     CLASS           |   IN\n");
    }
    idx+=4;
    //응답이있다면 응답 data출력(응답 RR이 1이상이라면)
    
    for (int i = 0; i < answerRR; i++) {
    	if(i!=0){
    		idx+=4;
    	}
    	printf("Answer Data (%d)\n", i+1);
    	fprintf(captureData, "           --------------------------------------------------------\n");
        fprintf(captureData, "                 Answer Data         |   %d\n", i+1);
        fprintf(captureData, "           --------------------------------------------------------\n");
        printf("Name: ");
    	fprintf(captureData, "                    Name             |   ");
        for(int j=0;j<websiteCount;j++){
        	printf("%c", domains[j]);
        	fprintf(captureData, "%c", domains[j]);
        }
        fprintf(captureData, "\n");
        printf("\n");
        type = (unsigned char)dnsHeader[idx];
        printf("Type: ");
	fprintf(captureData, "                    Type             |   ");
        if (type == 1){
            fprintf(stdout, " A\n");
            fprintf(captureData, "A\n");
            }
        else if (type == 28){
            fprintf(stdout, " AAAA\n");
            fprintf(captureData, "AAAA\n");
            }
        else if (type == 12){
            fprintf(stdout, " PTR\n");
            fprintf(captureData, "PTR\n");
            }
        else if (type == 5){
        	printf("CNAME (Carnonial NAME for an alias)\n");
        	fprintf(captureData, "CNAME (Carnonial NAME for an alias)\n");
        	}
        	
        else{
        	printf("Error\n");
        	fprintf(captureData, "Unknown\n");
        }
        idx += 2;
        fprintf(captureData, "                    CLASS            |   ");
        if(classQ==1){
        	printf("CLASS: IN\n");
        	fprintf(captureData, "IN\n");
        }
        idx+=1;
        //Time To Live
        unsigned int answerTTL = (dnsHeader[idx] << 24) + (dnsHeader[idx+1] << 16) + (dnsHeader[idx+2] << 8) + dnsHeader[idx+3];
        printf("Time To Live: %u\n", answerTTL);
        fprintf(captureData, "                Time To Live         |   %d\n", answerTTL);
	//length
        idx += 4;
        short ansLength = ((short)dnsHeader[idx] << 8) + dnsHeader[idx+1];
        printf("Length: %d\n", (int)ansLength);
        fprintf(captureData, "                   Length            |   %d\n", ansLength);
        idx += 2;
        if(ansLength == 4){
        	printf("Address ");
    		fprintf(captureData, "                  Address            |   ");
        	printf("%d.%d.%d.%d\n", dnsHeader[idx], dnsHeader[idx+1], dnsHeader[idx+2], dnsHeader[idx+3]);
        	fprintf(captureData, "%d.%d.%d.%d\n", dnsHeader[idx], dnsHeader[idx+1], dnsHeader[idx+2], dnsHeader[idx+3]);
        	idx+=3;
        }
        else if (ansLength == 16) {
                /* AAAA Record */
                printf("Address ");
                int j;
                for (j = 0; j < ansLength; j+=2) {
               
                    printf("%02x%02x", dnsHeader[idx+j], dnsHeader[idx+j+1]);
                    fprintf(captureData, "%02x%02x", dnsHeader[idx+j], dnsHeader[idx+j+1]);
                    if (j + 2 < ansLength) {
                    	printf(":");
                    	fprintf(captureData, ":");
                    }
                }
                fprintf(captureData, "\n");
                printf("\n");
                idx+=15;
        }
        else{
        printf("CNAME: ");
        fprintf(captureData, "                    CNAME            |   ");
        char cHeader[50];
        
	        for(int j=0;j<ansLength-1;j++){
	        	if(j!=0){
		        	if (dnsHeader[idx] == 0) break;
			        if (dnsHeader[idx] >= 32 && dnsHeader[idx] < 128){
		            	fprintf(stdout, "%c", (unsigned char)dnsHeader[idx]);  // data가 ascii라면 출력
			            fprintf(captureData, "%c", (unsigned char)dnsHeader[idx]);
			        }
		        	else{
			            fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
			            fprintf(captureData, ".");
				}
			}
			idx++;
    		}
    		printf("\n");
    		fprintf(captureData, "\n");
    	}
    }
    
}


void Change_hex_to_ascii(FILE *captureData, unsigned char *data, int op, int Size) {
    /*cmd에 ascill로 출력 */
    if (op == A) {
        fprintf(stdout, "\033[91m ");
        for (int i = 0; i < Size; i++) {
            if (data[i] >= 32 && data[i] < 128)
                fprintf(stdout, "%c", (unsigned char)data[i]);  // data가 ascii라면 출력
            else if (data[i] == 13)                             // cr(carrige return)라면 continue
                continue;
            else if (data[i] == 10)
                fprintf(stdout, "\n");  // lf(\n)라면 개행문자 출력
            else
                fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
        }
        fprintf(stdout, "\033[0m");
    }
    /*cmd에 hex로 출력*/
    else if (op == X) {
        fprintf(stdout, "\033[91m ");
        for (int i = 0; i < Size; i++) {
            fprintf(stdout, " %02X", (unsigned int)data[i]);  //앞의 빈자리 0으로 초기화한 16진수로 데이터 출력
        }
        fprintf(stdout, "\033[0m");
    }
    /*file에 write하는 경우*/
    else if (op == F) {
    /*
        fprintf(captureData, "\n\nDATA (Payload)\n");
        for (int i = 0; i < Size; i++) {
            if (i != 0 && i % 16 == 0) {          // 16개 데이터 출력 했다면, ascii코드 출력후 개행후 이어서 출력
                fprintf(captureData, "\t\t");     // 16진수 data랑 ascii data 구분
                for (int j = i - 16; j < i; j++)  // 16진수 data를 ascii로 변환
                {
                    if (data[j] >= 32 && data[j] < 128)
                        fprintf(captureData, "%c", (unsigned char)data[j]);  // data가 ascii라면 출력

                    else
                        fprintf(captureData, ".");  //그외 데이터는 . 으로 표현
                }
                fprintf(captureData, "\n");
            }

            if (i % 16 == 0) fprintf(captureData, "\t");  //가시성을 위해 처음 오는 data는 tab

            fprintf(captureData, " %02X", (unsigned int)data[i]);  //앞의 빈자리 0으로 초기화한 16진수로 데이터 출력

            if (i == Size - 1)  //마지막 data
            {
                for (int j = 0; j < (15 - (i % 16)); j++)
                    fprintf(captureData, "   ");  //마지막 데이터는 16개 꽉 안채울 수 있으니 데이터 포맷을 위해 남은 공간만큼 space

                fprintf(captureData, "\t\t");  // 16자리 까지 공백 채운후 ascii 출력 위해 구분

                for (int j = (i - (i % 16)); j <= i; j++)  //남은 데이터 ascii로 변환
                {
                    if (data[j] >= 32 && data[j] < 128)
                        fprintf(captureData, "%c", (unsigned char)data[j]);
                    else
                        fprintf(captureData, ".");
                }
                fprintf(captureData, "\n");
            }
        }
        */
    }
}

void MenuBoard() {
    system("clear");
    fprintf(stdout, "                     5종 패킷 분석 프로그램                \n");
    fprintf(stdout, "**************************** Menu **************************\n\n");
    fprintf(stdout, "                     1. Capture start \n");
    fprintf(stdout, "                     2. Capture stop \n");
    fprintf(stdout, "                     3. show menu \n");
    fprintf(stdout, "                     4. show credit \n");
    fprintf(stdout, "                     0. exit \n");
    fprintf(stdout, " \n**********************************************************\n\n");
}

void StartMenuBoard() {
    system("clear");
    fprintf(stdout, "\n****************************** Options ****************************\n\n");
    fprintf(stdout, "   \033[mprotocol\033[0m : *(all)(ARP) | tcp(http/https) | udp(DNS) \n");
    fprintf(stdout, "   \033[mport\033[0m     :  *(all) | 0 ~ 65535 | [http(80) | dns(53) | https(443)]  \n");
    fprintf(stdout, "   \033[mip\033[0m       :      *(all) | 0.0.0.0 ~ 255.255.255.255 \n");
    fprintf(stdout, "\n****************************** Example ****************************\n\n");
    fprintf(stdout,
            "                입력 순서 :  \033[100mprotocol\033[0m \033[100mport\033[0m \033[100mip\033[0m \n");
    fprintf(stdout, "\n*******************************************************************\n\n");
}
void CreditBoard(){
	system("clear");
	fprintf(stdout, "************************** CREDIT *************************\n");
	fprintf(stdout, "\033[mAuthor\033[0m  :    Lee Hwa Won\n");
	fprintf(stdout, "\033[mMajor\033[0m   :    School of Software\n");
	fprintf(stdout, "\033[mgithub\033[0m  :    http://www.github.com/andylhw\n");
	fprintf(stdout, "\033[mDate\033[0m    :    May 2021\n");		
}
void Menu_helper() {
    int isDigit, menuItem;  // menu판 입력 변수  ( isDigit = 1:숫자  false: 숫자아님 / menuItem : 메뉴번호)
    pthread_t capture_thd;  // Thread to capture packet
    int rawSocket;          // raw socket - 사용해서 받을 예정
    char str[128];

    if ((rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)  // raw socket 생성
    {
        printf("Socket 열기 실패\n");
        exit(1);
    }

    //프로그램 종료시까지 반복
    MenuBoard();
    while (1) {
        fprintf(stdout, "\n   \033[m메뉴 번호 입력 :\033[0m ");
        isDigit = scanf("%d", &menuItem);  //메뉴판 번호 입력
        buffer_flush();                    //입력버퍼 flush

        if (menuItem == 0 && isDigit == 1)  //프로그램 종료
        {
            fprintf(stderr, "   !!! Good bye !!!");
            break;
        } else if (menuItem == 1 && isDigit == 1)  // TCP 캡쳐 시작
        {
            if (captureStart)
                fprintf(stdout, "이미 시작 중입니다 !!\n");
            else {
                StartMenuBoard();
                fprintf(stdout, "\n   \033[93m필터 입력 :\033[0m ");
                scanf("%[^\n]s", str);  //메뉴판 번호 입력

                if (start_helper(str)) {
                    captureStart = true;
                    pthread_create(&capture_thd, NULL, PacketCapture_thread, (void *)&rawSocket);  // TCP 캡쳐 스레드 생성
                    pthread_detach(capture_thd);                                                   //스레드 종료시 자원 해제
                }
            }
        } else if (menuItem == 2 && isDigit == 1)  // 캡쳐 중지
        {
            if (!captureStart)
                fprintf(stdout, "시작 중이 아닙니다 !!\n");
            else {
                captureStart = false;
                fprintf(stdout, "\n\n캡쳐 중지.\n");
                fprintf(stdout, "%d packets received\n", total);
                fprintf(stdout, "%d filtered packets captured\n", filter);
                fprintf(stdout, "%d packets dropped (fail received)\n", drop);

                /*변수 초기화*/
                total = 0, filter = 0, drop = 0;
                protocolOption[0] = '\0', ipOption[0] = '\0', portOption[0] = '\0', printOption[0] = '\0';
            }
        } else if (menuItem == 3 && isDigit == 1)  // show Menu
        {
            MenuBoard();
        } else if (menuItem == 4 && isDigit == 1)
        {
            CreditBoard();
        }else {  // exception handling
            fprintf(stderr, "잘못 입력하셨습니다 !!\n\n");
        }
    }
    close(rawSocket);  // socket close
}
bool start_helper(char *str) {
    /*protocol*/
    char *option = strtok(str, " ");
    if (strcmp(option, "*") && strcmp(option, "tcp") && strcmp(option, "udp")) {
        fprintf(stderr, "* | tcp | udp 만 캡쳐가능합니다.\n");
        return false;
    }
    strcpy(protocolOption, option);

    /*port 번호*/
    option = strtok(NULL, " ");
    if (!IsPort(option)) {
        fprintf(stderr, "잘못된 port 입력입니다.\n");
        return false;
    }
    strcpy(portOption, option);

    /*ip 주소*/
    option = strtok(NULL, " ");
    char s[48];
    strcpy(s, option);
    if (!IsIpAddress(s)) {
        fprintf(stderr, "잘못된 Ip 주소 입니다.\n");
        return false;
    }
    strcpy(ipOption, option);



    return true;
}

bool IsPort(char *str) {
    if (!strcmp(str, "*")) return true;
    if (!IsDigit(str))  //숫자가 아니라면 flase
        return false;
    if (atoi(str) < 1 || atoi(str) > 65535)  //없는 포트번호거나  false
        return false;
    return true;
}

bool IsIpAddress(char *str) {
    if (!strcmp(str, "*"))  //모든 ip주소 filter
        return true;
    int numberOfOctet = 0;
    char *octet = strtok(str, ".");  // ip octet 규칙 검사
    while (octet != NULL) {
        if ((!isdigit(octet[0]) && atoi(octet) == 0) || atoi(octet) > 255)  //알파벳이거나 255를 넘는다면 false
        {
            return false;
        }
        numberOfOctet++;
        octet = strtok(NULL, ".");
    }
    if (numberOfOctet != 4)  // octet 이 4개가 안된다면 false
        return false;

    return true;
}

void buffer_flush() {
    while (getchar() != '\n')
        ;
}
bool IsDigit(char *str) {
    for (int i = 0; i < (int)strlen(str); i++) {
        if (!isdigit(str[i]))  //숫자아니라면 false
            return false;
    }
    return true;
}
