# NetworkProgramming_Final
네트워크프로그래밍 과제

## 개발환경
Linux - Ubuntu 20.24
IDE - gedit

## 코드 함수 소개
void *PacketCapture_thread(void *arg)
-	패킷 캡쳐 스레드
void ARP_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size) 
-	ARP 헤더 캡쳐할 때 사용하는 함수
void Arp_header_print(FILE *captureData, struct ethhdr *etherHeader, struct arpheader *arpHeader, unsigned char *Buffer, int Size)
-	캡쳐한 ARP 헤더를 프린트 할 때 사용하는 함수.
void Capture_helper(FILE *captureFile, unsigned char *, int)                                      
-	캡쳐한 패킷 프로토콜 분류 
void Ethernet_header_fprint(FILE *captureFile, struct iphdr *)
-	Ethernet 헤더 정보 fprint
void Ip_header_fprint(FILE *captureFile, struct iphdr *, struct sockaddr_in, struct sockaddr_in)
-	ip 헤더 정보 fprint 
void Tcp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int)  
-	 tcp 헤더 정보 capture
void Tcp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct tcphdr *, struct sockaddr_in, struct sockaddr_in, int Size)
-	tcp 헤더 정보 fprint
void Udp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int Size)
-	udp 헤더 정보 capture
void Udp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct udphdr *, struct sockaddr_in, struct sockaddr_in, int Size)
-	udp 헤더 정보 fprint
void Dns_header_frpint(); 
-	DNS 헤더 프린트
void Change_hex_to_ascii(FILE *captureFile, unsigned char *, int, int)
-	payload값 hex/ascii/file option에 맞게 출력
void MenuBoard();           
-	menu board
void Menu_helper();         
-	menu board exception handling
void StartMenuBoard();      
-	start menu board
bool start_helper(char *);  
-	start menu exception handling
bool IsPort(char *);        
-	포트 형식 검사 | 맞으면 true
bool IsIpAddress(char *);   
-	ip 형식 검사 | 맞으면 true
bool IsDigit();             
-	 string 이 숫자인지 검사 | 맞으면 true
void buffer_flush();        
-	입력 버퍼 지우기
void http_header_capture(FILE *captureData, unsigned char *response, int Size)
-	HTTP헤더캡쳐
void https_header_capture(FILE *captureData, unsigned char *httpsHeader, int Size)
-	HTTPS헤더캡쳐
void https_header_print(FILE *captureData, unsigned char *httpsHeader, int Size)
-	HTTP헤더 캡쳐한것을 파일에 쓰거나 보여주기
void https_handshake_capture(FILE *captureData, unsigned char *httpsHeader, int idx)
-	HTTPS- Handshake 캡쳐 (HTTPS가 너무 커서 쪼갬)
void https_ccs_capture(FILE *captureData, unsigned char *httpsHeader, int idx)
-	HTTPS ChangeCipherSpec 캡쳐
void https_appdata_capture(FILE *captureData, unsigned char *httpsHeader, int idx)
-	HTTPS Application Data캡쳐
void https_encalert_capture(FILE *captureData, unsigned char *httpsHeader, int idx)
-	HTTPS Encryption Alert 캡쳐
void dhcp_header_fprint(FILE *captureData, unsigned char *dhcpHeader, int Size)
-	DHCP헤더 영역 캡쳐.

## 설명서
우선 가장 큰 거름망은 포트번호이다. 각각의 프로토콜마다 포트번호가 다르게 움직인다. (ARP는 제외). HTTP: 80, HTTPS: 443, DNS: 53, DHCP: 67
따라서 포트 번호를 지정하면, 캡쳐할 수 있는 패킷이 달라지기 때문에, 패킷을 다르게 지정하는것이 중요하다.

사용자는 protocol port ip (띄어쓰기 중요)를 순서대로 입력해야하고, protocol에선 tcp, udp혹은 * (tcp+udp)를 입력해야하고, port는 위에 명시된 포트번호나 아니면 *(all)을 입력하면 된다. 특정 ip주소를 캡쳐할 수 있기도 하다.
해당 필터를 입력하고 나면, 패킷을 감지하기 시작하는데, 필터에 걸러진 것만 출력하면서 파일에 생성되게 된다. 파일은 해당 폴더에 captureFile(21-6-8T5:30:26).txt같은 형식으로 Read-only 파일이 생성된다.
패킷을 감지하는 것을 종료하고 싶으면, 2번을 누르고 엔터를 치면 되고, 메뉴로 돌아가고 싶으면, 3번을 누르면 된다.

## Packet별 함수 동작 방식
1. ARP Packet
  A. Capture_helper에서 함수를 감지한다.
  B. ARP 패킷이 감지되었을 경우 (0x0806), ARP_header_capture함수 실행  
  C. 해당 함수 안에서, struct arpheader 안에 있는 내용을 사용하여, CLI에 print
  D. 프린트가 끝나면, ARP_header_print함수 호출
  E. ARP_header_print는 해당 내용을 파일에 쓰는 함수로, Ethernet_header_fprint뒤에 ARP Packet정보를 파일에 표현함 (특수 UI를 사용함)
2. DNS Packet
  A.	Capture_helper함수에서 패킷을 감지한다.
  B.	udpHeader의 source나 dest에서 DNS(포트번호 53)를 감지하였을 때, Dns_header_frpint함수를 실행시킴.
  C.	해당 함수에서는 fprintf로 파일에 저장하는 함수와, printf로 CLI에 표현하는 방식을 동시에 적용시킴.
  D.	Index를 생성해서, DNS 패킷의 특수 패턴을 파악해서 프린트하게 함.
  E.	Answer가 여러 개일 경우를 고려하여, for문을 사용하여, answer의 개수만큼 Data를 받아서 분석함. 이 때, 네트워크프로그래밍 강의에 사용된 소스코드를 보고, 이런 방식으로 앞으로 짜면 되겠다라고 생각하였음.

3.	HTTP Packet
  A.	Capture_helper함수에서 패킷을 감지한다.
  B.	tcpHeader의 source나 dest에서 HTTP(포트번호 80)를 감지하였을 때, http_header_capture함수를 실행
  C.	해당 함수가 불리었을 때, response가 0x474554(GET)이 있으면, HTTP GET이 있을 것이라고 판단하게 하고, GET이 없으면 Response를 추가시키지 않음.
  D.	\r\n을 기점으로 계속 읽어들이고, 출력하게 하는 함수 작성. 이때도, 파일과 CLI에 동시 작성된다.
4.	HTTPS Packet
  A.	Capture_helper함수에서 패킷을 감지한다.
  B.	tcpHeader의 source나 dest에서 HTTP(포트번호 443)를 감지하였을 때, https_header_print함수를 실행
      - 해당 함수를 print로 실행한 이유는 HTTPS는 여러 개의 데이터를 가지고 있을 수 있기 때문에, 우선 큰 헤더파일을 먼저 프린트하고, 여러 개의 데이터 패킷이 나올 때, 복잡해지지 않게 보이기 위함이다. 코드 리팩토링 작업을 할 때, 이름을 직관적으로 바꿀필요가 있음.
  C.	기본적인 헤더를 프린트하고, https_print_capture를 실행한다.
  D.	DNS패킷을 분석할 때와 마찬가지로, index를 사용하여 https 패킷의 특징을 잡아가면서 프로그래밍 하였다. 처음 header가 20, 21, 22, 23일 때 각각 ChangeCipherSpec, EncryptedAlert, Handshake, ApplicationData 이기 때문에, 함수의 크기를 분할하고자, https_ccs_capture, https_encalert_capture, https_handshake_capture, https_appdata_capture함수로 나누었다.
  E.	각각의 함수 특징은 Wireshark에서 https패킷 분석을 할 때, 있는 것을 활용하였으며, 특별한 내용은 다음과 같다.
    i.	ApplicationData는 암호화되어 전송됨으로, 알아보기 힘든 내용이 많고, 모두 출력하면 깔끔해보이지 못해서 처음 10개의 바이트만 전송하게 하였다.
    ii.	https_handshake_capture는 너무 방대하여, 최대한 Wireshark로 테스트 환경에 있던 것을 구현해보았지만, 남는 부분은 Unknown처리를 통해서 할 수 있는 만큼 구현함.
    iii. 구현완료: Client Hello, Server Hello, New Session Ticket, Certificate, Server Hello Done, Client Key Exchange(EC Diffie Hellman)
  F.	각각의 함수가 끝날 때, 다음 패킷 정보가 https의 특징을 가르키고 있다면(20, 21, 22, 23) 계속 로딩함으로써, ApplicationData가 연속으로 와도 캡쳐 가능하게 코드를 작성하였다.
  
5.	DHCP 패킷
  A.	Capture_helper함수에서 패킷을 감지한다.
  B.	udpHeader의 source나 dest에서 DHCP(포트번호 67)를 감지하였을 때, dhcp_header_fprint함수를 실행
  C.	기존 함수들과 마찬가지로 index를 생성해서, DHCP패킷을 분석을 하게 된다. Fprintf를 사용하여 파일에 씀과 동시에 출력이 되게 함으로, 파일을 열지않고 간단한 정보를 접할 수 있게 작성함.
  D.	DHCP에 특징인 Option은 while문을 사용하여, dhcpHeader에서 특정 index 값에 따라서 다르게 출력하게 하였다. 여기서 특정 값은 DHCP Message Type, Parameter Request List, Maximum DHCP Message Size, Client identifier, Requested IP Address, DHCP Server Identifier, Host Name, Vender class identifier, End, Subnet Mask, Router, Domain Name Server, Domain Name, IP Address Lease Time이 있다. 나머지는 Not pre-coded Type을 통해서 묶었지만, 패킷 특성을 분석하여, 다음 Option이 정상출력하게 코드를 작성하였다. 이 While문은 Options – End가 발생하였을 때 끝나게 설정하였다. 
    i.	Parameter Request List에서는 Subnet Mask, Classless Static Route, Router, Domain Name Server, Domain Name, URL, Domain Search, Private/Proxy autodiscovery, LDAP, NetBIOS over TCP/IP Name Server, NetBIOS over TCP/IP Node Type, Time offset, Host Name, Interface MTU, Broadcast Address, Static Route, Network Interface Service Domain, Network Information Service Servers, Network Time Protocol Servers, Private/Classless Static Route, Root Path를 감지할 수 있다.
    
    
##참고:
리눅스 패킷캡쳐 프로그램
https://github.com/gowoonsori/linux_packetCaptureProgram
