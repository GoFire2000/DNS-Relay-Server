#include <winsock2.h>
#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib, "ws2_32.lib")  //���� ws2_32.dll
#pragma warning(disable:4996)
#define noneDebug 0
#define oneDebug 1
#define twoDebug 2
#define defaultDNSServer "202.106.0.20"//10.211.55.1=10.3.9.4
//#define defaultDNSServer "143.254.64.546"
#define defaultFileName "dnsrelay.txt"
#define ID_TRANS_MAX 2000
#define DNSSERVER_NO_REPLY 20

const char IP_ERROR[100] = {'\0','\0','\0' ,'\0' };


int d_or_f(char* s, int len) {//�����������ж���DNSSever����fileName�����ȫ�����ֺ�.,����DNSSever
    int d_flag = 1;
    for (int i = 0; i < len; i++) {
        if ((s[i] > '9' || s[i] < '0') && s[i] != '.') {
            d_flag = 0;
            break;
        }
    }
    return d_flag;
}
int paramater_set(int argc, char** argv, int* outputLevel, char* DNSServer, char* fileName) {
    int noneflag = 0;

    switch (argc) {
    case 1://��Ӧû������
        *outputLevel = noneDebug;
        strcpy(DNSServer, defaultDNSServer);
        strcpy(fileName, defaultFileName);
        //DNSServer = defaultDNSServer;
        //fileName = defaultFileName;
        break;
    case 2:
        if (argv[1][0] == '-') {// -d���� - dd
            if (strcmp(argv[1], "-d") == 0) {
                *outputLevel = oneDebug;
            }
            else {
                *outputLevel = twoDebug;
            }
            strcpy(DNSServer, defaultDNSServer);
            strcpy(fileName, defaultFileName);
            break;
        }
        if (d_or_f(argv[1], strlen(argv[1])) == 1) {//DNSSever
            *outputLevel = noneDebug;
            strcpy(DNSServer, argv[1]);
            strcpy(fileName, defaultFileName);
            break;
        }
        else {//fileName
            *outputLevel = noneDebug;
            strcpy(DNSServer, defaultDNSServer);
            strcpy(fileName, argv[1]);
            break;
        }
    case 3:
        if (argv[1][0] == '-') {//-d or -dd
            if (d_or_f(argv[2], strlen(argv[2])) == 1) {//+ DNSSever
                if (strcmp(argv[1], "-d") == 0) {
                    *outputLevel = oneDebug;
                }
                else {
                    *outputLevel = twoDebug;
                }
                //DNSServer = argv[2];
                strcpy(DNSServer, argv[2]);
                strcpy(fileName, defaultFileName);
                //fileName = defaultFileName;
            }
            else {//+ fileName
                if (strcmp(argv[1], "-d") == 0) {
                    *outputLevel = oneDebug;
                }
                else {
                    *outputLevel = twoDebug;
                }
                //DNSServer = argv[2];
                strcpy(DNSServer, defaultDNSServer);
                strcpy(fileName, argv[2]);
                //fileName = defaultFileName;
            }
        }
        else {//DNSSever fileName
            *outputLevel = noneDebug;
            strcpy(DNSServer, argv[1]);
            strcpy(fileName, argv[2]);
        }
        break;
    case 4:// -d or -dd DNSSever fileName
        if (strcmp(argv[1], "-d") == 0) {
            *outputLevel = oneDebug;
        }
        else {
            *outputLevel = twoDebug;
        }
        strcpy(DNSServer, argv[2]);
        strcpy(fileName, argv[3]);
        break;
    default:
        noneflag = 1;
        break;
    }
    if (noneflag == 0)
        return 0;
    else
        return 1;
}


struct header {//����ͷ����12���ֽ�
    unsigned short ID;//2B = 16 bits��id
    int QR;//1bit��Query or Response����ѯ/��Ӧ�ı�־λ��0Ϊ��ѯ��1Ϊ��Ӧ
    unsigned short Opcode;//4bits,operationCode,ͨ��ֵΪ 0 ����׼��ѯ��������ֵΪ 1 �������ѯ���� 2 ��������״̬����
    int AA;//1bit,Ȩ���� (Authoritative answer),1��ʾ���ַ�������Ȩ��������
    int TC;//1bit,���ضϵı��� (Truncated ),1��ʾ��Ӧ���ܳ��ȳ� 512 �ֽ�ʱ��ֻ����ǰ 512 ���ֽ�
    int RD;//1bit��1��ʾ�û�����ʹ�õݹ���� (Recursion desired)
    int RA;//1bit���ݹ���� (Recursion Available)��������ַ�����֧�ֵݹ��ѯ��������Ӧ�иñ�����Ϊ 1
    int Z;//3bits,����Ϊ 0 �������ֶ�
    unsigned int RCODE;//4bits,��Ӧ�� (Response coded) ����������Ӧ����,0��ʾ�޲��3��ʾ�в��

    //RR,resource record
    unsigned short QDCOUNT;//2B��question section ���������
    unsigned short ANCOUNT;//2B��answer section �� RR ����
    unsigned short NSCOUNT;//2B��authority records section �� RR ����
    unsigned short ARCOUNT;//2B��additional records section �� RR ����
}myHeader;

void setHeader(struct header* myheader, char* buf) {
    //ǰ2���ֽڻ�ȡid
    unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
    memcpy(t, buf, sizeof(unsigned short));

    myheader->ID = ntohs(*t);
    memset(t, 0, sizeof(t));

    int bits[8];
    bits[0] = ((buf[2] & 0x01) == 0x01) ? 1 : 0;
    bits[1] = ((buf[2] & 0x02) == 0x02) ? 1 : 0;
    bits[2] = ((buf[2] & 0x04) == 0x04) ? 1 : 0;
    bits[3] = ((buf[2] & 0x08) == 0x08) ? 1 : 0;
    bits[4] = ((buf[2] & 0x10) == 0x10) ? 1 : 0;
    bits[5] = ((buf[2] & 0x20) == 0x20) ? 1 : 0;
    bits[6] = ((buf[2] & 0x40) == 0x40) ? 1 : 0;
    bits[7] = ((buf[2] & 0x80) == 0x80) ? 1 : 0;
    myheader->QR = bits[7];
    myheader->Opcode = bits[3] + bits[4] * 2 + bits[5] * 4 + bits[6] * 8;
    myheader->AA = bits[2];
    myheader->TC = bits[1];
    myheader->RD = bits[0];

    //bits = buf[3];
    bits[0] = ((buf[3] & 0x01) == 0x01) ? 1 : 0;
    bits[1] = ((buf[3] & 0x02) == 0x02) ? 1 : 0;
    bits[2] = ((buf[3] & 0x04) == 0x04) ? 1 : 0;
    bits[3] = ((buf[3] & 0x08) == 0x08) ? 1 : 0;
    bits[4] = ((buf[3] & 0x10) == 0x10) ? 1 : 0;
    bits[5] = ((buf[3] & 0x20) == 0x20) ? 1 : 0;
    bits[6] = ((buf[3] & 0x40) == 0x40) ? 1 : 0;
    bits[7] = ((buf[3] & 0x80) == 0x80) ? 1 : 0;
    myheader->RCODE = bits[0] + bits[1] * 2 + bits[2] * 4 + bits[3] * 8;
    myheader->Z = bits[4] + bits[5] * 2 + bits[6] * 4;//����0
    myheader->RA = bits[7];

    memcpy(t, &buf[4], sizeof(unsigned short));
    myheader->QDCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[6], sizeof(unsigned short));
    myheader->ANCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[8], sizeof(unsigned short));
    myheader->NSCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[10], sizeof(unsigned short));
    myheader->ARCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

}

void printHeader(struct header* myHeader) {
    printf("��ͷ��Ϣ:\n");
    printf("\tID = %u   ", myHeader->ID);
    printf("QR = %u   ", myHeader->QR);
    printf("Opcode = %u   ", myHeader->Opcode);
    printf("AA = %u   ", myHeader->AA);
    printf("TC = %u   ", myHeader->TC);
    printf("RD = %u   ", myHeader->RD);
    printf("RA = %u   ", myHeader->RA);
    printf("Z = %u\n", myHeader->Z);
    printf("\tRCODE = %u   ", myHeader->RCODE);
    printf("QDCOUNT = %u   ", myHeader->QDCOUNT);
    printf("ANCOUNT = %u   ", myHeader->ANCOUNT);
    printf("NSCOUNT = %u   ", myHeader->NSCOUNT);
    printf("ARCOUNT = %u\n", myHeader->ARCOUNT);

}

void printBuf(char* buf, int buflen) {//��buf����wireshark�����
    for (int i = 0; i < buflen; i++) {
        if ((buf[i] & 0xf0) == 0x00) printf("0");
        //���ʮ��������
        printf("%x ", (unsigned char)buf[i]);
    }
    puts("");
}



struct id_transfer {
    unsigned short oldID;//��ID
    int done;//�Ƿ��Ѿ�����
    SOCKADDR_IN clientAddr;//�������׽��ֵ�ַ
    time_t ttl_end;
    char url[100];
    int timeout;
};


#define Mem(arr, val) memset(arr, val, sizeof(arr))

struct ip {
    char ip[100];
    time_t ttl_rend;
};

struct cache {
    char url[100];//domainname
//	char hex_url[100];//16����domainname
    int ip_num;//ip��ַ����
    struct ip Ip[100];
    time_t ttl_end;//��ʱʱ��
};

struct cache Cache[10000];
int cache_num = 0;

int if_in_cache(char* url) {
    for (int i = 1; i <= cache_num; i++) {
        //printf("\nttl_end=%lld   time(NULL)=%lld\n", Cache[i].ttl_end, time(NULL));
        if (Cache[i].ttl_end <= time(NULL)) {
            Cache[i] = Cache[cache_num];
			Cache[cache_num].ip_num = 0;
            cache_num--;
            //printf("��������������\n");
        }
        else {
            if (strcmp(Cache[i].url, url) == 0) {
                return i;
            }
        }
    }
    return 0;
}



typedef struct ipUrlNode {
    char ip[100];
    char url[100];
}IpUrlNode;
IpUrlNode ipUrlNodeSeq[500];
int ipUrlNodeNum;

void init_ip_url_table(char* fileName, int outputLevel) {//��dnsrelay.txt�洢��ipUrlNodeseq��
    FILE* fp = NULL;
    fp = fopen("dnsrelay.txt", "r");

    if (fp == NULL) {
        printf("dnsrelay.txt��ʧ��,�������!\n");
        exit(0);
    }

	char _ip[100]; memset(_ip, 0, sizeof(_ip));
	char _url[100];
    int findFlag = 0;
	if (outputLevel == twoDebug) printf("\n���ر�����Դ��:\n");
    while (!feof(fp)) {
		int x1, x2, x3, x4;
		fscanf(fp, "%d%*c%d%*c%d%*c%d %s", &x1, &x2, &x3, &x4,_url);
		_ip[0] = x1;
		_ip[1] = x2;
		_ip[2] = x3;
		_ip[3] = x4;

		//printf("%d.%d.%d.%d\n", x1, x2, x3, x4);
        //fscanf(fp, "%s %s", _ip, _url);
        ipUrlNodeNum++;
        strcpy(ipUrlNodeSeq[ipUrlNodeNum].ip, _ip);
        strcpy(ipUrlNodeSeq[ipUrlNodeNum].url, _url);
		if (outputLevel == twoDebug) {
			printf("\t%d: ", ipUrlNodeNum);
			for (int i = 0; i < 4; i++) {
				printf("%u", (unsigned char)_ip[i]);
				if (i != 3) {
					printf(".");
				}
				else {
					printf("      ");
				}
			}
			printf("%s\n", _url);
		}
    }

}
int num;//ip�ĸ���
char ip[20][100];//�洢���ip

void cache_to_ip(int which_url){
    num = Cache[which_url].ip_num;
    for (int i = 1; i <= num; i++) {
        strcpy(ip[i], Cache[which_url].Ip[i].ip);
    }
}
void makeUdpMessage(char* recvBuf, char* sendBuf, int num, int recvLen, int* len, int outputLevel) {//recvBuf��ֻ�б�ͷ��������ı��ģ���recvBuf�����챨�ģ�������Ϣ�洢��sendBuf��

    //��sendBuf�������Ӧ����
    for (int i = 0; i < 512; i++) {
        sendBuf[i] = recvBuf[i];
    }


    unsigned short us;

    //==================��ͷ==============
    //IDһ�£�sendBuf[0~1]

    //QR=1��OPCODE=1��AA=0,TC=0,RD=1,RA=1,Z=0,RCOED=0/3,sendBuf[2~3]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        us = htons(0x8183);
		if (outputLevel == twoDebug) printf("\n����0.0.0.0,���ι��ܣ�������վ����,�򱾵ؿͻ��˷��ʹ���Ϊ�յ����ݱ�!\n\n");
    }
    else {
        us = htons(0x8180);
		if (outputLevel == twoDebug) {
			for (int i = 1; i <= num; i++) {
				printf("\t");
				for (int j = 0; j < 4; j++) {
					printf("%u", (unsigned char)ip[i][j]);
					if (j != 3) {
						printf(".");
					}
					else {
						printf("\n");
					}
				}


				//printf("\t%s\n", ip[i]);
			}puts("");
		}
        
    }
    memcpy(&sendBuf[2], &us, 2);

    //QDCOUNT,sendBuf[4~5]

    //ANCOUNT��sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //���ι��ܣ������ֽ�ת�����ֽ�
        us = htons(0x0000); 
    }
    else {
        //���ӷ��������ܣ������ֽ�ת�����ֽ�
        us = htons(0x0000 | num);
    }
    memcpy(&sendBuf[6], &us, 2);

    //NSCOUNT,sendBuf[8~9]

    //ARCOUNT��sendBuf[10~11]


    //================������=============
    //�Ѿ�������ɣ��������һ��
    /*
    puts("===============");
    for (int i = 0; i < 512; i++) {

        //if ((sendBuf[i] & 0xf0) == 0x00) printf("0");
        //���ʮ��������
        printf("%x ", (unsigned char)sendBuf[i]);
    }
    puts("==================");
    */

    //================��Դ��¼=================
    //ѭ�����죬�м������켸��
    *len = recvLen;//�����ĳ��ȣ�ֱ���ں����޸�


	//ANCOUNT��sendBuf[6~7]
	if (strcmp(ip[1], IP_ERROR) == 0) {
		//���ι��ܣ������ֽ�ת�����ֽ�
		return;
	}

    for (int now = 1; now <= num; now++) {
        //0xc00c��NAME
        us = htons(0xc00c);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TYPE��IPV4Ϊ1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //CLASSΪ1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TTL=176
        unsigned long ul;
        ul = htonl(0x000000B0);
        memcpy(&sendBuf[*len], &ul, 4);
        *len += 4;

        //DATA LENGTH=4
        us = htons(0x0004);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;
        //ADDRESS
		for (int i = 0; i < 4; i++) {
			sendBuf[*len] = ip[now][i];
			*len += 1;
		}
		/*
        ul = (unsigned long)inet_addr(ip[now]);
        memcpy(&sendBuf[*len], &ul, 4);
        *len += 4;
		*/
    }
}

int main(int argc, char** argv) {
	puts("===Time: 2020��9��6��11:50:07\n===Designer: ��������³���������ӿ�");

	//Sleep(500);

	int outputLevel = -1;//����ȼ���0��1��2��Ӧ�ޡ�-d��-dd
	char DNSServer[100]; //Mem(DNSServer, 0);//�ⲿDNS��ַ
	char fileName[100]; //Mem(fileName, 0);//����dnsrelay�ĵ���ַ

	int base = 0;

	if (paramater_set(argc, argv, &outputLevel, DNSServer, fileName) == 1) {
		printf("�����ʽ���󣬳������!\n");
		return 0;
	}
	//�趨outputLevel��DNSSever��fileName

	//outputLevel = twoDebug;

	if (outputLevel == noneDebug) {
		printf("OutputLevel:noneDebug\n");
	}
	if (outputLevel == oneDebug) {
		printf("OutputLevel:oneDebug\n");
	}
	if (outputLevel == twoDebug) {
		printf("OutputLevel:twoDebug\n");
	}

	init_ip_url_table(fileName, outputLevel);//��ȡ�ļ������ݴ���ipUrlNodeSeq

	/*
	//���Զ�ȡ����
	printf("%d\n", ipUrlNodeNum);
	for (int i = 1; i <= ipUrlNodeNum; i++) {
		printf("%s %s\n", ipUrlNodeSeq[i].ip, ipUrlNodeSeq[i].url);
	}
	*/

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	//��������DNS�׽���
	SOCKET mySocket;
	mySocket = socket(AF_INET, SOCK_DGRAM, 0);//UDP,���ݱ�
	if (mySocket == SOCKET_ERROR) {
		printf("�׽��ִ���ʧ��\n");
		exit(1);
	}

	//�����׽��ֵ�ַ
	SOCKADDR_IN myAddr;
	myAddr.sin_family = AF_INET;
	myAddr.sin_port = htons(53);
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//�󶨱���DNS��������ַ
	int bRes = bind(mySocket, (SOCKADDR*)&myAddr, sizeof(myAddr));
	if (bRes == SOCKET_ERROR) {
		printf("��ʧ��\n");
		exit(2);
	}
	printf("�󶨳ɹ�\n");

	//�ⲿDNS�׽��ֵ�ַ
	SOCKADDR_IN DNSAddr;
	DNSAddr.sin_family = AF_INET;
	DNSAddr.sin_port = htons(53);
	DNSAddr.sin_addr.s_addr = inet_addr(DNSServer);

	//�ͻ����׽��ֵ�ַ
	SOCKADDR_IN clientAddr;
	int clientLen = sizeof(clientAddr);

	char sendBuf[512], recvBuf[512];
	int recvBufLen = sizeof(recvBuf);
	Mem(recvBuf, 0);

	struct id_transfer id_trans[ID_TRANS_MAX];//��һ���ṹ������洢�м�DNS��ԭ��Id���׽�����Ϣ
	int id_trans_size = 0;//��Ϣ����

	int mesNum = 0;

	while (1) {
		//����ʽ���ȴ��ͻ�������
		memset(recvBuf, 0, sizeof(recvBuf));
		int recvLen = recvfrom(mySocket, recvBuf, recvBufLen, 0, (SOCKADDR*)&clientAddr, &clientLen);
		if (outputLevel == twoDebug) {
			if (recvLen == SOCKET_ERROR) {
				printf("��������ʧ��\n\n");
				continue;
			}
			else if (recvLen == 0) {
				printf("�����ж�!\n\n");
				break;
			}
		}


		//���û���յ�DNS�ⲿ��������Ӧ������յ��ٵ�Ӧ���������ʱ��url��һ����������յ�Ӧ�𣬵������һ���ⲿDNS��������
		//���143.254.64.546��Ϊ�ⲿ������ʱ�������Ӧ�����
		for (int i = 0; i < id_trans_size; i++) {
			if (id_trans[i].done == 0 && time(NULL) >= id_trans[i].ttl_end && id_trans[i].timeout == 0) {
				id_trans[i].done = 1;
				id_trans[i].timeout = 1;
				if (outputLevel == twoDebug) printf("url of %s ��ʱ!\n", id_trans[i].url);
			}
		}

		char url[100] = ""; Mem(url, 0);
		int partlen = 0;//url�ĳ���
		char* msgBuf = recvBuf + 12;//ǰ12�ֽ��Ǳ�ͷ����

		//��������QNAME���õ�url,��url�洢��url�ַ�����
		char len = msgBuf[0];//����֮����ַ�����
		int flag = 1;//��ǰmsgBuf���±�
		while (len != 0) {
			for (char i = 0; i < len; i++) {
				url[partlen++] = msgBuf[flag++];
			}
			len = msgBuf[flag++];
			if (len != 0) {
				//url += '.';
				url[partlen++] = '.';
			}
		}
		//printf("url = %s\n", url);

		//QTYPE: ���Ͳ�ѯ(A(1)��MX(15)��CNAME(5)��PTR(12)...)
		//QCLASS: �������й̶�Ϊ1����ʾ��IN��
		unsigned short QTYPE, QCLASS;
		unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
		//��ȡQTYPE
		memcpy(t, &msgBuf[flag], sizeof(unsigned short));
		QTYPE = ntohs(*t);
		flag += 2;

		//��ȡQCLASS
		memcpy(t, &msgBuf[flag], sizeof(unsigned short));
		QCLASS = ntohs(*t);
		flag += 2;
		/*
		if (QTYPE != 1) {
			printf("���յ���IPV4�İ�!\n\n");
			continue;
		}

		printf("\n================���յ�IPV4���ݱ�===============\n");
		*/

		if (QTYPE != 28 && QTYPE != 1 && QTYPE != 5 && QTYPE != 15) {
			if (outputLevel == twoDebug) printf("���յ��Ƿ������ݱ�!\n\n");
			continue;
		}

		++mesNum;
		if (outputLevel >= oneDebug) {
			printf("%d:    ", mesNum);
			char szIP[16]; Mem(szIP, 0);
			strcpy(szIP, inet_ntoa(clientAddr.sin_addr));
			printf(__DATE__); printf("  ");  printf(__TIME__);
			printf("  client %s   ", szIP);
		}
		struct header myHeader;
		setHeader(&myHeader, recvBuf);//������ͷ
		if (outputLevel >= oneDebug) {
			//struct header myHeader;
			//setHeader(&myHeader, recvBuf);//������ͷ
			printf("%s", url);
			if (myHeader.QR == 1) {
				printf(", TYPE %d, CLASS %d\n", QTYPE, QCLASS);
			}
			else puts("");
		}
		if (outputLevel == twoDebug) {
			if (QTYPE == 28) printf("\n================���յ�IPV6���ݱ�===============\n");
			else if (QTYPE == 1)printf("\n================���յ�IPV4���ݱ�===============\n");
			else if (QTYPE == 5)printf("\n================���յ�CNAME���ݱ�===============\n");
			else printf("\n================���յ�MX���ݱ�===============\n");
		}

		if (outputLevel == twoDebug) {

			printHeader(&myHeader);//�����ͷ
			printf("��������Ϣ:\n");
			printf("\turl = %s   QTYPE = %u   QCLASS = %u\n\n\n", url, QTYPE, QCLASS);//������������͡���

		}

		if (myHeader.QR == 0) {//�������ݱ�

			num = 0;
			memset(ip, 0, sizeof(ip));
			int findFlag = 0;//0��ʾ����û�У�1��ʾ������

			int which_url = if_in_cache(url);//�����ڻ����е���һλ

			if (QTYPE != 1) which_url = 0;//ֻ�ж�ipv4�Ƿ��ڻ�����

			if (which_url != 0) {
				if (outputLevel == twoDebug) printf("��cache�������ҵ���Ӧip���򱾵ؿͻ��˷������ݱ�!\n");
				cache_to_ip(which_url);
				//���Ӵӻ�������ĺ���

				//���췢�͸����ؿͻ��˵����ݱ�
				makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);

				struct header sendHeader;
				setHeader(&sendHeader, sendBuf);
				if (outputLevel == twoDebug) {
					printf("Ҫ���͸����ؿͻ��˵����ݱ�:\n");
					printHeader(&sendHeader);

					printf("����ԭ��Ϣ:\n");
					printBuf(sendBuf, len);
				}


				//������Ӧ����
				int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
				if (outputLevel == twoDebug) {
					if (sendFlag == SOCKET_ERROR) {
						printf("\n(����)�򱾵ؿͻ��˷������ݱ�ʧ��!\n\n");
					}
					else {
						printf("\n(����)�򱾵ؿͻ��˷������ݱ��ɹ�!\n\n");
					}
					puts("===============================================\n\n\n");
				}

			}
			else {
				if (outputLevel == twoDebug) printf("��cache����δ���ҵ���Ӧip\n");
				for (int i = 1; i <= ipUrlNodeNum; i++) {
					//printf("<<%s %s>>\n", ipUrlNodeSeq[i].url, url);
					if (strcmp(ipUrlNodeSeq[i].url, url) == 0) {
						findFlag = 1;
						++num;
						memcpy(ip[num], ipUrlNodeSeq[i].ip, sizeof(ip[num]));
					}
				}
				if (QTYPE != 1) findFlag = 0;
				if (findFlag == 1) {

					if (outputLevel == twoDebug) printf("�ڱ�����Դ�����ҵ���Ӧip���򱾵ؿͻ��˷������ݱ�!\n");

					//������Ӧ���ķ��ظ�client������DNS������������

					makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);//ԭ���ģ��±��ģ�ip������recvBuf����

					struct header sendHeader;
					setHeader(&sendHeader, sendBuf);
					if (outputLevel == twoDebug) {
						printf("Ҫ���͸����ؿͻ��˵����ݱ�:\n");
						printHeader(&sendHeader);

						printf("����ԭ��Ϣ:\n");
						printBuf(sendBuf, len);
					}



					//if (strcmp(ip[1], IP_ERROR) == 0) {
					//	printf("�ҵ�0.0.0.0������������(������վ����),�ܾ�����!\n\n");
					//}
					//else {
						//������Ӧ����
					int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
					if (outputLevel == twoDebug) {
						if (sendFlag == SOCKET_ERROR) {
							printf("\n(������Դ��)�򱾵ؿͻ��˷������ݱ�ʧ��!\n\n");
						}
						else {
							printf("\n(������Դ��)�򱾵ؿͻ��˷������ݱ��ɹ�!\n\n");
						}
					}

					//}
					if (outputLevel == twoDebug) puts("===============================================\n\n\n");
					/*
					int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
					if (sendLen == SOCKET_ERROR) {
						//cout << "��������ʧ��";
						printf("��������ʧ��\n");
						continue;
					}*/
				}
				//�ļ���û�м�¼
				else {
					if (outputLevel == twoDebug) printf("�ڱ�����Դ����δ�ҵ���Ӧip�����ⲿDNS�������������ݱ�!\n");
					unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
					memcpy(t, recvBuf, sizeof(unsigned short));
					unsigned short oldID = ntohs(*t);
					struct id_transfer myTransfer;
					myTransfer.oldID = oldID;
					myTransfer.clientAddr = clientAddr;
					myTransfer.done = 0;
					myTransfer.ttl_end = time(NULL) + DNSSERVER_NO_REPLY;
					strcpy(myTransfer.url, url);
					myTransfer.timeout = 0;

					//id_trans���¾�idת�����У�����ÿ��Ԫ���ǰ�����id���ӿͻ����յ���id�����Ƿ��Ѿ������Ƿ��յ���dns��������Ӧ����
					//���������Ŀͻ��˵�clientAddr�������յ�dns��������Ӧ���͸����clientAddr��

					//����¾�idת���������˾�pop��ǰһ�룬base��Ϊ�������size-base
					//�Զ������sizeΪ1000Ϊ����base���ó�������ԭ����pop��ǰ500�������ӵ���idӦ����501������baseӦ�ñ��500
					//�ټ�500������idӦ����1��baseӦ����Ϊ0��������ÿ��һ��base��0��500֮��ת��һ��

					if (id_trans_size == ID_TRANS_MAX) {
						for (int i = 0; i < ID_TRANS_MAX / 2; i++) {
							id_trans[i] = id_trans[i + ID_TRANS_MAX / 2];
						}
						base = ID_TRANS_MAX / 2 - base;
						id_trans_size = ID_TRANS_MAX / 2;
					}

					//�����ǻ�ȡ��id
					unsigned short newID = (unsigned short)((base + id_trans_size) % ID_TRANS_MAX);
					newID = htons(newID);
					memcpy(recvBuf, &newID, sizeof(unsigned short));

					id_trans[id_trans_size] = myTransfer;
					id_trans_size++;
					//id_trans.push_back(myTransfer);

					int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&DNSAddr, sizeof(DNSAddr));
					if (outputLevel == twoDebug) {
						if (sendLen == SOCKET_ERROR) {
							printf("\n���ⲿDNS�������������ݱ�ʧ��!\n\n");
						}
						else {
							printf("\n���ⲿDNS�������������ݱ��ɹ�!\n\n");
						}
						puts("===============================================\n\n\n");
					}


				}
			}
		}
		else if (myHeader.QR == 1) {//�ӵ���Ӧ��
			if (QTYPE == 1) {
				cache_num++;
				msgBuf = recvBuf + 12;
				char len1 = msgBuf[0];
				flag = 1;
				char url0[100] = "";
				while (len1 != 0) {
					for (char i = 0; i < len1; i++) {
						//	printf("{{{%x}}}", msgBuf[flag]);
						url0[strlen(url0)] = msgBuf[flag++];
					}
					len1 = msgBuf[flag++];
					if (len1 != 0) {
						//*url0 += '.';
						url0[strlen(url0)] = '.';
					}
				}
				strcpy(Cache[cache_num].url, url0);
				//printf("<<<<<%s>>>>>\n", Cache[cache_num].url);

				//printf("\nmsgBUf=%s\n", msgBuf);

				flag = flag + 4;
				char qtype = 0;
				for (short j = 0; j < myHeader.ANCOUNT; j++) {
					Cache[cache_num].ip_num++;
					flag = flag + 3;
					qtype = msgBuf[flag];
					//printf("!!!!!!qtype=%d!!!!\n", qtype);
					flag = flag + 3;
					//time_t recent_ttl = 0;
					//int hex_num = 16777216;
					for (int i = 1; i <= 4; i++) {
						//recent_ttl += ((unsigned char)msgBuf[flag] * hex_num);
						//printf("\nhex_num=%d\n", hex_num);
						//hex_num /= 256;
						flag++;
						//printf("%u+ ",msgBuf[flag++]);
					}
					if (qtype == 1) {
						Cache[cache_num].ttl_end = 30 + time(NULL);
						//printf("\nttl=%u\n", recent_ttl);
						//time_t recent_time = time(NULL);
						//Cache[cache_num].Ip[Cache[cache_num].ip_num].ttl_rend = recent_ttl + recent_time;
						flag = flag + 2;
						for (int i = 0; i < 4; i++) {
							Cache[cache_num].Ip[Cache[cache_num].ip_num].ip[i] = (unsigned char)msgBuf[flag++];
							//printf("\n%u", Cache[cache_num].Ip[Cache[cache_num].ip_num].ip[i]);
						}
					}
					else {
						Cache[cache_num].ip_num = 0;
						Mem(Cache[cache_num].url, 0);
						cache_num--;
						break;
					}
				}
				if_in_cache(url);
				/*if (qtype == 1) {
					printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
					printf("����Ϊ��%s\n", Cache[cache_num].url);
					printf("Address:\n");
					for (int i = 1; i <= Cache[cache_num].ip_num; i++) {
						for (int j = 0; j < 4; j++) {
							printf("%u", (unsigned char)Cache[cache_num].Ip[i].ip[j]);
							if (i < 3) {
								printf(".");
							}
							else {
								printf("\n");
							}
						}
					}
					printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
				}*/


			}

			unsigned short* newID = (unsigned short*)malloc(sizeof(unsigned short));
			memcpy(newID, &recvBuf, sizeof(unsigned int));

			//id_trans[find]����id����dns�������յ���id����Ӧ�ľ�id���ڵĽṹ��
			*newID = ntohs(*newID);
			int find = (base + (int)*newID) % ID_TRANS_MAX;

			if (id_trans[find].done == 1) {
				continue;
			}

			unsigned short oldID = id_trans[find].oldID;
			oldID = htons(oldID);
			memcpy(recvBuf, &oldID, sizeof(unsigned short));
			id_trans[find].done = 1;

			//���
			struct header sendHeader;
			setHeader(&sendHeader, recvBuf);
			if (outputLevel == twoDebug) {
				printf("Ҫ���͸����ؿͻ��˵����ݱ�:\n");
				printHeader(&sendHeader);

				printf("����ԭ��Ϣ:\n");
				printBuf(recvBuf, recvLen);
			}


			int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
			if (outputLevel == twoDebug) {
				if (sendLen == SOCKET_ERROR) {
					printf("\n�򱾵ؿͻ��˷������ݱ�ʧ��!\n\n");
				}
				else {
					printf("\n�򱾵ؿͻ��˷������ݱ��ɹ�!\n\n");
				}
				puts("===============================================\n\n\n");
			}

		}
	}
	//�ر��׽���
	closesocket(mySocket);
	WSACleanup();
}