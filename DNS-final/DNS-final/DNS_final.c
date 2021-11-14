#include <winsock2.h>
#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib, "ws2_32.lib")  //加载 ws2_32.dll
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


int d_or_f(char* s, int len) {//根据内容来判断是DNSSever还是fileName，如果全是数字和.,就是DNSSever
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
    case 1://对应没有输入
        *outputLevel = noneDebug;
        strcpy(DNSServer, defaultDNSServer);
        strcpy(fileName, defaultFileName);
        //DNSServer = defaultDNSServer;
        //fileName = defaultFileName;
        break;
    case 2:
        if (argv[1][0] == '-') {// -d或者 - dd
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


struct header {//报文头部，12个字节
    unsigned short ID;//2B = 16 bits，id
    int QR;//1bit，Query or Response，查询/响应的标志位，0为查询、1为响应
    unsigned short Opcode;//4bits,operationCode,通常值为 0 （标准查询），其他值为 1 （反向查询）和 2 （服务器状态请求）
    int AA;//1bit,权威答案 (Authoritative answer),1表示名字服务器是权威服务器
    int TC;//1bit,被截断的报文 (Truncated ),1表示响应的总长度超 512 字节时，只返回前 512 个字节
    int RD;//1bit，1表示用户期望使用递归解析 (Recursion desired)
    int RA;//1bit，递归可用 (Recursion Available)，如果名字服务器支持递归查询，则在响应中该比特置为 1
    int Z;//3bits,必须为 0 ，保留字段
    unsigned int RCODE;//4bits,响应码 (Response coded) ，仅用于响应报文,0表示无差错，3表示有差错

    //RR,resource record
    unsigned short QDCOUNT;//2B，question section 的问题个数
    unsigned short ANCOUNT;//2B，answer section 的 RR 个数
    unsigned short NSCOUNT;//2B，authority records section 的 RR 个数
    unsigned short ARCOUNT;//2B，additional records section 的 RR 个数
}myHeader;

void setHeader(struct header* myheader, char* buf) {
    //前2个字节获取id
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
    myheader->Z = bits[4] + bits[5] * 2 + bits[6] * 4;//总是0
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
    printf("报头信息:\n");
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

void printBuf(char* buf, int buflen) {//将buf按照wireshark数输出
    for (int i = 0; i < buflen; i++) {
        if ((buf[i] & 0xf0) == 0x00) printf("0");
        //输出十六进制数
        printf("%x ", (unsigned char)buf[i]);
    }
    puts("");
}



struct id_transfer {
    unsigned short oldID;//旧ID
    int done;//是否已经解析
    SOCKADDR_IN clientAddr;//请求者套接字地址
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
//	char hex_url[100];//16进制domainname
    int ip_num;//ip地址数量
    struct ip Ip[100];
    time_t ttl_end;//超时时间
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
            //printf("错啦！！！！！\n");
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

void init_ip_url_table(char* fileName, int outputLevel) {//将dnsrelay.txt存储到ipUrlNodeseq中
    FILE* fp = NULL;
    fp = fopen("dnsrelay.txt", "r");

    if (fp == NULL) {
        printf("dnsrelay.txt打开失败,程序出错!\n");
        exit(0);
    }

	char _ip[100]; memset(_ip, 0, sizeof(_ip));
	char _url[100];
    int findFlag = 0;
	if (outputLevel == twoDebug) printf("\n加载本地资源库:\n");
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
int num;//ip的个数
char ip[20][100];//存储多个ip

void cache_to_ip(int which_url){
    num = Cache[which_url].ip_num;
    for (int i = 1; i <= num; i++) {
        strcpy(ip[i], Cache[which_url].Ip[i].ip);
    }
}
void makeUdpMessage(char* recvBuf, char* sendBuf, int num, int recvLen, int* len, int outputLevel) {//recvBuf是只有报头和问题域的报文，用recvBuf来构造报文，报文信息存储在sendBuf中

    //将sendBuf改造成响应报文
    for (int i = 0; i < 512; i++) {
        sendBuf[i] = recvBuf[i];
    }


    unsigned short us;

    //==================报头==============
    //ID一致，sendBuf[0~1]

    //QR=1，OPCODE=1，AA=0,TC=0,RD=1,RA=1,Z=0,RCOED=0/3,sendBuf[2~3]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        us = htons(0x8183);
		if (outputLevel == twoDebug) printf("\n发现0.0.0.0,屏蔽功能，不良网站拦截,向本地客户端发送答案域为空的数据报!\n\n");
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

    //ANCOUNT，sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //屏蔽功能，主机字节转网络字节
        us = htons(0x0000); 
    }
    else {
        //发挥服务器功能，主机字节转网络字节
        us = htons(0x0000 | num);
    }
    memcpy(&sendBuf[6], &us, 2);

    //NSCOUNT,sendBuf[8~9]

    //ARCOUNT，sendBuf[10~11]


    //================问题域=============
    //已经构造完成，和请求包一致
    /*
    puts("===============");
    for (int i = 0; i < 512; i++) {

        //if ((sendBuf[i] & 0xf0) == 0x00) printf("0");
        //输出十六进制数
        printf("%x ", (unsigned char)sendBuf[i]);
    }
    puts("==================");
    */

    //================资源记录=================
    //循环构造，有几个构造几个
    *len = recvLen;//请求报文长度，直接在后面修改


	//ANCOUNT，sendBuf[6~7]
	if (strcmp(ip[1], IP_ERROR) == 0) {
		//屏蔽功能，主机字节转网络字节
		return;
	}

    for (int now = 1; now <= num; now++) {
        //0xc00c，NAME
        us = htons(0xc00c);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TYPE，IPV4为1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //CLASS为1
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
	puts("===Time: 2020年9月6日11:50:07\n===Designer: 何泓川、鲁嘉祺、许子康");

	//Sleep(500);

	int outputLevel = -1;//输出等级，0、1、2对应无、-d、-dd
	char DNSServer[100]; //Mem(DNSServer, 0);//外部DNS地址
	char fileName[100]; //Mem(fileName, 0);//本地dnsrelay文档地址

	int base = 0;

	if (paramater_set(argc, argv, &outputLevel, DNSServer, fileName) == 1) {
		printf("输入格式错误，程序结束!\n");
		return 0;
	}
	//设定outputLevel、DNSSever、fileName

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

	init_ip_url_table(fileName, outputLevel);//读取文件的内容存至ipUrlNodeSeq

	/*
	//测试读取内容
	printf("%d\n", ipUrlNodeNum);
	for (int i = 1; i <= ipUrlNodeNum; i++) {
		printf("%s %s\n", ipUrlNodeSeq[i].ip, ipUrlNodeSeq[i].url);
	}
	*/

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	//创建本地DNS套接字
	SOCKET mySocket;
	mySocket = socket(AF_INET, SOCK_DGRAM, 0);//UDP,数据报
	if (mySocket == SOCKET_ERROR) {
		printf("套接字创建失败\n");
		exit(1);
	}

	//本地套接字地址
	SOCKADDR_IN myAddr;
	myAddr.sin_family = AF_INET;
	myAddr.sin_port = htons(53);
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定本地DNS服务器地址
	int bRes = bind(mySocket, (SOCKADDR*)&myAddr, sizeof(myAddr));
	if (bRes == SOCKET_ERROR) {
		printf("绑定失败\n");
		exit(2);
	}
	printf("绑定成功\n");

	//外部DNS套接字地址
	SOCKADDR_IN DNSAddr;
	DNSAddr.sin_family = AF_INET;
	DNSAddr.sin_port = htons(53);
	DNSAddr.sin_addr.s_addr = inet_addr(DNSServer);

	//客户端套接字地址
	SOCKADDR_IN clientAddr;
	int clientLen = sizeof(clientAddr);

	char sendBuf[512], recvBuf[512];
	int recvBufLen = sizeof(recvBuf);
	Mem(recvBuf, 0);

	struct id_transfer id_trans[ID_TRANS_MAX];//开一个结构体数组存储中继DNS的原来Id和套接字信息
	int id_trans_size = 0;//信息数量

	int mesNum = 0;

	while (1) {
		//阻塞式，等待客户端请求
		memset(recvBuf, 0, sizeof(recvBuf));
		int recvLen = recvfrom(mySocket, recvBuf, recvBufLen, 0, (SOCKADDR*)&clientAddr, &clientLen);
		if (outputLevel == twoDebug) {
			if (recvLen == SOCKET_ERROR) {
				printf("接收数据失败\n\n");
				continue;
			}
			else if (recvLen == 0) {
				printf("连接中断!\n\n");
				break;
			}
		}


		//如果没有收到DNS外部服务器的应答或者收到迟到应答则输出超时的url（一般情况都会收到应答，当随便设一个外部DNS服务器，
		//如把143.254.64.546作为外部服务器时会出现无应答情况
		for (int i = 0; i < id_trans_size; i++) {
			if (id_trans[i].done == 0 && time(NULL) >= id_trans[i].ttl_end && id_trans[i].timeout == 0) {
				id_trans[i].done = 1;
				id_trans[i].timeout = 1;
				if (outputLevel == twoDebug) printf("url of %s 超时!\n", id_trans[i].url);
			}
		}

		char url[100] = ""; Mem(url, 0);
		int partlen = 0;//url的长度
		char* msgBuf = recvBuf + 12;//前12字节是报头部分

		//解析报文QNAME，得到url,将url存储到url字符数组
		char len = msgBuf[0];//两点之间的字符个数
		int flag = 1;//当前msgBuf的下标
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

		//QTYPE: 类型查询(A(1)、MX(15)、CNAME(5)、PTR(12)...)
		//QCLASS: 因特网中固定为1，表示“IN”
		unsigned short QTYPE, QCLASS;
		unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
		//获取QTYPE
		memcpy(t, &msgBuf[flag], sizeof(unsigned short));
		QTYPE = ntohs(*t);
		flag += 2;

		//获取QCLASS
		memcpy(t, &msgBuf[flag], sizeof(unsigned short));
		QCLASS = ntohs(*t);
		flag += 2;
		/*
		if (QTYPE != 1) {
			printf("接收到非IPV4的包!\n\n");
			continue;
		}

		printf("\n================接收到IPV4数据报===============\n");
		*/

		if (QTYPE != 28 && QTYPE != 1 && QTYPE != 5 && QTYPE != 15) {
			if (outputLevel == twoDebug) printf("接收到非法的数据报!\n\n");
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
		setHeader(&myHeader, recvBuf);//分析报头
		if (outputLevel >= oneDebug) {
			//struct header myHeader;
			//setHeader(&myHeader, recvBuf);//分析报头
			printf("%s", url);
			if (myHeader.QR == 1) {
				printf(", TYPE %d, CLASS %d\n", QTYPE, QCLASS);
			}
			else puts("");
		}
		if (outputLevel == twoDebug) {
			if (QTYPE == 28) printf("\n================接收到IPV6数据报===============\n");
			else if (QTYPE == 1)printf("\n================接收到IPV4数据报===============\n");
			else if (QTYPE == 5)printf("\n================接收到CNAME数据报===============\n");
			else printf("\n================接收到MX数据报===============\n");
		}

		if (outputLevel == twoDebug) {

			printHeader(&myHeader);//输出报头
			printf("问题域信息:\n");
			printf("\turl = %s   QTYPE = %u   QCLASS = %u\n\n\n", url, QTYPE, QCLASS);//输出域名、类型、类

		}

		if (myHeader.QR == 0) {//请求数据报

			num = 0;
			memset(ip, 0, sizeof(ip));
			int findFlag = 0;//0表示本地没有，1表示本地有

			int which_url = if_in_cache(url);//返回在缓存中的哪一位

			if (QTYPE != 1) which_url = 0;//只判断ipv4是否在缓存中

			if (which_url != 0) {
				if (outputLevel == twoDebug) printf("在cache缓存内找到相应ip，向本地客户端发送数据报!\n");
				cache_to_ip(which_url);
				//增加从缓冲读出的函数

				//构造发送给本地客户端的数据报
				makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);

				struct header sendHeader;
				setHeader(&sendHeader, sendBuf);
				if (outputLevel == twoDebug) {
					printf("要发送给本地客户端的数据报:\n");
					printHeader(&sendHeader);

					printf("报文原信息:\n");
					printBuf(sendBuf, len);
				}


				//发送响应报文
				int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
				if (outputLevel == twoDebug) {
					if (sendFlag == SOCKET_ERROR) {
						printf("\n(缓存)向本地客户端发送数据报失败!\n\n");
					}
					else {
						printf("\n(缓存)向本地客户端发送数据报成功!\n\n");
					}
					puts("===============================================\n\n\n");
				}

			}
			else {
				if (outputLevel == twoDebug) printf("在cache缓存未内找到相应ip\n");
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

					if (outputLevel == twoDebug) printf("在本地资源库内找到相应ip，向本地客户端发送数据报!\n");

					//构造响应报文返回给client，代替DNS服务器的作用

					makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);//原报文，新报文，ip数量，recvBuf长度

					struct header sendHeader;
					setHeader(&sendHeader, sendBuf);
					if (outputLevel == twoDebug) {
						printf("要发送给本地客户端的数据报:\n");
						printHeader(&sendHeader);

						printf("报文原信息:\n");
						printBuf(sendBuf, len);
					}



					//if (strcmp(ip[1], IP_ERROR) == 0) {
					//	printf("找到0.0.0.0，域名不存在(不良网站拦截),拒绝发送!\n\n");
					//}
					//else {
						//发送响应报文
					int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
					if (outputLevel == twoDebug) {
						if (sendFlag == SOCKET_ERROR) {
							printf("\n(本地资源库)向本地客户端发送数据报失败!\n\n");
						}
						else {
							printf("\n(本地资源库)向本地客户端发送数据报成功!\n\n");
						}
					}

					//}
					if (outputLevel == twoDebug) puts("===============================================\n\n\n");
					/*
					int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
					if (sendLen == SOCKET_ERROR) {
						//cout << "发送数据失败";
						printf("发送数据失败\n");
						continue;
					}*/
				}
				//文件中没有记录
				else {
					if (outputLevel == twoDebug) printf("在本地资源库内未找到相应ip，向外部DNS服务器发送数据报!\n");
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

					//id_trans是新旧id转换队列，队列每个元素是包括旧id（从客户端收到的id）、是否已经处理（是否收到过dns服务器回应）、
					//和这个请求的客户端的clientAddr（用于收到dns服务器回应后发送给这个clientAddr）

					//如果新旧id转换队列满了就pop出前一半，base设为队列最大size-base
					//以队列最大size为1000为例，base设置成这样的原因是pop出前500后再增加的新id应该是501，所以base应该变成500
					//再加500条后新id应该是1，base应该设为0，即队列每满一次base从0和500之间转变一次

					if (id_trans_size == ID_TRANS_MAX) {
						for (int i = 0; i < ID_TRANS_MAX / 2; i++) {
							id_trans[i] = id_trans[i + ID_TRANS_MAX / 2];
						}
						base = ID_TRANS_MAX / 2 - base;
						id_trans_size = ID_TRANS_MAX / 2;
					}

					//下面是获取新id
					unsigned short newID = (unsigned short)((base + id_trans_size) % ID_TRANS_MAX);
					newID = htons(newID);
					memcpy(recvBuf, &newID, sizeof(unsigned short));

					id_trans[id_trans_size] = myTransfer;
					id_trans_size++;
					//id_trans.push_back(myTransfer);

					int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&DNSAddr, sizeof(DNSAddr));
					if (outputLevel == twoDebug) {
						if (sendLen == SOCKET_ERROR) {
							printf("\n向外部DNS服务器发送数据报失败!\n\n");
						}
						else {
							printf("\n向外部DNS服务器发送数据报成功!\n\n");
						}
						puts("===============================================\n\n\n");
					}


				}
			}
		}
		else if (myHeader.QR == 1) {//接到响应包
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
					printf("域名为：%s\n", Cache[cache_num].url);
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

			//id_trans[find]是新id（从dns服务器收到的id）对应的旧id所在的结构体
			*newID = ntohs(*newID);
			int find = (base + (int)*newID) % ID_TRANS_MAX;

			if (id_trans[find].done == 1) {
				continue;
			}

			unsigned short oldID = id_trans[find].oldID;
			oldID = htons(oldID);
			memcpy(recvBuf, &oldID, sizeof(unsigned short));
			id_trans[find].done = 1;

			//输出
			struct header sendHeader;
			setHeader(&sendHeader, recvBuf);
			if (outputLevel == twoDebug) {
				printf("要发送给本地客户端的数据报:\n");
				printHeader(&sendHeader);

				printf("报文原信息:\n");
				printBuf(recvBuf, recvLen);
			}


			int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
			if (outputLevel == twoDebug) {
				if (sendLen == SOCKET_ERROR) {
					printf("\n向本地客户端发送数据报失败!\n\n");
				}
				else {
					printf("\n向本地客户端发送数据报成功!\n\n");
				}
				puts("===============================================\n\n\n");
			}

		}
	}
	//关闭套接字
	closesocket(mySocket);
	WSACleanup();
}