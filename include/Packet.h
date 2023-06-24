#ifndef Packet_h
#define Packet_h


#define DEFAULT_TTL 120
#define GET_TTL 1
#define DECREASE_TTL 2

#define STRING_MAX_SIZE 8192
#define RR_NAME_MAX_SIZE 512

#define QR_QUERY 0
#define QR_ANSWER 1

#define OPCODE_QUERY 0
#define OPCODE_IQUERY 1
#define OPCODE_STATUS 2

#define QTYPE_A 1
#define QTYPE_NS 2
#define QTYPE_CNAME 5
#define QTYPE_SOA 6
#define QTYPE_PTR 12
#define QTYPE_HINFO 13
#define QTYPE_MINFO 15
#define QTYPE_MX 15
#define QTYPE_TXT 16
#define QTYPE_AAAA 28

#define QCLASS_IN 1

#define RCODE_OK 0
#define RCODE_NXDOMAIN 3

#include<stdint.h>
#include <string.h>
#include <limits.h>
#include <math.h>
/*
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct DNSPacketHeader { //注意内存对齐
    uint16_t ID ;      //报文标识的ID
    uint8_t RD : 1;       //=1DNS递归查询,=0迭代查询
    uint8_t TC : 1;       //超过512B，=1截断
    uint8_t AA : 1;       //=1权威服务器，=0非权威服务器
    uint8_t QR : 1;       //=0查询请求，=1响应
    uint8_t OPCODE : 4;   //=0标准查询，=1反查询，=2服务器状态
    uint8_t RCODE : 4;    //=0无差错，=1格式错误，=2链接服务器失败
                          //=3名字错误，=4查询类型不支持，=5拒绝响应
    uint8_t Z : 3;        //恒=0，保留
    uint8_t RA : 1;       //=1支持递归查询
    uint16_t QDCOUNT ; //查询请求计数
    uint16_t ANCOUNT ; //回答计数
    uint16_t NSCOUNT ; //权威名称服务计数
    uint16_t ARCOUNT ; //额外计数（权威服务器对应IP地址的数目
 }DNSPacketHeader;
/*
ID: 16 bits
RD: 1 bit
TC: 1 bit
AA: 1 bit
QR: 1 bit
OPCODE: 4 bits
RCODE: 4 bits
Z: 3 bits
RA: 1 bit
QDCOUNT: 16 bits
ANCOUNT: 16 bits
NSCOUNT: 16 bits
ARCOUNT: 16 bits
*/

typedef struct DNSPacketQD{
    uint16_t qtype;//DNS请求的资源类型    2B
    uint16_t qclass;//互联网查询恒为1    2B
    uint8_t* qname;
    DNSPacketQD* next;//链表实现
}DNSPacketQD;

typedef struct DNSPacketRR{//DNS资源记录
    uint8_t* rname;       //DNS请求的域名
    uint16_t rtype;        //资源记录的类型
    uint16_t rclass;     //地址类型（与问题中一致）
    uint32_t ttl;         //有效时间，即请求方
    uint16_t rdataLength; //rdata的长度
    uint8_t* rdata;          //资源数据（可能是answers、authorities或者additional的信息）
    DNSPacketRR* next;//≥3
}DNSPacketRR;

typedef struct DNSPacket {
    DNSPacketHeader* header;
    DNSPacketQD* question;
    DNSPacketRR* resourceRecord;
}DNSPacket;
/*
extern void DecodeHeader(DNSPacketHeader* header);//大端网络字节转小端本地字节
extern void EncodeHeader(DNSPacketHeader* header);//小端本地字节转大端网络字节
extern void ResolveQname(unsigned char*buffer, DNSPacketQD* DNSpacketQD);
extern unsigned int form_standard_response(unsigned char* buffer, char* domain_name, unsigned int ip, unsigned int* question_size);
extern void ResolveResourse(unsigned char* buffer, DNSPacketRR* DNSpacketRR)
*/
#endif // !Packet_h
