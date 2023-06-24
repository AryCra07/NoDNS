/**
 * @file dns_structure.h
 * @brief DNS报文结构体定义
 * @details 定义DNS报文相关的结构体与常量
 * @date 2023-6-24
 */

#ifndef GODNS_DNS_STRUCTURE_H
#define GODNS_DNS_STRUCTURE_H

#include <stdint.h>

#define DNSR_MAX_DOMAIN_LEN 256
#define DNSR_MAX_DOMAIN_NUM 256
#define DNSR_MAX_DOMAIN_SIZE 8192
#define DNSR_MAX_RR_NUM 256
#define DNSR_MAX_RR_SIZE 8192

#define DNSR_QR_QUERY 0
#define DNSR_QR_ANSWER 1

#define DNSR_OPCODE_QUERY 0
#define DNSR_OPCODE_IQUERY 1
#define DNSR_OPCODE_STATUS 2

#define DNSR_TYPE_A 1
#define DNSR_TYPE_NS 2
#define DNSR_TYPE_CNAME 5
#define DNSR_TYPE_SOA 6
#define DNSR_TYPE_PTR 12
#define DNSR_TYPE_HINFO 13
#define DNSR_TYPE_MINFO 15
#define DNSR_TYPE_MX 15
#define DNSR_TYPE_TXT 16
#define DNSR_TYPE_AAAA 28

#define DNSR_CLASS_IN 1

#define DNSR_RCODE_OK 0
#define DNSR_RCODE_NXDOMAIN 3

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
typedef struct dns_header {
    uint16_t id ;      //报文标识的ID
    uint8_t rd : 1;       //=1DNS递归查询,=0迭代查询
    uint8_t tc : 1;       //超过512B，=1截断
    uint8_t aa : 1;       //=1权威服务器，=0非权威服务器
    uint8_t qr : 1;       //=0查询请求，=1响应
    uint8_t opcode : 4;   //=0标准查询，=1反查询，=2服务器状态
    uint8_t rcode : 4;    //=0无差错，=1格式错误，=2链接服务器失败
    //=3名字错误，=4查询类型不支持，=5拒绝响应
    uint8_t z : 3;        //恒=0，保留
    uint8_t ra : 1;       //=1支持递归查询
    uint16_t qdcount ; //查询请求计数
    uint16_t ancount ; //回答计数
    uint16_t nscount ; //权威名称服务计数
    uint16_t arcount ; //额外计数（权威服务器对应IP地址的数目
} DNSHeader;

// 报文 Question Section 部分
typedef struct dns_question {
    uint8_t *qname;
    uint16_t qtype;
    uint16_t qclass;
    struct dns_question *next;
} DNSQuestion;

// 报文 Resource Record 部分
typedef struct dns_resource_record {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
    struct dns_resource_record *next;
} DNSResourceRecord;

// DNS 报文
typedef struct dns_message {
    DNSHeader *header;
    DNSQuestion *que;
    DNSResourceRecord *rr;
} DNSMessage;

#endif //GODNS_DNS_STRUCTURE_H
