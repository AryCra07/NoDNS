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

typedef struct {
    uint16_t id; // 16位标识符
    uint8_t qr: 1; // 1位，查询/响应标志，0为查询，1为响应
    uint8_t opcode: 4; // 4位，0为标准查询，1为反向查询，2为服务器状态请求
    uint8_t aa: 1; // 1位，授权回答标志
    uint8_t tc: 1; // 1位，可截断标志，表示响应已超过512字节
    uint8_t rd: 1; // 1位，期望递归标志，表示期望服务器递归查询
    uint8_t ra: 1; // 1位，支持递归标志，表示服务器支持递归查询
    uint8_t z: 3; // 3位，保留值，必须为0
    uint8_t rcode: 4; // 4位，响应码，0表示没有差错，3表示名字差错
    uint16_t qdcount; // 16位，问题计数，表示报文中的问题数
    uint16_t ancount; // 16位，回答计数，表示报文中的回答数
    uint16_t nscount; // 16位，授权计数，表示报文中的授权资源记录数
    uint16_t arcount; // 16位，附加计数，表示报文中的附加资源记录数
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
