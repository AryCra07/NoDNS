/**
 * @file dns_structure.h
 * @brief DNS报文结构体定义
 * @details 定义DNS报文相关的结构体与常量
 * @date 2023-6-24
 */

#ifndef GODNS_DNS_STRUCTURE_H
#define GODNS_DNS_STRUCTURE_H

#include <stdint.h>

#include <stdint.h>

#define DNS_STRING_MAX_SIZE 8192
#define DNS_RR_NAME_MAX_SIZE 512

#define DNS_QR_QUERY 0
#define DNS_QR_ANSWER 1

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13
#define DNS_TYPE_MINFO 15
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

#define DNS_CLASS_IN 1

#define DNS_RCODE_OK 0
#define DNS_RCODE_NXDOMAIN 3

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

// DNS报文头部结构体
typedef struct dns_header {
    uint16_t id;
    uint8_t qr: 1;
    uint8_t opcode: 4;
    uint8_t aa: 1;
    uint8_t tc: 1;
    uint8_t rd: 1;
    uint8_t ra: 1;
    uint8_t z: 3;
    uint8_t rcode: 4;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;

/// 报文Question Section结构体，以链表表示
typedef struct dns_question {
    uint8_t *qname;
    uint16_t qtype;
    uint16_t qclass;
    struct dns_question *next;
} DNSQuestion;

/// 报文Resource Record结构体，以链表表示
typedef struct dns_rr {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
    struct dns_rr *next;
} DNSResourceRecord;

/// DNS报文结构体
typedef struct dns_msg {
    DNSHeader *header; ///< 指向Header Section
    DNSQuestion *que; ///< 指向Question Section链表的头节点
    DNSResourceRecord *rr; ///< 指向Resource Record链表的头节点
} DNSMessage;

#endif //GODNS_DNS_STRUCTURE_H
