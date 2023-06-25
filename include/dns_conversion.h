//
// Created by 沈原灏 on 2023-06-25.
//

#ifndef GODNS_DNS_CONVERSION_H
#define GODNS_DNS_CONVERSION_H

#include "dns_structure.h"

/**
 * @brief DNS报文字节流转换到结构体
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @note 为Header Section、Question Section和Resource Record分配了空间
 */
void string_to_dnsmsg(DNSMessage * pmsg, const char * pstring);

/**
 * @brief DNS报文结构体转换到字节流
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @return 报文字节流的长度
 */
unsigned dnsmsg_to_string(const DNSMessage * pmsg, char * pstring);

/**
 * @brief 释放DNS报文RR结构体的空间
 *
 * @param prr DNS报文RR结构体
 */
void destroy_dnsrr(DNSResourceRecord * prr);

/**
 * @brief 释放DNS报文结构体的空间
 *
 * @param pmsg DNS报文结构体
 */
void destroy_dnsmsg(DNSMessage * pmsg);

/**
 * @brief 复制DNS报文RR结构体
 *
 * @param src 源RR结构体
 * @return 复制后的RR结构体
 * @note 为新的RR结构体分配了空间
 */
DNSResourceRecord * copy_dnsrr(const DNSResourceRecord * src);

/**
 * @brief 复制DNS报文结构体
 *
 * @param src 源结构体
 * @return 复制后的结构体
 * @note 为新的结构体分配了空间
 */
DNSMessage * copy_dnsmsg(const DNSMessage * src);

#endif //GODNS_DNS_CONVERSION_H
