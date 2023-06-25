//
// Created by 沈原灏 on 2023-06-24.
//

#ifndef GODNS_DNS_PRINT_H
#define GODNS_DNS_PRINT_H

#include "dns_structure.h"

/**
 * @brief 打印DNS报文字节流
 *
 * @param pstring DNS报文字节流
 * @param len 字节流长度
 */
void print_dns_string(const char * pstring, unsigned int len);

/**
 * @brief 打印DNS报文结构体
 *
 * @param pmsg DNS报文结构体
 */
void print_dns_message(const DNSMessage * pmsg);


#endif //GODNS_DNS_PRINT_H
