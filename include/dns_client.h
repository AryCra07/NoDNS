//
// Created by 沈原灏 on 2023-06-25.
//

#ifndef GODNS_DNS_CLIENT_H
#define GODNS_DNS_CLIENT_H

#include <uv.h>

#include "dns_structure.h"

/**
 * @brief 客户端初始化
 * @param loop 事件循环
 */
void init_client(uv_loop_t * loop);

/**
 * @brief 将DNS请求报文发送至远程
 *
 * @param msg DNS请求报文
 */
void send_to_remote(const DNSMessage * msg);

#endif //GODNS_DNS_CLIENT_H
