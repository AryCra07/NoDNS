/**
 * @file      dns_server.h
 * @brief     DNS服务端
 * @details 本文件定义了DNS服务器的接口，包括服务器初始化函数、向本地发送回复的函数
 *          DNS服务器通过server_socket与本地53端口通信，将收到的DNS查询报文加入查询池，查询池通过调用接口将回复报文发送到本地。
*/

#ifndef GODNS_DNS_SERVER_H
#define GODNS_DNS_SERVER_H

#include <uv.h>

#include "dns_structure.h"

/**
 * @brief 服务端初始化
 *
 * @param loop 事件循环
 */
void init_server(uv_loop_t * loop);

/**
 * @brief 将DNS回复报文发送至本地
 *
 * @param addr 本地地址
 * @param msg DNS回复报文
 */
void send_to_local(const struct sockaddr * addr, const DNSMessage * msg);


#endif //GODNS_DNS_SERVER_H
