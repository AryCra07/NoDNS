/**
 * @file      dns_client.c
 * @brief     DNS客户端
 * @details 本文件的内容是DNS 客户端的实现，用于发送 DNS 查询请求并接收服务器的回复报文
*/

#include "../include/dns_client.h"

#include <stdlib.h>

#include "../include/dns_log.h"
#include "../include/dns_conversion.h"
#include "../include/dns_print.h"
#include "../include/query_pool.h"

static uv_udp_t client_socket; // 客户端与远程通信的socket
static struct sockaddr_in local_addr; // 本地地址
static struct sockaddr send_addr; // 远程服务器地址
extern Query_Pool *qpool; // 查询池

/**
 * @brief 为缓冲区分配空间
 *
 * @param handle 分配句柄
 * @param suggested_size 期望缓冲区大小
 * @param buf 缓冲区
 *
 * 分配大小固定为DNS_STRING_MAX_SIZE的缓冲区，用于从远程接收DNS回复报文
 */
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
    if (!buf->base)
        log_fatal("内存分配错误")
    buf->len = DNS_STRING_MAX_SIZE;
}

/**
 * @brief 从远程接收回复报文的回调函数
 *
 * @param handle 查询句柄
 * @param nread 收到报文的字节数
 * @param buf 缓冲区，存放收到的报文
 * @param addr 发送方的地址
 * @param flags 标志
 */
static void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread < 0) { // 传输错误
        if (buf->base)
            free(buf->base);
        log_debug("传输错误")
        return;
    }
    if (nread == 0) { // 未接收到数据
        if (buf->base)
            free(buf->base);
        return;
    }
    log_info("从服务器接收到消息")
    print_dns_string(buf->base, nread);
    DNSMessage *msg = (DNSMessage *) calloc(1, sizeof(DNSMessage));
    if (!msg)
        log_fatal("内存分配错误")
    string_to_dnsmsg(msg, buf->base);
    print_dns_message(msg);
    qpool->finish(qpool, msg);
    destroy_dnsmsg(msg);
    if (buf->base)
        free(buf->base);
}

/**
 * @brief 向远程发送查询报文的回调函数
 *
 * @param req 发送句柄
 * @param status 发送状态
 */
static void on_send(uv_udp_send_t *req, int status) {
    free(*(char **) req->data);
    free(req->data);
    free(req);
    if (status)
        log_error("发送状态异常 %d", status)
}

void init_client(uv_loop_t *loop) {
    log_info("启动client")
    uv_udp_init(loop, &client_socket);
    // 设置本地地址，设置为 "0.0.0.0" 的作用是将客户端的 UDP socket 绑定到所有可用的网络接口上。
    uv_ip4_addr("0.0.0.0", CLIENT_PORT, &local_addr);
    // 绑定本地地址，启用端口复用，允许多个进程监听同一端口
    uv_udp_bind(&client_socket, (const struct sockaddr *) &local_addr, UV_UDP_REUSEADDR);
    uv_udp_set_broadcast(&client_socket, 1); // 允许发送广播
    uv_ip4_addr(REMOTE_HOST, 53, (struct sockaddr_in *) &send_addr); // 设置远程服务器地址
    uv_udp_recv_start(&client_socket, alloc_buffer, on_read); // 开始接收
}

/**
 * @brief 向远程发送报文
 *
 * @param msg
 */
void send_to_remote(const DNSMessage *msg) {
    char *str = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
    if (!str)
        log_fatal("内存分配错误")
    unsigned int len = dnsmsg_to_string(msg, str);

    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t)); // 分配发送句柄
    if (!req)
        log_fatal("内存分配错误")
    uv_buf_t send_buf = uv_buf_init((char *) malloc(len), len); // 分配发送缓冲区
    memcpy(send_buf.base, str, len); // 将报文拷贝到缓冲区
    req->data = (char **) malloc(sizeof(char **));
    *(char **) (req->data) = send_buf.base; // 将缓冲区的地址存入data

    log_info("向服务器发送消息")
    print_dns_message(msg);
    print_dns_string(send_buf.base, len);
    uv_udp_send(req, &client_socket, &send_buf, 1, &send_addr, on_send); // 发送报文
    free(str);
}