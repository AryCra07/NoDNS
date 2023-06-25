/**
 * @file dns_server.c
 * @brief DNS服务端
 * @details 实现DNS服务端，包括初始化服务器、处理接收报文和发送报文
*/

#include "../include/dns_server.h"

#include <stdlib.h>

#include "../include/dns_log.h"
#include "../include/dns_conversion.h"
#include "../include/dns_print.h"
#include "../include/query_pool.h"

static uv_udp_t server_socket; // 服务端与本地通信的socket
static struct sockaddr_in recv_addr; // 服务端收取DNS查询报文的地址
extern Query_Pool *qpool; // 查询池

/**
 * @brief 为缓冲区分配空间
 * @param handle 分配句柄
 * @param suggested_size 期望缓冲区大小
 * @param buf 缓冲区
 * @details 分配大小固定为DNS_STRING_MAX_SIZE的缓冲区，用于从本地接收DNS查询报文
 */
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
    if (!buf->base)
        log_fatal("内存分配错误")
    buf->len = DNS_STRING_MAX_SIZE;
}

/**
 * @brief 向本地发送回复报文的回调函数
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

/**
 * @brief 从本地接收查询报文的回调函数
 * @param handle 查询句柄
 * @param nread 收到报文的字节数
 * @param buf 缓冲区，存放收到的报文
 * @param addr 本地发送方的地址
 * @param flags 标志
 */
static void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread < 0) {
        if (buf->base)
            free(buf->base);
        log_debug("传输错误")
        return;
    }
    if (nread == 0) {
        if (buf->base)
            free(buf->base);
        return;
    }
    log_debug("收到本地DNS查询报文")
    print_dns_string(buf->base, nread);
    DNSMessage *msg = (DNSMessage *) calloc(1, sizeof(DNSMessage));
    if (!msg)
        log_fatal("内存分配错误")
    string_to_dnsmsg(msg, buf->base); // 将字节序列转化为结构体
    print_dns_message(msg);

    if (qpool->full(qpool)) {
        log_error("查询池满")
    } else
        qpool->insert(qpool, addr, msg); // 将DNS查询加入查询池
    destroy_dnsmsg(msg);
    if (buf->base)
        free(buf->base);
}

void init_server(uv_loop_t *loop) {
    log_info("启动server")
    uv_udp_init(loop, &server_socket); // 将server_docket绑定到事件循环
    uv_ip4_addr("0.0.0.0", 53, &recv_addr); // 初始化recv_addr为0.0.0.0:53，能够接收所有本地发送到53端口的报文
    uv_udp_bind(&server_socket, (struct sockaddr *) &recv_addr, UV_UDP_REUSEADDR); // 启用端口复用，允许多个进程监听同一端口
    uv_udp_recv_start(&server_socket, alloc_buffer, on_read); // 当收到DNS查询报文时，分配缓冲区并调用回调函数
}

/**
 * @brief 向本地发送回复报文
 * @param addr 本地地址
 * @param msg DNS回复报文
 */
void send_to_local(const struct sockaddr *addr, const DNSMessage *msg) {
    log_info("发送DNS回复报文到本地")
    print_dns_message(msg);
    char *str = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char)); // 将DNS结构体转化成字节流
    if (!str)
        log_fatal("内存分配错误")
    unsigned int len = dnsmsg_to_string(msg, str);
    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
    if (!req)
        log_fatal("内存分配错误")

    uv_buf_t send_buf = uv_buf_init((char *) malloc(len), len);
    memcpy(send_buf.base, str, len); // 将字节序列存入发送缓冲区中
    req->data = (char **) malloc(sizeof(char **));
    *(char **) (req->data) = send_buf.base;
    print_dns_string(send_buf.base, len);

    uv_udp_send(req, &server_socket, &send_buf, 1, addr, on_send); // 发送回复报文
    free(str);
}