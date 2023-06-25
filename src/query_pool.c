/**
 * @file      query_pool.c
 * @brief     查询池
 * @details   本文件的内容是查询池的实现，用于管理查询请求，包括查询请求的发送、接收、超时等操作
*/

#include "../include/query_pool.h"

#include <stdlib.h>

#include "../include/dns_log.h"
#include "../include/dns_conversion.h"
#include "../include/dns_client.h"
#include "../include/dns_server.h"

/**
 * @brief 超时回调函数
 * @param timer 超时的计时器
 */
static void timeout_cb(uv_timer_t *timer) {
    log_info("超时")
    uv_timer_stop(timer);
    Query_Pool *qpool = *(Query_Pool **) (timer->data + sizeof(uint16_t));
    qpool->delete(qpool, *(uint16_t *) timer->data);
}

// 检查查询池是否已满
static bool qpool_full(Query_Pool *this) {
    return this->count == QUERY_POOL_MAX_SIZE;
}

// 向查询池中插入查询请求
static void qpool_insert(Query_Pool *qpool, const struct sockaddr *addr, const DNSMessage *msg) {
    log_debug("添加新查询请求")
    // 为新的查询请求分配内存并初始化
    Dns_Query *query = (Dns_Query *) calloc(1, sizeof(Dns_Query));
    if (!query)
        log_fatal("内存分配错误")
    uint16_t id = qpool->queue->pop(qpool->queue);
    qpool->pool[id % QUERY_POOL_MAX_SIZE] = query;
    qpool->count++;

    query->id = id;
    query->prev_id = msg->header->id;
    query->addr = *addr;
    query->msg = copy_dnsmsg(msg);

    // 在cache中查询
    RBTreeValue *value = qpool->cache->query(qpool->cache, query->msg->que);
    if (value != NULL) { // cache命中
        query->msg->header->qr = DNS_QR_ANSWER; // 设置为响应报文
        if (query->msg->header->rd == 1)query->msg->header->ra = 1; // 如果原报文rd为1，则设置ra为1
        query->msg->header->ancount = value->ancount;
        query->msg->header->nscount = value->nscount;
        query->msg->header->arcount = value->arcount;
        query->msg->rr = value->rr;

        // 污染屏蔽
        if (value->rr->type == 255 && (*(int *) value->rr->rdata) == 0) {
            query->msg->header->rcode = DNS_RCODE_NXDOMAIN;
            destroy_dnsrr(query->msg->rr);
            query->msg->rr = NULL;
            query->msg->header->ancount = 0;
        }

        send_to_local(addr, query->msg);
        free(value);
        qpool->delete(qpool, query->id);
    } else { // cache未命中，交给远程服务器
        if (qpool->ipool->full(qpool->ipool)) {
            log_error("序号池满")
            qpool->delete(qpool, id);
            return;
        }
        Index *index = (Index *) calloc(1, sizeof(Index));
        if (!index)
            log_fatal("内存分配错误")
        index->id = qpool->ipool->insert(qpool->ipool, index);
        index->prev_id = id;
        query->msg->header->id = index->id;

        uv_timer_init(qpool->loop, &query->timer);
        query->timer.data = malloc(sizeof(uint16_t) + sizeof(Query_Pool *));
        if (!query->timer.data)
            log_fatal("内存分配错误")
        *(uint16_t *) query->timer.data = query->id;
        *(Query_Pool **) (query->timer.data + sizeof(uint16_t)) = qpool;
        uv_timer_start(&query->timer, timeout_cb, 5000, 5000);
        send_to_remote(query->msg);
    }
}

// 根据id处理查询请求
static bool qpool_query(Query_Pool *qpool, uint16_t id) {
    return qpool->pool[id % QUERY_POOL_MAX_SIZE] != NULL && qpool->pool[id % QUERY_POOL_MAX_SIZE]->id == id;
}

// 处理完成的查询请求，收到响应 | 发生错误
static void qpool_finish(Query_Pool *qpool, const DNSMessage *msg) {
    uint16_t uid = msg->header->id;
    if (!qpool->ipool->query(qpool->ipool, uid)) {
        log_error("序号池中不存在此序号")
        return;
    }
    Index *index = qpool->ipool->delete(qpool->ipool, uid); // 从序号池中删除
    if (qpool_query(qpool, index->prev_id)) { // 如果查询池中存在此查询请求
        Dns_Query *query = qpool->pool[index->prev_id % QUERY_POOL_MAX_SIZE];
        log_debug("结束查询 ID: 0x%04x", query->id)

        if (strcmp(msg->que->qname, query->msg->que->qname) == 0) { // 如果查询报文的域名与响应报文的域名相同
            destroy_dnsmsg(query->msg); // 销毁查询报文
            query->msg = copy_dnsmsg(msg); // 将响应报文复制到查询报文中
            query->msg->header->id = query->prev_id; // 设置响应报文的id为查询报文的id
            if (msg->header->rcode == DNS_RCODE_OK &&
                (msg->que->qtype == DNS_TYPE_A || msg->que->qtype == DNS_TYPE_CNAME ||
                 msg->que->qtype == DNS_TYPE_AAAA))  // 如果响应报文的rcode为0且查询报文的qtype为A、CNAME或AAAA
                qpool->cache->insert(qpool->cache, msg); // 将响应报文插入cache
            send_to_local(&query->addr, query->msg); // 发送响应报文
        }
        qpool->delete(qpool, query->id);
    }
    free(index);
}

// 从查询池中删除查询请求
static void qpool_delete(Query_Pool *qpool, uint16_t id) {
    if (!qpool_query(qpool, id)) {
        log_error("查询池中不存在此序号")
        return;
    }
    log_debug("删除查询 ID: 0x%04x", id)
    Dns_Query *query = qpool->pool[id % QUERY_POOL_MAX_SIZE]; // 获取查询请求
    qpool->queue->push(qpool->queue, id + QUERY_POOL_MAX_SIZE); // 将id放回序号池
    qpool->pool[id % QUERY_POOL_MAX_SIZE] = NULL; // 将查询池中的查询请求置空
    qpool->count--; // 查询池中的查询请求数量减一
    uv_timer_stop(&query->timer); // 停止定时器
    destroy_dnsmsg(query->msg); // 销毁查询报文
    free(query->timer.data); // 释放定时器数据
    free(query); // 释放查询请求
}

Query_Pool *new_qpool(uv_loop_t *loop, Cache *cache) {
    log_info("初始化查询池")
    Query_Pool *qpool = (Query_Pool *) calloc(1, sizeof(Query_Pool));
    if (!qpool)
        log_fatal("内存分配错误")
    qpool->count = 0;
    qpool->queue = new_queue();
    for (uint16_t i = 0; i < QUERY_POOL_MAX_SIZE; ++i)
        qpool->queue->push(qpool->queue, i);
    qpool->ipool = new_ipool();
    qpool->loop = loop;
    qpool->cache = cache;

    qpool->full = &qpool_full;
    qpool->insert = &qpool_insert;
    qpool->delete = &qpool_delete;
    qpool->finish = &qpool_finish;
    return qpool;
}
