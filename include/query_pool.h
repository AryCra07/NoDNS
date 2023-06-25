/**
 * @file query_pool.h
 * @brief 查询池
 * @details 本文件的内容是查询池的实现，用于管理查询请求，包括查询请求的发送、接收、超时等操作
 */

#ifndef GODNS_QUERY_POOL_H
#define GODNS_QUERY_POOL_H

#include <stdbool.h>
#include <uv.h>

#include "dns_structure.h"
#include "index_pool.h"
#include "dns_cache.h"

#define QUERY_POOL_MAX_SIZE 256

// DNS查询结构体
typedef struct dns_query {
    uint16_t id; // 查询ID
    uint16_t prev_id; // 原本DNS查询报文的ID
    struct sockaddr addr; // 请求方地址
    DNSMessage *msg; // DNS查询报文报文
    uv_timer_t timer; // 计时器
} Dns_Query;

// DNS查询池
typedef struct query_pool {
    Dns_Query *pool[QUERY_POOL_MAX_SIZE]; // 查询池
    unsigned short count; // 池内查询数量
    Queue *queue; // 未分配的查询ID的队列
    Index_Pool *ipool; // 序号池
    uv_loop_t *loop; // 事件循环
    Cache *cache; // 缓存

    /**
     * @brief 判断查询池是否已满
     *
     * @param qpool 查询池
     * @return 如果查询池已满，返回true
     */
    bool (*full)(struct query_pool *qpool);

    /**
     * @brief 向查询池中加入新查询
     *
     * @param qpool 查询池
     * @param addr 请求方地址
     * @param msg 查询报文
     */
    void (*insert)(struct query_pool *qpool, const struct sockaddr *addr, const DNSMessage *msg);

    /**
     * @brief 结束查询
     *
     * @param qpool 查询池
     * @param msg 查询报文
     */
    void (*finish)(struct query_pool *qpool, const DNSMessage *msg);

    /**
     * @brief 删除查询
     *
     * @param qpool 查询池
     * @param id 待删除的查询ID
     */
    void (*delete)(struct query_pool *qpool, uint16_t id);
} Query_Pool;

/**
 * @brief 创建查询池
 *
 * @param loop 事件循环
 * @param cache 缓存
 * @return 新的查询池
 */
Query_Pool *new_qpool(uv_loop_t *loop, Cache *cache);

#endif //GODNS_QUERY_POOL_H
