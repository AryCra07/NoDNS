/**
 * @file index_pool.c
 * @brief 序号池
 * @details 序号池用于管理DNS查询报文的序号，防止序号重复
*/

#include "../include/index_pool.h"

#include <stdlib.h>

#include "../include/dns_log.h"

// 检查序号池是否已满
static bool ipool_full(Index_Pool *ipool) {
    return ipool->count == INDEX_POOL_MAX_SIZE;
}

// 向序号池中插入序号
static uint16_t ipool_insert(Index_Pool *ipool, Index *req) {
    uint16_t id = ipool->queue->pop(ipool->queue);
    ipool->pool[id] = req;
    ipool->count++;
    return id;
}

// 查询序号是否在序号池中
static bool ipool_query(Index_Pool *ipool, uint16_t index) {
    return ipool->pool[index] != NULL;
}

// 从序号池中删除序号
static Index *ipool_delete(Index_Pool *ipool, uint16_t index) {
    Index *req = ipool->pool[index];
    ipool->queue->push(ipool->queue, index);
    ipool->pool[index] = NULL;
    ipool->count--;
    return req;
}

// 销毁序号池
static void ipool_destroy(Index_Pool *ipool) {
    ipool->queue->destroy(ipool->queue);
    free(ipool);
}

// 创建序号池
Index_Pool *new_ipool() {
    Index_Pool *ipool = (Index_Pool *) calloc(1, sizeof(Index_Pool));
    if (!ipool)
        log_fatal("内存分配错误")
    ipool->count = 0;
    ipool->queue = new_queue();
    // 初始化序号池
    for (uint16_t i = 0; i < INDEX_POOL_MAX_SIZE; ++i)
        ipool->queue->push(ipool->queue, i);
    ipool->full = &ipool_full;
    ipool->insert = &ipool_insert;
    ipool->query = &ipool_query;
    ipool->delete = &ipool_delete;
    ipool->destroy = &ipool_destroy;
    return ipool;
}