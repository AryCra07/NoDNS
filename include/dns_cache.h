/**
 * @file dns_cache.h
 * @brief DNS缓存
 * @details 本文件的内容是DNS缓存的实现。
 */

#ifndef GODNS_DNS_CACHE_H
#define GODNS_DNS_CACHE_H

#include <stdio.h>

#include "rbtree.h"

#define CACHE_SIZE 300

// 缓存结构体
typedef struct cache {
    DNSRRLinkList *head; // LRU头结点
    DNSRRLinkList *tail;
    int size;
    RBTree *tree; // 红黑树

    /**
     * @brief 向缓存中插入DNS回复
     * @param cache 缓存
     * @param msg DNS回复报文
     */
    void (*insert)(struct cache *cache, const DNSMessage *msg);

    /**
     * @brief 在缓存中查询
     * @param cache 缓存
     * @param que DNS Question Section
     * @return 如果查询到回复，则返回，否则返回NULL
     */
    RBTreeValue *(*query)(struct cache *cache, const DNSQuestion *que);
} Cache;

/**
 * @brief 创建缓存
 * @param hosts_file hosts文件路径
 * @return 新的缓存结构体
 */
Cache *new_cache(FILE *hosts_file);


#endif //GODNS_DNS_CACHE_H