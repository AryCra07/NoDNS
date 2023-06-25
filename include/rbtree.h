/**
 * @file rbtree.h
 * @brief 红黑树
 * @details 本文件中定义了一个红黑树，用于缓存DNS查询的结果，定义了插入、查询、删除的接口。
 */

#ifndef GODNS_RBTREE_H
#define GODNS_RBTREE_H

#include <time.h>

#include "dns_structure.h"

// 红黑树节点的颜色
typedef enum {
    BLACK, RED
} Color;

// 红黑树节点链表的节点的值，对应一个特定查询的答案
typedef struct rbtree_value {
    DNSResourceRecord *rr; // 指向一个Dns_RR的链表
    uint16_t ancount; // RR链表中Answer Section的数目
    uint16_t nscount; // RR链表中Authority Section的数目
    uint16_t arcount; // RR链表中Addition Section的数目
    uint8_t type; // RR对应的Question的类型
} RBTreeValue;

// 红黑树节点链表
typedef struct dns_rr_linklist {
    RBTreeValue *value; // 指向当前链表节点的值
    time_t expire_time; // 过期的时刻
    struct dns_rr_linklist *next; // 链表的下一个节点

    /**
     * @brief 向链表中插入结点
     * @param list 当前节点
     * @param new_list_node 新节点
     */
    void (*insert)(struct dns_rr_linklist *list, struct dns_rr_linklist *new_list_node);

    /**
     * @brief 删除链表中当前节点的下一个结点
     *
     * @param list 当前节点
     * @note list不能是链表的尾节点
     */
    void (*delete_next)(struct dns_rr_linklist *list);

    /**
     * @brief 在链表中查找特定的值
     *
     * @param list 链表起始节点
     * @param qname NAME字段
     * @param qtype type字段
     * @return 如果查找到节点，返回该节点在链表中的前驱，否则返回NULL
     */
    struct dns_rr_linklist *(*query_next)(struct dns_rr_linklist *list, const uint8_t *qname, const uint16_t qtype);
} DNSRRLinkList;

// 红黑树的节点
typedef struct rbtree_node {
    unsigned int key; // 红黑树节点的键
    DNSRRLinkList *rr_list; // 指向当前节点对应的链表
    Color color; // 当前节点的颜色
    struct rbtree_node *left; // 指向当前节点的左子节点
    struct rbtree_node *right; // 指向当前节点的右子节点
    struct rbtree_node *parent; // 指向当前节点的父亲节点
} RBTreeNode;

// 红黑树
typedef struct rbtree {
    RBTreeNode *root; // 指向红黑树的根节点

    /**
     * @brief 向红黑树中插入键-值对
     *
     * @param tree 红黑树
     * @param key 键
     * @param list 值
     *
     * 此函数从根节点开始迭代查找插入位置，如果该键对应的节点不存在，则创建一个新节点，并且维护树的平衡；否则在原有节点的链表上插入新元素。
     */
    void (*insert)(struct rbtree *tree, unsigned int key, DNSRRLinkList *list);

    /**
     * @brief 在红黑树中查找键对应的值
     *
     * @param tree 红黑树
     * @param data 键
     * @return 如果找到了对应的值，返回一个没有头节点的链表；否则返回NULL
     *
     * 此函数查找给定键的节点，如果该节点存在，则删去节点链表中已经超时的部分，此时若链表不为空，则返回该链表；否则删除该节点并返回NULL。
     */
    DNSRRLinkList *(*query)(struct rbtree *tree, unsigned int data);
} RBTree;

/**
 * @brief 创建链表节点
 *
 * @return 新的链表节点
 */
DNSRRLinkList *new_linklist();

/**
 * @brief 创建红黑树
 *
 * @return 新的红黑树
 */
RBTree *new_rbtree();

#endif //GODNS_RBTREE_H
