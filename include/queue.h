/**
 * @file queue.h
 * @brief 循环队列
 * @details 循环队列用于管理DNS查询报文的序号，防止序号重复
 */
#ifndef GODNS_QUEUE_H
#define GODNS_QUEUE_H

#include <stdint.h>

#define QUEUE_MAX_SIZE 65536

// 循环队列
typedef struct queue {
    uint16_t q[QUEUE_MAX_SIZE]; // 队列
    unsigned short head; // 队列头
    unsigned short tail; // 队列尾

    /**
     * @brief 将值加入队尾
     *
     * @param queue 队列
     * @param num 加入队列的值
     */
    void (*push)(struct queue *queue, uint16_t num);

    /**
     * @brief 队首出队
     *
     * @param queue 队列
     * @return 队首的值
     */
    uint16_t (*pop)(struct queue *queue);

    /**
     * @brief 销毁队列
     *
     * @param queue 队列
     */
    void (*destroy)(struct queue *queue);
} Queue;

/**
 * @brief 创建队列
 *
 * @return 新的队列
 */
Queue *new_queue();

#endif //GODNS_QUEUE_H
