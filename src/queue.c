/**
 * @file      queue.c
 * @brief     队列
 * @details   本文件的内容是队列的实现。
*/

#include "../include/queue.h"

#include <stdlib.h>

#include "../include/dns_log.h"

static void queue_push(Queue *queue, uint16_t num) {
    queue->q[++queue->tail] = num;
}

static uint16_t queue_pop(Queue *queue) {
    return queue->q[queue->head++];
}

static void queue_destroy(Queue *queue) {
    free(queue);
}

Queue *new_queue() {
    Queue *queue = (Queue *) calloc(1, sizeof(Queue));
    if (!queue)
        log_fatal("内存分配错误")
    queue->head = 0;
    queue->tail = QUEUE_MAX_SIZE - 1;

    queue->push = &queue_push;
    queue->pop = &queue_pop;
    queue->destroy = &queue_destroy;
    return queue;
}
