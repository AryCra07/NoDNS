/**
 * @file dns_log.h
 * @brief 日志模块
 * @details 本文件定义了日志模块的接口，定义了四个日志模式
 */

#ifndef GODNS_DNS_LOG_H
#define GODNS_DNS_LOG_H

#include <stdio.h>

#include "dns_config.h"

extern FILE * log_file;

// 输出 debug，可通过--log_mask=1开启
#define log_debug(args...) \
    if (LOG_MASK & 1) \
    { \
        if (log_file != stderr) \
            fprintf(log_file, "[DEBUG] %s:%d ", __FILE__, __LINE__); \
        else \
            fprintf(log_file, "\x1b[37m[DEBUG]\x1b[36m %s:%d \x1b[0m", __FILE__, __LINE__); \
        fprintf(log_file, args); \
        fprintf(log_file, "\n"); \
    }

// 输出 info，可通过--log_mask=2开启
#define log_info(args...) \
    if (LOG_MASK & 2) \
    { \
        if (log_file != stderr) \
            fprintf(log_file, "[INFO ] %s:%d ", __FILE__, __LINE__); \
        else \
            fprintf(log_file, "\x1b[34m[INFO ]\x1b[36m %s:%d \x1b[0m", __FILE__, __LINE__); \
        fprintf(log_file, args); \
        fprintf(log_file, "\n"); \
    }

// 输出 error，可通过--log_mask=4开启
#define log_error(args...) \
    if (LOG_MASK & 4) \
    { \
        if (log_file != stderr) \
            fprintf(log_file, "[ERROR] %s:%d ", __FILE__, __LINE__); \
        else \
            fprintf(log_file, "\x1b[33m[ERROR]\x1b[36m %s:%d \x1b[0m", __FILE__, __LINE__); \
        fprintf(log_file, args); \
        fprintf(log_file, "\n"); \
    }

// 输出 fatal，可通过--log_mask=8开启
#define log_fatal(args...) \
    if (LOG_MASK & 8) \
    { \
        if (log_file != stderr) \
            fprintf(log_file, "[FATAL] %s:%d ", __FILE__, __LINE__); \
        else \
            fprintf(log_file, "\x1b[31m[FATAL]\x1b[36m %s:%d \x1b[0m", __FILE__, __LINE__); \
        fprintf(log_file, args); \
        fprintf(log_file, "\n"); \
        exit(EXIT_FAILURE); \
    }


#endif //GODNS_DNS_LOG_H
