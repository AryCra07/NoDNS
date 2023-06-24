/**
 * @file dns_log.h
 * @brief 日志模块
 * @details 本文件定义了日志模块的接口，包括日志的打印和日志文件的初始化
 */

#ifndef GODNS_DNS_LOG_H
#define GODNS_DNS_LOG_H

#include <stdio.h>
#include "dns_structure.h"
#include "dns_config.h"

#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"

extern FILE *logFile;

void logDebug(const char *format, ...);
void logInfo(const char *format, ...);
void logError(const char *format, ...);
void logFatal(const char *format, ...);

#endif //GODNS_DNS_LOG_H
