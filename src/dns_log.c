//
// Created by 沈原灏 on 2023-06-24.
//
#include "../include/dns_log.h"

#include <stdlib.h>
#include <stdarg.h>

void logDebug(const char *format, ...) {
    if (LOG_MODE & 1) {
        if (logFile != stderr)
            fprintf(logFile, "[DEBUG] %s:%d ", __FILE__, __LINE__);
        else
            fprintf(logFile, "%s[DEBUG ]%s %s:%d %s", COLOR_GREEN, COLOR_CYAN, __FILE__, __LINE__, COLOR_RESET);

        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);

        fprintf(logFile, "\n");
    }
}

void logInfo(const char *format, ...) {
    if (LOG_MODE & 2) {
        if (logFile != stderr)
            fprintf(logFile, "[INFO ] %s:%d ", __FILE__, __LINE__);
        else
            fprintf(logFile, "%s[INFO ]%s %s:%d %s", COLOR_BLUE, COLOR_CYAN, __FILE__, __LINE__, COLOR_RESET);

        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);

        fprintf(logFile, "\n");
    }
}

void logError(const char *format, ...) {
    if (LOG_MODE & 4) {
        if (logFile != stderr)
            fprintf(logFile, "[ERROR] %s:%d ", __FILE__, __LINE__);
        else
            fprintf(logFile, "%s[ERROR ]%s %s:%d %s", COLOR_YELLOW, COLOR_CYAN, __FILE__, __LINE__, COLOR_RESET);

        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);

        fprintf(logFile, "\n");
    }
}

void logFatal(const char *format, ...) {
    if (LOG_MODE & 8) {
        if (logFile != stderr)
            fprintf(logFile, "[FATAL] %s:%d ", __FILE__, __LINE__);
        else
            fprintf(logFile, "%s[FATAL ]%s %s:%d %s", COLOR_RED, COLOR_CYAN, __FILE__, __LINE__, COLOR_RESET);

        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);

        fprintf(logFile, "\n");
        exit(EXIT_FAILURE);
    }
}