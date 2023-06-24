//
// Created by 沈原灏 on 2023-06-24.
//
#include "../include/dns_print.h"

#include <stdio.h>
#include <string.h>

#include "../include/dns_log.h"

void printDNSBytes(const char *ptr, unsigned int len) {
    if (!(LOG_MODE & 1)) return;
    logDebug("DNS报文字节形式：");
    for (int i = 0; i < len; i++) {
        fprintf(logFile, "%02x ", (unsigned char) ptr[i]);
        if (i % 16 == 15) {
            fprintf(logFile, "\n");
        }
    }
    fprintf(logFile, "\n");
}

void printDNSMessage(const DNSMessage *msg) {

}