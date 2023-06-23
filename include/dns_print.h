//
// Created by 沈原灏 on 2023-06-24.
//

#ifndef GODNS_DNS_PRINT_H
#define GODNS_DNS_PRINT_H

#include "dns_structure.h"

void printDNSBytes(const char *ptr, unsigned int len);

void printDNSMessage(const DNSMessage *msg);

#endif //GODNS_DNS_PRINT_H
