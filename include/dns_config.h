//
// Created by 沈原灏 on 2023-06-24.
//

#ifndef GODNS_DNS_CONFIG_H
#define GODNS_DNS_CONFIG_H

extern char * REMOTE_HOST;
extern int CLIENT_PORT;
extern char LOG_MODE;
extern char * LOG_PATH;
extern char * HOSTS_PATH;

void initDNSConfig(int argc, char * const * argv);

#endif //GODNS_DNS_CONFIG_H
