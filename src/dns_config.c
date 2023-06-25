/**
 * @file      config_jar.c
 * @brief     命令行参数解析
 * @author    Ziheng Mao
 * @date      2021/5/29
 * @copyright GNU General Public License, version 3 (GPL-3.0)
 *
 * 本文件中实现了命令行参数解析函数。
*/

#include "../include/dns_config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

#include "../include/dns_log.h"

char * REMOTE_HOST = "10.3.9.44";
int LOG_MASK = 15;
int CLIENT_PORT = 0;
char * HOSTS_PATH = "../hosts.txt";
char * LOG_PATH = NULL;

void init_config(int argc, char * const * argv)
{
    argc--;
    argv++;
    if (argc == 1 && strcmp(*argv, "--help") == 0)
    {
        //TODO: help
        exit(0);
    }
    int i = 0;
    while (i < argc)
    {
        char * field = argv[i];
        if (field[0] != '-' && field[1] != '-')log_fatal("命令行参数有误，参数标志必须以--开头")
        field += 2;
        if (i + 1 == argc)log_fatal("命令行参数有误，缺少参数值")
        if (strcmp(field, "remote_host") == 0)
        {
            char * dest = (char *) malloc(5 * sizeof(char));
            if (!dest)log_fatal("分配内存失败")
            if (uv_inet_pton(AF_INET, argv[i + 1], dest))log_fatal("命令行参数有误，输入了不合法的IP地址")
            free(dest);
            REMOTE_HOST = argv[i + 1];
            i += 2;
        }
        else if (strcmp(field, "log_mask") == 0)
        {
            int mask = strtol(argv[i + 1], NULL, 10);
            if (mask < 0 || mask > 15)log_fatal("命令行参数有误，mask必须是0-15的整数")
            LOG_MASK = mask;
            i += 2;
        }
        else if (strcmp(field, "client_port") == 0)
        {
            int port = strtol(argv[i + 1], NULL, 10);
            if (port < 1024 || port > 65535)log_fatal("命令行参数有误，端口必须是1024-65535的整数")
            CLIENT_PORT = port;
            i += 2;
        }
        else if (strcmp(field, "hosts_path") == 0)
        {
            HOSTS_PATH = argv[i + 1];
            i += 2;
        }
        else if (strcmp(field, "log_path") == 0)
        {
            LOG_PATH = argv[i + 1];
            i += 2;
        }
        else log_fatal("命令行参数有误，不合法的参数标志")
    }
}
