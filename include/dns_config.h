/**
 *
 */
#ifndef GODNS_DNS_CONFIG_H
#define GODNS_DNS_CONFIG_H

extern char * REMOTE_HOST; ///< 远程DNS服务器地址
extern int LOG_MASK; ///< log打印等级，一个四位二进制数，从低位到高位依次表示DEBUG、INFO、ERROR、FATAL
extern int CLIENT_PORT; ///< 本地DNS客户端端口
extern char * HOSTS_PATH; ///< hosts文件路径
extern char * LOG_PATH; ///< 日志文件路径

/**
 * @brief 解析命令行参数
 *
 * @param argc 参数个数
 * @param argv 参数字符串的数组
 */
void init_config(int argc, char * const * argv);


#endif //GODNS_DNS_CONFIG_H
