/**
 * @file     analysis.h
 * @brief    DNS报文解析与构造的接口定义文件，包括字节流转换到结构体、结构体转换到字节流、释放结构体空间、复制结构体等功能
 */
#ifndef analysis_h
#define analysis_h
#include "dns_structure.h"

/**
 * @brief DNS报文字节流转换到结构体
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @note 为Header Section、Question Section和Resource Record分配了空间
 */
extern void BufferToPacket(DNSMessage * dnsMessage,char* buffer);

/**
 * @brief DNS报文结构体转换到字节流
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @return 报文字节流的长度
 */
extern unsigned PacketToBuffer(DNSMessage * dnsMessage, char* buffer);

/**
 * @brief 释放DNS报文RR结构体的空间
 *
 * @param prr DNS报文RR结构体
 */
extern void DestroyRR(DNSResourceRecord * dnsRR);
extern void DestroyQD(DNSQuestion * dnsQD);
/**
 * @brief 释放DNS报文结构体的空间
 *
 * @param pmsg DNS报文结构体
 */
void DestroyPacket(DNSMessage * dnsP);

/**
 * @brief 复制DNS报文RR结构体
 *
 * @param src 源RR结构体
 * @return 复制后的RR结构体
 * @note 为新的RR结构体分配了空间
 */
extern DNSResourceRecord * CopyRR(DNSResourceRecord * dnsRR);
extern DNSQuestion * CopyQD(DNSQuestion * dnsQD);
/**
 * @brief 复制DNS报文结构体
 *
 * @param src 源结构体
 * @return 复制后的结构体
 * @note 为新的结构体分配了空间
 */
extern DNSMessage * CopyPacket(DNSMessage * src);

#endif // analysis_h
