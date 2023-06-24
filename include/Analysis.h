#ifndef Analysis_h
#define Analysis_h
#include "Packet.h"
//报文解析头文件

/**
 * @brief DNS报文字节流转换到结构体
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @note 为Header Section、Question Section和Resource Record分配了空间
 */
extern void BufferToPacket(DNSPacket* dnsPacket,char* buffer);

/**
 * @brief DNS报文结构体转换到字节流
 *
 * @param pmsg DNS报文结构体
 * @param pstring DNS报文字节流
 * @return 报文字节流的长度
 */
extern unsigned PacketToBuffer(DNSPacket* dnsPacket, char* buffer);

/**
 * @brief 释放DNS报文RR结构体的空间
 *
 * @param prr DNS报文RR结构体
 */
extern void DestroyRR(DNSPacketRR* dnsRR);
extern void DestroyQD(DNSPacketQD* dnsQD);
/**
 * @brief 释放DNS报文结构体的空间
 *
 * @param pmsg DNS报文结构体
 */
void DestroyPacket(DNSPacket* dnsP);

/**
 * @brief 复制DNS报文RR结构体
 *
 * @param src 源RR结构体
 * @return 复制后的RR结构体
 * @note 为新的RR结构体分配了空间
 */
extern DNSPacketRR * CopyRR(DNSPacketRR* dnsRR);
extern DNSPacketQD * CopyQD(DNSPacketQD* dnsQD);
/**
 * @brief 复制DNS报文结构体
 *
 * @param src 源结构体
 * @return 复制后的结构体
 * @note 为新的结构体分配了空间
 */
extern DNSPacket* CopyPacket(DNSPacket* src);

#endif // !Analysis_h
