#include "Analysis.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
//#include <WinSock2.h>
#include <winsock2.h>
#pragma comment(lib,"wsock32.lib")
/**
 * @brief 从字节流中读入一个大端法表示的16位数字
 *
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @return 从(pstring + *offset)开始的16位数字
 * @note 读入后，偏移量增加2
 */
static uint16_t Read2B(char* ptr, unsigned* offset)
{
    uint16_t ret = ntohs(*(uint16_t*)(ptr + *offset));
    *offset += 2;
    return ret;
}

/**
 * @brief 从字节流中读入一个大端法表示的32位数字
 *
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @return 从(pstring + *offset)开始的32位数字
 * @note 读入后，偏移量增加4
 */
static uint32_t Read4B(char* ptr, unsigned* offset)
{
    uint32_t ret = ntohl(*(uint32_t*)(ptr + *offset));
    *offset += 4;
    return ret;
}

/**
 * @brief 从字节流中读入一个NAME字段
 *
 * @param pname NAME字段
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @return NAME字段总长度
 * @note 读入后，偏移量增加到NAME字段后一个位置
 */
static unsigned BufferToName(uint8_t* namePtr, char* ptr, unsigned* offset)
{
    unsigned start_offset = *offset;
    while (true)
    {
        if ((*(ptr + *offset) >> 6) & 0x3) // 压缩报文
        {
            unsigned new_offset = Read2B(ptr, offset) & 0x3fff;//8bit标识符-->16bit指针
            return *offset - start_offset - 2 + BufferToName(namePtr, ptr, &new_offset);//恢复并递归指向第一个标识符
        }
        if (!*(ptr + *offset)) // 处理到0，表示NAME字段的结束
        {
            ++*offset;//offset的偏移值++
            *namePtr = 0;
            return *offset - start_offset;
        }
        int cur_length = (int)*(ptr + *offset);
        ++* offset;
        memcpy(namePtr, ptr  + *offset, cur_length);
        namePtr += cur_length;
        *offset += cur_length;
        *namePtr++ = '.';
    }
}

/**
 * @brief 从字节流中读入一个Header Section
 *
 * @param phead Header Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 读入后，偏移量增加到Header Section后一个位置
 */
static void BufferToHead(DNSPacketHeader* head, char* ptr, unsigned* offset)
{
    head->ID = Read2B(ptr, offset);
    uint16_t flag = Read2B(ptr, offset);//flag字段是2B
    head->QDCOUNT = (flag >> 15) & 0x1;//按 bit 获取字段
    head->OPCODE = (flag >> 11) & 0xF;
    head->AA = (flag >> 10) & 0x1;
    head->TC = (flag >> 9) & 0x1;
    head->RD = (flag >> 8) & 0x1;
    head->RA = (flag >> 7) & 0x1;
    head->Z = (flag >> 4) & 0x7;
    head->RCODE = flag & 0xF;
    head->QDCOUNT = Read2B(ptr, offset);//每次调用一次Read2B，offset都会+2
    head->ANCOUNT = Read2B(ptr, offset);
    head->NSCOUNT = Read2B(ptr, offset);
    head->ARCOUNT = Read2B(ptr, offset);
}

/**
 * @brief 从字节流中读入一个Question Section
 *
 * @param pque Question Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 读入后，偏移量增加到Question Section后一个位置；为QNAME字段分配了空间
 */
static void BufferToQD(DNSPacketQD* qd, char* ptr, unsigned* offset)
{
   qd->qname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));//分配空间
    BufferToName(qd->qname, ptr, offset);
    qd->qtype = Read2B(ptr, offset);
    qd->qclass = Read2B(ptr, offset);
}

/**
 * @brief 从字节流中读入一个Resource Record
 *
 * @param prr Resource Record
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 读入后，偏移量增加到Resource Record后一个位置；为NAME字段和RDATA字段分配了空间
 */
static void BufferToRR(DNSPacketRR* rr, char* ptr, unsigned* offset)
{
    rr->rname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
    BufferToName(rr->rname, ptr, offset);
    rr->rtype = Read2B(ptr, offset);
    rr->rclass = Read2B(ptr, offset);
    rr->ttl = Read4B(ptr, offset);
    rr->rdataLength = Read2B(ptr, offset);
    if (rr->rtype == QTYPE_CNAME || rr->rtype == QTYPE_NS) // CNAME和NS的RDATA是一个域名
    {
        uint8_t* temp = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
     
        rr->rdataLength = BufferToName(temp, ptr, offset);
        rr->rdata = (uint8_t*)calloc(rr->rdataLength, sizeof(uint8_t));
        memcpy(rr->rdata, temp, rr->rdataLength);
        free(temp);
    }
    else if (rr->rtype == QTYPE_MX) // RFC1035 3.3.9. MX RDATA format  这块我觉得也许可以删,然后把对应的QTYPE删掉就好
    {
        int i = 0;
        //删了的理由：等问我我再说
        /*
        uint8_t* temp = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
    
        unsigned temp_offset = *offset + 2;
        rr->rdataLength = string_to_rrname(temp, pstring, &temp_offset);
        rr->rdata = (uint8_t*)calloc(prr->rdlength + 2, sizeof(uint8_t));
        if (!prr->rdata)
            log_fatal("内存分配错误")
            memcpy(prr->rdata, pstring + *offset, 2);
        memcpy(prr->rdata + 2, temp, prr->rdlength);
        prr->rdlength += 2;
        *offset = temp_offset;
        free(temp);
        */
    }
    else if (rr->rtype == QTYPE_SOA) // RFC1035 3.3.13. SOA RDATA format  这块我也觉得可以删,然后把对应的QTYPE删掉就好
    {
        int i = 0;
        //删了的理由：等问我我再说
        /*
        uint8_t* temp = (uint8_t*)calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
        if (!temp)
            log_fatal("内存分配错误")
            prr->rdlength = string_to_rrname(temp, pstring, offset);
        prr->rdlength += string_to_rrname(temp + prr->rdlength, pstring, offset);
        prr->rdata = (uint8_t*)calloc(prr->rdlength + 20, sizeof(uint8_t));
        if (!prr->rdata)
            log_fatal("内存分配错误")
            memcpy(prr->rdata, temp, prr->rdlength);
        memcpy(prr->rdata + prr->rdlength, pstring + *offset, 20);
        *offset += 20;
        prr->rdlength += 20;
        free(temp);
        */
    }
    else
    {
        rr->rdata = (uint8_t*)calloc(rr->rdataLength, sizeof(uint8_t));
        memcpy(rr->rdata, ptr + *offset, rr->rdataLength);
        *offset += rr->rdataLength;
    }
}

void BufferToPacket(DNSPacket* packet, char* ptr)
{
    unsigned offset = 0;
    packet->header = (DNSPacketHeader*)calloc(1, sizeof(DNSPacketHeader));
    BufferToHead(packet->header, ptr, &offset);
    DNSPacketQD* qtail = NULL; // 链表的尾指针
    for (int i = 0; i < packet->header->QDCOUNT; i++)
    {
        DNSPacketQD* temp = (DNSPacketQD*)calloc(1, sizeof(DNSPacketQD));
        if (qtail == NULL) { // 链表的第一个节点
            packet->question = temp;
            qtail = temp;
        }
        else
        {
                qtail->next = temp;
                qtail = temp;
        }
        BufferToQD(qtail, ptr, &offset);
    }
    DNSPacketRR* rtail = NULL; // Resource Record链表的尾指针
    for (int i = 0; i < packet->header->ANCOUNT + packet->header->NSCOUNT + packet->header->ARCOUNT; i++)
    {
        DNSPacketRR* temp = (DNSPacketRR*)calloc(1, sizeof(DNSPacketRR));
        if (!rtail) { // 链表的第一个节点
            packet->resourceRecord = temp;
            rtail = temp;
        }
        else
        {
                rtail->next = temp;
                rtail = temp;
        }
        BufferToRR(rtail, ptr, &offset);
    }
}

/**
 * @brief 向字节流中写入一个小端法表示的16位数字
 *
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @param num 待写入的数字
 * @note 写入后，偏移量增加2
 */
static void Write2B(char* ptr, unsigned* offset, uint16_t num)
{
    *(uint16_t*)(ptr + *offset) = htons(num);
    *offset += 2;
}

/**
 * @brief 向字节流中写入一个小端法表示的32位数字
 *
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @param num 待写入的数字
 * @note 写入后，偏移量增加4
 */
static void Write4B(char* ptr, unsigned* offset, uint32_t num)
{
    *(uint32_t*)(ptr + *offset) = htonl(num);
    *offset += 4;
}

/**
 * @brief 向字节流中写入一个NAME字段
 *
 * @param pname NAME字段
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 写入后，偏移量增加到NAME字段后一个位置
 */
static void NameToBuffer(uint8_t* name, char* ptr, unsigned* offset)
{
    while (true)
    {
        uint8_t* loc = strchr(name, '.');//？？？
        if (loc == NULL)break;
        long cur_length = loc - name;
        ptr[(*offset)++] = cur_length;
        memcpy(ptr + *offset, name, cur_length);
        name += cur_length + 1;
        *offset += cur_length;
    }
    ptr[(*offset)++] = 0;
}

/**
 * @brief 向字节流中写入一个Header Section
 *
 * @param phead Header Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 写入后，偏移量增加到Header Section后一个位置
 */
static void HeadToBuffer(DNSPacketHeader* head, char* ptr, unsigned* offset)
{
    Write2B(ptr, offset, head->ID);
    uint16_t flag = 0;
    flag |= (head->QR << 15);
    flag |= (head->OPCODE << 11);
    flag |= (head->AA << 10);
    flag |= (head->TC << 9);
    flag |= (head->RD << 8);
    flag |= (head->RA << 7);
    flag |= (head->Z << 4);
    flag |= (head->RCODE);
    Write2B(ptr, offset, flag);
    Write2B(ptr, offset, head->QDCOUNT);
    Write2B(ptr, offset, head->ANCOUNT);
    Write2B(ptr, offset, head->NSCOUNT);
    Write2B(ptr, offset, head->ARCOUNT);
}

/**
 * @brief 向字节流中写入一个Question Section
 *
 * @param pque Question Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 写入后，偏移量增加到Question Section后一个位置
 */
static void QDToBuffer(DNSPacketQD* qd, char* ptr, unsigned* offset)
{
    NameToBuffer(qd->qname, ptr, offset);
    Write2B(ptr, offset, qd->qtype);
    Write2B(ptr, offset, qd->qclass);
}

/**
 * @brief 向字节流中写入一个Resource Record
 *
 * @param prr Resource Record
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 写入后，偏移量增加到Resource Record后一个位置
 */
static void RRToBuffer(DNSPacketRR* rr, char* ptr, unsigned* offset)
{
    NameToBuffer(rr->rname, ptr, offset);
    Write2B(ptr, offset, rr->rtype);
    Write2B(ptr, offset, rr->rclass);
    Write2B(ptr, offset, rr->ttl);
    Write2B(ptr, offset, rr->rdataLength);
    if (rr->rtype == QTYPE_CNAME || rr->rtype == QTYPE_NS)
        NameToBuffer(rr->rdata, ptr, offset);
    else if (rr->rtype == QTYPE_MX)//同理可删
    {
        int i = 0;
        /*
        unsigned temp_offset = *offset + 2;
        NameToBuffer(rr->rdata + 2, ptr, &temp_offset);
        memcpy(ptr + *offset, rr->rdata, 2);
        *offset = temp_offset;
        */
    }
    else if (rr->rtype == QTYPE_SOA)//同理可删
    {
        int i = 0;/*
        NameToBuffer(rr->rdata, ptr, offset);
        NameToBuffer(rr->rdata + strlen(rr->rdata) + 1, ptr, offset);
        memcpy(pstring + *offset, prr->rdata + prr->rdlength - 20, 20);
        *offset += 20;
        */
    }
    else
    {
        memcpy(ptr + *offset, rr->rdata, rr->rdataLength);
        *offset += rr->rdataLength;
    }
}

unsigned PacketToBuffer(DNSPacket* packet, char* ptr)
{
    unsigned offset = 0;
    HeadToBuffer(packet->header, ptr, &offset);
    DNSPacketQD* qtail = packet->question;
    for (int i = 0; i < packet->header->QDCOUNT; i++)
    {
        QDToBuffer(qtail, ptr, &offset);
        qtail = qtail->next;
    }
    DNSPacketRR* rtail = packet->resourceRecord;
    for (int i = 0; i < packet->header->ANCOUNT + packet->header->NSCOUNT + packet->header->ARCOUNT; i++)
    {
        RRToBuffer(rtail, ptr, &offset);
        rtail = rtail->next;
    }
    return offset;
}

void DestroyRR(DNSPacketRR* rr)
{
    while (rr != NULL)
    {
        DNSPacketRR * temp = rr->next;
        free(rr->rname);
        free(rr->rdata);
        free(rr);
        rr = temp;
    }
}
void DestroyQD(DNSPacketQD* qd)
{
    while (qd != NULL)
    {
        DNSPacketQD* temp = qd->next;
        free(qd->qname);
        free(qd);
        qd = temp;
    }
}

void DestroyPacket(DNSPacket* packet)
{
  //  log_debug("释放DNS报文空间 ID: 0x%04x", pmsg->header->id)
    free(packet->header);
    DestroyQD(packet->question);
    DestroyRR(packet->resourceRecord);
    free(packet);
}

DNSPacketRR* CopyRR(DNSPacketRR* dnsRR)
{
    if (dnsRR == NULL) return NULL;
    // 复制链表的头节点
    DNSPacketRR* oldDNSRR = dnsRR;
    DNSPacketRR* newDNSRR = (DNSPacketRR*)calloc(1, sizeof(DNSPacketRR));
  //  DNSPacketRR* tempRR = newDNSRR;
    memcpy(newDNSRR, oldDNSRR, sizeof(DNSPacketRR));
    newDNSRR->rname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
    memcpy(newDNSRR->rname, oldDNSRR->rname, RR_NAME_MAX_SIZE);
    newDNSRR->rdata = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
    memcpy(newDNSRR->rdata, oldDNSRR->rdata, RR_NAME_MAX_SIZE);
    // 复制链表的剩余节点
    while (oldDNSRR->next!=NULL)
    {
        newDNSRR->next = (DNSPacketRR*)calloc(1, sizeof(DNSPacketRR));
        oldDNSRR = oldDNSRR->next;
        newDNSRR = newDNSRR->next;
        memcpy(newDNSRR, oldDNSRR, sizeof(DNSPacketRR));
        newDNSRR->rname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
        memcpy(newDNSRR->rname, oldDNSRR->rname, RR_NAME_MAX_SIZE);
        newDNSRR->rdata = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
        memcpy(newDNSRR->rdata, oldDNSRR->rdata, RR_NAME_MAX_SIZE);
    }
    return newDNSRR;
}

DNSPacketQD* CopyQD(DNSPacketQD* dnsQD)
{
    if (dnsQD == NULL) return NULL;
    // 复制链表的头节点
    DNSPacketQD* oldDNSQD = dnsQD;
    DNSPacketQD* newDNSQD = (DNSPacketQD*)calloc(1, sizeof(DNSPacketQD));
  //  DNSPacketQD* tempQD = newDNSQD;
    memcpy(newDNSQD, oldDNSQD, sizeof(DNSPacketQD));
    newDNSQD->qname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
    memcpy(newDNSQD->qname, oldDNSQD->qname, RR_NAME_MAX_SIZE);
    // 复制链表的剩余节点
    while (oldDNSQD->next != NULL)
    {
        newDNSQD->next = (DNSPacketQD*)calloc(1, sizeof(DNSPacketQD));
        oldDNSQD = oldDNSQD->next;
        newDNSQD = newDNSQD->next;
        memcpy(newDNSQD, oldDNSQD, sizeof(DNSPacketQD));
        newDNSQD->qname = (uint8_t*)calloc(RR_NAME_MAX_SIZE, sizeof(uint8_t));
        memcpy(newDNSQD->qname, oldDNSQD->qname, RR_NAME_MAX_SIZE);
    }
    return newDNSQD;
}

DNSPacket* CopyPacket(DNSPacket* packet)
{
    if (packet == NULL) return NULL;
    DNSPacket* oldPacket = packet;
    DNSPacket* newPacket = (DNSPacket*)calloc(1, sizeof(DNSPacket));
    newPacket->header = (DNSPacketHeader*)calloc(1, sizeof(DNSPacketHeader));
    memcpy(newPacket->header, oldPacket->header, sizeof(DNSPacketHeader));
    // 复制链表的头节点
    newPacket->question = CopyQD(oldPacket->question);
    newPacket->resourceRecord = CopyRR(oldPacket->resourceRecord);
    return newPacket;
}