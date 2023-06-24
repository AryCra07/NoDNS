#include "../include/analysis.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <winsock2.h>

#pragma comment(lib, "wsock32.lib")

/**
 * @brief 从字节流中读入一个大端法表示的16位数字
 *
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @return 从(pstring + *offset)开始的16位数字
 * @note 读入后，偏移量增加2
 */
static uint16_t Read2B(char *ptr, unsigned *offset) {
    uint16_t ret = ntohs(*(uint16_t *) (ptr + *offset));
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
static uint32_t Read4B(char *ptr, unsigned *offset) {
    uint32_t ret = ntohl(*(uint32_t *) (ptr + *offset));
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
static unsigned BufferToName(uint8_t *namePtr, char *ptr, unsigned *offset) {
    unsigned start_offset = *offset;
    while (true) {
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
        int cur_length = (int) *(ptr + *offset);
        ++*offset;
        memcpy(namePtr, ptr + *offset, cur_length);
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
static void BufferToHead(DNSHeader *head, char *ptr, unsigned *offset) {
    head->id = Read2B(ptr, offset);
    uint16_t flag = Read2B(ptr, offset);//flag字段是2B
    head->qdcount = (flag >> 15) & 0x1;//按 bit 获取字段
    head->opcode = (flag >> 11) & 0xF;
    head->aa = (flag >> 10) & 0x1;
    head->tc = (flag >> 9) & 0x1;
    head->rd = (flag >> 8) & 0x1;
    head->ra = (flag >> 7) & 0x1;
    head->z = (flag >> 4) & 0x7;
    head->rcode = flag & 0xF;
    head->qdcount = Read2B(ptr, offset);//每次调用一次Read2B，offset都会+2
    head->ancount = Read2B(ptr, offset);
    head->nscount = Read2B(ptr, offset);
    head->arcount = Read2B(ptr, offset);
}

/**
 * @brief 从字节流中读入一个Question Section
 *
 * @param pque Question Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 读入后，偏移量增加到Question Section后一个位置；为QNAME字段分配了空间
 */
static void BufferToQD(DNSQuestion *qd, char *ptr, unsigned *offset) {
    qd->qname = (uint8_t *) calloc(DNSR_MAX_RR_SIZE, sizeof(uint8_t));//分配空间
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
static void BufferToRR(DNSResourceRecord *rr, char *ptr, unsigned *offset) {
    rr->name = (uint8_t *) calloc(DNSR_MAX_RR_SIZE, sizeof(uint8_t));
    BufferToName(rr->name, ptr, offset);
    rr->type = Read2B(ptr, offset);
    rr->class = Read2B(ptr, offset);
    rr->ttl = Read4B(ptr, offset);
    rr->rdlength = Read2B(ptr, offset);
    if (rr->type == DNSR_TYPE_CNAME || rr->type == DNSR_TYPE_NS) // CNAME和NS的RDATA是一个域名
    {
        uint8_t *temp = (uint8_t *) calloc(DNSR_MAX_RR_SIZE, sizeof(uint8_t));

        rr->rdlength = BufferToName(temp, ptr, offset);
        rr->rdata = (uint8_t *) calloc(rr->rdlength, sizeof(uint8_t));
        memcpy(rr->rdata, temp, rr->rdlength);
        free(temp);
    } else if (rr->type == DNSR_TYPE_MX) // RFC1035 3.3.9. MX RDATA format  这块我觉得也许可以删,然后把对应的QTYPE删掉就好
    {
        int i = 0;
        //删了的理由：等问我我再说
        /*
        uint8_t* temp = (uint8_t*)calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
    
        unsigned temp_offset = *offset + 2;
        rr->rdlength = string_to_rrname(temp, pstring, &temp_offset);
        rr->rdata = (uint8_t*)calloc(prr->rdlength + 2, sizeof(uint8_t));
        if (!prr->rdata)
            log_fatal("内存分配错误")
            memcpy(prr->rdata, pstring + *offset, 2);
        memcpy(prr->rdata + 2, temp, prr->rdlength);
        prr->rdlength += 2;
        *offset = temp_offset;
        free(temp);
        */
    } else if (rr->type == DNSR_TYPE_SOA) // RFC1035 3.3.13. SOA RDATA format  这块我也觉得可以删,然后把对应的QTYPE删掉就好
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
    } else {
        rr->rdata = (uint8_t *) calloc(rr->rdlength, sizeof(uint8_t));
        memcpy(rr->rdata, ptr + *offset, rr->rdlength);
        *offset += rr->rdlength;
    }
}

void BufferToPacket(DNSMessage *packet, char *ptr) {
    unsigned offset = 0;
    packet->header = (DNSHeader *) calloc(1, sizeof(DNSHeader));
    BufferToHead(packet->header, ptr, &offset);
    DNSQuestion *qtail = NULL; // 链表的尾指针
    for (int i = 0; i < packet->header->qdcount; i++) {
        DNSQuestion *temp = (DNSQuestion *) calloc(1, sizeof(DNSQuestion));
        if (qtail == NULL) { // 链表的第一个节点
            packet->que = temp;
            qtail = temp;
        } else {
            qtail->next = temp;
            qtail = temp;
        }
        BufferToQD(qtail, ptr, &offset);
    }
    DNSResourceRecord *rtail = NULL; // Resource Record链表的尾指针
    for (int i = 0; i < packet->header->ancount + packet->header->nscount + packet->header->arcount; i++) {
        DNSResourceRecord *temp = (DNSResourceRecord *) calloc(1, sizeof(DNSResourceRecord));
        if (!rtail) { // 链表的第一个节点
            packet->rr = temp;
            rtail = temp;
        } else {
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
static void Write2B(char *ptr, unsigned *offset, uint16_t num) {
    *(uint16_t *) (ptr + *offset) = htons(num);
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
static void Write4B(char *ptr, unsigned *offset, uint32_t num) {
    *(uint32_t *) (ptr + *offset) = htonl(num);
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
static void NameToBuffer(uint8_t *name, char *ptr, unsigned *offset) {
    while (true) {
        uint8_t *loc = strchr(name, '.');//？？？
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
static void HeadToBuffer(DNSHeader *head, char *ptr, unsigned *offset) {
    Write2B(ptr, offset, head->id);
    uint16_t flag = 0;
    flag |= (head->qr << 15);
    flag |= (head->opcode << 11);
    flag |= (head->aa << 10);
    flag |= (head->tc << 9);
    flag |= (head->rd << 8);
    flag |= (head->ra << 7);
    flag |= (head->z << 4);
    flag |= (head->rcode);
    Write2B(ptr, offset, flag);
    Write2B(ptr, offset, head->qdcount);
    Write2B(ptr, offset, head->ancount);
    Write2B(ptr, offset, head->nscount);
    Write2B(ptr, offset, head->arcount);
}

/**
 * @brief 向字节流中写入一个Question Section
 *
 * @param pque Question Section
 * @param pstring 字节流起点
 * @param offset 字节流偏移量
 * @note 写入后，偏移量增加到Question Section后一个位置
 */
static void QDToBuffer(DNSQuestion *qd, char *ptr, unsigned *offset) {
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
static void RRToBuffer(DNSResourceRecord *rr, char *ptr, unsigned *offset) {
    NameToBuffer(rr->name, ptr, offset);
    Write2B(ptr, offset, rr->type);
    Write2B(ptr, offset, rr->class);
    Write2B(ptr, offset, rr->ttl);
    Write2B(ptr, offset, rr->rdlength);
    if (rr->type == DNSR_TYPE_CNAME || rr->type == DNSR_TYPE_NS)
        NameToBuffer(rr->rdata, ptr, offset);
    else if (rr->type == DNSR_TYPE_MX)//同理可删
    {
        int i = 0;
        /*
        unsigned temp_offset = *offset + 2;
        NameToBuffer(rr->rdata + 2, ptr, &temp_offset);
        memcpy(ptr + *offset, rr->rdata, 2);
        *offset = temp_offset;
        */
    } else if (rr->type == DNSR_TYPE_SOA)//同理可删
    {
        int i = 0;/*
        NameToBuffer(rr->rdata, ptr, offset);
        NameToBuffer(rr->rdata + strlen(rr->rdata) + 1, ptr, offset);
        memcpy(pstring + *offset, prr->rdata + prr->rdlength - 20, 20);
        *offset += 20;
        */
    } else {
        memcpy(ptr + *offset, rr->rdata, rr->rdlength);
        *offset += rr->rdlength;
    }
}

unsigned PacketToBuffer(DNSMessage *packet, char *ptr) {
    unsigned offset = 0;
    HeadToBuffer(packet->header, ptr, &offset);
    DNSQuestion *qtail = packet->que;
    for (int i = 0; i < packet->header->qdcount; i++) {
        QDToBuffer(qtail, ptr, &offset);
        qtail = qtail->next;
    }
    DNSResourceRecord *rtail = packet->rr;
    for (int i = 0; i < packet->header->ancount + packet->header->nscount + packet->header->arcount; i++) {
        RRToBuffer(rtail, ptr, &offset);
        rtail = rtail->next;
    }
    return offset;
}

void DestroyRR(DNSResourceRecord *rr) {
    while (rr != NULL) {
        DNSResourceRecord *temp = rr->next;
        free(rr->name);
        free(rr->rdata);
        free(rr);
        rr = temp;
    }
}

void DestroyQD(DNSQuestion *qd) {
    while (qd != NULL) {
        DNSQuestion *temp = qd->next;
        free(qd->qname);
        free(qd);
        qd = temp;
    }
}

void DestroyPacket(DNSMessage *packet) {
    //  log_debug("释放DNS报文空间 ID: 0x%04x", pmsg->header->id)
    free(packet->header);
    DestroyQD(packet->que);
    DestroyRR(packet->rr);
    free(packet);
}

DNSResourceRecord *CopyRR(DNSResourceRecord *dnsRR) {
    if (dnsRR == NULL) return NULL;
    // 复制链表的头节点
    DNSResourceRecord *oldDNSRR = dnsRR;
    DNSResourceRecord *newDNSRR = (DNSResourceRecord *) calloc(1, sizeof(DNSResourceRecord));
    //  DNSResourceRecord* tempRR = newDNSRR;
    memcpy(newDNSRR, oldDNSRR, sizeof(DNSResourceRecord));
    newDNSRR->name = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
    memcpy(newDNSRR->name, oldDNSRR->name, DNSR_MAX_RR_NUM);
    newDNSRR->rdata = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
    memcpy(newDNSRR->rdata, oldDNSRR->rdata, DNSR_MAX_RR_NUM);
    // 复制链表的剩余节点
    while (oldDNSRR->next != NULL) {
        newDNSRR->next = (DNSResourceRecord *) calloc(1, sizeof(DNSResourceRecord));
        oldDNSRR = oldDNSRR->next;
        newDNSRR = newDNSRR->next;
        memcpy(newDNSRR, oldDNSRR, sizeof(DNSResourceRecord));
        newDNSRR->name = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
        memcpy(newDNSRR->name, oldDNSRR->name, DNSR_MAX_RR_NUM);
        newDNSRR->rdata = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
        memcpy(newDNSRR->rdata, oldDNSRR->rdata, DNSR_MAX_RR_NUM);
    }
    return newDNSRR;
}

DNSQuestion *CopyQD(DNSQuestion *dnsQD) {
    if (dnsQD == NULL) return NULL;
    // 复制链表的头节点
    DNSQuestion *oldDNSQD = dnsQD;
    DNSQuestion *newDNSQD = (DNSQuestion *) calloc(1, sizeof(DNSQuestion));
    //  DNSQuestion* tempQD = newDNSQD;
    memcpy(newDNSQD, oldDNSQD, sizeof(DNSQuestion));
    newDNSQD->qname = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
    memcpy(newDNSQD->qname, oldDNSQD->qname, DNSR_MAX_RR_NUM);
    // 复制链表的剩余节点
    while (oldDNSQD->next != NULL) {
        newDNSQD->next = (DNSQuestion *) calloc(1, sizeof(DNSQuestion));
        oldDNSQD = oldDNSQD->next;
        newDNSQD = newDNSQD->next;
        memcpy(newDNSQD, oldDNSQD, sizeof(DNSQuestion));
        newDNSQD->qname = (uint8_t *) calloc(DNSR_MAX_RR_NUM, sizeof(uint8_t));
        memcpy(newDNSQD->qname, oldDNSQD->qname, DNSR_MAX_RR_NUM);
    }
    return newDNSQD;
}

DNSMessage *CopyPacket(DNSMessage *packet) {
    if (packet == NULL) return NULL;
    DNSMessage *oldPacket = packet;
    DNSMessage *newPacket = (DNSMessage *) calloc(1, sizeof(DNSMessage));
    newPacket->header = (DNSHeader *) calloc(1, sizeof(DNSHeader));
    memcpy(newPacket->header, oldPacket->header, sizeof(DNSHeader));
    // 复制链表的头节点
    newPacket->que = CopyQD(oldPacket->que);
    newPacket->rr = CopyRR(oldPacket->rr);
    return newPacket;
}