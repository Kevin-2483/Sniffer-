// UDPParser.cpp
#include "UDPParser.h"
#include <winsock2.h>

// 定义 UDP 头部结构体
struct udp_header {
    ushort sport; // Source port
    ushort dport; // Destination port
    ushort len;   // Datagram length
    ushort crc;   // Checksum
};

void UDPParser::parseHeader(const uchar *packet, QStandardItem *parentItem) {
    // 解析 UDP 头部
    struct udp_header *udpHeader = (struct udp_header *)(packet + 14 + 20); // 假设 IP 头部长度为 20 字节

    QStandardItem *udpHeaderItem = new QStandardItem("UDP Header");
    parentItem->appendRow(udpHeaderItem);

    // 添加 UDP 头部信息的子节点
    udpHeaderItem->appendRow(new QStandardItem("Source Port: " + QString::number(ntohs(udpHeader->sport))));
    udpHeaderItem->appendRow(new QStandardItem("Destination Port: " + QString::number(ntohs(udpHeader->dport))));
    udpHeaderItem->appendRow(new QStandardItem("Datagram Length: " + QString::number(udpHeader->len)));
    udpHeaderItem->appendRow(new QStandardItem("Checksum: " + QString::number(ntohs(udpHeader->crc))));
}

void UDPParser::parsePayload(const uchar *packet, QStandardItem *parentItem) {
    // 解析 UDP 负载
    struct udp_header *udpHeader = (struct udp_header *)(packet + 14 + 20); // 假设 IP 头部长度为 20 字节

    // 计算 UDP 头部长度
    int udpHeaderLength = sizeof(struct udp_header);

    // 获取指向 UDP 负载的指针
    const uchar *payload = packet + 14 + 20 + udpHeaderLength;

    // 获取负载长度
    int payloadLength = ntohs(udpHeader->len) - udpHeaderLength;

    // 输出负载的16进制表示，每8个字节换一行
    QString hexPayload;
    for (int i = 0; i < payloadLength; ++i) {
        hexPayload.append(QString("%1\t").arg(payload[i], 2, 16, QChar('0')).toUpper());

        if ((i + 1) % 8 == 0) {
            hexPayload.append("\n");
        }
    }

    // 如果不是刚好8的倍数，添加换行符
    if (payloadLength % 8 != 0) {
        hexPayload.append("\n");
    }

    QStandardItem *payloadItem = new QStandardItem("Payload (Hex)");
    payloadItem->appendRow(new QStandardItem(hexPayload.trimmed()));
    parentItem->appendRow(payloadItem);
}
