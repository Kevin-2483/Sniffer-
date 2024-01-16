// TCPParser.cpp
#include "TCPParser.h"
#include <winsock2.h>
// TCP 头部结构体定义
struct tcp_header {
    uint16_t sport;     // Source port
    uint16_t dport;     // Destination port
    uint32_t seq;       // Sequence number
    uint32_t ack_seq;   // Acknowledgment number
    uint8_t doff;       // Data offset (header length)
    uint8_t flags;      // Flags
    uint16_t window;    // Window size
    uint16_t crc;       // Checksum
    uint16_t urg_ptr;    // Urgent pointer
    uint16_t payload_length;
};

void TCPParser::parseHeader(const uchar *packet, QStandardItem *parentItem) {
    // 解析 TCP 头部
    struct tcp_header *tcpHeader = (struct tcp_header*)(packet + 14 + 20);

    parentItem->appendRow(new QStandardItem("Source Port: " + QString::number(ntohs(tcpHeader->sport))));
    parentItem->appendRow(new QStandardItem("Destination Port: " + QString::number(ntohs(tcpHeader->dport))));
    parentItem->appendRow(new QStandardItem("Sequence Number: " + QString::number(ntohl(tcpHeader->seq))));
    parentItem->appendRow(new QStandardItem("Acknowledgment Number: " + QString::number(ntohl(tcpHeader->ack_seq))));
    parentItem->appendRow(new QStandardItem("Header Length: " + QString::number((tcpHeader->doff >> 4) * 4)));
    parentItem->appendRow(new QStandardItem("Flags: " + QString::number(tcpHeader->flags)));
    parentItem->appendRow(new QStandardItem("Window Size: " + QString::number(ntohs(tcpHeader->window))));
    parentItem->appendRow(new QStandardItem("Checksum: " + QString::number(ntohs(tcpHeader->crc))));
    parentItem->appendRow(new QStandardItem("Urgent Pointer: " + QString::number(ntohs(tcpHeader->urg_ptr))));
}
void TCPParser::parsePayload(const uchar *packet, QStandardItem *parentItem) {
    // 解析 TCP 负载
    struct tcp_header *tcpHeader = (struct tcp_header*)(packet + 14 + 20);
    int tcpHeaderLength = (tcpHeader->doff >> 4) * 4;

    const unsigned char *payload = packet + 14 + 20 + tcpHeaderLength; // 使用 unsigned char
    int payloadLength = ntohs(tcpHeader->payload_length) - tcpHeaderLength;

    if (payloadLength > 0) {
        QString hexString;
        for (int i = 0; i < payloadLength; ++i) {
            hexString += QString("%1").arg(payload[i], 2, 16, QChar('0')).toUpper() + "\t";

            if ((i + 1) % 8 == 0) {
                hexString += "\n";
            }
        }

        parentItem->appendRow(new QStandardItem("Payload (Hex):\n" + hexString));
    } else {
        parentItem->appendRow(new QStandardItem("No Payload"));
    }
}
