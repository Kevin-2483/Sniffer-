#ifndef TCPPARSER_H
#define TCPPARSER_H

#pragma once

#include "ProtocolParser.h"
#include <winsock2.h>

class TCPParser : public ProtocolParser {
public:
    void parseHeader(const uchar *packet, QStandardItem *parentItem) override;
    void parsePayload(const uchar *packet, QStandardItem *parentItem) override;
};


#endif
