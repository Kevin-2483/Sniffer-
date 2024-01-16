#ifndef UDPPARSER_H
#define UDPPARSER_H

#pragma once

#include "ProtocolParser.h"

class UDPParser : public ProtocolParser {
public:
    void parseHeader(const uchar *packet, QStandardItem *parentItem) override;
    void parsePayload(const uchar *packet, QStandardItem *parentItem) override;
};

#endif
