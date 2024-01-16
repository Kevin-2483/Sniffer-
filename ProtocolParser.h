#ifndef PROTOCOLPARSER_H
#define PROTOCOLPARSER_H

#pragma once

#include <QStandardItem>

class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;
    virtual void parseHeader(const uchar *packet, QStandardItem *parentItem) = 0;
    virtual void parsePayload(const uchar *packet, QStandardItem *parentItem) = 0;
};
#endif
