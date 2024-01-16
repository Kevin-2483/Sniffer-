#include "newwindow.h"
#include "ui_newwindow.h"
#include <QFileInfo>
#include <QStandardItemModel>
#include <QDir>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include "TCPParser.h"
#include "UDPParser.h"
#include <QRegularExpression>

#pragma comment(lib, "ws2_32.lib")
/* 4 bytes IP address */
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

/* IPv4 header */
struct ip_header {
    u_char ver_ihl;         // Version (4 bits) + IP header length (4 bits)
    u_char tos;             // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;             // Time to live
    u_char proto;           // Protocol
    u_short crc;            // Header checksum
    ip_address saddr;       // Source address
    ip_address daddr;       // Destination address
    u_int op_pad;           // Option + Padding
};

/* UDP header*/
struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
};


extern QString currentPath;
extern QString folderPath;
extern QString relativePath;


NewWindow::NewWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::NewWindow)
{
    ui->setupUi(this);
    setWindowTitle("解析喵~");
    setWindowIcon(QIcon("OIG2.png"));
    setFixedSize(width(), height());
    connect(ui->NRButton, SIGNAL(clicked()), this, SLOT(onNRButtonClicked()));
    connect(ui->tableView, SIGNAL(clicked(const QModelIndex &)), this, SLOT(onTableClicked(const QModelIndex &)));
    // 创建表格模型
    QStandardItemModel *model = new QStandardItemModel(this);
    // 设置表头
    model->setHorizontalHeaderLabels({"日期", "时间", "源IP", "源端口", "目标IP", "目标端口","UUID"});
    // 将模型设置给QTableView
    ui->tableView->setModel(model);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->filters->setText("*.pcap");
    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->HexText->setReadOnly(true);  // 使其只读
}
void NewWindow::onNRButtonClicked(){
    // 创建表格模型
    QStandardItemModel *model = new QStandardItemModel(this);

    // 设置表头
    model->setHorizontalHeaderLabels({"日期", "时间", "源IP", "源端口", "目标IP", "目标端口","UUID"});


    QString InputFilters = ui->filters->text();
    // 遍历文件夹
    QDir folderDir(folderPath);
    // 使用正则表达式定义过滤规则
    QRegularExpression regExp(InputFilters);
    // 设置过滤规则
    folderDir.setNameFilters(QStringList() << regExp.pattern());
    QFileInfoList fileList = folderDir.entryInfoList();
    qDebug() << folderPath;
    // 解析文件名并添加到表格模型
    foreach (QFileInfo fileInfo, fileList) {
        QString fileName = fileInfo.fileName();
        qDebug() << "遍历到文件：" << fileName;
        QStringList parts = fileName.split('_');
        if (parts.size() == 7) {
            QList<QStandardItem *> rowItems;
            for (int i = 0; i < 7; ++i) {
                rowItems.append(new QStandardItem(parts.at(i)));
            }
            model->appendRow(rowItems);
        }
    }

    // 将模型设置给QTableView
    ui->tableView->setModel(model);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void NewWindow::onTableClicked(const QModelIndex &index){
    int row = index.row();  // 获取点击的行号
    QStandardItemModel *model = qobject_cast<QStandardItemModel*>(ui->tableView->model());

    if (model) {
        QStringList rowData;  // 用于存储一行的数据
        for (int col = 0; col < model->columnCount(); ++col) {
            QModelIndex cellIndex = model->index(row, col);
            QString cellData = model->data(cellIndex).toString();
            rowData.append(cellData);
        }

        // 将rowData中的数据进行拼接或处理，根据需要进行操作
        QString concatenatedData = rowData.join("_");
        qDebug() << "点击的行数据：" << concatenatedData;
        parsePcapFile(folderPath+concatenatedData);
    }
}



ProtocolParser* createParser(int protocol) {

    switch (protocol) {
    case IPPROTO_TCP:
        return new TCPParser();
    case IPPROTO_UDP:
        return new UDPParser();
    default:
        return nullptr;
    }
}



void NewWindow::parsePcapFile(const QString &filePath) {
    ui->HexText->clear();
    // 打开 pcap 文件
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filePath.toStdString().c_str(), errbuf);
    if (handle == nullptr) {
        qDebug() << "无法打开 pcap 文件:" << errbuf << "喵~";
        return;
    }

    // 创建 Qt 树形模型
    QStandardItemModel *model = new QStandardItemModel;

    // 解析 pcap 文件中的数据包
    struct pcap_pkthdr header;
    const u_char *packet;
    // 用于存储16进制文本
    QString hexText;

    while ((packet = pcap_next(handle, &header)) != nullptr) {
        hexText += "Raw Bytes:\n";
        QString asciiText = "ASCII:\n";
        for (u_int i = 0; i < header.len; ++i) {
            hexText += QString("%1\t").arg(packet[i], 2, 16, QLatin1Char('0')).toUpper();
            // 添加两个缩进，每8个字节
            if ((i + 1) % 8 == 0) {
                hexText += "\t";
            }
            // 每16个字节换行
            if ((i + 1) % 16 == 0) {
                hexText += "\n";
            }
            // 输出ASCII字符
            if (packet[i] >= 32 && packet[i] <= 126) {
                asciiText += QString(QChar(packet[i]))+"\t";
            } else {
                asciiText += ".\t";
            }
            // 添加空格，每8个字节
            if ((i + 1) % 8 == 0) {
                asciiText += "\t";
            }
            // 每16个字节换行
            if ((i + 1) % 16 == 0) {
                asciiText += "\n";
            }
        }
        hexText += "\n\n";
        asciiText += "\n\n";

        // 将ASCII字符追加到hexText
        hexText += asciiText;


        // 解析 IP 头部信息
        struct ip_header *ipHeader = (struct ip_header*)(packet + 14); // 假设以太网头部长度为 14 字节
        QStandardItem *ipHeaderItem = new QStandardItem("IPv4 Header");
        model->appendRow(ipHeaderItem);

        // 添加 Version 和 Header Length 信息的子节点
        u_char version = (ipHeader->ver_ihl >> 4) & 0xF;
        u_char headerLength = (ipHeader->ver_ihl & 0xF) * 4; // Header Length 以 32 位为单位，需要乘以 4
        ipHeaderItem->appendRow(new QStandardItem("Version: " + QString::number(version)));
        ipHeaderItem->appendRow(new QStandardItem("Header Length: " + QString::number(headerLength)));
        ipHeaderItem->appendRow(new QStandardItem("Type of Service: " + QString::number(ipHeader->tos)));
        ipHeaderItem->appendRow(new QStandardItem("Total Length: " + QString::number(ipHeader->tlen/256)));
        ipHeaderItem->appendRow(new QStandardItem("Identification: " + QString::number(ipHeader->identification)));
        // 解析 Flags 和 Fragment offset
        u_short flags_fo = ntohs(ipHeader->flags_fo);
        int flags = (flags_fo >> 13) & 0x07;  // 取高 3 位作为 Flags
        int fragmentOffset = flags_fo & 0x1FFF; // 取低 13 位作为 Fragment offset
        ipHeaderItem->appendRow(new QStandardItem("Flags: " + QString::number(flags)));
        ipHeaderItem->appendRow(new QStandardItem("Fragment Offset: " + QString::number(fragmentOffset)));

        ipHeaderItem->appendRow(new QStandardItem("Time to Live: " + QString::number(ipHeader->ttl)));
        ipHeaderItem->appendRow(new QStandardItem("Protocol: " + QString::number(ipHeader->proto)));
        ipHeaderItem->appendRow(new QStandardItem("Header Checksum: " + QString::number(ipHeader->crc)));
        // 将 Source address 转换为字符串并添加子节点
        QString sourceAddress = QString("%1.%2.%3.%4").arg(ipHeader->saddr.byte1).arg(ipHeader->saddr.byte2)
                                    .arg(ipHeader->saddr.byte3).arg(ipHeader->saddr.byte4);
        ipHeaderItem->appendRow(new QStandardItem("Source address: " + sourceAddress));
        // 将 Destination address 转换为字符串并添加子节点
        QString destAddress = QString("%1.%2.%3.%4").arg(ipHeader->daddr.byte1).arg(ipHeader->daddr.byte2)
                                  .arg(ipHeader->daddr.byte3).arg(ipHeader->daddr.byte4);
        ipHeaderItem->appendRow(new QStandardItem("Destination address: " + destAddress));
        ipHeaderItem->appendRow(new QStandardItem("Option + Padding: " + QString::number(ipHeader->op_pad)));

        int protocol = ipHeader->proto;
        qDebug() << "解析协议：" << protocol;

        // 创建对应协议的解析器
        ProtocolParser *parser = createParser(protocol);
        if (parser) {
            // 解析头部和负载
            QStandardItem *protocolItem = new QStandardItem("Protocol");
            model->appendRow(protocolItem);
            parser->parseHeader(packet, protocolItem);
            parser->parsePayload(packet, protocolItem);

            delete parser;
        } else {
            qDebug() << "未知协议，协议编号：" << protocol;
        }

    }

    // 关闭 pcap 文件
    pcap_close(handle);


    ui->treeView->setModel(model);
    // 将16进制文本设置给ui->HexText
    ui->HexText->appendPlainText(hexText);
}


NewWindow::~NewWindow()
{
    delete ui;
    delete model;
}
