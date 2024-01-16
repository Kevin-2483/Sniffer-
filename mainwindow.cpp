#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QDir>
#include <QCoreApplication>
#include <QUuid>

// 获取当前应用程序的路径
QString currentPath = QCoreApplication::applicationDirPath();
// 创建相对路径
QString relativePath = "captured_packets/";
// 创建文件名
QString folderPath = QDir(currentPath).filePath(relativePath);

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

int fileCounter;
bool Capturing = false;


pcap_dumper_t *pcapDumper;
// // 获取当前应用程序的路径
// QString currentPath = QCoreApplication::applicationDirPath();
// // 创建相对路径
// QString relativePath = "captured_packets/";
// // 创建文件名
// QString folderPath = QDir(currentPath).filePath(relativePath);
std::thread t1;


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow),
    packetCounter(0),
    maxConsoleLines(5000)
{
    ui->setupUi(this);
    setWindowTitle("嗅探喵~");
    setWindowIcon(QIcon("OIG.png"));
    setFixedSize(width(), height());
    // 从文件加载条目
    QFile file("list.txt");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        while (!stream.atEnd()) {
            QString itemText = stream.readLine();
            ui->listWidget->addItem(itemText);
        }
        file.close();
    }
    // 连接按钮的点击事件到槽函数
    connect(ui->RButton, SIGNAL(clicked()), this, SLOT(onRButtonClicked()));
    connect(ui->SButton, SIGNAL(clicked()), this, SLOT(onSButtonClicked()));
    connect(ui->DButton, SIGNAL(clicked()), this, SLOT(deleteTemp()));
    connect(ui->ADDITEM, SIGNAL(clicked()), this, SLOT(onAButtonClicked()));
    connect(ui->SETITEM, SIGNAL(clicked()), this, SLOT(on_pushButton_clicked()));
    connect(ui->DELETEITEM, SIGNAL(clicked()), this, SLOT(onDButtonClicked()));

    connect(this, &MainWindow::messageReceived, this, &MainWindow::printToConsole);
    connect(ui->NewWindow, SIGNAL(clicked()), this, SLOT(onButtonClicked()));
    ui->consoleOutput->setReadOnly(true);  // 使其只读
    ui->consoleOutput->setPlaceholderText("控制台输出信息");
    ui->lineEdit->setText("ip and udp");
    newWindow = new NewWindow();  // 实例化新窗口类
}
void MainWindow::onAButtonClicked() {
    QString InputFilter = ui->lineEdit->text();
    QListWidgetItem *newItem = new QListWidgetItem(InputFilter);
    ui->listWidget->addItem(newItem);
    // 保存条目到文件
    QFile file("list.txt");
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        for (int i = 0; i < ui->listWidget->count(); ++i) {
            stream << ui->listWidget->item(i)->text() << "\n";
        }
        file.close();
    }


}
void MainWindow::onDButtonClicked() {
    qDeleteAll(ui->listWidget->selectedItems());
    // 保存条目到文件
    QFile file("list.txt");
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        for (int i = 0; i < ui->listWidget->count(); ++i) {
            stream << ui->listWidget->item(i)->text() << "\n";
        }
        file.close();
    }

}
void MainWindow::on_pushButton_clicked()
{
    // 获取当前选择的条目
    QListWidgetItem *selectedItem = ui->listWidget->currentItem();

    // 检查是否有选择的条目
    if (selectedItem) {
        // 将条目的内容添加到lineEdit中
        ui->lineEdit->setText(selectedItem->text());
    }
}
void MainWindow::onButtonClicked() {
    newWindow->show();  // 显示新窗口
}

void MainWindow::onRButtonClicked()
{
    emit messageReceived("查找网络设备...");
    populateNetworkDevices();  // 调用填充网络设备的函数
}
void MainWindow::populateNetworkDevices()
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 使用 Npcap 函数查找所有网络设备
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
        qDebug() << "Error in pcap_findalldevs_ex: " << errbuf;
        QString errorMessage = QString::fromUtf8(errbuf);
        emit messageReceived("Error in pcap_findalldevs_ex: "+errorMessage);
        return;
    }

    // 遍历设备列表，将设备名称添加到下拉菜单
    for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next) {
        ui->comboBox->addItem(dev->description, QString(dev->name));
        // 输出设备信息
        ifprint(dev);
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
}
// 将 unsigned int 类型的 IP 地址转换为字符串表示

QString iptos(uint32_t inAddr)
{
    struct in_addr addr;
    addr.s_addr = inAddr;

    char ipStr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr)) == nullptr) {
        // 处理错误
        return QString("Error converting IP address to string");  // 返回空字符串或其他错误处理方式
    }

    return QString(ipStr);
}
// 将 IPv6 地址转换为字符串表示
QString ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    if (sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sockaddr_in6 = (struct sockaddr_in6 *)sockaddr;
        inet_ntop(AF_INET6, &(sockaddr_in6->sin6_addr), address, addrlen);
        return QString(address);
    }
    return QString("Not an IPv6 address");
}

/* Print all the available information on the given interface */
void MainWindow::ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];

    /* Name */
    qDebug() << d->name;

    emit messageReceived(d->name);

    /* Description */
    if (d->description){
        qDebug() << "\tDescription: " << d->description;
        emit messageReceived("\tDescription: "+ QString(d->description));
    }


    /* Loopback Address*/
    qDebug() << "\tLoopback: " << ((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
    emit messageReceived("\tLoopback: "+ QString((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no"));

    /* IP addresses */
    for (a = d->addresses; a; a = a->next) {
        qDebug() << "\tAddress Family: #" << a->addr->sa_family;
        emit messageReceived("\tAddress Family: #"+ QString(a->addr->sa_family));

        switch (a->addr->sa_family) {
        case AF_INET:
            qDebug() << "\tAddress Family Name: AF_INET";
            emit messageReceived("\tAddress Family Name: AF_INET");
            if (a->addr){
                qDebug() << "\tAddress: " << iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                emit messageReceived("\tAddress: "+ iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));

            }

            if (a->netmask){
                qDebug() << "\tNetmask: " << iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                emit messageReceived("\tNetmask: "+ iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            }

            if (a->broadaddr){
                qDebug() << "\tBroadcast Address: " << iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
                emit messageReceived("\tBroadcast Address: "+ iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            }

            if (a->dstaddr){
                qDebug() << "\tDestination Address: " << iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr);
                emit messageReceived("\tDestination Address: "+ iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            }

            break;

        case AF_INET6:
            qDebug() << "\tAddress Family Name: AF_INET6";
            if (a->addr){
                qDebug() << "\tAddress: " << ip6tos(a->addr, ip6str, sizeof(ip6str));
                emit messageReceived("\tAddress: "+ ip6tos(a->addr, ip6str, sizeof(ip6str)));
            }

            break;

        default:
            qDebug() << "\tAddress Family Name: Unknown";
            emit messageReceived("\tAddress Family Name: Unknown");
            break;
        }
    }
    qDebug() << "\n";
    emit messageReceived("\n");
}



void MainWindow::onSButtonClicked()
{
    if(Capturing){
        pcap_breakloop(pcapHandle);
    }else{
        emit messageReceived("打开网络设备...");

        // 获取用户选择的网络设备名称
        QString selectedDeviceName = ui->comboBox->currentData().value<QString>();

        char errbuf[PCAP_ERRBUF_SIZE];
        pcapHandle = pcap_open_live(selectedDeviceName.toStdString().c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuf);
        if (pcapHandle == nullptr)
        {
            qDebug() << "无法打开网络设备: " << errbuf;
            QString errorMessage = QString::fromUtf8(errbuf);
            emit messageReceived("无法打开网络设备: "+errorMessage);
            return;
        }

        // 设置过滤器

        QString InputFilter = ui->lineEdit->text();
        QByteArray filterArray = InputFilter.toUtf8(); // 将QString转换为QByteArray
        const char* filterString = filterArray.constData();
        struct bpf_program filter;

        // 编译过滤器表达式
        if (pcap_compile(pcapHandle, &filter, filterString, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            emit messageReceived("Could not parse filter"+InputFilter+": "+pcap_geterr(pcapHandle));
            return;
        }
        // 应用过滤器
        if (pcap_setfilter(pcapHandle, &filter) == -1) {
            emit messageReceived("Could not install filter"+InputFilter+": "+pcap_geterr(pcapHandle));
            return;
        }

        // 初始化文件计数器
        fileCounter = 0;

        emit messageReceived("初始化缓存区域...");
        // 检查目录是否存在，如果不存在则创建
        QDir dir(QFileInfo(folderPath).absolutePath());
        if (!dir.exists()) {
            if (!dir.mkpath(QFileInfo(folderPath).absolutePath())) {
                qDebug() << "无法创建目录：" << QFileInfo(folderPath).absolutePath();
                emit messageReceived("无法创建目录: "+QFileInfo(folderPath).absolutePath());
                // 可以添加适当的错误处理逻辑
                return;
            }
        }
        packetCounter = 0;


        t1= std::thread(&MainWindow::startPcapLoop, this); // 建立一个新线程且执行函数
        t1.detach();//线程分离，不阻塞主线程

    }
}
void MainWindow::deleteTemp(){
    emit messageReceived("初始化缓存区域...");
    // 检查目录是否存在，如果不存在则创建
    QDir dir(QFileInfo(folderPath).absolutePath());
    if (!dir.exists()) {
        if (!dir.mkpath(QFileInfo(folderPath).absolutePath())) {
            qDebug() << "无法创建目录：" << QFileInfo(folderPath).absolutePath();
            emit messageReceived("无法创建目录: "+QFileInfo(folderPath).absolutePath());
            // 可以添加适当的错误处理逻辑
            return;
        }
    }
    QDir directory(folderPath);
    // 获取目录下的所有文件
    QStringList fileList = directory.entryList(QDir::Files);

    // 遍历文件列表并删除每个文件
    foreach(QString fileName, fileList)
    {
        QString filePath = directory.filePath(fileName);
        QFile file(filePath);

        // 尝试删除文件
        if (file.remove())
        {
            qDebug() << "已删除文件：" << filePath;
            emit messageReceived("已删除文件: "+filePath);
        }
        else
        {
            qDebug() << "无法删除文件：" << filePath;
            emit messageReceived("无法删除文件: "+filePath);
            // 在这里添加适当的错误处理逻辑
        }
    }
}
void MainWindow::startPcapLoop()
{
    Capturing=true;
    emit messageReceived("pcap_loop()后台执行中");
    int result = pcap_loop(pcapHandle, 0, &MainWindow::globalPacketHandler, reinterpret_cast<u_char*>(this));
    // 检查是否因为pcap_breakloop()而终止循环
    if (result == 0)
    {
        qDebug() << "pcap_loop()正常终止";
        emit messageReceived("pcap_loop()正常终止");
        pcap_close(pcapHandle);
    }
    else if (result == -1)
    {
        qDebug() << "pcap_loop()发生错误: " << pcap_geterr(pcapHandle);
        QString errorMessage = QString::fromUtf8(pcap_geterr(pcapHandle));
        emit messageReceived("pcap_loop()发生错误: "+ errorMessage);
        pcap_close(pcapHandle);
    }
    else if (result == -2)
    {
        qDebug() << "pcap_breakloop()触发的终止";
        emit messageReceived("pcap_breakloop()触发的终止");
        pcap_close(pcapHandle);
    }
    Capturing=false;

}


// 在 MainWindow.cpp 中实现全局函数
void MainWindow::globalPacketHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    MainWindow* instance = reinterpret_cast<MainWindow*>(userData);
    instance->packetHandler(userData, pkthdr, packet);
}


void MainWindow::packetHandler(unsigned char *userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    // 处理抓到的数据包
    qDebug() << "抓到一个数据包，长度：" << pkthdr->len << "字节";

    // 打印数据包的详细信息
    qDebug() << "时间戳：" << pkthdr->ts.tv_sec << "秒" << pkthdr->ts.tv_usec << "微秒";
    qDebug() << "捕获长度：" << pkthdr->caplen << "字节";

    // 获取IPv4头部
    ip_header *ih = (ip_header *)(packet + 14); // 偏移以太网头部

    // 获取源和目标IP地址及端口信息
    QString srcAddr = QString("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
    QString destAddr = QString("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);

    // 获取UDP头部
    u_int ipLen = (ih->ver_ihl & 0xf) * 4;
    udp_header *uh = (udp_header *)((u_char *)ih + ipLen);

    // 获取源和目标端口
    QString srcPort = QString::number(ntohs(uh->sport));
    QString destPort = QString::number(ntohs(uh->dport));
    QUuid uuid = QUuid::createUuid();
    // 将 UUID 转换为字符串形式
    QString uuidString = uuid.toString();
    // 创建文件名
    QString timestamp = QDateTime::fromSecsSinceEpoch(pkthdr->ts.tv_sec).toString("yyyyMMdd_HHmmss");
    QString fileName = QString("%1_%2_%3_%4_%5_%6.pcap").arg(timestamp).arg(srcAddr).arg(srcPort).arg(destAddr).arg(destPort).arg(uuidString);

    // 创建相对路径
    QString SavePath = QDir(folderPath).filePath(fileName);

    // 检查目录是否存在，如果不存在则创建
    QDir dir(QFileInfo(SavePath).absolutePath());
    if (!dir.exists()) {
        if (!dir.mkpath(QFileInfo(SavePath).absolutePath())) {
            qDebug() << "无法创建目录：" << QFileInfo(SavePath).absolutePath();
            emit messageReceived("无法创建目录: "+QFileInfo(SavePath).absolutePath());
            return;
        }
    }

    // 打开文件
    pcap_dumper_t *pcapDumperPerPacket = pcap_dump_open(pcapHandle, SavePath.toStdString().c_str());

    // 将数据包写入文件
    pcap_dump(reinterpret_cast<u_char*>(pcapDumperPerPacket), pkthdr, packet);

    // 关闭文件
    pcap_dump_close(pcapDumperPerPacket);

    // 增加文件计数器
    fileCounter++;

    packetCounter++;
    QString message = "抓到一个数据包，长度：" + QString::number(pkthdr->len) + "字节 喵~";
    emit messageReceived(message);
    qDebug() << "喵~";

}



// 实现输出字符串的函数
void MainWindow::printToConsole(const QString &message)
{
    // 获取当前行数
    int currentLines = ui->consoleOutput->document()->blockCount();

    // 如果当前行数超过最大行数，删除前面的旧信息
    if (currentLines >= maxConsoleLines)
    {
        QTextCursor cursor(ui->consoleOutput->document());
        cursor.movePosition(QTextCursor::Start);
        cursor.movePosition(QTextCursor::Down, QTextCursor::KeepAnchor, currentLines - maxConsoleLines + 1);
        cursor.removeSelectedText();
    }

    // 输出字符串到控制台区域
    ui->consoleOutput->appendPlainText(message);
}

MainWindow::~MainWindow()
{

    // 关闭文件和抓包会话
    if (pcapDumper != nullptr)
    {
        pcap_dump_close(pcapDumper);
    }

    if (pcapHandle != nullptr)
    {
        // 关闭抓包会话
        pcap_close(pcapHandle);
    }

    delete ui;
}
