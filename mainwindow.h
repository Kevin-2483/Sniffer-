#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap.h>
#include <QTableWidgetItem>
#include "newwindow.h"  // 新窗口类的头文件


QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    static void globalPacketHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void populateNetworkDevices();  // 声明用于填充网络设备的函数
    void packetHandler(unsigned char *userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);
    void printToConsole(const QString &message);
    void ifprint(pcap_if_t *d);

signals:
    void messageReceived(const QString &message);
private:
    Ui::MainWindow *ui;
    pcap_t *pcapHandle;
private:
    int packetCounter;  // 计数器，记录抓到的包数量
    int maxConsoleLines;
    NewWindow *newWindow;  // 新窗口类的指针
public slots:
    void onRButtonClicked();
    void onSButtonClicked();
    void onAButtonClicked();
    void onDButtonClicked();
    void on_pushButton_clicked();
    void startPcapLoop();
    void onButtonClicked();
    void deleteTemp();
};
#endif




