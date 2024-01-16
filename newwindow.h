#ifndef NEWWINDOW_H
#define NEWWINDOW_H
#include <QMainWindow>
#include <QStandardItemModel>



QT_BEGIN_NAMESPACE
namespace Ui {
class NewWindow;
}
QT_END_NAMESPACE

class NewWindow : public QMainWindow
{
    Q_OBJECT

public:
    NewWindow(QWidget *parent = nullptr);
    ~NewWindow();
private:
    Ui::NewWindow *ui;
    QStandardItemModel *model;


public slots:
    void onNRButtonClicked();
    void onTableClicked(const QModelIndex &index);
    void parsePcapFile(const QString &filePath);

};
#endif
