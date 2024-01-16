QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    TCPParser.cpp \
    UDPParser.cpp \
    main.cpp \
    mainwindow.cpp \
    newwindow.cpp

HEADERS += \
    ProtocolParser.h \
    TCPParser.h \
    UDPParser.h \
    mainwindow.h \
    newwindow.h

FORMS += \
    mainwindow.ui \
    newwindow.ui

TRANSLATIONS += \
    sniffer_zh_CN.ts
CONFIG += lrelease
CONFIG += embed_translations

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -L$$PWD/npcap-sdk/Lib/x64/ -lPacket
INCLUDEPATH += $$PWD/npcap-sdk/Include
DEPENDPATH += $$PWD/npcap-sdk/Include
win32: LIBS += -L$$PWD/npcap-sdk/Lib/x64/ -lwpcap
LIBS += -lws2_32
INCLUDEPATH += $$PWD/npcap-sdk/Include
DEPENDPATH += $$PWD/npcap-sdk/Include

RC_ICONS = OIG-_2_.ico
