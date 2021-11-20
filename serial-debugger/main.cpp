#pragma pack(1)
#include "mainwindow.h"

#include <QApplication>

MainWindow *window;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    window = &w;
    w.show();
    return a.exec();
}
