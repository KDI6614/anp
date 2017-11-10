#include "vub.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Vub w;
    w.show();

    return a.exec();
}
