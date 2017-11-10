#ifndef VUB_H
#define VUB_H
#include <mainwindow.h>
#include <QWidget>
#include <snifer11.h>

namespace Ui {
class Vub;
}

class Vub : public QWidget
{
    Q_OBJECT

public:
    explicit Vub(QWidget *parent = 0);
    ~Vub();

private slots:
    void on_Butpcap_clicked();

    void on_Butcal_clicked();

private:
    Ui::Vub *ui;
    MainWindow mainwindow;
    snifer11 Snif;
};

#endif // VUB_H
