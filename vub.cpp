#include "vub.h"
#include "ui_vub.h"
#include "mainwindow.h"
#include "snifer11.h"
Vub::Vub(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Vub)
{
    ui->setupUi(this);
}

Vub::~Vub()
{
    delete ui;
}


void Vub::on_Butcal_clicked()
{
   mainwindow.show();
}

void Vub::on_Butpcap_clicked()
{

    Snif.show();
}
