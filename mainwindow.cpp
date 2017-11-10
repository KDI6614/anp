#include "mainwindow.h"
#include "ui_mainwindow.h"
QString value;
int Sum;
bool plusbool, minusbool, umnbool, delbool;
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_But1_clicked()
{
value = value + "1";
ui->textEdit->setText(value);
}

void MainWindow::on_But2_clicked()
{
    value = value + "2";
    ui->textEdit->setText(value);
}

void MainWindow::on_But3_clicked()
{
    value = value + "3";
    ui->textEdit->setText(value);
}

void MainWindow::on_But4_clicked()
{
    value = value + "4";
    ui->textEdit->setText(value);
}

void MainWindow::on_But5_clicked()
{
    value = value + "5";
    ui->textEdit->setText(value);
}

void MainWindow::on_But6_clicked()
{
    value = value + "6";
    ui->textEdit->setText(value);
}

void MainWindow::on_But7_clicked()
{
    value = value + "7";
    ui->textEdit->setText(value);
}

void MainWindow::on_But8_clicked()
{
    value = value + "8";
    ui->textEdit->setText(value);
}

void MainWindow::on_But9_clicked()
{
    value = value + "9";
    ui->textEdit->setText(value);
}

void MainWindow::on_But0_clicked()
{
    value = value + "0";
    ui->textEdit->setText(value);
}

void MainWindow::on_plus_clicked()
{
    Sum=value.toInt();
    value="";
    ui->textEdit->setText("");
    plusbool = true;
}

void MainWindow::on_minus_clicked()
{
    Sum=value.toInt();
    value="";
    ui->textEdit->setText("");
    minusbool = true;
}

void MainWindow::on_Umn_clicked()
{
    Sum=value.toInt();
    value="";
    ui->textEdit->setText("");
    umnbool = true;
}

void MainWindow::on_del_clicked()
{
    Sum=value.toInt();
    value="";
    ui->textEdit->setText("");
    delbool = true;
}

void MainWindow::on_ravno_clicked()
{
    if (plusbool)
    {
        Sum=Sum + value.toInt();
        value = QString::number(Sum);
        ui->textEdit->setText(value);
        Sum=0;
        plusbool = false;

    }
    if (minusbool)
    {
        Sum=Sum - value.toInt();
        value = QString::number(Sum);
        ui->textEdit->setText(value);
        Sum=0;
        minusbool = false;

    }
    if (delbool)
    {
        Sum=Sum / value.toInt();
        value = QString::number(Sum);
        ui->textEdit->setText(value);
        Sum=0;
        delbool = false;

    }
    if (umnbool)
    {
        Sum=Sum * value.toInt();
        value = QString::number(Sum);
        ui->textEdit->setText(value);
        Sum=0;
        umnbool = false;

    }

}


void MainWindow::on_actionMenuCalculator_triggered()
{
   form.show();

}

void MainWindow::on_Clear_clicked()
{
    value = "";
    Sum = 0;
    ui->textEdit->setText(value);
}
