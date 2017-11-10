#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <form.h>
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_But1_clicked();

    void on_But2_clicked();

    void on_But3_clicked();

    void on_But4_clicked();

    void on_But5_clicked();

    void on_But6_clicked();

    void on_But7_clicked();

    void on_But8_clicked();

    void on_But9_clicked();

    void on_But0_clicked();

    void on_plus_clicked();

    void on_minus_clicked();

    void on_Umn_clicked();

    void on_del_clicked();

    void on_ravno_clicked();

    void on_actionMenuCalculator_triggered();

    void on_Clear_clicked();

private:
    Ui::MainWindow *ui;
    Form form;
};

#endif // MAINWINDOW_H
