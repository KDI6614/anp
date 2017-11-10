
#include "snifer11.h"
#include "ui_snifer11.h"
#include <QFile>
#include <QByteArray>
#include <QObject>
#include <QDebug>
#include <QFileDialog>
#include <QString>
snifer11::snifer11(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::snifer11)
{
    ui->setupUi(this);
}

snifer11::~snifer11()
{
    delete ui;
}
Deny ph;
PacketStream fh;
QString fName;
int ez[100000]; int l=0;
void snifer11::on_analize_clicked()
{
    // Вывод в файл

    fName = QFileDialog::getOpenFileName(0,"Open File:","","CAP files (*.cap)");
    if (fName=="")
        return ;
    QFile filein(fName);
    if (!filein.open(QIODevice::ReadOnly))
    {
        qDebug() << "Error while openning file";
        return ;
    }

  /*  QString dName = QFileDialog::getOpenFileName(0,"Open File:","","TXT files (*.txt)");
    if (dName=="")
        return ;
    QFile fileout(dName);
    if (!fileout.open(QIODevice::WriteOnly))
    {
        qDebug() << "Error while openning file";
        return ;
    }
*/





    filein.read((char*)&fh.fHeader, 24);

    // Вывод в ТекстЕдит


   ui->textEdit->append("ГЛОБАЛЬНЫЙ ЗАГОЛОВОК:");
   ui->textEdit->append("Число для определения самого формата файла и порядка байтов - " + QByteArray::number(fh.fHeader.magic_number));
   ui->textEdit->append("Номер версии этого файла: ");
   ui->textEdit->append("Основной номер версии - " + QByteArray::number(fh.fHeader.version_major));
   ui->textEdit->append("Неосновной номер версии - " + QByteArray::number(fh.fHeader.version_minor));
   ui->textEdit->append("Время коррекции - " + QByteArray::number(fh.fHeader.thiszone));
   ui->textEdit->append("Точность временных меток в захвате - " + QByteArray::number(fh.fHeader.sigfigs));
   ui->textEdit->append("Максимальная длина захваченных пакетов - " + QByteArray::number(fh.fHeader.snaplen));
   ui->textEdit->append("Тип линии передачи данных - " + QByteArray::number(fh.fHeader.network));
   ui->textEdit->append("\n");
   ui->textEdit->append("\n");


   // Вывод в файл

/*
    fileout.write("ГЛОБАЛЬНЫЙ ЗАГОЛОВОК:");
    fileout.write("\r\n");
    fileout.write("Число для определения самого формата файла и порядка байтов - ");
    fileout.write(QByteArray::number(fh.fHeader.magic_number));
    fileout.write("\r\n");
    fileout.write("Номер версии этого файла: ");
    fileout.write("\r\n");
    fileout.write("Основной номер версии - ");
    fileout.write(QByteArray::number(fh.fHeader.version_major));
    fileout.write("\r\n");
    fileout.write("Неосновной номер версии - ");
    fileout.write(QByteArray::number(fh.fHeader.version_minor));
    fileout.write("\r\n");
    fileout.write("Время коррекции - ");
    fileout.write(QByteArray::number(fh.fHeader.thiszone));
    fileout.write("\r\n");
    fileout.write("Точность временных меток в захвате - ");
    fileout.write(QByteArray::number(fh.fHeader.sigfigs));
    fileout.write("\r\n");
    fileout.write("Максимальная длина захваченных пакетов - ");
    fileout.write(QByteArray::number(fh.fHeader.snaplen));
    fileout.write("\r\n");
    fileout.write("Тип линии передачи данных - ");
    fileout.write(QByteArray::number(fh.fHeader.network));
    fileout.write("\r\n");
    fileout.write("\r\n");
*/

     int min = 999999, max = 0;

    for (int i=24; i<=filein.size();)
    {

    if((i!=24) and (ph.pHeader.orig_len < min))
        min=ph.pHeader.orig_len;


    if((i!=24) and (ph.pHeader.orig_len > max))
        max=ph.pHeader.orig_len;

    l=l+1;

    ez[l]=filein.pos();
    filein.read((char*)&ph.pHeader, 16);


    // вывод пакетов текст едит
    ui->textEdit->append("ЗАГОЛОВОК ПАКЕТА: " + QByteArray::number(l));
    ui->textEdit->append("Дата и время, когда этот пакет был захвачен - " + QByteArray::number(ph.pHeader.ts_sec));
    ui->textEdit->append("Время в микросекундах, когда этот пакет был захвачен - " + QByteArray::number(ph.pHeader.ts_usec));
    ui->textEdit->append("Количество байтов пакета, сохраненных в файле - " + QByteArray::number(ph.pHeader.incl_len));
    ui->textEdit->append("Фактическая длина пакета - " + QByteArray::number(ph.pHeader.orig_len));
    ui->textEdit->append("\n");

    // вывод в файл
    /*
    fileout.write("ЗАГОЛОВОК ПАКЕТА: ");
    fileout.write(QByteArray::number(l));
    fileout.write("\r\n");
    fileout.write("Дата и время, когда этот пакет был захвачен - ");
    fileout.write(QByteArray::number(ph.pHeader.ts_sec));
    fileout.write("\r\n");
    fileout.write("Время в микросекундах, когда этот пакет был захвачен - ");
    fileout.write(QByteArray::number(ph.pHeader.ts_usec));
    fileout.write("\r\n");
    fileout.write("Количество байтов пакета, сохраненных в файле - ");
    fileout.write(QByteArray::number(ph.pHeader.incl_len));
    fileout.write("\r\n");
    fileout.write("Фактическая длина пакета - ");
    fileout.write(QByteArray::number(ph.pHeader.orig_len));
    fileout.write("\r\n");
    fileout.write("\r\n");
    */

    filein.read((char*)&ph.data, ph.pHeader.orig_len);
    ui->textEdit->append("ПАКЕТНЫЕ ДАННЫЕ: ");
    ui->textEdit->append("\n");
    for (int t=0; t<ph.pHeader.orig_len; t++)
    {
    QString a;
    a=QString::number(ph.data[t]);
    int k=a.toInt();
    QString z=QString::number(k,16).toUpper();
    ui->textEdit->insertPlainText(z+" ");

     }
    ui->textEdit->append("\n");

    i=16+i+ph.pHeader.orig_len;



  }




    ui->textmin->append(QByteArray::number(min));
    ui->textmax->append(QByteArray::number(max));
    filein.close();




}


void snifer11::on_pushButton_clicked()
{


    QString tyt ;
    tyt = ui->textone->toPlainText();
    QFile filein(fName);
    int n = tyt.toInt();
    filein.seek(ez[n]);

    if (n <= l)
    {
    filein.read((char*)&ph.pHeader, 16);

    ui->textpock->setText("");
    ui->textpock->append("ЗАГОЛОВОК ПАКЕТА: " + QByteArray::number(n));
    ui->textpock->append("Дата и время, когда этот пакет был захвачен - " + QByteArray::number(ph.pHeader.ts_sec));
    ui->textpock->append("Время в микросекундах, когда этот пакет был захвачен - " + QByteArray::number(ph.pHeader.ts_usec));
    ui->textpock->append("Количество байтов пакета, сохраненных в файле - " + QByteArray::number(ph.pHeader.incl_len));
    ui->textpock->append("Фактическая длина пакета - " + QByteArray::number(ph.pHeader.orig_len));
    ui->textpock->append("\n");

    filein.read((char*)&ph.data, ph.pHeader.orig_len);
    ui->textpock->append("ПАКЕТНЫЕ ДАННЫЕ: ");
    ui->textpock->append("\n");
    for (int t=0; t<ph.pHeader.orig_len; t++)
    {
    QString a;
    a=QString::number(ph.data[t]);
    int k=a.toInt();
    QString z=QString::number(k,16).toUpper();
    ui->textpock->insertPlainText(z+" ");
   }
  }
    else
       ui->textpock->setText("Takogo paketa net");

}
