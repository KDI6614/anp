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
int l=0;
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
     filein.read((char*)&ph.pHeader, 16);
     filein.read((char*)&ph.data, ph.pHeader.incl_len);
     fh.packets.append(ph);
    if((i!=24) and (fh.packets[l].pHeader.incl_len < min))
        min=fh.packets[l].pHeader.incl_len;


    if((i!=24) and (fh.packets[l].pHeader.incl_len > max))
        max=fh.packets[l].pHeader.incl_len;





    // вывод пакетов текст едит
    ui->textEdit->append("ЗАГОЛОВОК ПАКЕТА: " + QByteArray::number(l+1));
    ui->textEdit->append("Дата и время, когда этот пакет был захвачен - " + QByteArray::number(fh.packets[l].pHeader.ts_sec));
    ui->textEdit->append("Время в микросекундах, когда этот пакет был захвачен - " + QByteArray::number(fh.packets[l].pHeader.ts_usec));
    ui->textEdit->append("Количество байтов пакета, сохраненных в файле - " + QByteArray::number(fh.packets[l].pHeader.incl_len));
    ui->textEdit->append("Фактическая длина пакета - " + QByteArray::number(fh.packets[l].pHeader.orig_len));
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


    ui->textEdit->append("ПАКЕТНЫЕ ДАННЫЕ: ");
    ui->textEdit->append("\n");
    for (int t=0; t<fh.packets[l].pHeader.incl_len; t++)
    {
     ui->textEdit->insertPlainText(QString::number(fh.packets[l].data[t], 16)+" ");
     }
    ui->textEdit->append("\n");
    l=l+1;

    i=16+i+ph.pHeader.orig_len;



  }



    ui->textkol->setText(QByteArray::number(l));
    ui->textmin->setText(QByteArray::number(min));
    ui->textmax->setText(QByteArray::number(max));
    filein.close();




}


void snifer11::on_pushButton_clicked()
{


    QString tyt ;
    tyt = ui->textone->toPlainText();


    if ((tyt.toInt()) <= l and (tyt.toInt()!= 0))
  {
        ui->textpock->setText("");
        ui->textpock->append("ЗАГОЛОВОК ПАКЕТА: " + QByteArray::number(tyt.toInt()));
        ui->textpock->append("Дата и время, когда этот пакет был захвачен - " + QByteArray::number(fh.packets[tyt.toInt()-1].pHeader.ts_sec));
        ui->textpock->append("Время в микросекундах, когда этот пакет был захвачен - " + QByteArray::number(fh.packets[tyt.toInt()-1].pHeader.ts_usec));
        ui->textpock->append("Количество байтов пакета, сохраненных в файле - " + QByteArray::number(fh.packets[tyt.toInt()-1].pHeader.incl_len));
        ui->textpock->append("Фактическая длина пакета - " + QByteArray::number(fh.packets[tyt.toInt()-1].pHeader.orig_len));
        ui->textpock->append("ПАКЕТНЫЕ ДАННЫЕ: ");
        ui->textpock->append("\n");

        for (int t=0; t<fh.packets[tyt.toInt()-1].pHeader.incl_len; t++)
        {

        ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 16)+" ");

         }

  }
    else
       ui->textpock->setText("Takogo paketa net");

}
