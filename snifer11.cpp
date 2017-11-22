#include "snifer11.h"
#include "ui_snifer11.h"
#include <QFile>
#include <QByteArray>
#include <QObject>
#include <QDebug>
#include <QFileDialog>
#include <QString>
#include <QTableWidget>

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
QTableWidgetItem *itm;
int l;
void snifer11::on_analize_clicked()
{
    // Вывод в файл
    l=0;
    fName = QFileDialog::getOpenFileName(0,"Open File:","","CAP files (*.cap)");
    if (fName=="")
        return ;
    QFile filein(fName);
    if (!filein.open(QIODevice::ReadOnly))
    {
        qDebug() << "Error while openning file";
        return ;
    }


    filein.read((char*)&fh.fHeader, 24);

    // Вывод в ТекстЕдит

   ui->textEdit->setText("");
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


   ui->tableWidget->setColumnCount(10);
   ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "Время 1" << "Время 2" << "Incl len" << "Orig len"<<"Конечный МАС"<<"Исходный МАС"<<"Источник"<<"Получатель"<<"Порт иточника"<<"Порт приемника");

     int min = 999999, max = 0;

    for (int i=24; i<filein.size();)
    {
     filein.read((char*)&ph.pHeader, 16);


     ph.data = new unsigned char[ph.pHeader.incl_len];




     filein.read((char*)ph.data, ph.pHeader.incl_len);


     fh.packets.append(ph);



     if(fh.packets[l].pHeader.incl_len < min)
        min=fh.packets[l].pHeader.incl_len;


    if (fh.packets[l].pHeader.incl_len > max)
        max=fh.packets[l].pHeader.incl_len;


    ui->tableWidget->setRowCount(l+1);

    ui->tableWidget->setItem(l,0, itm = new QTableWidgetItem(tr("%1").arg(fh.packets[l].pHeader.ts_sec)));
    ui->tableWidget->setItem(l,1, itm = new QTableWidgetItem(tr("%1").arg(fh.packets[l].pHeader.ts_usec)));
    ui->tableWidget->setItem(l,2, itm = new QTableWidgetItem(tr("%1").arg(fh.packets[l].pHeader.incl_len)));
    ui->tableWidget->setItem(l,3, itm = new QTableWidgetItem(tr("%1").arg(fh.packets[l].pHeader.orig_len)));

     QString macp = "";
    for (int t=0; t<6; t++)
    {


        QString l1 = QString::number(fh.packets[l].data[t], 10);
        if ((l1.toInt()>=0) and (l1.toInt()<16))
        {
        macp = macp + "0" + QString::number(fh.packets[l].data[t], 16).toUpper();
        if (t!=5)
            macp = macp + ":";
        }
        else
        {
        macp = macp + QString::number(fh.packets[l].data[t], 16).toUpper();
        if (t!=5)
            macp = macp + ":";
        }

    }
   ui->tableWidget->setItem(l,4, itm = new QTableWidgetItem);
   itm->setText(macp);




   macp = "";
  for (int t=6; t<12; t++)
  {
      QString l1 = QString::number(fh.packets[l].data[t], 10);
      if ((l1.toInt()>=0) and (l1.toInt()<16))
      {
      macp = macp + "0" + QString::number(fh.packets[l].data[t], 16).toUpper();
      if (t!=11)
          macp = macp + ":";
      }
      else
      {
      macp = macp + QString::number(fh.packets[l].data[t], 16).toUpper();
      if (t!=11)
          macp = macp + ":";
      }

  }

 ui->tableWidget->setItem(l,5, itm = new QTableWidgetItem);
 itm->setText(macp);


 macp = "";
     QString l1 = QString :: number(fh.packets[l].data[12], 16);
     QString l2 = QString :: number (fh.packets[l].data[13], 16);

     if((l1.toInt()==8) and (l2.toInt()==0))
     {
    QString l1 = QString :: number(fh.packets[l].data[14], 16);
    int k1 = l1.toInt();
    k1 = k1 / 10;
    int k2 = (l1.toInt() -  k1*10)*4;

   for (int t=6+k2; t<10+k2; t++)
   {
       macp = macp + QString::number(fh.packets[l].data[t], 10).toUpper();
       if (t!=9+k2)
           macp = macp + ".";
       }

   ui->tableWidget->setItem(l,6, itm = new QTableWidgetItem);
   itm->setText(macp);

  macp = "";
   for (int t=10+k2; t<14+k2; t++)
   {
       macp = macp + QString::number(fh.packets[l].data[t], 10).toUpper();
       if (t!=13+k2)
           macp = macp + ".";
       }

  ui->tableWidget->setItem(l,7, itm = new QTableWidgetItem);
  itm->setText(macp);


  k1 = (QString::number(fh.packets[l].data[3+k2],16)).toInt();

    if ((k1==6) or (k1==11))
    {
    l1 = QString::number(fh.packets[l].data[14+k2],16) + QString::number(fh.packets[l].data[15+k2],16);
    ui->tableWidget->setItem(l,8,itm = new QTableWidgetItem);
    itm->setText(QString :: number (l1.toInt(0,16),10));

    l1 = QString::number(fh.packets[l].data[16+k2],16) + QString::number(fh.packets[l].data[17+k2],16);
    ui->tableWidget->setItem(l,9,itm = new QTableWidgetItem);
    itm->setText(QString :: number (l1.toInt(0,16),10));

}
    else
    {
        ui->tableWidget->setItem(l, 8 , itm = new QTableWidgetItem);
        itm->setText("НЕ TCP, НЕ UDP");
        ui->tableWidget->setItem(l, 9 , itm = new QTableWidgetItem);
        itm->setText("НЕ TCP, НЕ UDP");
    }

}
   else
     {
     ui->tableWidget->setItem(l, 6 , itm = new QTableWidgetItem);
     itm->setText("НЕ IP");
     ui->tableWidget->setItem(l, 7 , itm = new QTableWidgetItem);
     itm->setText("НЕ IP");
     ui->tableWidget->setItem(l, 8 , itm = new QTableWidgetItem);
     itm->setText("НЕ TCP, НЕ UDP");
     ui->tableWidget->setItem(l, 9 , itm = new QTableWidgetItem);
     itm->setText("НЕ TCP, НЕ UDP");
     }

    l=l+1;
    i=16+i+ph.pHeader.incl_len;

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


        ui->textpock->append("\n");
        ui->textpock->append("ПАКЕТНЫЕ ДАННЫЕ: \n");


        for (int t=0; t<fh.packets[tyt.toInt()-1].pHeader.incl_len; t++)
        {

        ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 16)+" ");

         }
        ui->textpock->append("\n");
        ui->textpock->append("ПРОТОКОЛ ETHERNET: ");

        ui->textpock->append("Конечный MAC адрес: ");



        for (int t=0; t<6; t++)
        {
         ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 16)+" ");
         }


        ui->textpock->append("Исходный МАС-адрес: ");

        for (int t=6; t<12; t++)
        {
         ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 16)+" ");
         }


        ui->textpock->append("Длина/Тип: ");

        for (int t=12; t<14; t++)
        {
         ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 16)+" ");
         }


         QString l1 = QString :: number(fh.packets[tyt.toInt()-1].data[12], 16);
         QString l2 = QString :: number (fh.packets[tyt.toInt()-1].data[13], 16);

         if((l1.toInt()==8) and (l2.toInt()==0))
         {
           ui->textpock->append("ПРОТОКОЛ IP: ");

        QString l1 = QString :: number(fh.packets[tyt.toInt()-1].data[14], 16);

        int k1 = l1.toInt();
        k1 = k1 / 10;
        int k2 = (l1.toInt() -  k1*10)*4;

        ui->textpock->append("Версия: ");
        ui->textpock->insertPlainText(QString::number(k1));
        ui->textpock->append("Количество байт: ");
        ui->textpock->insertPlainText(QString::number(k2));


        ui->textpock->append("Источник: ");
        for (int t=6+k2; t<10+k2;t++)

        {

         ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 10));
         if (t!=9+k2)
          ui->textpock->insertPlainText(".");
         }


        ui->textpock->append("Получатель: ");

        for (int t=10+k2; t<14+k2;t++)

        {

         ui->textpock->insertPlainText(QString::number(fh.packets[tyt.toInt()-1].data[t], 10));
         if (t!=13+k2)
          ui->textpock->insertPlainText(".");
         }

        k1 = (QString::number(fh.packets[tyt.toInt()-1].data[3+k2],16)).toInt();
        if (k1==6)
           {
         ui->textpock->append("ПРОТОКОЛ TCP: ");
         ui->textpock->append("Порт источника: ");

         l1 = QString::number(fh.packets[tyt.toInt()-1].data[14+k2],16) + QString::number(fh.packets[tyt.toInt()-1].data[15+k2],16);
         ui->textpock->insertPlainText(QString :: number (l1.toInt(0,16), 10));


         ui->textpock->append("Порт приемника: ");

         l1 = QString::number(fh.packets[tyt.toInt()-1].data[16+k2],16) + QString::number(fh.packets[tyt.toInt()-1].data[17+k2],16);
         ui->textpock->insertPlainText(QString :: number (l1.toInt(0,16), 10));


        }
        else
        if (k1==11)
        {
            ui->textpock->append("ПРОТОКОЛ UDP: ");
            ui->textpock->append("Порт источника: ");

            l1 = QString::number(fh.packets[tyt.toInt()-1].data[14+k2],16) + QString::number(fh.packets[tyt.toInt()-1].data[15+k2],16);
            ui->textpock->insertPlainText(QString :: number (l1.toInt(0,16), 10));


            ui->textpock->append("Порт приемника: ");

            l1 = QString::number(fh.packets[tyt.toInt()-1].data[16+k2],16) + QString::number(fh.packets[tyt.toInt()-1].data[17+k2],16);
            ui->textpock->insertPlainText(QString :: number (l1.toInt(0,16), 10));

        }
        else
             ui->textpock->append("Другой протокол");

            }

         else
             ui->textpock->append("Другой протокол");
        }
      else
       ui->textpock->setText("Takogo paketa net");

}
