#ifndef SNIFER11_H
#define SNIFER11_H

#include <QWidget>

namespace Ui {
class snifer11;
}

class snifer11 : public QWidget
{
    Q_OBJECT

public:
    explicit snifer11(QWidget *parent = 0);
    ~snifer11();

private slots:
    void on_analize_clicked();

    void on_findpocket_clicked();

    void on_pushButton_clicked();

private:
    Ui::snifer11 *ui;

};

struct pcaprec_hdr_s
{
        quint32 ts_sec;
        quint32 ts_usec;
        quint32 incl_len;
        quint32 orig_len;
};

struct pcap_hdr_s
{
        quint32 magic_number;
        quint16 version_major;
        quint16 version_minor;
        qint32  thiszone;
        quint32 sigfigs;
        quint32 snaplen;
        quint32 network;
};

class Deny
{
public:
    pcaprec_hdr_s pHeader;
    unsigned char data [10000];

};

class PacketStream {
public:
    pcap_hdr_s fHeader;
    QVector <Deny> packets;
};

#endif // SNIFER11_H
