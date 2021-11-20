#ifndef PACKET_H
#define PACKET_H

#pragma pack(1)
#include <QString>
#include <QHash>
#include "KagamiCore/RF protocol.h"

/*enum eRFFunction {
    rfNumberUnits = 0x00,
    rfGetDescription = 0x02,
    rfSetDescription = 0x03,

    rfSetKey = 0x10,
    rfSetAddress = 0x12,
    rfGetStatistics = 0x13,
    rfResetTransactionId = 0x14,
    rfNOP = 0x15,
    rfSetChannel = 0x16,
    rfSetMode = 0x17,
    rfGetBuildVersion = 0x20,
};*/

extern const QHash<fDataID, QString> functionName;


class Packet
{
public:
    Packet();
    static QByteArray parseHex(QString text);
    static QByteArray serializeRequest(uint8_t version, uint8_t transactionID, uint8_t unit, uint8_t function, QByteArray data);
    static QString parseBaseRequest(QByteArray packet);
    static QString ParseRequest(QByteArray packet);
    static QString parseBaseResponse(QByteArray packet);
    static QString ParseResponse(uint8_t unit, uint8_t function, QByteArray packet);
};

#endif // PACKET_H
