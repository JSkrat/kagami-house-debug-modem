#include "packet.h"
extern "C" {
    #include "KagamiCore/RF protocol.h"
    #include "KagamiCore/RF functions.h"
}
#include <QMap>
#include <QHash>
#include <QString>

uint qHash(const fDataID &struc) {
    return struc.byte;
}

bool operator==(const fDataID &p1, const fDataID &p2) {
    return (p1.byte == p2.byte);
}


bool qMapLessThanKey(const fDataID &key1, const fDataID &key2)
{
    return (key1.data.dataId | (key1.data.type << 7)) <
            (key2.data.dataId | (key2.data.type << 7));
}

const QMap<fDataID, QString> functionName = {
    {{.data = {.type = ediNode, .dataId = eFProperties}}, "info"},
    {{.data = {.type = ediNode, .dataId = eFTextDescription}}, "text description"},

    {{.data = {.type = ediNode, .dataId = eFSessionKey}}, "set key"},
    {{.data = {.type = ediNode, .dataId = eFAddress}}, "set address"},
    {{.data = {.type = ediNode, .dataId = eFStatistics}}, "get statistics"},
    {{.data = {.type = ediNode, .dataId = eFRFChannel}}, "set channel"},
    {{.data = {.type = ediNode, .dataId = eFMode}}, "set mode"},

    {{.data = {.type = ediMethod, .dataId = eFNOP}}, "nop"},
    {{.data = {.type = ediMethod, .dataId = eFResetTransactionId}}, "reset transaction id"},
};
/*const QHash<fDataID, QString> functionName = {

};*/

const QHash<uint8_t, QString> responseCode = {
    {ercOk, "ok"},
    {ercNotImplemented, "function is not implemented"},
    {ercBadVersion, "bad protocol version"},
    {ercBadUnitId, "bad unit number"},
    {ercNotConsecutiveTransactionId, "bad transaction id"},
    {ercBadFunctionId, "bad function number"},
    {ercResponseTooBig, "response is too big"},
    {ercBadRequestData, "bad request data"},
    {ercNodePermissionViolation, "node permission violation"},
    {ercBadArguments, "bad arguments"},
    {ercInternalError, "firmware internal error"},
};

const QHash<uint8_t, QString> dataType = {
    {edtNone, "none"},
    {edtBool, "bool"},
    {edtByte, "byte"},
    {edtInt32, "int32"},
    {edtString, "string"},
    {edtByteArray, "byte array"},
    {edtUnspecified, "unspecified"},
};

Packet::Packet()
{

}

QByteArray Packet::parseHex(QString text)
{
    QByteArray ret;
    if ("" == text) return ret;
    for (QString b: text.split(":")) {
        ret.append(static_cast<char>(b.toInt(nullptr, 16)));
    }
    return ret;
}

QByteArray Packet::serializeRequest(uint8_t version, uint8_t transactionID, uint8_t unit, uint8_t function, QByteArray data)
{
    if (28 < data.length()) throw std::runtime_error("data can not be longer than 28 bytes");
    QByteArray ret;
    ret.append(version);
    ret.append(transactionID);
    ret.append(unit);
    ret.append(function);
    ret.append(data);
    return ret;
}

QString Packet::parseBaseRequest(QByteArray packet)
{
    if (4 > packet.length()) throw std::runtime_error("request packet can not be shorter than 4 bytes");
    if (32 < packet.length()) throw std::runtime_error("request packet can not be longer than 32 bytes");
    QString function = "unknown";
    fDataID packetDataId = {.byte = static_cast<uint8_t>(packet.at(3))};
    if (functionName.contains(packetDataId)) {
        function = functionName[packetDataId];
    }
    QString dataType = "node";
    if (ediMethod == packetDataId.data.type) dataType = "func";
    return QString("V%1 T%2, unit %3, %4 %5 (0x%6)")
            .arg(static_cast<uint8_t>(packet[0]), 2, 16, QChar('0'))
            .arg(static_cast<uint8_t>(packet[1]), 2, 16, QChar('0'))
            .arg(static_cast<uint8_t>(packet[2]), 2, 16, QChar('0'))
            .arg(dataType)
            .arg(function)
            .arg(static_cast<uint8_t>(packet[3]), 2, 16, QChar('0'))
            ;
}

QString Packet::ParseRequest(QByteArray packet)
{
    QString base = Packet::parseBaseRequest(packet);
    QString data;
    fDataID packetDataId = {.byte = static_cast<uint8_t>(packet[3])};
    if (ediNode == packetDataId.data.type) {
        switch (packetDataId.data.dataId) {
        case eFTextDescription: {
            data = QString::fromUtf8(packet.mid(4));
            break;
        }
        case eFSessionKey: {
            data = QString("type 0x%1 key %2")
                    .arg(static_cast<uint8_t>(packet[4]), 2, 16, QChar('0'))
                    .arg(QString(packet.mid(5).toHex(':')))
                    ;
            break;
        }
        case eFAddress: {
            if (4 + 5 != packet.length()) throw std::runtime_error("incorrect payload length");
            data = "addr " + packet.mid(4).toHex(':');
            break;
        }
        case eFRFChannel: {
            if (4 + 1 != packet.length()) throw std::runtime_error("incorrect payload length");
            data = QString("channel 0x%1").arg(static_cast<uint8_t>(packet[4]));
            break;
        }
        case eFMode: {
            if (4 + 1 != packet.length()) throw std::runtime_error("incorrect payload length");
            switch (packet[4]) {
            case 1: {
                data = "adv mode";
                break;
            }
            case 2: {
                data = "normal mode";
                break;
            }
            default: {
                data = "incorrect mode";
                break;
            }
            }
            break;
        }
        default: break;
        }
    } else {
        // methods
    }
    if ("" != data) data = ", " + data;
    return base + data;
}

QString Packet::parseBaseResponse(QByteArray packet)
{
    if (3 > packet.length()) throw std::runtime_error("response packet can not be shorter than 3 bytes");
    if (32 < packet.length()) throw std::runtime_error("response packet can not be longer than 32 bytes");
    QString code = "";
    if (responseCode.contains(packet[2])) {
        code = " " + responseCode[packet[2]];
    }
    return QString("V%1 T%2, code %4 (0x%3)")
            .arg(static_cast<uint8_t>(packet[0]), 2, 16, QChar('0'))
            .arg(static_cast<uint8_t>(packet[1]), 2, 16, QChar('0'))
            .arg(static_cast<uint8_t>(packet[2]), 2, 16, QChar('0'))
            .arg(code)
            ;
}

QString Packet::ParseResponse(uint8_t unit, uint8_t function, QByteArray packet)
{
    QString base = Packet::parseBaseResponse(packet);
    if (0x80 <= static_cast<uint8_t>(packet[2])) return base;
    QString data = "";
    fDataID dataId = {.byte = function};
    if (ediNode == dataId.data.type) {
        switch (dataId.data.dataId) {
        case eFProperties: {
            if (3 + 2 > packet.length()) throw std::runtime_error("too short payload");
            if (0 == unit) {
                data = QString("units %1, serial %2")
                        .arg(static_cast<uint8_t>(packet[3]))
                        .arg(QString(packet.mid(4).toHex(':')))
                        ;
            } else {
                if ((packet.length()-3) % 2 != 0) throw std::runtime_error("incorrect payload length");
                for (int i = 3; i < packet.length(); i += 2) {
                    fDataID dataId = {.byte = static_cast<uint8_t>(packet[i])};
                    if (ediMethod == dataId.data.type) {
                        int input = packet[i+1] >> 4;
                        int output = packet[i+1] & 0x0F;
                        QString inp = "?"; QString outp = "?";
                        if (dataType.contains(input)) inp = dataType[input];
                        if (dataType.contains(output)) outp = dataType[output];
                        if (3 < i) data += "\n";
                        data += QString("func %1(%2): %3")
                                .arg(static_cast<uint8_t>(packet[i]), 2, 16, QChar('0'))
                                .arg(inp)
                                .arg(outp)
                                ;
                    } else {
                        QString rw;
                        switch ((packet[i+1] & 0xE0) >> 6) {
                        case 0: rw = "no access???"; break;
                        case 1: rw = "WO"; break;
                        case 2: rw = "RO"; break;
                        case 3: rw = "RW"; break;
                        }
                        int dataTypeValue = packet[i+1] & 0x0F;
                        QString dataTypeName = "?";
                        if (dataType.contains(dataTypeValue)) dataTypeName = dataType[dataTypeValue];
                        if (3 < i) data += "\n";
                        data += QString("node %1(%2) %3")
                                .arg(static_cast<uint8_t>(packet[i]), 2, 16, QChar('0'))
                                .arg(dataTypeName)
                                .arg(rw);
                    }
                }
            }
            break;
        }
        case eFTextDescription: {
            data = QString::fromUtf8(packet.mid(3));
            break;
        }
        case eFStatistics: {
            if (3+12 != packet.length()) throw std::runtime_error("incorrect payload length");
            data = QString("Requests %1 \nResponses %2 \nError %3 \nTransaction errors %4 \nAck t/o %5 \nValidation errors %6")
                    .arg(packet[3] + packet[4]*256)
                    .arg(packet[5] + packet[6]*256)
                    .arg(packet[7] + packet[8]*256)
                    .arg(packet[9] + packet[10]*256)
                    .arg(packet[11] + packet[12]*256)
                    .arg(packet[13] + packet[14]*256)
                    ;
            break;
        }
        default: break;
        }
    } else {
        // methods
    }
    return base + "\n" + data;
}
