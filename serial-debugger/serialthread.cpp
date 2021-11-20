#pragma pack(1)
#include "serialthread.h"
#include <QSerialPort>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <QTime>
#include <algorithm>

SerialThread::SerialThread(QObject *parent) : QThread(parent)
{
    this->m_quit = false;
    this->m_waitTimeout = 10000;
    // initialize parsing
    this->init();
    this->esc = false;
    this->state = epsEnd;
    // start the thread ("run" method)
    this->start();
}

SerialThread::~SerialThread() {
    this->m_mutex.lock();
    this->m_quit = true;
    this->m_cond.wakeAll();
    this->m_mutex.unlock();
    wait();
}

void SerialThread::transaction(const QString &portName, int waitTimeout, const QByteArray &request)
{
    this->m_mutex.lock();
    this->msgQueue.enqueue(Message(request, portName, waitTimeout));
    this->m_cond.wakeAll();
    this->m_mutex.unlock();
}

int SerialThread::getQueueSize()
{
    return this->msgQueue.size();
}

void SerialThread::run()
{
    bool currentPortNameChanged = false;
    QString currentPortName;
    int currentWaitTimeout = 0;
    QSerialPort serial;

    while (!this->m_quit) {
        this->m_mutex.lock();
        if (this->msgQueue.isEmpty()) {
            m_cond.wait(&this->m_mutex);
            // we have to re-check if queue is not empty even if mutex was unlocked
            this->m_mutex.unlock();
            continue;
        }
        Message *msg = &(this->msgQueue.head());
        this->m_mutex.unlock();
        if (currentPortName != msg->portName) {
            currentPortName = msg->portName;
            currentPortNameChanged = true;

            if (currentPortName.isEmpty()) {
                emit this->error(tr("No port name specified"));
                this->syncDequeue();
                continue;
            }
        } else {
            currentPortNameChanged = false;
        }
        currentWaitTimeout = msg->waitTimeout;

        if (currentPortNameChanged) {
            serial.close();
            serial.setPortName(currentPortName);
            serial.setBaudRate(200000);

            if (!serial.open(QIODevice::ReadWrite)) {
                emit this->error(tr("Can't open %1, error code %2")
                           .arg(currentPortName).arg(serial.error()));
                this->syncDequeue();
                continue;
            }
        }
        // write request
        serial.write(this->stuffBytes(msg->request));
        if (serial.waitForBytesWritten(currentWaitTimeout)) {
            // read response
            if (serial.waitForReadyRead(currentWaitTimeout)) {
                QByteArray responseData = serial.readAll();
                while (serial.waitForReadyRead(currentWaitTimeout))
                    responseData += serial.readAll();
                // unstuff here <--
                for (char c: responseData) {
                    this->parseByte(static_cast<uint8_t>(c));
                }
            } else {
                emit this->timeout(tr("Wait read response timeout %1")
                             .arg(QTime::currentTime().toString()));
            }
        } else {
            emit this->timeout(tr("Wait write request timeout %1")
                         .arg(QTime::currentTime().toString()));
        }
        this->syncDequeue();
    }
}

void SerialThread::init()
{
    this->responseCode = 0xFF;
    this->responseCommand = 0xFF;
    this->currentPacketLength = 0;
    this->currentResponse.clear();
}

void SerialThread::syncDequeue()
{
    this->m_mutex.lock();
    this->msgQueue.dequeue();
    this->m_mutex.unlock();
}

void SerialThread::parseByte(uint8_t byte) {
#define sbyte static_cast<char>(byte)
//    static unsigned int currentPacketLength = 0;

    switch (static_cast<uint8_t>(byte)) {
    case 0xC0: {
        this->esc = false;
        if (epsError == this->state) {
            // ignore, we already emitted signal about that
        } else if (epsEnd != this->state) {
            this->emitError(QString("Byte unstuffing error: received 0xC0 in not-end (%1) state.").arg(this->state));
        }
        this->state = epsHeader;
        break;
    }
    case 0xDB: {
        if (this->esc) {
            this->emitError("Byte unstuffing error, 0xDB twice in a row");
            this->state = epsError;
            return;
            break;
        }
        this->esc = true;
        return;
        break;
    }
    case 0xDC: {
        if (this->esc) {
            byte = 0xC0;
            this->esc = false;
        }
        break;
    }
    case 0xDD: {
        if (this->esc) {
            byte = 0xDB;
            this->esc = false;
        }
        break;
    }
    }

    // now lets parse packet itself
    switch (this->state) {
    case epsHeader: {
        if (0xC0 != byte) {
            this->emitError("Response parsing error: parser in header state at not 0xC0 byte");
            this->state = epsError;
            return;
        } else {
            this->init();
            this->state = epsVersion;
        }
        break;
    }
    case epsVersion: {
        if (0x00 != byte) {
            this->emitError(QString("Response parsing error: protocol version is %s, not 0x00").arg(byte, 2, 16));
            this->state = epsError;
            return;
        } else {
            this->state = epsCommand;
        }
        break;
    }
    case epsCommand: {
        if (0 == (0x80 & byte)) {
            this->emitError("Response parsing error: command in response has msb zero");
            this->state = epsError;
            return;
        } else {
            this->responseCommand = byte & 0x7F;
            this->state = epsResponseCode;
        }
        break;
    }
    case epsResponseCode: {
        this->responseCode = byte;
        this->state = epsLength;
        break;
    }
    case epsLength: {
        // no validation for length until end of packet
        this->currentPacketLength = byte;
        this->state = epsData;
        if (0 == this->currentPacketLength) goto parseData;
        break;
    }
    case epsData: {
        // we can validate length here \0/
        if (static_cast<unsigned int>(this->currentResponse.length()) >= this->currentPacketLength) {
            this->emitError("Response parsing error: length is less than bytes received");
            this->state = epsError;
            return;
        } else {
            this->currentResponse.append(sbyte);
parseData:
            if (static_cast<unsigned int>(this->currentResponse.length()) == this->currentPacketLength) {
                emit this->response(
                            this->responseCommand,
                            this->responseCode,
                            this->currentResponse
                        );
                // switch to error, because next byte should be either 0xC0 or be ignored
                this->state = epsEnd;
            }
        }
        break;
    }
    case epsError:
    case epsEnd: {
        // silently ignore
        break;
    }
    }
}

void SerialThread::emitError(QString message)
{
    emit this->error(
                QString("%1\nResponse command is %2, code is %3, buffer contents is %4")
                .arg(message)
                .arg(this->responseCommand, 2, 16)
                .arg(this->responseCode, 2, 16)
                .arg(QString(this->currentResponse.toHex(':')))
                );
}

QByteArray SerialThread::stuffByte(int8_t byte)
{
    QByteArray ret;
    if ('\xC0' == byte) {
        ret.append('\xDB');
        ret.append('\xDC');
    } else if ('\xDB' == byte) {
        ret.append('\xDB');
        ret.append('\xDD');
    } else {
        ret.append(byte);
    }
    return ret;
}

QByteArray SerialThread::stuffBytes(const QByteArray &from)
{
    if (255 <= from.length()) {
        throw std::runtime_error("serialthread::stuffBytes attempt to send too big package (more than 255 bytes long)");
    } else if (0 == from.length()) {
        throw std::runtime_error("serialthread::stuffBytes no command specified, it should be 0th byte of the packet");
    }
    QByteArray tmp;
    tmp.append('\xC0');
    tmp.append('\x00');
    tmp.append(this->stuffByte(from[0]));
    tmp.append(this->stuffByte(static_cast<char>(std::min(from.length() - 1, 255))));
    for (uint8_t i = 1; i < from.length(); i++) {
        tmp.append(this->stuffByte(from[i]));
    }
    return tmp;
}


Message::Message(const QByteArray &request, const QString &portName, int waitTimeout)
{
    this->request = request;
    this->portName = portName;
    this->waitTimeout = waitTimeout;
}
