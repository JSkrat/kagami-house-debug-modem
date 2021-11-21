#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "serialthread.h"
#include "packet.h"
#include "KagamiCore/UART protocol.h"
#include <QObject>
#include <QMessageBox>
#include <QCheckBox>
#include <QHash>
#include <iostream>


const QHash<eModemCommand, QString> responseEtcText = {
    {mcListen, "listening"},
    {mcSetMode, "requested mode set"},
    {mcClearTX, "clear TX ok"},
    {mcSetListenAddress, "master address set"},
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , StatusUpgradeTimer(this)
    , serial(this)
    , title("Kagami house usb2nrf debugger")
{
    ui->setupUi(this);
    ui->centralwidget->setLayout(ui->horizontalLayout);
    this->ui->teConsole->clear();

    ui->leSerialPort->setText(this->port);

    this->ui->statusbar->addPermanentWidget(this->ui->lQueueSize);

    this->StatusUpgradeTimer.setInterval(150);
    connect(&(this->StatusUpgradeTimer), &QTimer::timeout, this, &MainWindow::statusUpgrade);
//    this->StatusUpgradeTimer.start();

    qRegisterMetaType<uint8_t>("uint8_t");
    connect(&(this->serial), &SerialThread::response, this, &MainWindow::serialResponse);
    connect(&(this->serial), &SerialThread::timeout, this, &MainWindow::serialTimeout);
    connect(&(this->serial), &SerialThread::error, this, &MainWindow::serialError);

    // setup packet constructor
    ui->tab_packet_constructor->setLayout(ui->vlPacketConstructor);
    std::cout << "functionName size " << functionName.size() << std::endl;
    for (auto i = functionName.begin(); i != functionName.end(); ++i) {
        std::cout << "add function " << i.value().toStdString().c_str() << std::endl;
        ui->pcFunctionList->addItem(
                    QString("0x%1 %2")
                        .arg(i.key().byte, 2, 16, QChar('0'))
                        .arg(i.value()),
                    i.key().byte
        );
    }
}

MainWindow::~MainWindow()
{
    this->StatusUpgradeTimer.stop();
    delete ui;
    //delete this->serial;
}

void MainWindow::setCheckBoxValue(QCheckBox *checkbox, bool value)
{
    if (value) checkbox->setCheckState(Qt::CheckState::Checked);
    else checkbox->setCheckState(Qt::CheckState::Unchecked);
}

void MainWindow::serialTransaction(QByteArray data)
{
    this->serial.transaction(this->port, this->ui->sbPortTimeout->value(), data);
    this->ui->lQueueSize->setText(QString("serial msg queued: %1").arg(this->serial.getQueueSize()));
}


void MainWindow::addMessage(QByteArray from, QString decorator, QString message, QColor background) {
    this->ui->teConsole->append(
                QString("<p>&nbsp;</p>"
                        "<span style='background-color:#%1%2%3;'><span style='font-weight:600; background-color:#%1%2%3;'>%6 %4 </span></span>"
                        "<span style='background-color:#%1%2%3;'><span style='font-family:\"monospace\"; background-color:#%1%2%3;'>%5</span></span>"
                        "")
                .arg(background.red(), 2, 16, QChar('0'))
                .arg(background.green(), 2, 16, QChar('0'))
                .arg(background.blue(), 2, 16, QChar('0'))
                .arg(QString(from.toHex(':')).toUpper())
                .arg(message.replace('\n', "<br>"))
                .arg(decorator.toHtmlEscaped())
                );
}

void MainWindow::addMessage(QByteArray from, QString decorator, QByteArray message, QColor background) {
    this->addMessage(from, decorator, QString(message.toHex(':').toUpper()), background);
}

void MainWindow::addSendMessage(QByteArray from, QByteArray message) {
    QString packet = message.toHex(':');
    try {
        packet += "\n" + Packet::ParseRequest(message);
        this->curUnit = message[2];
        this->curFunc = message[3];
        this->requestPending = true;
    } catch (std::runtime_error &e) {
        // do nothing
    }
    this->addMessage(from, "> Send to", packet, QColor::fromRgbF(1, 0.9, 0.9));
}

void MainWindow::addACKMessage(QByteArray from, QByteArray message, bool timeout) {
    if (! timeout) {
        this->addMessage(from, "< ACK from", message, QColor::fromRgbF(1, 1, 0.9));
    } else {
        this->addMessage(from, "< ACK timeout from", message, QColor::fromRgbF(1, 0.9, 0.8));
    }
}

void MainWindow::addReceiveMessage(QByteArray from, QByteArray message, bool timeout) {
    QString packet = message.toHex(':');
    try {
        if (this->requestPending) {
            this->requestPending = false;
            packet += "\n" + Packet::ParseResponse(this->curUnit, this->curFunc, message);
        }
    } catch (std::runtime_error &e) {
        // do nothing
    }

    if (! timeout) {
        this->addMessage(from, "< Receive from", packet, QColor::fromRgbF(0.9, 1, 0.9));
    } else {
        this->addMessage(from, "< Response timeout from", packet, QColor::fromRgbF(0.9, 1, 0.8));
    }
}

void MainWindow::addEtcMessage(QByteArray from, QString message) {
    this->addMessage(from, "system message", QString("<i>%1</i>").arg(message.toHtmlEscaped()), QColor::fromRgbF(0.9, 0.9, 0.9));
}

void MainWindow::statusUpgrade()
{
    /// request modem status upgrade
    this->serialTransaction(QByteArray(1, mcVersion));
}

void MainWindow::serialResponse(const uint8_t command, const uint8_t code, const QByteArray &response)
{
    eModemCommand eCommand = static_cast<eModemCommand>(command);

    switch (eCommand) {
    case mcVersion: {
        QString version;
        if (eucOk == code) {
            uint64_t v = 0;
            for (uint8_t i: response) {
                v <<= 8;
                v += i;
            }
            version = QString::number(v, 16);
        } else version = QString("(version error 0x%1)").arg(code, 2, 16, QChar('0'));
        this->setWindowTitle(QString("%1 — build %2").arg(this->title).arg(version));
        this->serialTransaction(QByteArray(1, mcStatus));
        break;
    }
    case mcStatus: {
        // modem status
//        this->ui->statusbar->showMessage(response.toHex(':'));
        // config
        uint8_t modemConfig = static_cast<uint8_t>(response[0]);
        this->setCheckBoxValue(this->ui->cbMASK_RX_DR, 0x40 & modemConfig);
        this->setCheckBoxValue(this->ui->cbMASK_TX_DS, 0x20 & modemConfig);
        this->setCheckBoxValue(this->ui->cbMASK_MAX_RT, 0x10 & modemConfig);
        this->setCheckBoxValue(this->ui->cbEN_CRC, 0x08 & modemConfig);
        this->setCheckBoxValue(this->ui->cbCRCO, 0x04 & modemConfig);
        this->setCheckBoxValue(this->ui->cbPWR_UP, 0x02 & modemConfig);
        this->setCheckBoxValue(this->ui->cbPRIM_RX, 0x01 & modemConfig);
        // EN_AA
        uint8_t modemEN_AA = static_cast<uint8_t>(response[1]);
        this->setCheckBoxValue(this->ui->cbEN_AA_P0, 0x01 & modemEN_AA);
        this->setCheckBoxValue(this->ui->cbEN_AA_P1, 0x02 & modemEN_AA);
        this->setCheckBoxValue(this->ui->cbEN_AA_P2, 0x04 & modemEN_AA);
        this->setCheckBoxValue(this->ui->cbEN_AA_P3, 0x08 & modemEN_AA);
        this->setCheckBoxValue(this->ui->cbEN_AA_P4, 0x10 & modemEN_AA);
        this->setCheckBoxValue(this->ui->cbEN_AA_P5, 0x20 & modemEN_AA);
        // EN_RXADDR
        uint8_t modemEN_RXADDR = static_cast<uint8_t>(response[2]);
        this->setCheckBoxValue(this->ui->cbERX_P0, 0x01 & modemEN_RXADDR);
        this->setCheckBoxValue(this->ui->cbERX_P1, 0x02 & modemEN_RXADDR);
        this->setCheckBoxValue(this->ui->cbERX_P2, 0x04 & modemEN_RXADDR);
        this->setCheckBoxValue(this->ui->cbERX_P3, 0x08 & modemEN_RXADDR);
        this->setCheckBoxValue(this->ui->cbERX_P4, 0x10 & modemEN_RXADDR);
        this->setCheckBoxValue(this->ui->cbERX_P5, 0x20 & modemEN_RXADDR);
        // SETUP_AW
        uint8_t modemAW = static_cast<uint8_t>(response[3]);
        if (0 == (modemAW & 0x03)) {
            this->ui->lSETUP_AW->setText("illegal");
        } else {
            this->ui->lSETUP_AW->setText(QString("%1 bytes").arg((modemAW & 0x03) + 2));
        }
        // SETUP_RETR
        uint8_t modemRETR = static_cast<uint8_t>(response[4]);
        this->ui->lARD->setText(QString("%1μS").arg(((modemRETR >> 4) + 1) * 250));
        if (0 == (modemRETR & 0x0F)) {
            this->ui->lARC->setText("disabled");
        } else {
            this->ui->lARC->setText(QString("up to %1").arg(modemRETR & 0x0F));
        }
        // RF_CH
        uint8_t modemRF_CH = static_cast<uint8_t>(response[5]);
        this->ui->lRF_CH->setText(QString("%1").arg(modemRF_CH & 0x7F, 2, 16));
        // RF_SETUP
        uint8_t modemRF_SETUP = static_cast<uint8_t>(response[6]);
        this->setCheckBoxValue(this->ui->cbCONT_WAVE, 0x80 & modemRF_SETUP);
        this->setCheckBoxValue(this->ui->cbPLL_LOCK, 0x10 & modemRF_SETUP);
        QStringList RF_DR = {"1Mbps", "2Mbps", "250kbps", "reserved"};
        this->ui->lRF_DR->setText(RF_DR[2 * (modemRF_SETUP >> 5 & 1) + (modemRF_SETUP >> 3 & 1)]);
        QStringList RF_PWR = {"-18dBm", "-12dBm", "-6dBm", "0dBm"};
        this->ui->lRF_PWR->setText(RF_PWR[(modemRF_SETUP >> 1) & 0x03]);
        // status
        uint8_t modemStatus = static_cast<uint8_t>(response[7]);
        this->setCheckBoxValue(this->ui->cbRX_DR, 0x40 & modemStatus);
        this->setCheckBoxValue(this->ui->cbTX_DS, 0x20 & modemStatus);
        this->setCheckBoxValue(this->ui->cbMAX_RT, 0x10 & modemStatus);
        this->setCheckBoxValue(this->ui->cbTX_FULL, 0x01 & modemStatus);
        uint8_t RX_P_NO = (modemStatus & 0x0E) >> 1;
        if (7 == RX_P_NO) this->ui->lRX_P_NO->setText("empty");
        else this->ui->lRX_P_NO->setText(QString("%1").arg(RX_P_NO));
        // OBSERVE_TX
        uint8_t modemOBSERVE_TX = static_cast<uint8_t>(response[8]);
        this->ui->lPLOS_CNT->setNum(modemOBSERVE_TX >> 4);
        this->ui->lARC_CNT->setNum(modemOBSERVE_TX & 0x0F);
        // RPD
        this->setCheckBoxValue(this->ui->cbRPD, 0x01 & response[9]);
        // RX_PW
        QLabel *RX_PW[6] = {
            this->ui->lRX_PW_P0,
            this->ui->lRX_PW_P1,
            this->ui->lRX_PW_P2,
            this->ui->lRX_PW_P3,
            this->ui->lRX_PW_P4,
            this->ui->lRX_PW_P5,
        };
        for (int i = 0; i < 6; i++) {
            RX_PW[i]->setText(QString("RX_PW_P%1 %2").arg(i).arg(0x3F & response[0x0A + i]));
        }
        // FIFO_STATUS
        QCheckBox *FIFO_STATUS[8] = {
            this->ui->cbRX_EMPTY,
            this->ui->cbRX_FULL,
            nullptr,
            nullptr,
            this->ui->cbTX_EMPTY,
            this->ui->cbTX_FULL_2,
            this->ui->cbTX_REUSE,
            nullptr,
        };
        for (int i = 0; i < 8; i++) {
            if (nullptr != FIFO_STATUS[i]) {
                this->setCheckBoxValue(FIFO_STATUS[i], response[0x10] & (1 << i));
            }
        }
        // DYNPD
        QCheckBox *DYNPD[6] = {
            this->ui->cbDPL_P0,
            this->ui->cbDPL_P1,
            this->ui->cbDPL_P2,
            this->ui->cbDPL_P3,
            this->ui->cbDPL_P4,
            this->ui->cbDPL_P5,
        };
        for (int i = 0; i < 6; i++) {
            this->setCheckBoxValue(DYNPD[i], response[0x11] & (1 << i));
        }
        // FEATURE
        QCheckBox *FEATURE[3] = {
            this->ui->cbEN_DYN_ACK,
            this->ui->cbEN_ACK_PAY,
            this->ui->cbEN_DPL,
        };
        for (int i = 0; i < 3; i++) {
            this->setCheckBoxValue(FEATURE[i], response[0x12] & (1 << i));
        }
        ////////////////////////////////////////////////////////////////
        /// trigger second request with addresses //////////////////////
        ////////////////////////////////////////////////////////////////
        this->serialTransaction(QByteArray(1, mcAddresses));
        break;
    }
    case mcAddresses: {
        this->ui->lRX_ADDR_P0->setText(response.mid(0x00, 5).toHex(':'));
        this->ui->lRX_ADDR_P1->setText(response.mid(0x05, 5).toHex(':'));
        this->ui->lTX_ADDR->setText(response.mid(0x0E, 5).toHex(':'));
        QLabel *RX_ADDR_P1[4] = {
            this->ui->lRX_ADDR_P2,
            this->ui->lRX_ADDR_P3,
            this->ui->lRX_ADDR_P4,
            this->ui->lRX_ADDR_P5,
        };
        for (int i = 0; i < 4; i++) {
            RX_ADDR_P1[i]->setText(
                        QString("(%1):%2")
                        .arg(QString(response.mid(0x05, 4).toHex(':')))
                        .arg(static_cast<uint8_t>(response[0x0A + i]), 2, 16, QChar('0'))
                        );
        }
        this->serialTransaction(QByteArray(1, mcReadRFBuffer));
        break;
    }
    case mcReadRFBuffer: {
        switch (code) {
        case eucNoPackets: {
            break;
        }
        case eucAckPacket: {
            this->addACKMessage(response.mid(0, 5), response.mid(5), false);
            break;
        }
        case eucAckTimeout: {
            this->addACKMessage(response.mid(0, 5), response.mid(5), true);
            break;
        }
        case eucDataPacket: {
            this->addReceiveMessage(response.mid(0, 5), response.mid(5), false);
            break;
        }
        case eucSlaveResponseTimeout: {
            this->addReceiveMessage(response.mid(0, 5), response.mid(5), true);
            break;
        }
        }
        break;
    }
    case mcTransmit: {
        this->addEtcMessage(
                    response.mid(0, 5),
                    QString("< Transmission accepted %1").arg(QString("0x%1").arg(code, 2, 16, QChar('0')))
                    );
        break;
    }
    default: {
        if (responseEtcText.keys().contains(eCommand)) {
            this->addEtcMessage(
                        response,
                        QString("< %1 0x%2 <%3>")
                            .arg(responseEtcText[eCommand])
                            .arg(code, 2, 16, QChar('0'))
                            .arg(QString(response.toHex(':')))
                        );
        } else {
            this->ui->statusbar->showMessage(QString("Unknown response %1").arg(static_cast<uint8_t>(eCommand), 2, 16, QChar('0')), 5000);
            this->addEtcMessage(
                        QByteArray(),
                        QString("< Unknown response cmd %1 0x%2 <%3>")
                            .arg(command, 2, 16, QChar('0'))
                            .arg(code, 2, 16, QChar('0'))
                            .arg(QString(response.toHex(':')))
                        );
        }
        break;
    }
    }
}

void MainWindow::serialTimeout(const QString &message)
{
    this->ui->statusbar->showMessage("Timeout: " + message, 5000);
    this->addEtcMessage(
                QByteArray(),
                QString("serial timeout %1").arg(message)
                );}

void MainWindow::serialError(const QString &message)
{
    this->ui->statusbar->showMessage("Error: " + message, 5000);
    this->addEtcMessage(
                QByteArray(),
                QString("serial error %1").arg(message)
    );
}


void MainWindow::on_pushButton_clicked()
{
    this->port = this->ui->leSerialPort->text();
}

void MainWindow::on_checkBox_stateChanged(int arg1)
{
    if (arg1) {
        this->StatusUpgradeTimer.start();
    } else {
        this->StatusUpgradeTimer.stop();
    }
}

void MainWindow::on_pbClearTx_clicked()
{
    QByteArray pkt;
    pkt.append(mcClearTX);
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt, "> Clear tx queue");
}

void MainWindow::on_pbSetModeMaster_clicked()
{
    QByteArray pkt;
    pkt.append(mcSetMode);
    pkt.append(2);
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt, "> Set mode Master");
}

void MainWindow::on_pbSetModeSlave_clicked()
{
    QByteArray pkt;
    pkt.append(mcSetMode);
    pkt.append(1);
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt, "> Set mode Slave");
}

void MainWindow::on_pbSetModeDebug_clicked()
{
    QByteArray pkt;
    pkt.append(mcSetMode);
    pkt.append(static_cast<char>(0));
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt, "> Set mode Debug");
}

void MainWindow::on_pbSetMasterAddress_clicked()
{
    QByteArray pkt;
    pkt.append(mcSetListenAddress);
    pkt.append(Packet::parseHex(this->ui->leAddressListen->text()));
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt.mid(1), "> Set master address");
}

void MainWindow::on_pbListen_clicked()
{
    QByteArray pkt;
    pkt.append(mcListen);
    pkt.append(Packet::parseHex(this->ui->leAddressListen->text()));
    this->serialTransaction(pkt);
    this->addEtcMessage(pkt.mid(1), "> Listen");
}

void MainWindow::on_pbTransmitTo_clicked()
{
    QByteArray pkt;
    pkt.append(mcTransmit);
    pkt.append(Packet::parseHex(this->ui->leAddressTransmitTo->text()));
    pkt.append(Packet::parseHex(this->ui->lePayloadToTransmit->text()));
    this->serialTransaction(pkt);
    this->addSendMessage(pkt.mid(1, 5), pkt.mid(6));
}

void MainWindow::on_pushButton_2_clicked()
{
    // serialize to payload
    QByteArray req = Packet::serializeRequest(
                ui->pcVersion->text().toUInt(nullptr, 16),
                ui->pcTransaction->text().toUInt(nullptr, 16),
                ui->pcUnitId->text().toUInt(nullptr, 16),
                ui->pcFunctionList->currentData().toUInt(),
                Packet::parseHex(ui->pcData->text())
    );
    ui->lePayloadToTransmit->setText(req.toHex(':'));
}

void MainWindow::on_pushButton_3_clicked()
{
    this->on_pushButton_2_clicked();
    this->on_pbTransmitTo_clicked();
}
