#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->leMoney->setEnabled(false);
    ui->pbCoffee->setEnabled(false);
    ui->pbTea->setEnabled(false);
    ui->pbYul->setEnabled(false);

}

Widget::~Widget()
{
    delete ui;
}


int Widget::put_value(int i, int num) {

    QString value;
    if(num == 1) {
        ui->leMoney->setText(value.setNum(ui->leMoney->text().toInt() + i));
    }
    else if(num == 2) {
        if(ui->leMoney->text().toInt() > 0) {
            ui->leMoney->setText(value.setNum(ui->leMoney->text().toInt() - i));
        }
    }
    if(ui->leMoney->text().toInt() >= 200) ui->pbCoffee->setEnabled(true);
    else ui->pbCoffee->setEnabled(false);
    if(ui->leMoney->text().toInt() >= 100) ui->pbTea->setEnabled(true);
    else ui->pbTea->setEnabled(false);
    if(ui->leMoney->text().toInt() >= 250) ui->pbYul->setEnabled(true);
    else ui->pbYul->setEnabled(false);

}

int Widget::reset() {

    QString value;
    QString write = "Total : "; // if 750
    write.append(ui->leMoney->text());
    write.append("\n500 : ");
    write.append(value.setNum(ui->leMoney->text().toInt() / 500)); // 750won = 500, 1
    write.append("\n100 : ");
    write.append(value.setNum((ui->leMoney->text().toInt() / 100) // 750won = 100, 2
                 - (ui->leMoney->text().toInt() / 500)*5)); // but 7, because 7-5 = 2
    write.append("\n50 : ");
    write.append(value.setNum((ui->leMoney->text().toInt() % 100)/50));

    ui->leMoney->setText(0);
    ui->pbCoffee->setEnabled(false);
    ui->pbTea->setEnabled(false);
    ui->pbYul->setEnabled(false);

    QMessageBox msgBox;
    msgBox.information(this, "Total Value", write, "Exit");

}

int Widget::on_pb500_clicked()
{
    Widget::put_value(500, 1);
}

int Widget::on_pb100_clicked()
{
    Widget::put_value(100, 1);
}

void Widget::on_pb50_clicked()
{
    Widget::put_value(50, 1);
}

void Widget::on_pbCoffee_clicked()
{
    Widget::put_value(200, 2);
}

void Widget::on_pbTea_clicked()
{
    Widget::put_value(100, 2);
}

void Widget::on_pbYul_clicked()
{
    Widget::put_value(250, 2);
}

void Widget::on_pbReset_clicked()
{
    Widget::reset();

}

void Widget::on_leMoney_cursorPositionChanged(int arg1, int arg2)
{

}


void Widget::on_lineEdit_cursorPositionChanged(int arg1, int arg2)
{

}
