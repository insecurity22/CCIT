#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

int Widget::put_value(int i) {

    QString s = ui->leMoney->text(); // save s from text value
    int first = 0;
    first = s.toInt(); // 0
    first = first + i;

    s = s.setNum(first);
    ui->leMoney->setText(s);

}

int Widget::reset() {
    QString s = ui->leMoney->text();
    int first = 0;
    first = s.toInt();

    int five = 0, one = 0, fifty = 0;

    five = first / 500; // 500
    one = first / 100; // 100
    fifty = first / 50; // 50

    QMessageBox msgBox;
    msgBox.setText(QString("500 : ").arg(five));
    msgBox.setText(QString("100 : ").arg(one));
    msgBox.setText(QString("50 : ").arg(fifty));
}

void Widget::on_leMoney_cursorPositionChanged(int arg1, int arg2)
{

}

int Widget::on_pb500_clicked()
{
    Widget::put_value(500);
}

int Widget::on_pb100_clicked()
{
    Widget::put_value(100);
}

void Widget::on_pb50_clicked()
{
    Widget::put_value(50);
}

void Widget::on_pbCoffee_clicked()
{
    Widget::put_value(200);
}

void Widget::on_pbTea_clicked()
{
    Widget::put_value(100);
}

void Widget::on_pbYul_clicked()
{
    Widget::put_value(250);
}

void Widget::on_pbReset_clicked()
{
    Widget::reset();

}


