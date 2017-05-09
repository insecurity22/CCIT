#ifndef WIDGET_H
#define WIDGET_H

#include <QtWidgets>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();
    int put_value(int i, int num);
    int reset();

private slots:

    int on_pb500_clicked();

    int on_pb100_clicked();

    void on_pb50_clicked();

    void on_leMoney_cursorPositionChanged(int arg1, int arg2);

    void on_pbCoffee_clicked();

    void on_pbTea_clicked();

    void on_pbYul_clicked();

    void on_pbReset_clicked();

    void on_leMoney_overflow();

    void on_lineEdit_cursorPositionChanged(int arg1, int arg2);

private:
    Ui::Widget *ui;
};

#endif // WIDGET_H
