#include <QObject>

#include "extra.hpp"

namespace passman {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", ":memory:");

    // Wrapper function to make translation easier.
    const QString tr(const QString &s) {
        return QObject::tr(s.toStdString().data());
    }

    // Wrapper function to make translation easier.
    const QString tr(const std::string &s) {
        return QObject::tr(s.data());
    }

    // Wrapper function to make translation easier.
    const QString tr(const char *s) {
        return QObject::tr(s);
    }
}
