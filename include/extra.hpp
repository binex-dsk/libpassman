#ifndef EXTRA_H
#define EXTRA_H
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <botan/secmem.h>

#include <QSqlDatabase>

extern QSqlDatabase db;

typedef Botan::secure_vector<uint8_t> secvec;

enum PasswordOptions {
    Convert = (1 << 0),
    Open = (1 << 1),
    Lock = (1 << 2)
};
Q_DECLARE_FLAGS(PasswordOptionsFlag, PasswordOptions)

const QString tr(const QString &s);
const QString tr(const std::string &s);
const QString tr(const char *s);

// Generate a range list of an integer type.
template <typename NumberType = int>
QList<NumberType> range(int start, int amount) {
    QList<NumberType> rangeList;
    for (int i = 0; i < amount; ++i) {
        rangeList.emplaceBack(static_cast<NumberType>(start + i));
    }

    return rangeList;
}

#endif