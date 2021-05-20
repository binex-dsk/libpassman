#include <botan/hex.h>
#include <botan/base32.h>

#include "vector_union.hpp"

namespace passman {
    VectorUnion::VectorUnion(const QString &data) {
        *this = data.toStdString();
    }

    VectorUnion::VectorUnion(const std::string &data) {
        *this = secvec(data.begin(), data.end());
    }

    VectorUnion::VectorUnion(const char *data, const int length) {
        if (length == 0) {
            *this = QString(data);
        } else {
            *this = std::string(data, length);
        }
    }

    VectorUnion::VectorUnion(const secvec &data) {
        this->assign(data.begin(), data.end());
    }

    VectorUnion::VectorUnion(const std::vector<uint8_t> &data) {
        this->operator=(secvec(data.begin(), data.end()));
    }

    VectorUnion::VectorUnion(const QVariant &data) {
        this->operator=(data.toString());
    }

    VectorUnion::VectorUnion(const bool data) {
        this->operator=(QVariant(data));
    }

    VectorUnion::VectorUnion(const double data) {
        this->operator=(QVariant(data));
    }

    VectorUnion::VectorUnion(const QByteArray &data) {
        *this = VectorUnion(data.constData(), static_cast<int>(data.size()));
    }

    const char *VectorUnion::asConstChar() const {
        return reinterpret_cast<const char *>(this->data());
    }

    QString VectorUnion::asQStr() const {
        return QString::fromStdString(asStdStr());
    }

    std::string VectorUnion::asStdStr() const {
        return std::string(this->begin(), this->end());
    }

    QVariant VectorUnion::asQVariant() const {
        return QVariant(this->data());
    }

    QByteArray VectorUnion::asQByteArray() const {
        return QByteArray(this->asConstChar());
    }

    VectorUnion VectorUnion::hex_encode() const {
        return Botan::hex_encode(*this);
    }

    VectorUnion VectorUnion::hex_decode() const {
        return Botan::hex_decode(this->asStdStr());
    }

    VectorUnion VectorUnion::base32_encode() const {
        return Botan::base32_encode(*this);
    }

    VectorUnion VectorUnion::base32_decode() const {
        return Botan::base32_decode(this->asStdStr());
    }

    VectorUnion::operator bool() const {
        return this->asQVariant().toBool();
    }

    VectorUnion::operator double() const {
        return this->asQVariant().toDouble();
    }

    VectorUnion &VectorUnion::operator+=(QString s) {
        QString t_str = this->asQStr();
        t_str.append(s);
        *this = t_str;
        return *this;
    }
}
