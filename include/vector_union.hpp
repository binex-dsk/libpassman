#ifndef VECTORUNION_H
#define VECTORUNION_H
#include <QVariant>

#include "extra.hpp"

namespace passman {
    /* Helper class which stores a Botan::secure_vector<uint8_t>.
     * Primary use is secure storage of many different types, allowing for assignment and conversion to/from these types. Supported types include:
     * QString, std::string, const char *, secure vector, QVariant, bool, and double */
    class VectorUnion : public secvec
    {
    public:
        VectorUnion() = default;
        virtual ~VectorUnion() = default;
        VectorUnion(const QString &data);
        VectorUnion(const std::string &data);
        VectorUnion(const char *data, const int length = 0);
        VectorUnion(const secvec &data);

        VectorUnion(const std::vector<uint8_t> &data);

        VectorUnion(const QVariant &data);
        VectorUnion(const bool data);
        VectorUnion(const double data);
        VectorUnion(const QByteArray &data);

        const char *asConstChar() const;
        QString asQStr() const;
        std::string asStdStr() const;
        QVariant asQVariant() const;
        QByteArray asQByteArray() const;

        VectorUnion hex_encode() const;
        VectorUnion hex_decode() const;

        VectorUnion base32_encode() const;
        VectorUnion base32_decode() const;

        explicit operator bool() const;
        explicit operator double() const;

        VectorUnion &operator+=(QString s);
    };
}
#endif // VECTORUNION_H
