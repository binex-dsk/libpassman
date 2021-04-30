#include "field.hpp"

namespace passman {
    const QString &Field::name() {
        return m_name;
    }

    const QString &Field::setName(const QString &t_name) {
        this->m_name = t_name;
        return t_name;
    }

    const QString Field::lowerName() {
        return this->m_name.toLower();
    }

    const VectorUnion &Field::data() {
        return this->m_data;
    }

    const VectorUnion &Field::setData(const VectorUnion &t_data) {
        this->m_data = t_data;
        return t_data;
    }

    QString Field::dataStr() {
        return this->m_data.asQStr();
    }

    QMetaType::Type Field::type() {
        return this->m_type;
    }

    QMetaType::Type Field::setType(const QMetaType::Type t_type) {
        this->m_type = t_type;
        return t_type;
    }

    bool Field::isName() {
        return this->lowerName() == "name";
    }

    bool Field::isPass() {
        return this->lowerName() == "password";
    }

    bool Field::isMultiLine() {
        return this->m_type == QMetaType::QByteArray;
    }
}
