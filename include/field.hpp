#ifndef FIELD_H
#define FIELD_H
#include "vector_union.hpp"

// Class that wraps around an entry data field.
class Field
{
    QString m_name;
    VectorUnion m_data;
    QMetaType::Type m_type;
public:
    Field(const QString &t_name, const VectorUnion &t_data, const QMetaType::Type t_type)
        : m_name(t_name)
        , m_data(t_data)
        , m_type(t_type) {}

    const QString &name();
    const QString &setName(const QString &t_name);
    const QString lowerName();

    const VectorUnion &data();
    const VectorUnion &setData(const VectorUnion &t_data);
    QString dataStr();

    QMetaType::Type type();
    QMetaType::Type setType(const QMetaType::Type t_type);

    bool isName();
    bool isPass();
    bool isMultiLine();
};

#endif // FIELD_H
