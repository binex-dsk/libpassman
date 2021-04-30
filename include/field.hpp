#ifndef FIELD_H
#define FIELD_H
#include "vector_union.hpp"

namespace passman {
    /** Class that wraps around an entry data field. */
    class Field
    {
        QString m_name;
        VectorUnion m_data;
        QMetaType::Type m_type;
    public:
        /**
         *  @param t_name Name of the field.
         *  @param t_data Data to be stored in the field.
         *  @param t_type QMetaType indicating what type the data is. String for strings, Double for numbers, Bool for bools, and QByteArray for multi-line text.
         */
        Field(const QString &t_name, const VectorUnion &t_data, const QMetaType::Type t_type)
            : m_name(t_name)
            , m_data(t_data)
            , m_type(t_type) {}

        const QString &name();
        const QString &setName(const QString &t_name);

        /**
         * Get the lowercase name of the field.
         */
        const QString lowerName();

        const VectorUnion &data();
        const VectorUnion &setData(const VectorUnion &t_data);

        /**
         * Get the field's data as a QString.
         */
        QString dataStr();

        QMetaType::Type type();
        QMetaType::Type setType(const QMetaType::Type t_type);

        /**
         * Returns true if the field represents an entry's name.
         */
        bool isName();

        /**
         * Returns true if the field represents an entry's password.
         */
        bool isPass();

        /**
         * Returns true if the field is multi-line.
         */
        bool isMultiLine();
    };
}

#endif // FIELD_H
