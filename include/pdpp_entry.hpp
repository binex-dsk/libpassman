#ifndef PDPPENTRY_H
#define PDPPENTRY_H

#include "field.hpp"

namespace passman {
    class PDPPDatabase;
    // Class that wraps a database entry.
    class PDPPEntry
    {
        QList<Field *> m_fields;
        PDPPDatabase *m_database;
        QString m_name;
    public:
        PDPPEntry(QList<Field *> t_fields, PDPPDatabase *t_database);
        PDPPEntry() = default;
        virtual ~PDPPEntry() = default;

        inline void addField(Field *t_field) {
            this->m_fields.emplaceBack(t_field);
        }

        inline bool removeField(Field *t_field) {
            return this->m_fields.removeOne(t_field);
        }

        inline qsizetype indexOf(Field *t_field) {
            return this->m_fields.indexOf(t_field);
        }

        inline Field *fieldNamed(QString t_name) {
            for (Field *f : this->m_fields) {
                if (f->lowerName() == t_name) {
                    return f;
                }
            }
            return new Field("", "", QMetaType::QString);
        }

        inline Field *fieldAt(const int t_index) {
            return this->m_fields[t_index];
        }

        inline const QList<Field *> &fields() {
            return this->m_fields;
        }

        inline QList<Field *> &setFields(QList<Field *> &t_fields) {
            this->m_fields = t_fields;
            return t_fields;
        }

        inline qsizetype fieldLength() {
            return this->m_fields.length();
        }

        virtual inline PDPPDatabase *database() {
            return this->m_database;
        }

        virtual inline PDPPDatabase *setDb(PDPPDatabase *t_database) {
            this->m_database = t_database;
            return t_database;
        }

        inline const QString &name() {
            return this->m_name;
        }

        inline QString &setName(QString &t_name) {
            this->m_name = t_name;
            return t_name;
        }

        // Open the entry editor dialog.
        inline void edit() {

        }
    };
}
#endif // PDPPENTRY_H
