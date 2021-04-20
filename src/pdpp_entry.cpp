#include <QList>
#include <QMetaType>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>

#include "pdpp_entry.hpp"
#include "extra.hpp"

Entry::Entry(QList<Field *> t_fields, PDPPDatabase *t_database)
    : m_fields(t_fields)
    , m_database(t_database)
{
    if (t_fields.empty()) {
        for (const QString &s : {"Name", "Email", "URL", "Notes", "Password"}) {
            QMetaType::Type ftype = (s == "Notes" ? QMetaType::QByteArray : QMetaType::QString);
            this->addField(new Field(s, "", ftype));
        }
    } else {
        this->m_name = t_fields[0]->dataStr();
    }
}
