#ifndef DATABASE_H
#define DATABASE_H

#include <botan/compression.h>
#include <botan/pwdhash.h>
#include <botan/hash.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

#include "constants.hpp"
#include "vector_union.hpp"
#include "kdf.hpp"

class Entry;

// TODO: getters and setters for variables

// Drives all operations related to database access.
class PDPPDatabase
{
    QList<Entry *> m_entries;
public:
    PDPPDatabase(const QVariantMap &p);
    PDPPDatabase() = default;

    inline bool save() {
        this->encrypt();

        this->modified = false;
        return true;
    }

    inline void addEntry(Entry *entry) {
        this->m_entries.emplaceBack(entry);
        this->modified = true;
    }

    inline bool removeEntry(Entry *entry) {
        return this->m_entries.removeOne(entry);
        this->modified = true;
    }

    inline qsizetype entryLength() {
        return this->m_entries.length();
    }

    inline QList<Entry *> &entries() {
        return this->m_entries;
    }

    inline void setEntries(QList<Entry *> t_entries) {
        this->m_entries = t_entries;
        this->modified = true;
    }

    bool setParams(const QVariantMap &p);

    Entry *entryNamed(const QString &t_name);
    Entry *entryWithPassword(const QString &t_pass);

    void get();
    bool saveSt();

    bool isOld();
    bool convert(const VectorUnion &t_password);

    VectorUnion encryptedData();
    void encrypt();

    std::pair<VectorUnion, int> decryptData(VectorUnion t_data, const VectorUnion &t_password, const VectorUnion &t_keyFile = {});
    int verify(const VectorUnion &t_password);
    bool decrypt(PasswordOptionsFlag t_options = PasswordOptions(), const VectorUnion &t_password = "", const VectorUnion &t_keyFile = {});

    bool parse();

    bool open(const QString &t_password, const QString &t_keyFile);
    int saveAs(const QString &t_fileName);

    KDF *makeKdf(uint8_t t_hmac = 63, uint8_t t_hash = 63, uint8_t t_encryption = 63, VectorUnion t_seed = {}, VectorUnion t_keyFile = {}, uint8_t t_hashIters = 0, uint16_t t_memoryUsage = 0);

    bool keyFile = false;
    bool modified = false;

    uint8_t hmac = 0;
    uint8_t hash = 0;
    uint8_t hashIters = 8;
    uint8_t encryption = 0;
    uint8_t version = Constants::maxVersion;

    uint16_t memoryUsage = 64;
    uint8_t clearSecs = 15;

    bool compress = true;

    VectorUnion iv{};
    size_t ivLen = 12;

    VectorUnion data{};

    VectorUnion name = "None";
    VectorUnion desc = "None";

    VectorUnion path = "";
    VectorUnion keyFilePath = "";

    VectorUnion stList = "";
    VectorUnion passw{};
};

#endif // DATABASE_H
