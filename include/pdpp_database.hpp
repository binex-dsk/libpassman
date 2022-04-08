#ifndef PDPPDATABASE_H
#define PDPPDATABASE_H

#include <botan/compression.h>
#include <botan/pwdhash.h>
#include <botan/hash.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

#include "constants.hpp"
#include "vector_union.hpp"
#include "kdf.hpp"

namespace passman {
    class PDPPEntry;

    // TODO: getters and setters for variables

    /** Drives all operations related to database access. */
    class PDPPDatabase
    {
        QList<PDPPEntry *> m_entries;
    public:
        /**
         * Construct a database from a parameter map. See PDPPDatabase::setParams.
         * @param p Parameter map.
         */
        PDPPDatabase(const QVariantMap &p);
        PDPPDatabase() = default;
        virtual ~PDPPDatabase() = default;

        /**
         * Encrypt the database and set it to be modified.
         */
        inline void save() {
            this->encrypt();

            this->modified = false;
        }

        /**
         * Add an entry to the database.
         * @param entry Entry to add.
         */
        inline void addEntry(PDPPEntry *entry) {
            this->m_entries.emplaceBack(entry);
            this->modified = true;
        }

        /**
         * Remove an entry from the database.
         * @param entry Entry to remove.
         * @return Whether or not removing the entry was successful.
         */
        inline bool removeEntry(PDPPEntry *entry) {
            bool ok = this->m_entries.removeOne(entry);
            this->modified = ok;
            return ok;
        }

        /**
         * Return the amount of entries in the database.
         */
        inline qsizetype entryLength() {
            return this->m_entries.length();
        }

        inline QList<PDPPEntry *> &entries() {
            return this->m_entries;
        }

        inline void setEntries(QList<PDPPEntry *> t_entries) {
            this->m_entries = t_entries;
            this->modified = true;
        }

        /**
         * Sets up the databases's params through a parameter map.
         * @param p Parameter map.
         * Provide the parameter map as {"key", "value"}, i.e.
         * {"name", "funny database"}, etc.
         *
         * @return Whether or not setting the parameters was successful.
         */
        bool setParams(const QVariantMap &p);

        /**
         * Return an entry with the specified name.
         * @param t_name Name to look for.
         */
        PDPPEntry *entryNamed(const QString &t_name);

        /**
         * Returns an entry with the specified password.
         * @param t_pass Password to look for.
         */
        PDPPEntry *entryWithPassword(const QString &t_pass);

        /**
         * Turns SQL statements from the global SQL database into entries.
         */
        void get();

        /**
         * Turns entries into SQL statements.
         *
         * @return Whether or not it was successful.
         */
        bool saveSt();

        bool isOld();

        /**
         * Converts a pre-2.0.0 database into a 2.0.0-style database
         * @param t_password Password to attempt for decryption.
         */
        bool convert(const VectorUnion &t_password);

        /**
         * Gets the data and encrypts it.
         *
         * @return The encrypted data.
         */
        VectorUnion encryptedData();

        /**
         * Encrypt and write data to the database file.
         */
        void encrypt();

        /**
         * Decrypt and verify that the data is still valid.
         *
         * @return 0 or 3 if invalid, 1 if valid.
         */
        int verify(const VectorUnion &t_password);

        /**
         * Unused
         */
        std::pair<VectorUnion, int> decryptData(VectorUnion t_data, const VectorUnion &t_password, const VectorUnion &t_keyFile = {});

        /**
         * Decrypts data from disk.
         * @param t_options PasswordOptions flags; Open (load data into Database) and/or Convert (convert from pre-2.0.0 database).
         * Generally not needed to be set directly; open() and convert() will do this for you.
         * @param t_password The password to attempt.
         * @param t_keyFile The keyfile to attempt.
         *
         * @return Whether or not decryption was successful.
         */
        bool decrypt(PasswordOptionsFlag t_options = PasswordOptions(), const VectorUnion &t_password = "", const VectorUnion &t_keyFile = {});

        /**
         * Parses data from disk to prepare for decryption.
         *
         * Note: This contains backward-compatibility for all previous 2.0.0-style databases.
         *
         * @return 2 if the database is old, throws if it fails, returns true if it succeeds.
         */
        int parse();

        /**
         * Decrypt the database and loads data.
         * @param t_password Password to attempt.
         * @param t_keyFile Key file to attempt.
         *
         * @return true or false if succeeded or failed
         */
        int open(const QString &t_password, const QString &t_keyFile);

        /**
         * Save the database to the specified location.
         * @param t_fileName Location to save to.
         *
         * @return 3 if no location is passed, 17 if the file can't be opened, true otherwise
         * TODO: throw
         */
        int saveAs(const QString &t_fileName);

        /**
         * Makes a @link{KDF} object with all the specified parameters.
         *
         * @return The generated KDF object.
         */
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
}

#endif // PDPPDATABASE_H
