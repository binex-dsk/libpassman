#include <QSqlRecord>
#include <QSqlQuery>
#include <QSqlField>
#include <QSqlError>
#include <QFile>
#include <QFileInfo>

#include "pdpp_database.hpp"
#include "pdpp_entry.hpp"
#include "data_stream.hpp"

namespace passman {
    PDPPDatabase::PDPPDatabase(const QVariantMap &p) {
        setParams(p);
    }

    bool PDPPDatabase::setParams(const QVariantMap &p) {
        uint8_t t_hmac = static_cast<uint8_t>(p.value("hmac", 0).toUInt());
        hmac = t_hmac;

        uint8_t t_hash = static_cast<uint8_t>(p.value("hash", 0).toUInt());
        hash = t_hash;

        uint8_t t_hashIters = static_cast<uint8_t>(p.value("hashiters", 8).toUInt());
        hashIters = t_hashIters;

        uint8_t t_encryption = static_cast<uint8_t>(p.value("encryption", 0).toUInt());
        encryption = t_encryption;

        uint8_t t_version = static_cast<uint8_t>(p.value("version", Constants::maxVersion).toUInt());
        version = t_version;

        uint16_t t_memoryUsage = static_cast<uint16_t>(p.value("memory", 64).toUInt());
        memoryUsage = t_memoryUsage;

        uint8_t t_clearSecs = static_cast<uint8_t>(p.value("clearsecs", 15).toUInt());
        clearSecs = t_clearSecs;

        VectorUnion t_iv = p.value("iv", {}).toByteArray();
        iv = t_iv;
        ivLen = t_iv.size();

        VectorUnion t_path = p.value("path", {}).toByteArray();
        path = t_path;

        VectorUnion t_name = p.value("name", "None").toByteArray();
        name = t_name;

        VectorUnion t_desc = p.value("desc", "None").toByteArray();
        desc = t_desc;

        VectorUnion t_keyFile = p.value("keyfile", "").toString();
        keyFilePath = t_keyFile;
        keyFile = !t_keyFile.empty();

        return true;
    }

    PDPPEntry *PDPPDatabase::entryNamed(const QString &t_name) {
        for (PDPPEntry *e : m_entries) {
            if (e->name() == t_name) {
                return e;
            }
        }

        return nullptr;
    }

    PDPPEntry *PDPPDatabase::entryWithPassword(const QString &t_pass) {
        for (PDPPEntry *e : m_entries) {
            if (e->fieldNamed("password")->dataStr() == t_pass) {
                return e;
            }
        }

        return nullptr;
    }

    void PDPPDatabase::get() {
        setEntries({});

        for (const QString &tbl : db.tables()) {
            QSqlQuery q(db);
            q.exec("SELECT * FROM " + tbl);
            q.next();
            QList<Field *> fields;
            QSqlRecord rec = q.record();
    #ifdef DEBUG
            qDebug() << "generating entry from table" << tbl;
            qDebug() << rec;
    #endif

            for (const int i : range(0, rec.count())) {
                QString vName = rec.fieldName(i);
                const QString val = rec.value(i).toString().replace(" || char(10) || ", "\n");
                QMetaType::Type id = static_cast<QMetaType::Type>(rec.field(i).metaType().id());

                if (isOld()) {
                    vName.replace(0, 1, vName[0].toUpper());
                    if (vName.toLower() == "notes") {
                        id = QMetaType::QByteArray;
                    }
                }
                fields.emplaceBack(new Field(vName, val, id));
            }

            PDPPEntry *entry = new PDPPEntry(fields, this);
            addEntry(entry);
        }
    }

    bool PDPPDatabase::saveSt() {
        for (const QString &tbl : db.tables()) {
    #ifdef DEBUG
            qDebug() << "deleting table" << tbl;
    #endif
            db.exec("DROP TABLE \"" + tbl + '"');
        }
        stList = "";

        for (PDPPEntry *entry : m_entries) {
            if (entry->name().isEmpty()) {
                continue;
            }

            QString createStr = "CREATE TABLE '" + entry->fieldAt(0)->dataStr() + "' (";
            QString insertStr = "INSERT INTO '" + entry->fieldAt(0)->dataStr().replace('"', '\'') + "' (";
            QString valueStr = ") VALUES (";

            for (const int i : range(0, static_cast<int>(entry->fieldLength()))) {
                Field *field = entry->fieldAt(i);
                QString fName = field->name();
                fName.replace('"', '\'');

                const QList<QMetaType::Type> varTypes = {QMetaType::QString, QMetaType::Double, QMetaType::Int, QMetaType::QByteArray};
                const QList<QString> sqlTypes = {"text", "real", "integer", "blob"};

                createStr += fName + ' ' + sqlTypes[varTypes.indexOf(field->type())];
                insertStr += fName;

                QString quote = field->type() == QMetaType::QString || field->isMultiLine() ? "\"" : "";
                valueStr += quote + field->dataStr().replace('"', '\'').replace('\n', " || char(10) || ") + quote;

                createStr += ", ";
                insertStr += ", ";
                valueStr += ", ";
            }

            createStr.chop(2);
            insertStr.chop(2);
            valueStr.chop(2);

            db.exec(createStr + ')');
            db.exec(insertStr + valueStr + ')');
            stList += createStr + ")\n" + insertStr + valueStr + ")\n";
        }
        return true;
    }

    bool PDPPDatabase::isOld() {
        QFile f(path.asQStr());
        f.open(QIODevice::ReadOnly);

        const VectorUnion t_iv = f.readLine().trimmed();
        try {
            t_iv.hex_decode();
        } catch (...) {
            return false;
        }

        return true;
    }

    bool PDPPDatabase::convert(const VectorUnion &t_password) {
        QFile f(path.asQStr());
        f.open(QIODevice::ReadOnly);

        const VectorUnion t_iv = f.readLine().trimmed();
        VectorUnion ivd;
        try {
            ivd = t_iv.hex_decode();
        } catch (...) {
            return false;
        }

        this->iv = ivd;
        this->name = QFileInfo(path.asQStr()).baseName().split('.')[0];;
        this->desc = "Converted from old database format.";

        secvec mptr(32);
        auto ph = Botan::PasswordHashFamily::create("PBKDF2(SHA-256)")->default_params();

        ph->derive_key(mptr.data(), mptr.size(), t_password.asConstChar(), t_password.size(), iv.data(), iv.size());

        KDF *kdf = makeKdf();
        auto decr = kdf->makeDecryptor(0);
        decr->set_key(mptr);
        decr->start(ivd);

        VectorUnion vData = f.readAll();

        try {
            decr->finish(vData);
            this->passw = kdf->transform(t_password);
        }  catch (std::exception &e) {
            return false;
        }

        this->stList = vData;

        for (const QString &s : vData.asQStr().split('\n')) {
            if (s.isEmpty()) {
                continue;
            }

            QSqlQuery finalQ(db);

            if (!finalQ.exec(s)) {
                std::cerr << "libpassman warning: SQL execution error during database conversion: " + finalQ.lastError().text().toStdString() + "\nQuery: " + s.toStdString() << std::endl;
            }

            finalQ.finish();
        }

        get();

        encrypt();
        f.close();
        return true;
    }

    VectorUnion PDPPDatabase::encryptedData() {
        KDF *kdf = makeKdf();
        auto enc = kdf->makeEncryptor();
        enc->set_key(passw);
    #ifdef DEBUG
        qDebug() << "STList before saveSt:" << stList.asStdStr().data();
    #endif

        saveSt();

    #ifdef DEBUG
        qDebug() << "STList after saveSt:" << stList.asStdStr().data();
    #endif

        VectorUnion pt = stList;

        if (compress) {
            auto ptComp = Botan::Compression_Algorithm::create("gzip");

            ptComp->start();
            ptComp->finish(pt);
        }

        enc->start(iv);
        enc->finish(pt);

        if (keyFile) {
            const VectorUnion keyPw = kdf->readKeyFile();

            auto keyEnc = kdf->makeEncryptor();

            keyEnc->set_key(kdf->transform(keyPw));
            keyEnc->start(iv);
            keyEnc->finish(pt);
        }

        return pt;
    }

    void PDPPDatabase::encrypt() {
        DataStream pd(path.asStdStr(), std::fstream::binary | std::fstream::trunc);

        pd << "PD++";

        pd << Constants::maxVersion;
        pd << hmac;
        pd << hash;

        if (hash != 3) {
            pd << hashIters;
        }

        pd << keyFile;
        pd << encryption;

        if (hash == 0) {
            pd << memoryUsage;
        }

        pd << clearSecs;
        pd << compress;

        pd << iv;

        pd << name << '\n';
        pd << desc << '\n';

        data = this->encryptedData();
    #ifdef DEBUG
        qDebug() << "Data (Encryption):" << data.hex_encode().asQStr();
    #endif

        pd << data;
        pd.finish();
    }

    int PDPPDatabase::verify(const VectorUnion &t_password) {
        if (isOld()) {
            return convert(t_password);
        }

        VectorUnion t_data = data;
        KDF *kdf = makeKdf();
        VectorUnion vPtr = kdf->transform(t_password);

        if (keyFile) {
            VectorUnion keyPw = kdf->readKeyFile();

            auto keyDec = kdf->makeDecryptor();

            keyDec->set_key(kdf->transform(keyPw));
            keyDec->start(iv);

            try {
                keyDec->finish(t_data);
            } catch (std::exception& e) {
                std::cerr << e.what() << std::endl;
                return 3;
            }
        }

        auto decr = kdf->makeDecryptor();

        decr->set_key(vPtr);
        decr->start(iv);

    #ifdef DEBUG
        qDebug() << "Data (Decryption):" << t_data.hex_encode().asQStr();
    #endif

        try {
            decr->finish(t_data);
            if (compress) {
                auto dataDe = Botan::Decompression_Algorithm::create("gzip");
                dataDe->start();
                dataDe->finish(t_data);
            }

            this->passw = vPtr;
            this->stList = t_data;

            return true;
        } catch (std::exception& e) {
            std::cerr << e.what() << std::endl;
            return false;
        }
    }

    bool PDPPDatabase::decrypt(PasswordOptionsFlag t_options, const VectorUnion &t_password, const VectorUnion &t_keyFile) {
        if (keyFile && !t_keyFile.empty()) {
            keyFilePath = t_keyFile;
        }

        int ok = verify(t_password);

        if (ok == true) {
            if (t_options & Open) {
                if (!(t_options & Convert)) {
                    for (const QString &line : stList.asQStr().split('\n')) {
                        if (line.isEmpty()) {
                            continue;
                        }

                        QSqlQuery q(db);
                        if (!q.exec(line)) {
                           std::cerr << "Warning: Error during database initialization: " + q.lastError().text().toStdString() << std::endl;
                        }
                    }
                }
                get();
            }
            return true;
        }

        if (ok == 3) {
            std::cerr << "Key File is invalid.\n";
        } else {
            std::cerr << "Password is incorrect.\nIf this problem continues, the database may be corrupt.\n";
        }
        return false;
    }

    int PDPPDatabase::parse() {
        if (isOld()) {
            return 2;
        }
        QFile f(path.asQStr());
        f.open(QIODevice::ReadOnly);
        QDataStream q(&f);

        char readData[4];
        q.readRawData(readData, 4);

        if (std::string(readData, 4) != "PD++") {
            throw std::runtime_error("Invalid magic number. Should be PD++.");
        }

        q >> version;
        if (version > Constants::maxVersion) {
            throw std::runtime_error("Invalid version number.");
        }

        q >> hmac;
        if (hmac >= Constants::hmacMatch.size()){
            throw std::runtime_error("Invalid HMAC option.");
        }

        if (version < 6) {
            q.skipRawData(1);
        }

        q >> hash;
        if (hash >= Constants::hashMatch.size()){
            throw std::runtime_error("Invalid hash option.");
        }

        if (hash != 3) {
            q >> hashIters;
        }

        q >> keyFile;

        q >> encryption;
        if (encryption >= Constants::encryptionMatch.size()){
            throw std::runtime_error("Invalid encryption option.");
        }

        if (version >= 7) {
            if (hash == 0) {
                q >> memoryUsage;
            }
            q >> clearSecs;
            q >> compress;
        }

        ivLen = (new KDF({{"encryption", encryption}}))->makeEncryptor()->default_nonce_length();

        char *ivc = new char[ivLen];
        q.readRawData(ivc, static_cast<int>(ivLen));
        iv = VectorUnion(ivc, static_cast<int>(ivLen));

        name = QString(f.readLine()).trimmed();
        desc = QString(f.readLine()).trimmed();

        const qint64 available = f.bytesAvailable();
        char *datac = new char[available];

        q.readRawData(datac, static_cast<int>(available));
        data = VectorUnion(datac, static_cast<int>(available));

        return true;
    }

    int PDPPDatabase::open(const QString &t_password, const QString &t_keyFile) {
        if (QFile::exists(path.asQStr())) {
            int ok = parse();
            if (ok != 1) {
                return ok;
            }

            if (stList.empty()) {
                try {
                    if (!decrypt(PasswordOptions::Open, t_password, t_keyFile)) {
                        return false;
                    }
                } catch (std::exception& e) {
                    std::cerr << e.what() << std::endl;
                    return false;
                }
            }

            for (const QString &line : stList.asQStr().split('\n')) {
                if (line.isEmpty()) {
                    continue;
                }

                QSqlQuery q(db);
                if (!q.exec(line)) {
                   std::cerr << "Warning: Error during database initialization: " + q.lastError().text().toStdString() << std::endl;
                }
            }
            return true;
        }
        std::cerr << "Invalid path provided.\n";
        return false;
    }

    int PDPPDatabase::saveAs(const QString &t_fileName) {
        if (t_fileName.isEmpty()) {
            return 3;
        }

        QFile file(t_fileName);
        if (!file.open(QIODevice::WriteOnly)) {
            return 17;
        }

        try {
            path = t_fileName;
            save();
        } catch (std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
        return true;
    }

    KDF *PDPPDatabase::makeKdf(uint8_t t_hmac, uint8_t t_hash, uint8_t t_encryption, VectorUnion t_seed, VectorUnion t_keyFile, uint8_t t_hashIters, uint16_t t_memoryUsage)
    {
        QVariantMap kdfMap({
            {"hmac", t_hmac == 63 ? hmac : t_hmac},
            {"hash", t_hash == 63 ? hash : t_hash},
            {"encryption", t_encryption == 63 ? encryption : t_encryption},
            {"seed", t_seed.empty() ? iv.asQByteArray() : t_seed.asQByteArray()},
            {"keyfile", t_keyFile.empty() ? keyFilePath.asQVariant() : t_keyFile.asQVariant()}
        });

        uint16_t iters = t_hashIters == 0 ? hashIters : t_hashIters;

        switch (t_hash == 63 ? hash : t_hash) {
            case 0: {
                kdfMap.insert({
                                  {"i1", (t_memoryUsage == 0 ? memoryUsage : t_memoryUsage) * 1000},
                                  {"i2", iters},
                                  {"i3", 1}
                              });
                break;
            } case 2: {
                kdfMap.insert({
                                  {"i1", 32768},
                                  {"i2", iters},
                                  {"i3", 1}
                              });
                break;
            } default: {
                kdfMap.insert("i1", iters);
                break;
            }
        }
        return new KDF(kdfMap);
    }
}
