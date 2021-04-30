#ifndef CONSTANTS_H
#define CONSTANTS_H
#include <QList>
#include <QString>

#include "extra.hpp"

/* Constants for libpassman. */
namespace passman {
    namespace Constants {
        constexpr int maxVersion {7};
        const QList<std::string> hmacMatch {"Blake2b", "SHA-3", "SHAKE-256", "Skein-512", "SHA-512"};
        const QList<std::string> hashMatch {"Argon2id", "Bcrypt-PBKDF", "Scrypt", "No hashing, only derivation"};
        const QList<std::string> encryptionMatch {"AES-256/GCM", "Twofish/GCM", "SHACAL2/EAX", "Serpent/GCM"};

        const std::string libpassmanVersion {"2.1.1"};

        const std::string libpassmanGithub {"https://github.com/binex-dsk/libpassman/"};

        const QString allF {";;All Files (*)"};
        const QString fileExt {"passman++ Database Files (*.pdpp)" + allF};
        const QString keyExt {"passman++ Key Files (*.pkpp)" + allF};
    }
}

#endif // CONSTANTS_H
