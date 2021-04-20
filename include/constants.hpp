#ifndef CONSTANTS_H
#define CONSTANTS_H
#include <QList>
#include <QString>

#include "extra.hpp"

namespace Constants {
    constexpr int maxVersion {7};
    const QList<std::string> hmacMatch {"Blake2b", "SHA-3", "SHAKE-256", "Skein-512", "SHA-512"};
    const QList<std::string> hashMatch {"Argon2id", "Bcrypt-PBKDF", "Scrypt", "No hashing, only derivation"};
    const QList<std::string> encryptionMatch {"AES-256/GCM", "Twofish/GCM", "SHACAL2/EAX", "Serpent/GCM"};

    const std::string passmanVersion {"2.1.0"};

    const std::string github {"https://github.com/binex-dsk/libpassman/"};
}

#endif // CONSTANTS_H
