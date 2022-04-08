#ifndef KDF_HPP
#define KDF_HPP
#include <botan/cipher_mode.h>
#include <botan/pwdhash.h>

#include "vector_union.hpp"
#include "constants.hpp"

namespace passman {
    class Database;

    /** Class for managing password encryption, hashing, etc. as well as keyfiles, benchmarking, and transforming passwords. */
    class KDF
    {
        uint16_t m_i1;
        uint16_t m_i2;
        uint16_t m_i3;

        uint8_t m_hmacFunction;
        uint8_t m_hashFunction;
        uint8_t m_encryptionFunction;

        VectorUnion m_seed;
        VectorUnion m_keyFile;
    public:
        /**
         * Construct a KDF from a parameter map. See KDF::setParams.
         * @param p Parameter map.
         */
        KDF(const QVariantMap &p);
        KDF() = default;
        virtual ~KDF() = default;

        /**
         * Sets up the KDF's params through a parameter map.
         * @param p Parameter map.
         * Provide the parameter map as {"key", "value"}, i.e.
         * {"i1", "10"}, etc.
         *
         * Available params: i1, i2, i3, rounds, hmac, hash, encryption,
         * seed, keyfile
         *
         * i1, i2, and i3's function depend on the selected hash function.
         * Check their docs for details.
         *
         * @return Whether or not setting the parameters was successful.
         */
        bool setParams(const QVariantMap &p);

        uint16_t i1();
        void setI1(uint16_t t_i1);
        uint16_t i2();
        void setI2(uint16_t t_i2);
        uint16_t i3();
        void setI3(uint16_t t_i3);
        uint16_t rounds();
        uint16_t memoryUsage();
        uint16_t parallelism();

        uint8_t hmacFunction();
        bool setHmacFunction(uint8_t t_hmacFunction);
        uint8_t hashFunction();
        bool setHashFunction(uint8_t t_hashFunction);
        uint8_t encryptionFunction();
        bool setEncryptionFunction(uint8_t t_encryptionFunction);

        VectorUnion seed();
        bool setSeed(VectorUnion t_seed);
        VectorUnion keyFile();
        bool setKeyFile(VectorUnion t_keyFile);

        /**
         * Reads the key file.
         * @return The contents of the key file.
         */
        VectorUnion readKeyFile();

        /**
         * Creates a Botan::Cipher_Mode for encryption.
         * @param t_encryptionFunction (Optional) Encryption function to use. Set to 63 to use the KDF's encryption function. Defaults to 63.
         * @return A Botan::Cipher_Mode for encryption.
         */
        std::unique_ptr<Botan::Cipher_Mode> makeEncryptor(uint8_t t_encryptionFunction = 63);

        /**
         * Creates a Botan::Cipher_Mode for decryption.
         * @param t_encryptionFunction (Optional) Encryption function to use. Set to 63 to use the KDF's encryption function. Defaults to 63.
         * @return A Botan::Cipher_Mode for decryption.
         */
        std::unique_ptr<Botan::Cipher_Mode> makeDecryptor(uint8_t t_encryptionFunction = 63);

        /**
         * Creates a Botan::PasswordHash for derivation.
         * @param t_hmacFunction (Optional) HMAC function to use. Set to 63 to use the KDF's HMAC function. Defaults to 63.
         * @return A Botan::PasswordHash for derivation.
         */
        std::unique_ptr<Botan::PasswordHash> makeDerivation(uint8_t t_hmacFunction = 63);

        /**
         * Creates a Botan::PasswordHash for hashing.
         * @param t_hashFunction (Optional) Hash function to use. Set to 63 to use the KDF's hash function. Defaults to 63.
         * @return A Botan::PasswordHash for hashing.
         */
        std::unique_ptr<Botan::PasswordHash> makeHasher(uint8_t t_hashFunction = 63);

        /**
         * Transform data using the KDF.
         * @param t_data Data to transform.
         * @param t_seed Optional seed to use. Defaults to the KDF's seed.
         *
         * @return The transformed data.
         */
        VectorUnion transform(VectorUnion t_data, VectorUnion t_seed = {});

        /**
         * Benchmarks the KDF.
         * @param t_msec How long the resulting rounds should take in milliseconds.
         *
         * @return The amount of rounds required for encryption/decryption to take t_msec milliseconds.
         */
        int benchmark(const int t_msec);

        /**
         * Returns a string briefly describing the KDF.
         */
        QString toString();
    };
}

#endif // KDF_HPP
