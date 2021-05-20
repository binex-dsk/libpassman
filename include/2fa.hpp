#include <botan/symkey.h>
#include "vector_union.hpp"

namespace passman {
    /**
     * Class for dealing with 2FA (OTPs)
     * Named "TFA" because variable/class/function names can't start with numbers
     */
    class TFA {
    private:
        VectorUnion url_decode(const std::string &url);

        VectorUnion type = "totp";
        VectorUnion uri;
        VectorUnion account;
        VectorUnion secret;
        VectorUnion issuer;
        VectorUnion algorithm = "SHA-1";

        int digits = 6;
        int period = 30;
        int counter = 0;
    public:
        /**
         * Construct a TFA from an OTP URI.
         * @param t_uri OTP uri.
         */
        TFA(VectorUnion &t_uri);

        /**
         * Construct a TFA from OTP parameters.
         * @param t_secret Required client secret key, base32 encoded.
         * @param t_account Required account name.
         * @param t_type The OTP type. Must be "totp" or "hotp", defaults to "totp".
         * @param t_algorithm The algorithm to use. Must be "SHA-1", "SHA-256", or "SHA-512", defaults to "SHA-1". RFC 4228 only supports SHA-1, but TOTP and some HOTP libs do support SHA-256 and SHA-512.
         * @param t_issuer The OTP issuer.
         * @param t_digits The amount of digits for the OTP. Must be between 6 and 8 inclusive. Defaults to 6 as most OTP implementations have 6 digits.
         * @param t_period For TOTP, the period in which the key is refreshed in seconds. Defaults to 30, the most common value.
         * @param t_counter For HOTP, the counter to start at. Defaults to 0.
         */
        TFA(const VectorUnion &t_secret, const VectorUnion &t_account, const VectorUnion &t_type = {"totp"}, const VectorUnion &t_algorithm = {"SHA-1"}, const VectorUnion &t_issuer = {}, const int t_digits = 6, const int t_period = 30, const int t_counter = 0);

        /**
         * Validates the OTP parameters and throws if invalid.
         */
        void validate();

        /**
         * Generate a URI from the OTP parameters.
         * @return The generated URI.
         */
        const VectorUnion make_uri();

        /**
         * Generate an OTP.
         * @return The generated code, zero-padded.
         */
        QString code();
    };
}
