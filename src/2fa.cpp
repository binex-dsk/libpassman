#include <regex>
#include <botan/otp.h>
#include <botan/hex.h>

#include <QUrl>

#include "2fa.hpp"

namespace passman {
    // https://github.com/tadfisher/pass-otp/blob/develop/otp.bash
    TFA::TFA(VectorUnion &t_uri) {
        const std::regex uri_pattern("^otpauth://(totp|hotp)(/(([^:?]+)?(:([^:?]*))?))?\?(.+)$", std::regex::extended);
        std::smatch uri_match;

        const std::string uri_str{t_uri.asStdStr()};

        if (std::regex_match(uri_str, uri_match, uri_pattern)) {
            uri = uri_match[0].str();
            type = uri_match[1].str();

            account = url_decode(uri_match[6].str());
            if (account.empty()) {
                account = url_decode(uri_match[4].str());
                if (account.empty()) {
                    throw std::runtime_error("Invalid key URI (missing account name): " + t_uri.asStdStr());
                }
            } else {
                issuer = url_decode(uri_match[4].str());
            }

            const VectorUnion p = uri_match[7].str();
            const QStringList params = p.asQStr().split('&');

            const std::regex param_pattern("^([^=]+)=(.+)$");
            std::smatch param_match;

            for (const QString &param : params) {
                const std::string param_str{param.toStdString()};
                if (std::regex_match(param_str, param_match, param_pattern)) {
                    const std::string param_key = param_match[1].str();
                    const std::string param_value = param_match[2].str();
                    bool ok;
                    if (param_key == "?secret") {
                        secret = param_value;
                    } else if (param_key == "digits") {
                        digits = QString::fromStdString(param_value).toInt(&ok);
                        if (!ok) {
                            throw std::runtime_error("Invalid key URI (invalid digit count): " + t_uri.asStdStr());
                        }
                    } else if (param_key == "algorithm") {
                        algorithm = QString::fromStdString(param_value).insert(3, '-');
                    } else if (param_key == "period") {
                        period = QString::fromStdString(param_value).toInt(&ok);
                        if (!ok) {
                            throw std::runtime_error("Invalid key URI (invalid period): " + t_uri.asStdStr());
                        }
                    } else if (param_key == "counter") {
                        counter = QString::fromStdString(param_value).toInt(&ok);
                        if (!ok) {
                            throw std::runtime_error("Invalid key URI (invalid counter): " + t_uri.asStdStr());
                        }
                    } else if (param_key == "issuer") {
                        issuer = param_value;
                    }
                }
            }

            validate();
        } else {
            throw std::runtime_error("Unable to parse URI " + t_uri.asStdStr());
        }
    }

    TFA::TFA(const VectorUnion &t_secret, const VectorUnion &t_account, const VectorUnion &t_type, const VectorUnion &t_algorithm, const VectorUnion &t_issuer, const int t_digits, const int t_period, const int t_counter)
    {
        secret = t_secret;
        account = t_account;
        type = t_type;
        algorithm = t_algorithm;
        issuer = t_issuer;
        digits = t_digits;
        period = t_period;
        counter = t_counter;

        validate();

        uri = make_uri();
    }

    VectorUnion TFA::url_decode(const std::string &url) {
        return QUrl(QString::fromStdString(url)).toDisplayString();
    }

    void TFA::validate() {
        if (secret.empty()) {
            throw std::runtime_error("Invalid key URI or parameter input: missing secret");
        }

        if (account.empty()) {
            throw std::runtime_error("Invalid key URI or parameter input: missing account name");
        }

        if (!QStringList{"totp", "hotp"}.contains(type.asQStr())) {
            throw std::runtime_error("Invalid key URI or parameter input: invalid type (must be totp or hotp, got " + type.asStdStr() + ")");
        }

        if (!QStringList{"SHA-1", "SHA-256", "SHA-512"}.contains(algorithm.asQStr())) {
            throw std::runtime_error("Invalid key URI or parameter input: invalid algorithm (must be SHA-1, SHA-256, or SHA-512, got " + algorithm.asStdStr() + ")");
        }

        if (digits < 6 || digits > 8) {
            throw std::runtime_error("Invalid key URI or parameter input: digit amount out of range (must be between 6 and 8, got " + std::to_string(digits) + ")");
        }
    }

    const VectorUnion TFA::make_uri() {
        QString separator = (!account.empty() && !issuer.empty() ? ":" : "");
        VectorUnion p_uri = "otpauth://" + type.asQStr() + "/" + issuer.asQStr() + separator + account.asQStr() + "?secret=" + secret.asQStr();

        if (!issuer.empty()) {
            p_uri += "&issuer=" + issuer.asQStr();
        }

        if (!algorithm.empty()) {
            p_uri += "&algorithm=" + algorithm.asQStr().replace('-', "");
        }

        p_uri += "&digits=" + QString::number(digits);

        if (type.asStdStr() == "hotp") {
            p_uri += "&counter=" + QString::number(counter);
        } else if (type.asStdStr() == "totp") {
            p_uri += "&period=" + QString::number(period);
        }

        return p_uri;
    }

    QString TFA::code() {
        Botan::HOTP hotp = Botan::HOTP(secret.base32_decode(), algorithm.asStdStr(), digits);
        auto unix_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        int p_counter = (type.asStdStr() == "hotp" ? counter : unix_timestamp / period);

        uint32_t code = hotp.generate_hotp(p_counter);

        if (type.asStdStr() == "hotp") {
            counter += 1;
            uri = make_uri();
        }

        return QString("%1").arg(code, 6, 10, QChar('0'));
    }
}
