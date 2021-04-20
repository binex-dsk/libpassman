#include <QCoreApplication>
#include <QCommandLineParser>
#include <QSqlError>
#include <QVariant>

#include <botan/bigint.h>

#include "extra.hpp"
#include "constants.hpp"
#include "database.hpp"

// TODO: constexpr, noexcept

QSqlDatabase db;

int main(int argc, char** argv) {
    QCoreApplication app (argc, argv);
    QCoreApplication::setApplicationName(tr("passman++"));
    QCoreApplication::setApplicationVersion(tr(Constants::passmanVersion));

    QCommandLineParser parser;
    parser.setApplicationDescription(tr("A simple, minimal, and just as powerful and secure password manager."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(tr("path"), tr("Path to a database file, or a path to where you want to create a new database."));

    QCommandLineOption newOption(QStringList() << "n" << "new", tr("Create a new database."));
    QCommandLineOption debugOption(QStringList() << "d" << "debug", tr("Activate debug mode."));
    QCommandLineOption verboseOption(QStringList() << "V" << "verbose", tr("Activate verbose mode."));

    parser.addOptions({newOption, debugOption, verboseOption});

    parser.process(app);

    const QStringList args = parser.positionalArguments();

    QString path{};
    if (args.length() > 0) {
        path = args.at(0);
    }

    db = QSqlDatabase::addDatabase("QSQLITE", ":memory:");

    if (!db.open()) {
        qDebug() << "Error while opening database: " + db.lastError().text() + tr("\nPlease open an issue on " + Constants::github + " for help with this.");
        return 1;
    }

    Database *database = new Database();

    if (parser.isSet(newOption)) {
        //createDatabase(database, path);
    } else if (!path.isEmpty()) {
        database->path = path;

        if (!database->open()) {
            return 1;
        }
    } else {
    }

    app.setProperty("debug", parser.isSet(debugOption));
    app.setProperty("verbose", parser.isSet(verboseOption));

    return app.exec();
}
