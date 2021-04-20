#ifndef DATASTREAM_H
#define DATASTREAM_H
#include "extra.hpp"
#include "vector_union.hpp"

/* Utility class for writing a couple extra types to an std::ofstream.
 * Prefer over direct operator overloads when overloading already-existing overloads. */
class DataStream
{
public:
    DataStream(const std::string &path, const std::fstream::openmode mode);

    DataStream &operator<<(const uint8_t val);
    DataStream &operator<<(const uint16_t val);
    DataStream &operator<<(const int val);
    DataStream &operator<<(const bool val);
    DataStream &operator<<(const char *val);
    DataStream &operator<<(const VectorUnion val);

    void finish();

    std::ofstream stream;
};

#endif // DATASTREAM_H
