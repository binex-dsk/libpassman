cmake_minimum_required(VERSION 3.9)

project(passman LANGUAGES CXX VERSION 2.1.0 DESCRIPTION "Library for interaction with passman++ database files.")

set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOMOC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

add_library(passman SHARED
        src/pdpp_database.cpp
        src/pdpp_entry.cpp

        src/kdf.cpp

        src/extra.cpp
        src/field.cpp
        src/vector_union.cpp
        src/data_stream.cpp
)

set_target_properties(passman PROPERTIES
    VERSION 2.1.0
    SOVERSION 1
)

set_property(TARGET passman
    PROPERTY PUBLIC_HEADER
    include/extra.hpp
    include/field.hpp
    include/data_stream.hpp
    include/kdf.hpp
    include/pdpp_database.hpp
    include/pdpp_entry.hpp
    include/vector_union.hpp)

configure_file(passman.pc.in passman.pc @ONLY)

target_include_directories(passman PRIVATE include)
target_include_directories(passman PRIVATE src)

find_library(BOTAN botan-2)
if (NOT BOTAN)
    message(FATAL_ERROR "Botan library not found. Please install through your distribution's password manager.")
endif()

find_package(Qt6 COMPONENTS Core REQUIRED)
find_package(Qt6 COMPONENTS Sql REQUIRED)

target_include_directories(passman PUBLIC /usr/include/botan-2)

target_link_libraries(passman PRIVATE
	Qt::Core
        Qt::Sql
        botan-2
)

install(TARGETS passman
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(FILES ${CMAKE_BINARY_DIR}/passman.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

set(CMAKE_CXX_FLAGS_DEBUG "-O0 -march=native -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wunused -Wold-style-cast -Wconversion -Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches -pedantic -Wuseless-cast -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -march=native")
