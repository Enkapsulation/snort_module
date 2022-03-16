cmake_minimum_required ( VERSION 3.4.3 )
project ( heuristic CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    heuristic MODULE
	heuristic.hpp
    heuristic.cpp
    heuristic_types.hpp
    heuristic_module.hpp
    heuristic_module.cpp
    utils.hpp
    utils.cpp
)

set_target_properties (
    heuristic
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    heuristic PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS heuristic
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
