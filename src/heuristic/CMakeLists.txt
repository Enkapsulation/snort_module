cmake_minimum_required ( VERSION 3.4.3 )
project ( heuristic CXX )

set (CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    heuristic MODULE
    config.hpp
    config.cpp
    create_module.hpp
    create_module.cpp
	heuristic.hpp
    heuristic.cpp
    heuristic_module.hpp
    heuristic_module.cpp
    utils.hpp
    utils.cpp
    flag.hpp
    flag_config.cpp
    flag_config.hpp
    dangerous_ip_addr.cpp
    dangerous_ip_addr.hpp
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
