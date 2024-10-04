file(GLOB_RECURSE postgresql_mock_SRCS *.cpp)
set(sems_module_name postgresql_mock)

find_package(Lua 5.3 EXACT REQUIRED)
include_directories(${LUA_INCLUDE_DIR})
SET(sems_module_libs lua5.3)

include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
