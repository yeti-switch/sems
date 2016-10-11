find_package(Hiredis REQUIRED)

set (mod_redis_SRCS
ModRedis.cpp
RedisPool.cpp
)

INCLUDE_DIRECTORIES(${HIREDIS_INCLUDE_DIR})

SET(sems_dsm_module_name mod_redis)
SET(sems_dsm_module_libs ${HIREDIS_LIBRARIES})

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/dsm.lib.rules.txt)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/config.rules.txt)
SEMS_INSTALL_DIST_CONFIGS(redis)

