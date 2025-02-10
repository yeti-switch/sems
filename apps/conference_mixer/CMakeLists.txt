set(sems_module_name conference_mixer)

file(GLOB conference_mixer_SRCS "*.cpp")
list(FILTER conference_mixer_SRCS EXCLUDE REGEX "unit_tests")

if(SEMS_USE_GTEST)
    file(GLOB conference_mixer_UNIT_SRCS unit_tests/*.cpp)
    set(conference_mixer_UNIT_INSTALL TRUE)
endif(SEMS_USE_GTEST)

set(conference_mixer_config_files "")
set(conference_mixer_config_dist_files conference_mixer)

include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
