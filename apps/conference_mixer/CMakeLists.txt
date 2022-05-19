set(sems_module_name conference_mixer)

file(GLOB conference_mixer_SRCS "*.cpp")

set(conference_mixer_config_files "")
set(conference_mixer_config_dist_files conference_mixer)

include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
