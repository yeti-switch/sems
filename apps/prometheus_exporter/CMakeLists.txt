SET(sems_module_name prometheus_exporter)

file(GLOB_RECURSE prometheus_exporter_SRCS "*.cpp")

SET(prometheus_exporter_config_files "")
SET(prometheus_exporter_config_dist_files prometheus_exporter)
SET(sems_module_libs event)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)

