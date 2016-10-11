INSTALL(FILES sems.default DESTINATION /etc/default RENAME sems)
INSTALL(FILES sems.logrotate DESTINATION /etc/logrotate.d RENAME sems)
INSTALL(FILES sems.syslog DESTINATION /etc/rsyslog.d RENAME sems.conf)
