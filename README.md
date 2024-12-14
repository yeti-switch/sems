[![Build Status](https://github.com/yeti-switch/sems/actions/workflows/build.yml/badge.svg)](https://github.com/yeti-switch/sems/actions/workflows/build.yml)

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct.svg)](https://stand-with-ukraine.pp.ua)

# sems

sems core is a part of project [Yeti]

## Installation via Package (Debian)
```sh
# apt install wget gnupg
# echo "deb [arch=amd64] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list
# wget -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
# echo "deb [arch=amd64] https://deb.yeti-switch.org/debian/1.13 bookworm main" > /etc/apt/sources.list.d/yeti.list
# wget http://deb.yeti-switch.org/yeti.gpg -O /etc/apt/trusted.gpg.d/deb.yeti-switch.org.asc
# apt install sems sems-modules-base
```
check [Documentation] for additional versions/distributions info

## Building from sources (Debian)

### install prerequisites
```sh
# apt install git cmake build-essential devscripts
```

### get sources
```sh
$ git clone https://github.com/yeti-switch/sems.git --recursive
$ cd sems
```

### install dependencies
```sh
# apt build-deps .
```

### build packages
```sh
$ dpkg-buildpackage -us -uc -b
```

[Yeti]:https://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
