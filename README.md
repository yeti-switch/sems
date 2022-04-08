[![Build Status](https://github.com/yeti-switch/sems/actions/workflows/build.yml/badge.svg)](https://github.com/yeti-switch/sems/actions/workflows/build.yml)

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct.svg)](https://stand-with-ukraine.pp.ua)

# sems

sems core is a part of project [Yeti]

## Installation via Package (Debian)
```sh
# echo "deb [arch=amd64] http://pkg.yeti-switch.org/debian/bullseye 1.12 main" > /etc/apt/sources.list.d/yeti.list
# curl https://pkg.yeti-switch.org/key.gpg | gpg --dearmor > /etc/apt/trusted.gpg.d/pkg.yeti-switch.org.gpg
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
$ debuild -us -uc -b
```

[Yeti]:https://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
