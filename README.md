# sems

sems core is a part of project [Yeti]

## Installation via Package (Debian 9)
```sh
# echo "deb http://pkg.yeti-switch.org/debian/stretch stable main ext" > /etc/apt/sources.list.d/yeti.list
# apt-key adv --keyserver keys.gnupg.net --recv-key 9CEBFFC569A832B6
# apt update
# apt install sems sems-modules-base
```
check [Documentation] for additional versions/distributions info

## Building from sources (Debian 8/9)

### install prerequisites
```sh
# apt install git cmake build-essential devscripts
```

### get sources
```sh
$ git clone https://github.com/yeti-switch/sems.git --recursive
$ cd sems
```

### build and install dependencies package
```sh
# mk-build-deps -i
```

### build packages
```sh
$ debuild -us -uc -b
```

[Yeti]:https://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
