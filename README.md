# sems

sems core is a part of project [Yeti]

## Installation via Package (Debian 10)
```sh
# echo "deb [arch=amd64] http://pkg.yeti-switch.org/debian/buster 1.10 main" > /etc/apt/sources.list.d/yeti.list
# apt-key adv --keyserver keys.gnupg.net --recv-key 9CEBFFC569A832B6
# wget -O- https://pkg.yeti-switch.org/key.gpg | apt-key add -
# apt install sems sems-modules-base
```
check [Documentation] for additional versions/distributions info

## Building from sources (Debian 10)

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
$ debuild -us -uc -b -j$(nproc)
```

[Yeti]:https://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
