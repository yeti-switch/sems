# sems

sems core is a part of project [Yeti]

## Installation via Package (Debian 8)
```sh
# echo "deb http://pkg.yeti-switch.org/debian/jessie stable main ext" > /etc/apt/sources.list.d/yeti.list
# apt-key adv --keyserver keys.gnupg.net --recv-key 9CEBFFC569A832B6
# apt update
# apt install sems sems-modules-base
```

## Building from sources (Debian 8/9)

### install build prerequisites
```sh
# aptitude install git cmake build-essential libssl-dev libpqxx3-dev libxml2-dev libspandsp-dev libsamplerate-dev libcurl3-dev libhiredis-dev librtmp-dev libzrtpcpp-dev libev-dev python-dev libspeex-dev libgsm1-dev
```

### get sources & build debian packages
```sh
$ git clone git@github.com:yeti-switch/sems.git
$ cd sems
$ ./package.sh
```

[Yeti]:http://yeti-switch.org/
