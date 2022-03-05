FROM debian:bullseye

ARG KANIKO_CONTEXT=/workspace
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends wget gnupg ssh-client
RUN echo "deb [arch=amd64] http://pkg.in.didww.com/debian/bullseye bullseye misc-unstable" >> /etc/apt/sources.list && \
    wget -qO - http://pkg.in.didww.com/key.gpg | gpg --dearmor > /etc/apt/trusted.gpg.d/pkg.in.didww.com.gpg && \
    echo "    StrictHostKeyChecking=no" >> /etc/ssh/ssh_config
RUN apt-get update && apt-get -y --no-install-recommends install python3-pip debhelper git cmake build-essential libssl-dev libxml2-dev libsamplerate-dev libcurl4-openssl-dev libhiredis-dev librtmp-dev libev-dev python2-dev libspeex-dev libgsm1-dev libmp3lame-dev libopus-dev libprotobuf-dev protobuf-compiler libsctp-dev libevent-dev libc-ares-dev libkrb5-dev libboost-all-dev libtiff5-dev libnghttp2-dev libwslay-dev libbzrtp-dev libbctoolbox-dev libbrotli-dev libsqlite3-dev && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip3 install aptly-ctl

# for ci comment the following
#ADD . /workspace

WORKDIR $KANIKO_CONTEXT
