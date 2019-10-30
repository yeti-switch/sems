#!/bin/bash

debuild -us -uc -b -j`grep -c ^processor /proc/cpuinfo`
