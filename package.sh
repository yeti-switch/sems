#!/bin/bash

debuild -us -uc -b -j$(nproc)
