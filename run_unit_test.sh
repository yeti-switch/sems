#!/bin/bash

set -e

cd $(dirname "${BASH_SOURCE[0]}")

BUILD_DIR=./build
TEST_TMP_DIR=$BUILD_DIR/unit_tests

SEMS_TESTER=$BUILD_DIR/unit_tests/sems-tester
SEMS_TESTER_CFG=./unit_tests/etc/sems_test.cfg

for d in rsr logs lib; do
    mkdir -p $TEST_TMP_DIR/$d
done

#prepare lib dir
for m in \
apps/http/http_client.so \
apps/jsonrpc/jsonrpc.so \
core/plug-in/wav/wav.so \
apps/postgresql/postgresql_unit.so \
apps/registrar/registrar_unit.so \
apps/redis/redis_unit.so \
apps/conference_mixer/conference_mixer_unit.so
do
    name=$(basename $m)
    cp -uv $BUILD_DIR/$m $TEST_TMP_DIR/lib/${name//"_unit"/}
done

if [ $# -lt 1 ]; then
    cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_list_tests"
else
    filter=$1
    shift
    if [ $filter == "all" ]; then
        cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG $@"
    else
        cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_also_run_disabled_tests --gtest_filter=$filter $@"
    fi
fi

echo $cmd
exec $cmd
