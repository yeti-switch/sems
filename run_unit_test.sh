#! /usr/bin/bash

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
core/plug-in/wav/wav.so
do
    cp -uv $BUILD_DIR/$m $TEST_TMP_DIR/lib/
done

if [ $# -lt 1 ]; then
    $SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_list_tests
    exit 0
fi

echo $1

if [ $1 == "all" ]; then
    $SEMS_TESTER -c $SEMS_TESTER_CFG
    exit 0
fi

$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_also_run_disabled_tests --gtest_filter=$1
