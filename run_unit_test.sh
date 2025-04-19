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
