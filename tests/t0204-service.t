#!/bin/bash

# Test service API

. ./preamble.sh

test_description="Basic tests for service API"

. ./sharness.sh

test_expect_success "Inserting core driver" "
	insmod ../../../../slingshot_base_link/cxi-sbl.ko &&
	insmod ../../../../sl-driver/knl/cxi-sl.ko &&
	insmod ../../../cxi/cxi-ss1.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Inserting service API test driver" "
	dmesg --clear &&
	insmod ../../../cxi/tests/test-service.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing service API test driver" "
	rmmod test-service
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
