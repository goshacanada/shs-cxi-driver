#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright 2024 Hewlett Packard Enterprise Development LP

# Test User CXI access

. ./preamble.sh

test_description="Basic tests for UCXI Rgroups"

. ./sharness.sh

test_expect_success "Inserting core driver" "
	insmod ../../../../slingshot_base_link/cxi-sbl.ko &&
	insmod ../../../../sl-driver/knl/cxi-sl.ko &&
	insmod ../../../cxi/cxi-ss1.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Inserting CXI User test driver" "
	dmesg --clear &&
	insmod ../../../cxi/cxi-user.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"
test_expect_success "Run test program" "
	../../../ucxi/test_rgroup &> ../$(basename "$0").output
"
echo
echo "test output:"
cat "$(pwd)"/../../tmptests/$(basename "$0").output
echo

test_expect_success "Check for oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
