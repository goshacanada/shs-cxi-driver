// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Hewlett Packard Enterprise Development LP */

/* User API RX Profile test */

#include <linux/types.h>

#include <sys/errno.h>

#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_ucxi_common.h"

#define DEVICE_NAME "cxi0"

static const uid_t   invalid_uid = (uid_t) -1;
static const gid_t   invalid_gid = (gid_t) -1;

bool verbose;

int print_error_line(int r, int line)
{
	if (r)
		printf("Error return %s at line %i\n", errstr(r), line);
	return r;
}

#define return_on_error(r) print_error_line(r, __LINE__)

/* __printf(1, 2) */
void verbose_printf(const char *fmt, ...)
{
	if (!verbose)
		return;
	printf("   ");

	va_list    ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

int test_alloc_rx_profile(struct cass_dev *dev,
			  const struct ucxi_rx_attr *attr,
			  unsigned int *id,
			  int expected_return_code)
{
	int    ret = alloc_rx_profile(dev, attr, id);

	if (ret != expected_return_code) {
		printf("RX Profile allocation returned %s, expected %s\n",
		       errstr(ret), errstr(expected_return_code));
		return (ret) ? ret : -1;
	}
	if (ret)
		verbose_printf("Allocation of RX Profile failed as expected: %s\n",
			       errstr(ret));
	else
		verbose_printf("Allocated RX Profile id: %u\n", *id);

	return 0;
}

int alloc_all_entries(struct cass_dev *dev,
		      const struct ucxi_rx_attr *attr,
		      size_t num_entries,
		      unsigned int *ids)
{
	for (size_t i = 0; i < num_entries; i++) {
		int ret = test_alloc_rx_profile(dev, attr+i, ids+i, 0);

		if (ret) {
			printf("Unable to allocate entry %zu.\n", i);
			return ret;

		}
	}
	return 0;
}

int test_release_rx_profile(struct cass_dev *dev,
			    unsigned int id,
			    int expected_return_code)
{
	int ret = release_rx_profile(dev, id);

	if (ret != expected_return_code) {
		printf("Release RX Profile %u returns %s, expected %s\n",
		       id, errstr(ret), errstr(expected_return_code));
		return (ret) ? ret : -1;
	}

	verbose_printf("Release RX Profile %u returns %s, as expected.\n",
		       id, errstr(ret));
	return 0;
}

int release_all_entries(struct cass_dev *dev,
			size_t num_entries,
			unsigned int *ids)
{
	for (size_t i = 0; i < num_entries; i++) {
		int ret = test_release_rx_profile(dev, ids[i], 0);

		if (ret)
			return ret;
	}

	return 0;
}

int test_revoke_entry(struct cass_dev *dev,
		      unsigned int id,
		      int expected_return_code)
{
	int ret = revoke_rx_profile(dev, id);

	if (ret != expected_return_code) {
		printf("Revoke RX Profile %u returns %s, expected %s\n",
		       id, errstr(ret), errstr(expected_return_code));
		return (ret) ? ret : -1;
	}

	verbose_printf("Revoke RX Profile %u returns %s, as expected.\n",
		       id, errstr(ret));
	return 0;
}

int test_get_entry_info(struct cass_dev *dev,
			unsigned int id,
			struct ucxi_rx_attr *attr,
			struct ucxi_rxtx_state *state,
			int expected_return_code)
{
	int ret = get_rx_profile_info(dev, id, attr, state);

	if (ret != expected_return_code) {
		printf("Get RX Profile info returned %s, expected %s.\n",
		       errstr(ret), errstr(expected_return_code));
		return (ret) ? ret : -1;
	}

	verbose_printf("Get RX Profile info returned %s as expected.\n",
		       errstr(ret));
	return 0;
}

int test_get_entry_ids(struct cass_dev *dev,
		       size_t max_ids,
		       unsigned int *rx_profile_ids,
		       size_t *num_ids,
		       int expected_return_code)
{
	int ret = get_rx_profile_ids(dev, max_ids, rx_profile_ids, num_ids);

	if (ret != expected_return_code) {
		printf("Get RX Profile IDs returned %s, expected %s.\n",
		       errstr(ret), errstr(expected_return_code));
		return (ret) ? ret : -1;
	}

	verbose_printf("Get RX Profile IDs returned %s, as expected.\n",
		       errstr(ret));
	if (ret)
		return 0;

	verbose_printf("Get RX Profile IDs found %zu ids.\n", *num_ids);
	return 0;
}

int test_rx_profile_add_ac(struct cass_dev *dev,
			   unsigned int rx_profile_id,
			   enum ucxi_ac_type type,
			   const union ucxi_ac_data *data,
			   unsigned int *ac_entry_id,
			   int expected_result)
{
	int ret = rx_profile_add_ac(dev, rx_profile_id,
				    type, data,
				    ac_entry_id);

	if (ret != expected_result) {
		printf("RX Profile add AC returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	if (ret) {
		verbose_printf("RX Profile add AC returned %s, as expected.\n",
			       errstr(ret));
	} else {
		verbose_printf("Added AC Entry id %u to RX Profile %u\n",
			       *ac_entry_id, rx_profile_id);
	}
	return 0;
}

int test_rx_profile_remove_ac(struct cass_dev *dev,
			      unsigned int rx_profile_id,
			      unsigned int ac_entry_id,
			      int expected_result)
{
	int ret = rx_profile_remove_ac(dev, rx_profile_id,
				       ac_entry_id);

	if (ret != expected_result) {
		printf("RX Profile remove AC returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	if (ret) {
		verbose_printf("RX Profile remove AC returned %s, as expected.\n",
			       errstr(ret));
	} else {
		verbose_printf("Removed AC Entry %u from RX Profile %u\n",
			       ac_entry_id, rx_profile_id);
	}
	return 0;
}

int test_rx_profile_get_ac_ids(struct cass_dev *dev,
			       unsigned int rx_profile_id,
			       size_t max_ids,
			       unsigned int *ids,
			       size_t *num_ids,
			       int expected_result)
{
	int ret = rx_profile_get_ac_ids(dev, rx_profile_id,
					max_ids, ids, num_ids);

	if (ret != expected_result) {
		printf("RX Profile get AC ids returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	verbose_printf("RX Profile get AC Ids returned %s, as expected.\n",
		       errstr(ret));

	return 0;
}

int test_rx_profile_get_ac_data(struct cass_dev *dev,
				unsigned int rx_profile_id,
				unsigned int ac_entry_id,
				enum ucxi_ac_type *type,
				union ucxi_ac_data *data,
				int expected_result)
{
	int ret = rx_profile_get_ac_data(dev, rx_profile_id,
					 ac_entry_id, type, data);

	if (ret != expected_result) {
		printf("RX Profile get AC data returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	verbose_printf("RX Profile get AC data returned %s, as expected.\n",
		       errstr(ret));

	return 0;
}

int test_rx_profile_get_ac_id_by_data(struct cass_dev *dev,
				      unsigned int rx_profile_id,
				      enum ucxi_ac_type type,
				      union ucxi_ac_data *data,
				      unsigned int *ac_entry_id,
				      int expected_result)
{
	int ret = rx_profile_get_ac_id_by_data(dev, rx_profile_id, type,
					       data, ac_entry_id);

	if (ret != expected_result) {
		printf("RX Profile get AC Id by data returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	verbose_printf("RX Profile get AC Id by data returned %s, as expected.\n",
		       errstr(ret));

	return 0;
}

int test_rx_profile_get_ac_id_by_user(struct cass_dev *dev,
				      unsigned int rx_profile_id,
				      uid_t uid,
				      gid_t gid,
				      unsigned int desired_types,
				      unsigned int *ac_entry_id,
				      int expected_result)
{
	int ret = rx_profile_get_ac_id_by_user(dev, rx_profile_id,
					       uid, gid, desired_types,
					       ac_entry_id);

	if (ret != expected_result) {
		printf("RX Profile get AC Id by user returned %s, expected %s\n",
		       errstr(ret), errstr(expected_result));
		return (ret) ? ret : -1;
	}

	verbose_printf("RX Profile get AC Id by user returned %s, as expected.\n",
		       errstr(ret));

	return 0;
}

int alloc_delete_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr rx_attr = {
		.vni_attr.match = 5,
		.vni_attr.ignore = 0,
		.vni_attr.name = "Test RX Profile",
	};

	unsigned int   rx_profile_id;

	int ret = test_alloc_rx_profile(dev, &rx_attr,
					&rx_profile_id, 0);

	if (return_on_error(ret))
		return ret;

	/* Retrieve the info to see that it really was created */

	struct ucxi_rx_attr     attr;
	struct ucxi_rxtx_state  state;

	ret = test_get_entry_info(dev, rx_profile_id, &attr, &state, 0);
	if (return_on_error(ret))
		return ret;

	release_all_entries(dev, 1, &rx_profile_id);

	/* See that it's really gone */

	ret = test_get_entry_info(dev, rx_profile_id, &attr, &state, -EBADR);
	if (return_on_error(ret))
		return ret;

	return 0;
}

int get_list_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr rx_attr[] = {
		{ .vni_attr.ignore = 0,
		  .vni_attr.match = 5,
		  .vni_attr.name   = "Five" },
		{ .vni_attr.ignore = 0,
		  .vni_attr.match  = 6,
		  .vni_attr.name   = "Six" },
		{ .vni_attr.ignore = 0,
		  .vni_attr.match  = 7,
		  .vni_attr.name   = "Seven" },
		{ .vni_attr.ignore = 0,
		  .vni_attr.match  = 15,
		  .vni_attr.name   = "Fifteen" },
		{ .vni_attr.ignore = 0,
		  .vni_attr.match  = 16,
		  .vni_attr.name  = "Sixteen" },
	};

	const size_t   NUM_ENTRIES = ARRAY_SIZE(rx_attr);
	unsigned int   rx_profile_id[NUM_ENTRIES];

	int ret = alloc_all_entries(dev, rx_attr,
				    NUM_ENTRIES,
				    rx_profile_id);

	if (return_on_error(ret))
		return ret;

	unsigned int   rx_profiles_found[2*NUM_ENTRIES];
	size_t         num_rx_profiles_found;

	/* Get all the existing RX Profile ids */

	ret = test_get_entry_ids(dev, ARRAY_SIZE(rx_profiles_found),
				 rx_profiles_found, &num_rx_profiles_found, 0);
	if (return_on_error(ret))
		return ret;

	if (num_rx_profiles_found != NUM_ENTRIES) {
		printf("Retrieved %zu RX Profile ids, but expected %zu.\n",
		       num_rx_profiles_found, NUM_ENTRIES);
		return -1;
	}

	verbose_printf("Retrieved %zu RX Profile Ids, as expected.\n",
		       num_rx_profiles_found);

	for (size_t i = 0; i < NUM_ENTRIES; i++) {
		for (size_t j = 0; j < num_rx_profiles_found; j++) {
			if (rx_profile_id[i] == rx_profiles_found[j])
				goto found_rx_profile;
		}
		printf("RX Profile %u created, but not retrieved.\n",
		       rx_profile_id[i]);
		return 1;
found_rx_profile:
		verbose_printf("RX Profile %u found.\n", rx_profile_id[i]);
		continue;
	}

	verbose_printf("All RX Profiles previously created were found.\n");

	/* Free resources */

	release_all_entries(dev, NUM_ENTRIES, rx_profile_id);
	return 0;
}

int vni_collision_test(struct cass_dev *dev)
{
	struct {
		const struct ucxi_rx_attr   attr;
		int                         expected_return_code;
		unsigned int                id;
	} test_data[] = {
		{ .attr.vni_attr.ignore = 0,
		  .attr.vni_attr.match  = 4,
		  .expected_return_code = 0 },
		{ .attr.vni_attr.ignore = 1,
		  .attr.vni_attr.match  = 4,
		  .expected_return_code = -EEXIST },
		{ .attr.vni_attr.ignore = 2,
		  .attr.vni_attr.match  = 6,
		  .expected_return_code = -EDOM },
		{ .attr.vni_attr.ignore = 3,
		  .attr.vni_attr.match  = 7,
		  .expected_return_code = -EDOM },
		{ .attr.vni_attr.ignore = 1,
		  .attr.vni_attr.match  = 6,
		  .expected_return_code = 0 },
	};

	/* try to create them all, some are expected to fail */
	for (size_t i = 0; i < ARRAY_SIZE(test_data); i++) {
		int ret = test_alloc_rx_profile(dev,
						&test_data[i].attr,
						&test_data[i].id,
						test_data[i].expected_return_code);

		if (return_on_error(ret))
			return ret;
	}

	/* delete the ones we expected to pass creation */
	for (size_t i = 0; i < ARRAY_SIZE(test_data); i++) {
		if (test_data[i].expected_return_code)
			continue;
		release_all_entries(dev, 1, &test_data[i].id);
	}

	return 0;
}

int rx_profile_release_revoke_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr   rx_attr = {
		.vni_attr.match  = 5,
		.vni_attr.ignore = 0,
		.vni_attr.name   = "Test RX Profile",
	};

	/* Release and Revoke non-existant RX Profile.  This should fail. */

	unsigned int    rx_profile_id = 5;
	int    ret;

	ret = test_release_rx_profile(dev, rx_profile_id, -EBADR);
	if (return_on_error(ret))
		return ret;

	ret = test_revoke_entry(dev, rx_profile_id, -EBADR);
	if (return_on_error(ret))
		return ret;

	/* Allocate and Release.  This should pass. */

	ret = test_alloc_rx_profile(dev, &rx_attr, &rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	ret = test_release_rx_profile(dev, rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	/* Release and revoke again.  This should fail */

	ret = test_release_rx_profile(dev, rx_profile_id, -EBADR);
	if (return_on_error(ret))
		return ret;

	ret = test_revoke_entry(dev, rx_profile_id, -EBADR);
	if (return_on_error(ret))
		return ret;

	/* Allocate and Revoke.  This should pass. */

	ret = test_alloc_rx_profile(dev, &rx_attr, &rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	ret = test_revoke_entry(dev, rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	/* Release again.  Should fail. */

	ret = test_release_rx_profile(dev, rx_profile_id, -EBADR);
	if (return_on_error(ret))
		return ret;

	return 0;
}

int missing_args_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr   std_attr = {
		.vni_attr.match  = 5,
		.vni_attr.ignore = 0,
		.vni_attr.name   = "Test RX Profile",
	};

	unsigned int    id;
	int             ret;

	ret = test_alloc_rx_profile(dev, NULL, &id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_alloc_rx_profile(dev, &std_attr, NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_alloc_rx_profile(dev, &std_attr, &id, 0);
	if (return_on_error(ret))
		return ret;

	ret = test_release_rx_profile(dev, id+1, -EBADR);
	if (return_on_error(ret))
		return ret;

	ret = test_revoke_entry(dev, id+1, -EBADR);
	if (return_on_error(ret))
		return ret;

	struct ucxi_rx_attr     rx_attr;
	struct ucxi_rxtx_state  state;

	ret = test_get_entry_info(dev, id+1, &rx_attr, &state, -EBADR);
	if (return_on_error(ret))
		return ret;

	ret = test_get_entry_info(dev, id, NULL, &state, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_get_entry_info(dev, id, &rx_attr, NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	unsigned int   ids[10];
	size_t         count;
	size_t         max_entries = ARRAY_SIZE(ids);

	ret = test_get_entry_ids(dev, max_entries, NULL, &count, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_get_entry_ids(dev, 0, ids, &count, -ENOSPC);
	if (return_on_error(ret))
		return ret;

	ret = test_get_entry_ids(dev, max_entries, ids, NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	/* cleanup */

	ret = test_release_rx_profile(dev, id, 0);
	if (return_on_error(ret))
		return ret;

	return 0;
}

int ac_missing_args_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr   std_attr = {
		.vni_attr.match  = 15,
		.vni_attr.ignore = 0,
		.vni_attr.name   = "Test RX Profile AC",
	};

	unsigned int    rx_profile_id;
	int             ret;

	ret = test_alloc_rx_profile(dev, &std_attr, &rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	enum ucxi_ac_type   ac_type = UCXI_AC_GID;
	union ucxi_ac_data  ac_data = { .gid = 7, };
	unsigned int        ac_entry_id;

	ret = test_rx_profile_add_ac(NULL, rx_profile_id,
				     ac_type, &ac_data,
				     &ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_add_ac(dev, rx_profile_id,
				     ac_type, NULL,
				     &ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_add_ac(dev, rx_profile_id,
				     ac_type, &ac_data,
				     NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_remove_ac(NULL, rx_profile_id,
					ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	unsigned int   ids[20];
	size_t max_ids = ARRAY_SIZE(ids);
	size_t num_ids;

	ret = test_rx_profile_get_ac_ids(NULL, rx_profile_id,
					 max_ids, ids, &num_ids,
					 -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_ids(dev, rx_profile_id,
					 max_ids, NULL, &num_ids,
					 0);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_ids(dev, rx_profile_id,
					 max_ids, ids, NULL,
					 -EINVAL);
	if (return_on_error(ret))
		return ret;

	enum ucxi_ac_type   my_type;
	union ucxi_ac_data  my_data;

	ret = test_rx_profile_get_ac_data(NULL, rx_profile_id,
					  ac_entry_id, &my_type,
					  &my_data, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_data(dev, rx_profile_id,
					  ac_entry_id, NULL,
					  &my_data, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_data(dev, rx_profile_id,
					  ac_entry_id, &my_type,
					  NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_id_by_data(NULL, rx_profile_id,
						ac_type, &ac_data,
						&ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_id_by_data(dev, rx_profile_id,
						ac_type, NULL,
						&ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_id_by_data(dev, rx_profile_id,
						ac_type, &ac_data,
						NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	uid_t   uid = 100;
	gid_t   gid = 200;

	ret = test_rx_profile_get_ac_id_by_user(NULL, rx_profile_id,
						uid, gid, UCXI_AC_ANY,
						&ac_entry_id, -EINVAL);
	if (return_on_error(ret))
		return ret;

	ret = test_rx_profile_get_ac_id_by_user(dev, rx_profile_id,
						uid, gid, UCXI_AC_ANY,
						NULL, -EINVAL);
	if (return_on_error(ret))
		return ret;

	/* cleanup */

	ret = test_release_rx_profile(dev, rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;
	return 0;
}

int ac_add_delete_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr   std_attr = {
		.vni_attr.match  = 11,
		.vni_attr.ignore = 0,
		.vni_attr.name   = "Test RX Profile AC",
	};

	unsigned int    rx_profile_id;
	int             ret;

	ret = test_alloc_rx_profile(dev, &std_attr, &rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;

	struct {
		enum ucxi_ac_type    ac_type;
		union ucxi_ac_data   ac_data;
		unsigned int         ac_id;
		int                  expected_result;
	} ac_info[] = {
		{ .ac_type = UCXI_AC_UID, .ac_data.uid = 10, .expected_result = 0 },
		{ .ac_type = UCXI_AC_UID, .ac_data.uid = 11, .expected_result = 0 },
		{ .ac_type = UCXI_AC_GID, .ac_data.gid = 6,  .expected_result = 0 },
		{ .ac_type = UCXI_AC_GID, .ac_data.gid = 7,  .expected_result = 0 },
		{ .ac_type = UCXI_AC_OPEN,                   .expected_result = 0 },
		{ .ac_type = UCXI_AC_OPEN,                   .expected_result = -EEXIST },
		{ .ac_type = UCXI_AC_UID, .ac_data.uid = 10, .expected_result = -EEXIST },
		{ .ac_type = UCXI_AC_GID, .ac_data.gid = 7,  .expected_result = -EEXIST },
		{ .ac_type = UCXI_AC_UID, .ac_data.uid = -1, .expected_result = -EBADR },
		{ .ac_type = UCXI_AC_GID, .ac_data.gid = -1, .expected_result = -EBADR },
	};

	/* create them */

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		int ret = test_rx_profile_add_ac(dev, rx_profile_id, ac_info[i].ac_type,
						 &ac_info[i].ac_data, &ac_info[i].ac_id,
						 ac_info[i].expected_result);

		if (return_on_error(ret))
			return ret;
	}

	/* retrieve them */

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		if (ac_info[i].expected_result)
			continue;

		enum ucxi_ac_type   type;
		union ucxi_ac_data  data;

		int ret = test_rx_profile_get_ac_data(dev, rx_profile_id,
						      ac_info[i].ac_id,
						      &type, &data, 0);

		if (return_on_error(ret))
			return ret;

		if (ac_info[i].ac_type != type) {
			printf("AC type mismatch: expected %u, got %u for ac_info[%zu]\n",
			       ac_info[i].ac_type, type, i);
			return -1;
		}
		switch (type) {
		case UCXI_AC_UID:
			if (data.uid != ac_info[i].ac_data.uid) {
				printf("UID mismatch: expected %u, got %u for ac_info[%zu]\n",
				       ac_info[i].ac_data.uid, data.uid, i);
				return -2;
			}
			break;
		case UCXI_AC_GID:
			if (data.gid != ac_info[i].ac_data.gid) {
				printf("GID mismatch: expected %u, got %u for ac_info[%zu]\n",
				       ac_info[i].ac_data.gid, data.gid, i);
				return -3;
			}
			break;
		case UCXI_AC_OPEN:
			break;
		default:
			printf("Unknown AC Type: %u\n", type);
			return -4;
		}
	}

	/* delete them */

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		if (ac_info[i].expected_result)
			continue;
		int ret = test_rx_profile_remove_ac(dev, rx_profile_id,
						    ac_info[i].ac_id,
						    ac_info[i].expected_result);

		if (return_on_error(ret))
			return ret;
	}

	/* cleanup */

	ret = test_release_rx_profile(dev, rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;
	return 0;
}

int retrieve_acs_test(struct cass_dev *dev)
{
	const struct ucxi_rx_attr   std_attr = {
		.vni_attr.match  = 9,
		.vni_attr.ignore = 0,
		.vni_attr.name   = "Test RX Profile AC",
	};

	unsigned int    rx_profile_id;

	int ret = test_alloc_rx_profile(dev, &std_attr, &rx_profile_id, 0);

	if (return_on_error(ret))
		return ret;

	struct {
		enum ucxi_ac_type    ac_type;
		union ucxi_ac_data   ac_data;
		unsigned int         ac_id;
		int                  expected_result;
		int                  by_user_result;
	} ac_info[] = {
		{ .ac_type         = UCXI_AC_UID,
		  .ac_data.uid     = 10,
		  .expected_result = 0,
		  .by_user_result  = 0 },
		{ .ac_type         = UCXI_AC_UID,
		  .ac_data.uid     = 11,
		  .expected_result = 0,
		  .by_user_result  = 0 },
		{ .ac_type         = UCXI_AC_GID,
		  .ac_data.gid     = 6,
		  .expected_result = 0,
		  .by_user_result  = 0 },
		{ .ac_type         = UCXI_AC_GID,
		  .ac_data.gid     = 7,
		  .expected_result = 0, .
		  by_user_result   = 0 },
		{ .ac_type         = UCXI_AC_OPEN,
		  .expected_result = 0,
		  .by_user_result  = 0 },
	};

	/* setup */

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		int ret = test_rx_profile_add_ac(dev, rx_profile_id, ac_info[i].ac_type,
						 &ac_info[i].ac_data, &ac_info[i].ac_id,
						 ac_info[i].expected_result);
		if (return_on_error(ret))
			return ret;
	}

	/* retrieve the list of ids */

	unsigned int   ac_entry_ids[ARRAY_SIZE(ac_info)+2];
	size_t         max_ids = ARRAY_SIZE(ac_entry_ids);
	size_t         num_ids;

	ret = test_rx_profile_get_ac_ids(dev, rx_profile_id, 0,
					 ac_entry_ids, &num_ids, -ENOSPC);
	if (return_on_error(ret))
		return ret;

	if (num_ids != ARRAY_SIZE(ac_info)) {
		printf("RX Profile Get AC Entry ids returns %zu ids, expected %zu\n",
		       num_ids, ARRAY_SIZE(ac_info));
		return -1;
	}
	verbose_printf("RX Profile Get AC Entry ids returns %zu ids, as expected\n",
		       ARRAY_SIZE(ac_info));

	ret = test_rx_profile_get_ac_ids(dev, rx_profile_id, max_ids,
					 ac_entry_ids, &num_ids, 0);
	if (return_on_error(ret))
		return ret;

	if (num_ids != ARRAY_SIZE(ac_info)) {
		printf("RX Profile Get AC Entry ids returns %zu ids, expected %zu\n",
		       num_ids, ARRAY_SIZE(ac_info));
		return -1;
	}
	verbose_printf("RX Profile Get AC Entry ids returns %zu ids, as expected\n",
		       ARRAY_SIZE(ac_info));

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		bool found = false;

		for (size_t j = 0; j < num_ids; j++) {
			if (ac_info[i].ac_id != ac_entry_ids[j])
				continue;
			found = true;
			break;
		}
		if (found)
			continue;
		printf("AC Id %u not found in RX Profile %u\n",
		       ac_info[i].ac_id, rx_profile_id);
		return -2;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		unsigned int        ac_entry_id;
		int ret = test_rx_profile_get_ac_id_by_data(dev, rx_profile_id,
							    ac_info[i].ac_type,
							    &ac_info[i].ac_data,
							    &ac_entry_id, 0);
		if (return_on_error(ret))
			return ret;

		if (ac_entry_id == ac_info[i].ac_id) {
			verbose_printf("Found AC Entry id %u by data, as expected.\n",
				       ac_entry_id);
			continue;
		}
		printf("Found AC Entry Id %u by data, expected %u\n",
		       ac_entry_id, ac_info[i].ac_id);
		return -3;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		unsigned int        ac_entry_id;
		uid_t               uid = (ac_info[i].ac_type == UCXI_AC_UID) ?
					   ac_info[i].ac_data.uid : invalid_uid;
		gid_t               gid = (ac_info[i].ac_type == UCXI_AC_GID) ?
					   ac_info[i].ac_data.gid : invalid_gid;
		int ret = test_rx_profile_get_ac_id_by_user(dev, rx_profile_id,
							    uid, gid,
							    UCXI_AC_ANY,
							    &ac_entry_id,
							    ac_info[i].by_user_result);
		if (return_on_error(ret))
			return ret;

		if (ac_info[i].by_user_result)
			continue;

		if (ac_entry_id == ac_info[i].ac_id) {
			verbose_printf("Found AC Entry id %u by user, as expected.\n",
				       ac_entry_id);
			continue;
		}
		printf("Found AC Entry Id %u by user, expected %u\n",
		       ac_entry_id, ac_info[i].ac_id);
		return -3;
	}

	static struct {
		uid_t           uid;
		gid_t           gid;
		unsigned int    desired_types;
		int             expected_result;
	} invalid_ac_info[] = {
		{ .uid = -1,
		  .gid =  6,
		  .desired_types   = UCXI_AC_UID,
		  .expected_result = -EPERM },
		{ .uid = -1,
		  .gid =  6,
		  .desired_types = UCXI_AC_GID, .
		  expected_result = 0 },
		{ .uid = 10,
		  .gid = -1,
		  .desired_types = UCXI_AC_GID,
		  .expected_result = -EPERM },
		{ .uid = 10,
		  .gid = -1,
		  .desired_types = UCXI_AC_UID,
		  .expected_result = 0 },
		{ .uid =  1,
		  .gid = -1,
		  .desired_types = UCXI_AC_ANY,
		  .expected_result = 0 },
		{ .uid = -1,
		  .gid =  1,
		  .desired_types = UCXI_AC_ANY,
		  .expected_result = 0 },
		{ .uid = -1,
		  .gid = -1,
		  .desired_types = (UCXI_AC_UID | UCXI_AC_GID),
		  .expected_result = -EPERM },
	};

	for (size_t i = 0; i < ARRAY_SIZE(invalid_ac_info); i++) {
		unsigned int ac_entry_id;
		int ret = test_rx_profile_get_ac_id_by_user(dev, rx_profile_id,
							    invalid_ac_info[i].uid,
							    invalid_ac_info[i].gid,
							    invalid_ac_info[i].desired_types,
							    &ac_entry_id,
							    invalid_ac_info[i].expected_result);

		if (return_on_error(ret))
			return ret;
	}

	/* cleanup */

	for (size_t i = 0; i < ARRAY_SIZE(ac_info); i++) {
		int ret = test_rx_profile_remove_ac(dev, rx_profile_id,
						    ac_info[i].ac_id, 0);

		if (return_on_error(ret))
			return ret;
	}

	ret = test_release_rx_profile(dev, rx_profile_id, 0);
	if (return_on_error(ret))
		return ret;
	return 0;
}

int cleanup_check(struct cass_dev *dev)
{
	unsigned int      ids[100];
	size_t            num_ids;

	int ret = test_get_entry_ids(dev, ARRAY_SIZE(ids), ids, &num_ids, 0);

	if (return_on_error(ret))
		return ret;

	if (num_ids > 0) {
		printf("Found %zu IDs during cleanup check.  Should be 0.\n", num_ids);
		for (size_t i = 0; i < num_ids; i++)
			printf("   ID: %u\n", ids[i]);
		return -1;
	}

	return 0;
}

void usage(const char *prog_name)
{
	char *copy = strdup(prog_name);

	printf("Usage: %s [-vh]\n"
	       "       -v: verbose output\n"
	       "       -h: help\n",
	       basename(copy));
	free(copy);
}

typedef int (*test_func)(struct cass_dev *dev);

#define TEST_INFO(x)   { x, #x }

struct test_info {
	test_func   func;
	const char  *name;
} tests[] = {
	TEST_INFO(alloc_delete_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(get_list_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(vni_collision_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(rx_profile_release_revoke_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(missing_args_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(ac_missing_args_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(ac_add_delete_test),
	TEST_INFO(cleanup_check),
	TEST_INFO(retrieve_acs_test),
	TEST_INFO(cleanup_check),
};

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 0;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		struct cass_dev *dev = open_device(DEVICE_NAME);

		if (!dev) {
			printf("Cannot open %s\n", DEVICE_NAME);
			exit(1);
		}

		printf("Executing: %s\n", tests[i].name);

		int ret = (*tests[i].func)(dev);

		if (ret) {
			printf("Test %s fails: %d\n", tests[i].name, ret);
			exit(ret);
		}

		close_device(dev);

		verbose_printf("Test %s passes.\n", tests[i].name);
		fflush(stdout);
		fflush(stderr);
	}

	printf("All tests pass.\n");
	fflush(stdout);
	fflush(stderr);

	exit(0);
}
