// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Hewlett Packard Enterprise Development LP */

/* User space rgroup test */

#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_ucxi_common.h"

#define DEVICE_NAME "cxi0"

bool verbose;

void verbose_printf(const char *fmt, ...)
{
	va_list    ap;

	if (!verbose)
		return;

	printf("   ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}


static const char *true_false(bool truth)
{
	return (truth) ? "true" : "false";
}

int alloc_release_test(struct cass_dev *dev)
{
	unsigned int rgroup_id;
	struct ucxi_rgroup_attr attr = {
		.cntr_pool_id = 0,
		.system_service = false,
		.name = "ucxi_test",
	};

	/* Get a Resource Group */
	int ret = alloc_rgroup(dev, &attr, &rgroup_id);

	if (ret) {
		printf("cannot get a Resource Group. rc: %s\n", errstr(ret));
		return ret;
	}
	verbose_printf("Resource Group Allocated: %u\n",
		       rgroup_id);

	ret = release_rgroup(dev, rgroup_id);
	if (ret) {
		printf("Unable to release rgroup %u: %s\n",
		       rgroup_id, errstr(ret));
		return ret;
	}
	verbose_printf("Resource Group %u released\n",
		       rgroup_id);

	return 0;
}

int get_rgroup_id_count(struct cass_dev *dev,
			size_t *num_ids)
{
	unsigned int     rgroup_ids[500];
	size_t   i;

	int ret = get_rgroup_ids(dev, ARRAY_SIZE(rgroup_ids),
				 rgroup_ids, num_ids);

	if (ret) {
		printf("get_rgroup_ids returns %s\n",
		       errstr(ret));
		return ret;
	}

	verbose_printf("get_rgroup_ids finds %zu ids\n",
		       *num_ids);

	for (i = 0; i < *num_ids; i++) {
		verbose_printf("Found rgroup id %u\n",
			       rgroup_ids[i]);
	}

	return 0;
}

static struct ucxi_rgroup_attr rgroup_attr[] = {
	{
		.cntr_pool_id = 0,
		.system_service = false,
		.name = "ucxi_test_1",
	},
	{
		.cntr_pool_id = 1,
		.system_service = false,
		.name = "ucxi_test_2",
	},
};
static const size_t num_rgroup_attr = ARRAY_SIZE(rgroup_attr);

int rgroup_id_test(struct cass_dev *dev)
{
	unsigned int rgroup_ids[num_rgroup_attr];
	unsigned int ids[num_rgroup_attr];
	size_t   num_ids;
	size_t   i, j;
	int      ret;

	for (i = 0; i < num_rgroup_attr; i++) {
		ret = alloc_rgroup(dev, rgroup_attr + i, rgroup_ids + i);
		if (ret) {
			printf("Unable to allocate resource group %zu, %s\n",
			       i, errstr(ret));
			return ret;
		}
		verbose_printf("Allocated resource group %u\n",
			       rgroup_ids[i]);
	}


	ret = get_rgroup_ids(dev, num_rgroup_attr, ids, &num_ids);
	if (ret) {
		printf("unable to get rgroup ids: %s\n",
		       errstr(ret));
		return ret;
	}
	verbose_printf("Found %zu rgroup ids.\n", num_ids);

	if (num_ids != num_rgroup_attr) {
		printf("Number of rgroup ids (%zu) is not %zu.\n",
		       num_ids, num_rgroup_attr);
		return -1;
	}

	for (i = 0; i < num_ids; i++) {
		for (j = 0; j < num_ids; j++) {
			if (rgroup_ids[i] == ids[j])
				goto found;
		}
		printf("Rgroup id %u not retrieved.\n",
		       rgroup_ids[i]);
		return -1;
found:
		verbose_printf("Rgroup id %u successfully retrieved.\n",
			       rgroup_ids[i]);
	}

	for (i = 0; i < num_ids; i++) {
		ret = release_rgroup(dev, ids[i]);
		if (ret) {
			printf("Unable to release rgroup %u: %s\n",
			       ids[i], errstr(ret));
			return ret;
		}
		verbose_printf("Released rgroup %u\n",
			       ids[i]);
	}

	return 0;
}

int get_info_test(struct cass_dev *dev)
{
	struct ucxi_rgroup_attr    attr;
	struct ucxi_rgroup_state   state;
	unsigned int   rgroup_ids[num_rgroup_attr];
	size_t   i;
	int      ret;

	for (i = 0; i < num_rgroup_attr; i++) {
		ret = alloc_rgroup(dev, rgroup_attr + i, rgroup_ids + i);
		if (ret) {
			printf("Unable to allocate resource group %zu, %s\n",
			       i, errstr(ret));
			return ret;
		}
		verbose_printf("Allocated resource group %u\n",
			       rgroup_ids[i]);
	}

	for (i = 0; i < num_rgroup_attr; i++) {
		ret = get_rgroup_info(dev, rgroup_ids[i], &attr, &state);
		if (ret) {
			printf("Unable to get info for rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}
		verbose_printf("Retrieved info for rgroup %u\n", rgroup_ids[i]);

		if ((rgroup_attr[i].cntr_pool_id != attr.cntr_pool_id) ||
		    (rgroup_attr[i].system_service != attr.system_service) ||
		    (strcmp(rgroup_attr[i].name, attr.name) != 0)) {
			printf("Attributes don't match for rgroup %u\n",
			       rgroup_ids[i]);
			return -1;
		}

		if (state.released || state.enabled || state.refcount != 1) {
			printf("States are incorrect for rgroup %u\n",
			       rgroup_ids[i]);
			printf("   enabled: %s\n"
			       "   released: %s\n"
			       "   refcount: %i\n",
			       true_false(state.enabled),
			       true_false(state.released),
			       state.refcount);
			return -1;
		}

		verbose_printf("Rgroup id: %u\n"
			       "   cntr_pool_id: %u\n"
			       "   system_service: %s\n"
			       "   name: %s\n"
			       "   enabled: %s\n"
			       "   released: %s\n"
			       "   refcount: %i\n",
			       rgroup_ids[i],
			       attr.cntr_pool_id,
			       true_false(attr.system_service),
			       attr.name,
			       true_false(state.enabled),
			       true_false(state.released),
			       state.refcount);

		ret = enable_rgroup(dev, rgroup_ids[i]);
		if (ret) {
			printf("Unable to enable rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}

		ret = get_rgroup_info(dev, rgroup_ids[i], &attr, &state);
		if (ret) {
			printf("Unable to get info for rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}

		if (!state.enabled) {
			printf("Rgroup %u should be enabled, but is disabled.\n",
			       rgroup_ids[i]);
			return -1;
		}
		verbose_printf("Successfully enabled rgroup %u\n", rgroup_ids[i]);

		ret = disable_rgroup(dev, rgroup_ids[i]);
		if (ret) {
			printf("Unable to disable rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}

		ret = get_rgroup_info(dev, rgroup_ids[i], &attr, &state);
		if (ret) {
			printf("Unable to get info for rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}

		if (state.enabled) {
			printf("Rgroup %u should be disabled, but is enabled.\n",
			       rgroup_ids[i]);
			return -1;
		}
		verbose_printf("Successfully disabled rgroup %u\n",
			       rgroup_ids[i]);
	}

	for (i = 0; i < num_rgroup_attr; i++) {
		ret = release_rgroup(dev, rgroup_ids[i]);
		if (ret) {
			printf("Unable to release rgroup %u: %s\n",
			       rgroup_ids[i], errstr(ret));
			return ret;
		}
		verbose_printf("Released rgroup %u\n",
			       rgroup_ids[i]);
	}

	return 0;
}

int add_resource_test(struct cass_dev *dev)
{
	const struct ucxi_rgroup_attr    attr = {
		.cntr_pool_id = 3,
		.system_service = true,
		.name = "add_resource_test",
	};
	const struct {
		enum ucxi_resource_type      resource_type;
		struct ucxi_resource_limits  limits;
	} resources[] = {
		{
			.resource_type   = UCXI_RESOURCE_PTLTE,
			.limits.reserved = 1,
			.limits.max      = 2,
		},
		{
			.resource_type   = UCXI_RESOURCE_TXQ,
			.limits.reserved = 3,
			.limits.max      = 4,
		},
		{
			.resource_type   = UCXI_RESOURCE_TGQ,
			.limits.reserved = 5,
			.limits.max      = 6,
		},
		{
			.resource_type   = UCXI_RESOURCE_EQ,
			.limits.reserved = 7,
			.limits.max      = 8,
		},
		{
			.resource_type   = UCXI_RESOURCE_CT,
			.limits.reserved = 9,
			.limits.max      = 10,
		},
		{
			.resource_type   = UCXI_RESOURCE_PE0_LE,
			.limits.reserved = 11,
			.limits.max      = 12,
		},
		{
			.resource_type   = UCXI_RESOURCE_PE1_LE,
			.limits.reserved = 13,
			.limits.max      = 14,
		},
		{
			.resource_type   = UCXI_RESOURCE_PE2_LE,
			.limits.reserved = 15,
			.limits.max      = 16,
		},
		{
			.resource_type   = UCXI_RESOURCE_PE3_LE,
			.limits.reserved = 17,
			.limits.max      = 18,
		},
		{
			.resource_type   = UCXI_RESOURCE_TLE,
			.limits.reserved = 19,
			.limits.max      = 20,
		},
		{
			.resource_type   = UCXI_RESOURCE_AC,
			.limits.reserved = 21,
			.limits.max      = 22,
		},
	};

	struct ucxi_resource_limits    limits;
	enum ucxi_resource_type        type;
	enum ucxi_resource_type        types[100];
	unsigned int    rgroup_id;
	size_t   num_types;
	size_t   i, j;
	int      ret;

	ret = alloc_rgroup(dev, &attr, &rgroup_id);
	if (ret) {
		printf("unable to alloc rgroup: %s\n", errstr(ret));
		return ret;
	}
	verbose_printf("Created rgroup %u\n", rgroup_id);

	/* add the resources */

	for (i = 0; i < ARRAY_SIZE(resources); i++) {
		ret = rgroup_add_resource(dev, rgroup_id,
					  resources[i].resource_type,
					  &resources[i].limits);
		if (ret) {
			printf("Unable to add resource %u to rgroup %u: %s\n",
			       resources[i].resource_type, rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Added resource %u to rgroup %u\n",
			       resources[i].resource_type, rgroup_id);
	}

	/* Try to add them again, it should fail with -EEXIT */

	for (i = 0; i < ARRAY_SIZE(resources); i++) {
		verbose_printf("Attempting to add resource %u again.\n",
			       resources[i].resource_type);
		ret = rgroup_add_resource(dev, rgroup_id,
					  resources[i].resource_type,
					  &resources[i].limits);
		switch (ret) {
		case 0:
			printf("Adding resource %u a second time should fail, but passed.\n",
			       resources[i].resource_type);
			return -1;
		case -EEXIST:
			verbose_printf("Adding resource %u a second time failed, as it should.\n",
				       resources[i].resource_type);
			break;
		default:
			printf("Adding resource %u a second time failed with %s, should be %s.\n",
			       resources[i].resource_type, errstr(ret), errstr(-EEXIST));
			return -1;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(resources); i++) {
		type = resources[i].resource_type;
		ret  = rgroup_get_resource(dev, rgroup_id, type, &limits);
		if (ret) {
			printf("Unable to get resource %u from rgroup %u: %s\n",
			       type, rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Retrieved resource %u from rgroup %u\n",
			       type, rgroup_id);

		if ((limits.reserved != resources[i].limits.reserved) ||
		    (limits.max != resources[i].limits.max)) {
			printf("Resource limits don't match for resource %u rgroup %u\n",
			       type, rgroup_id);
			return -1;
		}
		verbose_printf("Resource limits match for resource %u rgroup %u\n",
			       type, rgroup_id);
	}

	ret = rgroup_get_resource_types(dev,
					rgroup_id,
					ARRAY_SIZE(types),
					types,
					&num_types);
	if (ret) {
		printf("Unable to get list of resource types from rgroup %u: %s\n",
		       rgroup_id, errstr(ret));
		return ret;
	}
	verbose_printf("Retrieved list of resource types from rgroup %u: %zu types.\n",
		       rgroup_id, num_types);
	for (i = 0; i < num_types; i++)
		verbose_printf("  Type: %u\n", types[i]);

	if (num_types != ARRAY_SIZE(resources)) {
		printf("Error: number of resource types retrieved %zu is not %zu.\n",
		       num_types, ARRAY_SIZE(resources));
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(resources); i++) {
		type = resources[i].resource_type;
		for (j = 0; j < num_types; j++) {
			if (type == types[j]) {
				types[j] = (unsigned int) -1;  /* don't match again */
				goto found_type;
			}
		}
		printf("Resource %u not found in rgroup %u\n", type, rgroup_id);
		return -1;
found_type:
		verbose_printf("Resource type %u found in rgroup %u.\n", type, rgroup_id);
	}

	for (i = 0; i < ARRAY_SIZE(resources); i++) {
		type = resources[i].resource_type;
		ret = rgroup_delete_resource(dev, rgroup_id, type);

		if (ret) {
			printf("Unable to delete resource %u from rgroup %u: %s\n",
			       type, rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Deleted resource %u from rgroup %u\n", type, rgroup_id);
	}

	ret = rgroup_get_resource_types(dev,
					rgroup_id,
					ARRAY_SIZE(types),
					types,
					&num_types);
	if (ret) {
		printf("Unable to get list of resource types from rgroup %u: %s\n",
		       rgroup_id, errstr(ret));
		return ret;
	}
	if (num_types > 0) {
		for (i = 0; i < num_types; i++) {
			printf("Resource %u present after deletion in rgroup %u\n",
			       types[i], rgroup_id);
		}
		return -1;
	}

	ret = release_rgroup(dev, rgroup_id);
	if (ret) {
		printf("Unable to release rgroup %u: %s\n", rgroup_id, errstr(ret));
		return ret;
	}
	verbose_printf("Rgroup %u released.\n", rgroup_id);

	return 0;
}

/* **************************************************************** */

struct ac_data {
	const enum ucxi_ac_type      type;
	const union ucxi_ac_data     data;
	unsigned int                 id;
} test_acs[] = {
	{
		.type = UCXI_AC_UID,
		.data.uid = 7,
	},
	{
		.type = UCXI_AC_UID,
		.data.uid = 9,
	},
	{
		.type = UCXI_AC_GID,
		.data.gid = 5,
	},
	{
		.type = UCXI_AC_GID,
		.data.gid = 7,
	},
	{
		.type = UCXI_AC_OPEN,
	},
};

struct ac_test_data {
	struct ucxi_rgroup_attr  rgroup_attr;
	unsigned int             rgroup_id;
	struct ac_data           *acs;
	size_t                   num_acs;
};

struct ac_test_data   ac_test_data = {
	.rgroup_attr.cntr_pool_id = 2,
	.rgroup_attr.system_service = true,
	.rgroup_attr.name = "add_ac_test",
	.acs = test_acs,
	.num_acs = ARRAY_SIZE(test_acs),
};

int ac_test_setup(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	size_t i;
	int    ret;

	ret = alloc_rgroup(dev, &data->rgroup_attr, &data->rgroup_id);
	if (ret) {
		printf("unable to alloc rgroup: %s\n", errstr(ret));
		return ret;
	}
	verbose_printf("Created rgroup %u\n", data->rgroup_id);

	/* Add all the access control entries */

	for (i = 0; i < data->num_acs; i++) {
		ret = rgroup_add_ac_entry(dev, data->rgroup_id,
					  data->acs[i].type,
					  &data->acs[i].data,
					  &data->acs[i].id);
		if (ret) {
			printf("Unable to add AC Entry %zu to rgroup %u: %s\n",
			       i, data->rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Added AC Entry %zu to rgroup %u, id %u\n",
			       i, data->rgroup_id, data->acs[i].id);
	}

	return 0;
}

int ac_test_retrieve_by_id(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	union ucxi_ac_data  ac_data;
	enum ucxi_ac_type   ac_type;
	size_t i;
	int    ret;

	/* Retrieve them, and check the type and data values */

	for (i = 0; i < data->num_acs; i++) {
		ret = rgroup_get_ac_entry_by_id(dev, data->rgroup_id,
						data->acs[i].id,
						&ac_type, &ac_data);
		if (ret) {
			printf("Unable to get AC Entry %u from rgroup %u: %s\n",
			       ac_type, data->rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Retrieved AC Entry %u from rgroup %u\n",
			       data->acs[i].id, data->rgroup_id);

		if (ac_type != data->acs[i].type) {
			printf("AC Entry type does not match: %u != %u.\n",
			       ac_type, data->acs[i].type);
			return -1;
		}
		verbose_printf("AC Entry type for entry %i correct: %u\n",
			       data->acs[i].id, ac_type);

		switch (ac_type) {
		case UCXI_AC_UID:
			if (data->acs[i].data.uid != ac_data.uid) {
				printf("AC Entry data incorrect: %u != %u\n",
				       data->acs[i].data.uid, ac_data.uid);
				return -1;
			}
			verbose_printf("AC Entry data correct: %u\n", ac_data.uid);
			break;
		case UCXI_AC_GID:
			if (data->acs[i].data.gid != ac_data.gid) {
				printf("AC Entry data incorrect: %u != %u\n",
				       data->acs[i].data.gid, ac_data.gid);
				return -1;
			}
			verbose_printf("AC Entry data correct: %u\n", ac_data.gid);
			break;
		case UCXI_AC_OPEN:
			verbose_printf("No AC Entry data to compare for this type.\n");
			break;
		default:
			printf("Bad type: %u\n", ac_type);
			return -2;
		}
	}

	return 0;
}

int ac_test_retrieve_by_data(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	unsigned int  id;
	size_t   i;
	int      ret;

	/* Retrieve them by data, ensure we get the proper id */

	for (i = 0; i < data->num_acs; i++) {
		ret = rgroup_get_ac_entry_id_by_data(dev, data->rgroup_id,
						     data->acs[i].type,
						     &data->acs[i].data,
						     &id);
		if (ret) {
			printf("Unable to AC Entry %zu by data: %s\n",
			       i, errstr(ret));
			return ret;
		}
		verbose_printf("Retrieved AC Entry %zu by data successfully.\n", i);
		if (id != data->acs[i].id) {
			printf("Expected id %u for AC Entry %zu, but got %u.\n",
			       data->acs[i].id, i, id);
			return -1;
		}
		verbose_printf("Got id %u as expected.\n", id);
	}

	return 0;
}

int ac_test_add_again(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	unsigned int new_id;
	size_t i;
	int    ret;

	/* try to add them again, it should fail with -EEXIST. */

	for (i = 0; i < data->num_acs; i++) {
		verbose_printf("Attempt to add AC Entry %zu a second time.\n", i);
		ret = rgroup_add_ac_entry(dev, data->rgroup_id,
					  data->acs[i].type,
					  &data->acs[i].data,
					  &new_id);
		switch (ret) {
		case 0:
			printf("Added AC Entry %zu to rgroup %u a second time.\n",
			       i, data->rgroup_id);
			return -1;
		case -EEXIST:
			verbose_printf("Attempting to add AC Entry %zu again fails, %s", i,
				       "as it should.\n");
			break;
		default:
			printf("Attempting to add AC Entry %zu again fails with code: ", i);
			printf("%s should be %s.\n", errstr(ret), errstr(-EEXIST));
		}
	}

	return 0;
}

int ac_test_get_ids(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	unsigned int ids[100];
	unsigned int id;
	size_t   num_ids;
	size_t   i, j;
	int      ret;

	ret = rgroup_get_ac_entry_ids(dev, data->rgroup_id,
				      ARRAY_SIZE(ids),
				      ids,
				      &num_ids);
	if (ret) {
		printf("Unable to get list of AC Entry ids from rgroup %u: %s\n",
		       data->rgroup_id, errstr(ret));
		return ret;
	}
	verbose_printf("Retrieved list of AC Entry ids from rgroup %u: %zu ids.\n",
		       data->rgroup_id, num_ids);
	for (i = 0; i < num_ids; i++)
		verbose_printf("   Id: %u\n", ids[i]);

	if (num_ids != data->num_acs) {
		printf("Error: number of AC Entry ids retrieved %zu is not %zu.\n",
		       num_ids, data->num_acs);
		return -1;
	}

	for (i = 0; i < data->num_acs; i++) {
		id = data->acs[i].id;
		for (j = 0; j < num_ids; j++) {
			if (id == ids[j]) {
				ids[j] = (unsigned int) -1;  /* don't match again */
				goto found_id;
			}
		}
		printf("AC Entry ID  %u not found in rgroup %u\n", id, data->rgroup_id);
		return -1;
found_id:
		verbose_printf("AC Entry ID %u found in rgroup %u.\n", id, data->rgroup_id);
	}

	return 0;
}

int ac_test_retrieve_by_user(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	size_t   num_uids    = 0;
	size_t   num_gids    = 0;
	uid_t    biggest_uid = 0;
	gid_t    biggest_gid = 0;
	unsigned int open_id = -1;
	unsigned int id;
	uid_t    uids[50];
	gid_t    gids[50];
	uid_t    bogus_uid;
	gid_t    bogus_gid;
	size_t   i, j;
	int      ret;

	/* find the biggest uid and gid */

	for (i = 0; i < data->num_acs; i++) {
		switch (data->acs[i].type) {
		case UCXI_AC_UID:
			uids[num_uids] = data->acs[i].data.uid;
			if (uids[num_uids] > biggest_uid)
				biggest_uid = uids[num_uids];
			num_uids++;
			break;
		case UCXI_AC_GID:
			gids[num_gids] = data->acs[i].data.gid;
			if (gids[num_gids] > biggest_gid)
				biggest_gid = gids[num_gids];
			num_gids++;
			break;
		case UCXI_AC_OPEN:
			open_id = data->acs[i].id;
			break;
		default:
			printf("Gah!\n");
			return -2;
		}
	}

	bogus_uid = biggest_uid + 1;
	bogus_gid = biggest_gid + 1;

	/* Check for UIDs */

	for (i = 0; i < num_uids; i++) {
		ret = rgroup_get_ac_entry_id_by_user(dev, data->rgroup_id, uids[i],
						     bogus_gid, &id);
		if (ret) {
			printf("Unable to retrieve AC Entry for uid %u, gid %u: %s\n",
			       uids[i], bogus_gid, errstr(ret));
			return ret;
		}
		verbose_printf("Got AC Entry Id %u for uid %u, gid %u\n",
			       id, uids[i], bogus_gid);
		for (j = 0; j < data->num_acs; j++) {
			if (data->acs[j].id != id)
				continue;
			if ((data->acs[j].type      != UCXI_AC_UID) ||
			    (data->acs[j].data.uid  != uids[i])) {
				printf("AC Entry %u does match UID %u\n",
				       id, uids[i]);
				return -3;
			}
			verbose_printf("AC Entry %u matches UID %u as desired.\n",
				       id, uids[i]);
			break;
		}
	}

	/* Check for GIDs */

	for (i = 0; i < num_gids; i++) {
		ret = rgroup_get_ac_entry_id_by_user(dev, data->rgroup_id, bogus_uid,
						     gids[i], &id);
		if (ret) {
			printf("Unable to retrieve AC Entry for uid %u, gid %u: %s\n",
			       bogus_uid, gids[i], errstr(ret));
			return ret;
		}
		verbose_printf("Got AC Entry Id %u for uid %u, gid %u\n",
			       id, bogus_uid, gids[i]);
		for (j = 0; j < data->num_acs; j++) {
			if (data->acs[j].id != id)
				continue;
			if ((data->acs[j].type      != UCXI_AC_GID) ||
			    (data->acs[j].data.gid  != gids[i])) {
				printf("AC Entry %u does match GID %u\n",
				       id, gids[i]);
				return -4;
			}
			verbose_printf("AC Entry %u matches GID %u as desired.\n",
				       id, gids[i]);
			break;
		}
	}

	ret = rgroup_get_ac_entry_id_by_user(dev, data->rgroup_id,
					     bogus_uid, bogus_gid,
					     &id);

	if (ret) {
		printf("Failed to get AC Entry Id for bogus uid:gid pair (%s).\n",
		       errstr(ret));
		return ret;
	}

	if (open_id != id) {
		printf("Got AC Entry id %u, expected %u for bogus uid:gid pair\n",
		       id, open_id);
		return -5;
	}
	verbose_printf("Got AC Entry Id %u for bogus uid:gid pair, as expected.\n",
		       id);

	return 0;
}

int ac_test_teardown(struct cass_dev *dev)
{
	struct ac_test_data *data = &ac_test_data;
	unsigned int  ids[123];
	unsigned int  id;
	size_t   num_ids;
	size_t i;
	int    ret;

	for (i = 0; i < data->num_acs; i++) {
		id = data->acs[i].id;
		ret = rgroup_delete_ac_entry(dev, data->rgroup_id, id);
		if (ret) {
			printf("Unable to delete AC Entry ID %u from rgroup %u: %s\n",
			       id, data->rgroup_id, errstr(ret));
			return ret;
		}
		verbose_printf("Deleted AC Entry ID %u from rgroup %u\n",
			       id, data->rgroup_id);
	}

	ret = rgroup_get_ac_entry_ids(dev,
				      data->rgroup_id,
				      ARRAY_SIZE(ids),
				      ids,
				      &num_ids);
	if (ret) {
		printf("Unable to get list of AC Entry IDs from rgroup %u: %s\n",
		       data->rgroup_id, errstr(ret));
		return ret;
	}
	if (num_ids > 0) {
		for (i = 0; i < num_ids; i++) {
			printf("AC Entry ID %u present after deletion in rgroup %u\n",
			       ids[i], data->rgroup_id);
		}
		return -1;
	}

	ret = release_rgroup(dev, data->rgroup_id);
	if (ret) {
		printf("Unable to release rgroup %u: %s\n", data->rgroup_id, errstr(ret));
		return ret;
	}
	verbose_printf("Rgroup %u released.\n", data->rgroup_id);

	return 0;
}

int cleanup_check(struct cass_dev *dev)
{
	size_t     num_rgroup_ids;

	int ret = get_rgroup_id_count(dev, &num_rgroup_ids);

	if (ret)
		return ret;

	if (num_rgroup_ids > 0) {
		printf("%zu rgroup ids found during %s\n",
		       num_rgroup_ids, __func__);

		return -1;
	}
	return 0;
}

void usage(const char *prog_name)
{
	char *copy = strdup(prog_name);

	printf("%s: %s [-vh]\n"
	       "       -v: verbose output\n"
	       "       -h: %s\n",
	       __func__, basename(copy), __func__);
	free(copy);
}

typedef int (*test_func)(struct cass_dev *dev);

#define TI(x)   { x, #x }

struct test_info {
	test_func   func;
	const char  *name;
} tests[] = {
	TI(alloc_release_test),
	TI(cleanup_check),
	TI(rgroup_id_test),
	TI(cleanup_check),
	TI(get_info_test),
	TI(cleanup_check),
	TI(add_resource_test),
	TI(cleanup_check),
	TI(ac_test_setup),
	TI(ac_test_retrieve_by_id),
	TI(ac_test_retrieve_by_data),
	TI(ac_test_get_ids),
	TI(ac_test_add_again),
	TI(ac_test_teardown),
	TI(cleanup_check),
};

int main(int argc, char *argv[])
{
	int     opt;
	size_t  i;
	int     ret;

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

	for (i = 0; i < ARRAY_SIZE(tests); i++) {

		struct cass_dev *dev = open_device(DEVICE_NAME);

		if (!dev) {
			printf("Cannot open %s\n", DEVICE_NAME);
			exit(1);
		}

		printf("Executing: %s\n", tests[i].name);

		ret = tests[i].func(dev);

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
