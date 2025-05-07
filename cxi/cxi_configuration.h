/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2025 Hewlett Packard Enterprise Development LP */

#ifndef _CXI_CONFIGURATION_H_
#define _CXI_CONFIGURATION_H_

/* Parameter for use with the 'by_user' retrieve functions */
#define CXI_AC_ANY (CXI_AC_UID | CXI_AC_GID | CXI_AC_OPEN)

union cxi_ac_data {
	uid_t     uid;
	gid_t     gid;
};

void cxi_ac_entry_list_init(struct cxi_ac_entry_list *list);

void cxi_ac_entry_list_purge(struct cxi_ac_entry_list *list);

void cxi_ac_entry_list_destroy(struct cxi_ac_entry_list *list);

bool cxi_ac_entry_list_empty(struct cxi_ac_entry_list *list);

int cxi_ac_entry_list_insert(struct cxi_ac_entry_list *list,
			     enum cxi_ac_type ac_type,
			     const union cxi_ac_data *ac_data,
			     unsigned int *id);

int cxi_ac_entry_list_delete(struct cxi_ac_entry_list *list,
			     unsigned int id);

int cxi_ac_entry_list_retrieve_by_id(struct cxi_ac_entry_list *list,
				     unsigned int id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *data);

int cxi_ac_entry_list_retrieve_by_data(struct cxi_ac_entry_list *list,
				       enum cxi_ac_type ac_type,
				       const union cxi_ac_data *ac_data,
				       unsigned int *id);

int cxi_ac_entry_list_retrieve_by_user(struct cxi_ac_entry_list *list,
				       uid_t uid,
				       gid_t gid,
				       cxi_ac_typeset_t desired_types,
				       unsigned int *id);

int cxi_ac_entry_list_get_ids(struct cxi_ac_entry_list *list,
			      size_t max_ids,
			      unsigned int *ids,
			      size_t *num_ids);

/* Common list for RX and TX Profiles */
struct cxi_rxtx_profile_list {
	struct xarray    xarray;
	struct xa_limit  *limits;
	gfp_t            flags;
	gfp_t            gfp_opts;
};

int tx_profile_find_inc_refcount(struct cxi_dev *dev,
				 unsigned int tx_profile_id,
				 struct cxi_tx_profile **tx_profile);
int cxi_dev_rx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    struct cxi_rx_profile *rx_profile,
				    unsigned int *ac_entry_id);
void cxi_rx_profile_remove_ac_entries(struct cxi_rx_profile *rx_profile);

int cxi_rx_profile_release(struct cxi_dev *dev,
			   unsigned int rx_profile_id);
int cxi_rx_profile_revoke(struct cxi_dev *dev,
			  unsigned int rx_profile_id);

int cxi_rx_profile_enable(struct cxi_dev *dev,
			   struct cxi_rx_profile *rx_profile);
void cxi_rx_profile_disable(struct cxi_dev *dev,
			   struct cxi_rx_profile *rx_profile);

struct cxi_rx_profile *cxi_dev_find_rx_profile(struct cxi_dev *dev,
					       uint16_t vni);
void cxi_rx_profile_update_pid_table(struct cxi_rx_profile *rx_profile, int pid,
				     int count, bool set);
void cxi_rx_profile_andnot_pid_table(struct cxi_reserved_pids *pids,
				     int len);
int cxi_rx_profile_alloc_pid(struct cxi_lni_priv *lni_priv,
			     struct cxi_rx_profile *rx_profile,
			     int pid, int vni, int count, bool reserve);

int cxi_rx_profile_get_info(struct cxi_dev *dev,
			    struct cxi_rx_profile *rx_profile,
			    struct cxi_rx_attr *rx_attr,
			    struct cxi_rxtx_profile_state *state);

int cxi_rx_profile_add_ac_entry(struct cxi_rx_profile *rx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);
int cxi_rx_profile_remove_ac_entry(struct cxi_rx_profile *rx_profile,
				   unsigned int ac_entry_id);
int cxi_rx_profile_get_ac_entry_ids(struct cxi_rx_profile *rx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_rx_profile_get_ac_entry_data(struct cxi_rx_profile *rx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);
int cxi_rx_profile_get_ac_entry_id_by_data(struct cxi_rx_profile *rx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);
int cxi_rx_profile_get_ac_entry_id_by_user(struct cxi_rx_profile *rx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

void cxi_dev_init_eth_tx_profile(struct cass_dev *hw);
void cxi_eth_tx_profile_cleanup(struct cass_dev *hw);
struct cxi_tx_profile *cxi_dev_get_eth_tx_profile(struct cxi_dev *dev);

struct cxi_tx_profile *cxi_dev_find_tx_profile(struct cxi_dev *dev,
					       uint16_t vni);
bool cxi_tx_profile_valid_tc(struct cxi_tx_profile *tx_profile,
			     unsigned int tc);

int cxi_tx_profile_release(struct cxi_dev *dev,
			   unsigned int tx_profile_id);
int cxi_tx_profile_revoke(struct cxi_dev *dev,
			  unsigned int tx_profile_id);

int cxi_tx_profile_get_info(struct cxi_dev *dev,
			    struct cxi_tx_profile *tx_profile,
			    struct cxi_tx_attr *tx_attr,
			    struct cxi_rxtx_profile_state *state);

int cxi_tx_profile_add_ac_entry(struct cxi_tx_profile *tx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);
int cxi_tx_profile_remove_ac_entry(struct cxi_tx_profile *tx_profile,
				   unsigned int ac_entry_id);
int cxi_tx_profile_get_ac_entry_ids(struct cxi_tx_profile *tx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_tx_profile_get_ac_entry_data(struct cxi_tx_profile *tx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);
int cxi_tx_profile_get_ac_entry_id_by_data(struct cxi_tx_profile *tx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);
int cxi_tx_profile_get_ac_entry_id_by_user(struct cxi_tx_profile *tx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

/* Resource Group Entries */

struct cxi_rgroup;

struct cxi_rgroup_list {
	struct xarray    xarray;
};

enum cxi_resource_type {
	CXI_RESOURCE_PTLTE  = 1,
	CXI_RESOURCE_TXQ,
	CXI_RESOURCE_TGQ,
	CXI_RESOURCE_EQ,
	CXI_RESOURCE_CT,
	CXI_RESOURCE_PE0_LE,
	CXI_RESOURCE_PE1_LE,
	CXI_RESOURCE_PE2_LE,
	CXI_RESOURCE_PE3_LE,
	CXI_RESOURCE_TLE,
	CXI_RESOURCE_AC,
	CXI_RESOURCE_MAX,
};

static const char * const cxi_resource_type_strs[] = {
	[CXI_RESOURCE_PTLTE] = "PTLTE",
	[CXI_RESOURCE_TXQ] = "TXQ",
	[CXI_RESOURCE_TGQ] = "TGQ",
	[CXI_RESOURCE_EQ] = "EQ",
	[CXI_RESOURCE_CT] = "CT",
	[CXI_RESOURCE_PE0_LE] = "PE0_LE",
	[CXI_RESOURCE_PE1_LE] = "PE1_LE",
	[CXI_RESOURCE_PE2_LE] = "PE2_LE",
	[CXI_RESOURCE_PE3_LE] = "PE3_LE",
	[CXI_RESOURCE_TLE] = "TLE",
	[CXI_RESOURCE_AC] = "AC",
};

static inline
const char *cxi_resource_type_to_str(enum cxi_resource_type type)
{
	if (type >= CXI_RESOURCE_PTLTE && type < CXI_RESOURCE_MAX)
		return cxi_resource_type_strs[type];

	return "(invalid)";
}

struct cxi_resource_limits {
	size_t     reserved;
	size_t     max;
	size_t     in_use;
};

struct cxi_resource_use {
	size_t     reserved;
	size_t     shared;
	size_t     shared_use;
	size_t     in_use;
	size_t     max;
};

struct cxi_resource_entry {
	struct cxi_rgroup          *rgroup;
	enum cxi_resource_type     type;
	struct cxi_resource_limits limits;
};

struct cxi_resource_entry_list {
	struct cxi_rgroup   *rgroup;
	struct xarray       xarray;
};

struct cxi_rgroup_pools {
	int            le_pool_id[C_PE_COUNT];
	int            tle_pool_id;
};

/* Resource Group */

struct cxi_rgroup_attr;
struct cxi_rgroup_state;

void cxi_dev_lock_rgroup_list(struct cass_dev *hw);
void cxi_dev_unlock_rgroup_list(struct cass_dev *hw);

void cxi_rgroup_get_info(struct cxi_rgroup *rgroup,
			struct cxi_rgroup_attr *attr,
			struct cxi_rgroup_state *state);

int cxi_rgroup_add_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type resource_type,
			    const struct cxi_resource_limits *limits);

int cxi_rgroup_delete_resource(struct cxi_rgroup *rgroup,
			       enum cxi_resource_type resource_type);

int cxi_rgroup_get_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type resource_type,
			    struct cxi_resource_limits *limits);

int cxi_rgroup_get_resource_entry(struct cxi_rgroup *rgroup,
				  enum cxi_resource_type type,
				  struct cxi_resource_entry **entry);

int cxi_rgroup_get_resource_types(struct cxi_rgroup *rgroup,
				  size_t max_resources,
				  enum cxi_resource_type *resource_types,
				  size_t *num_resources);

int cxi_rgroup_add_ac_entry(struct cxi_rgroup *rgroup,
			    enum cxi_ac_type type,
			    const union cxi_ac_data *data,
			    unsigned int *ac_entry_id);

int cxi_rgroup_delete_ac_entry(struct cxi_rgroup *rgroup,
			       unsigned int ac_entry_id);

int cxi_rgroup_get_ac_entry_ids(struct cxi_rgroup *rgroup,
				size_t max_ids,
				unsigned int *ids,
				size_t *num_ids);

int cxi_rgroup_get_ac_entry_data(struct cxi_rgroup *rgroup,
				 unsigned int ac_entry_id,
				 enum cxi_ac_type *type,
				 union cxi_ac_data *ac_data);

int cxi_rgroup_get_ac_entry_id_by_data(struct cxi_rgroup *rgroup,
				       enum cxi_ac_type type,
				       const union cxi_ac_data *ac_data,
				       unsigned int *ac_entry_id);

int cxi_rgroup_get_ac_entry_by_user(struct cxi_rgroup *rgroup,
				    uid_t uid,
				    gid_t gid,
				    cxi_ac_typeset_t desired_types,
				    unsigned int *ac_entry_id);

void cxi_rgroup_inc_refcount(struct cxi_rgroup *rgroup);
int cxi_rgroup_dec_refcount(struct cxi_rgroup *rgroup);

struct cxi_rgroup *cxi_dev_alloc_rgroup(struct cxi_dev *dev,
					const struct cxi_rgroup_attr *attr);

int cxi_dev_find_rgroup_inc_refcount(struct cxi_dev *dev,
				     unsigned int id,
				     struct cxi_rgroup **rgroup);

int cxi_dev_get_rgroup_ids(struct cxi_dev *dev,
			   size_t max_ids,
			   unsigned int *rgroup_ids,
			   size_t *num_ids);

int cxi_dev_rgroup_get_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits);

int cxi_dev_rgroup_get_resource_types(struct cxi_dev *dev,
				      unsigned int rgroup_id,
				      size_t max_types,
				      enum cxi_resource_type *resource_types,
				      size_t *num_types);

int cxi_dev_rgroup_add_ac_entry(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);

int cxi_dev_rgroup_delete_ac_entry(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   unsigned int ac_entry_id);

int cxi_dev_rgroup_get_ac_entry_ids(struct cxi_dev *dev,
				    unsigned int rgroup_id,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_dev_rgroup_get_ac_entry_data(struct cxi_dev *dev,
				     unsigned int rgroup_id,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);

int cxi_dev_rgroup_get_ac_entry_id_by_data(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   enum cxi_ac_type ac_type,
					   union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);

int cxi_dev_rgroup_get_ac_entry_id_by_user(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

#endif /* _CXI_CONFIGURATION_H_ */
