/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2025 Hewlett Packard Enterprise Development LP */

#ifndef _CXI_CONFIGURATION_H_
#define _CXI_CONFIGURATION_H_

/* Access Control Entries */
typedef unsigned int __bitwise cxi_ac_typeset_t;
enum cxi_ac_type {
	CXI_AC_UID  = (__force cxi_ac_typeset_t)BIT(0),
	CXI_AC_GID  = (__force cxi_ac_typeset_t)BIT(1),
	CXI_AC_OPEN = (__force cxi_ac_typeset_t)BIT(2),
};

/* Parameter for use with the 'by_user' retrieve functions */
#define CXI_AC_ANY (CXI_AC_UID | CXI_AC_GID | CXI_AC_OPEN)

union cxi_ac_data {
	uid_t     uid;
	gid_t     gid;
};

struct cxi_ac_entry;

struct cxi_ac_entry_list {
	struct cxi_ac_entry *open_entry;
	struct {
		struct xarray       xarray;
	} uid;
	struct {
		struct xarray       xarray;
	} gid;
	struct {
		struct xarray       xarray;
	} id;
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

/* Common parts of RX and TX Profiles */
#define CXI_VNI_NAME_LEN    64

struct cxi_rxtx_vni_attr {
	uint16_t         match;
	uint16_t         ignore;
	char             name[CXI_VNI_NAME_LEN];
};

struct cxi_rxtx_profile_state {
	atomic_t         released;
	bool             revoked;
	bool             enable;
	refcount_t       refcount;
};

struct cxi_rxtx_profile {
	unsigned int                   id;
	struct cxi_rxtx_vni_attr       vni_attr;
	struct cxi_rxtx_profile_state  state;
	struct cxi_ac_entry_list       ac_entry_list;
};

/* RX Profile */

/* Struct to hold HW configuration */
struct cxi_rx_config {
	int rmu_index;
	DECLARE_BITMAP(pid_table, 1 << MAX_PID_BITS);
	spinlock_t pid_lock;
};

/* Struct for creation and listing */
struct cxi_rx_attr {
	struct cxi_rxtx_vni_attr        vni_attr;
	/* TODO: other RX specific attributes */
};

struct cxi_rx_profile {
	struct cxi_rxtx_profile         profile_common;
	struct cxi_rx_config            config;
	/* TODO: other RX parameters */
};

/* TX Profile */

struct cxi_tx_config {
	int              cp_id;  /* this is a guess */
};

/* Struct for creation and listing */
struct cxi_tx_attr {
	struct cxi_rxtx_vni_attr        vni_attr;
	/* TODO: other TX specific attributes */
};

struct cxi_tx_profile {
	struct cxi_rxtx_profile         profile_common;
	struct cxi_tx_config            config;
};

int tx_profile_find_inc_refcount(struct cxi_dev *dev,
				 unsigned int tx_profile_id,
				 struct cxi_tx_profile **tx_profile);
int rx_profile_find_inc_refcount(struct cxi_dev *dev,
				 unsigned int rx_profile_id,
				 struct cxi_rx_profile **rx_profile);

struct cxi_rx_profile *cxi_dev_alloc_rx_profile(struct cxi_dev *dev,
					const struct cxi_rx_attr *rx_attr);
int cxi_dev_get_rx_profile_ids(struct cxi_dev *dev,
			       size_t max_entries,
			       unsigned int *rx_profile_ids,
			       size_t *num_entries);
int cxi_dev_rx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    struct cxi_rx_profile *rx_profile,
				    unsigned int *ac_entry_id);
void cxi_dev_rx_profile_remove_ac_entries(struct cxi_rx_profile *rx_profile);

int cxi_rx_profile_find_inc_refcount(struct cxi_dev *dev,
				     unsigned int vni_entry_id,
				     struct cxi_rx_profile **rx_profile);
int cxi_rx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_rx_profile *rx_profile);

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

struct cxi_tx_profile *cxi_dev_alloc_tx_profile(struct cxi_dev *dev,
					const struct cxi_tx_attr *tx_attr);
int cxi_dev_get_tx_profile_ids(struct cxi_dev *dev,
			       size_t max_entries,
			       unsigned int *tx_profile_ids,
			       size_t *num_entries);
int cxi_dev_tx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    struct cxi_tx_profile *tx_profile,
				    unsigned int *ac_entry_id);
void cxi_dev_tx_profile_remove_ac_entries(struct cxi_tx_profile *tx_profile);

int cxi_tx_profile_release(struct cxi_dev *dev,
			   unsigned int tx_profile_id);
int cxi_tx_profile_revoke(struct cxi_dev *dev,
			  unsigned int tx_profile_id);

int cxi_tx_profile_get_info(struct cxi_dev *dev,
			    struct cxi_tx_profile *tx_profile,
			    struct cxi_tx_attr *tx_attr,
			    struct cxi_rxtx_profile_state *state);

int cxi_tx_profile_find_inc_refcount(struct cxi_dev *dev,
				     unsigned int vni_entry_id,
				     struct cxi_tx_profile **tx_profile);
int cxi_tx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_tx_profile *tx_profile);

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

struct cxi_rgroup_attr {
	unsigned int   cntr_pool_id;
	bool           system_service;
	char           name[50];
	unsigned int   lnis_per_rgid;
};

struct cxi_rgroup_state {
	bool           enabled;
	bool           released;
	refcount_t     refcount;
};

struct cxi_rgroup {
	unsigned int                   id;
	struct cass_dev                *hw;
	struct cxi_rgroup_attr         attr;
	struct cxi_rgroup_state        state;
	struct cxi_resource_entry_list resource_entry_list;
	struct cxi_ac_entry_list       ac_entry_list;
	struct cxi_rgroup_pools        pools;
};

void cxi_dev_lock_rgroup_list(struct cass_dev *hw);
void cxi_dev_unlock_rgroup_list(struct cass_dev *hw);

int cxi_rgroup_enable(struct cxi_rgroup *rgroup);

void cxi_rgroup_disable(struct cxi_rgroup *rgroup);

bool cxi_rgroup_is_enabled(struct cxi_rgroup *rgroup);

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

int cxi_dev_rgroup_enable(struct cxi_dev *dev,
			  unsigned int rgroup_id);

int cxi_dev_rgroup_disable(struct cxi_dev *dev,
			   unsigned int rgroup_id);

int cxi_dev_rgroup_get_info(struct cxi_dev *dev,
			    unsigned int rgroup_id,
			    struct cxi_rgroup_attr *attr,
			    struct cxi_rgroup_state *state);

int cxi_dev_rgroup_add_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits);

int cxi_dev_rgroup_delete_resource(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   enum cxi_resource_type resource_type);

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
