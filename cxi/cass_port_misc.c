// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020 Hewlett Packard Enterprise Development LP */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/sbl.h>

#include "cass_core.h"

/*
 * create and initialise the port array
 */
int cass_port_new_port_db(struct cass_dev *hw)
{
	hw->port = kzalloc(sizeof(struct cass_port), GFP_KERNEL);
	if (!hw->port)
		return -ENOMEM;

	spin_lock_init(&hw->port->lock);
	hw->port->lstate = CASS_LINK_STATUS_UNCONFIGURED;
	init_waitqueue_head(&hw->port->lmon_wq);
	spin_lock_init(&hw->port->pause_lock);
	hw->port->pause_type = CASS_PAUSE_TYPE_NONE;
	hw->port->tx_pause = false;
	hw->port->rx_pause = false;
	hw->port->lmon_counters = NULL;
	hw->port->start_time = 0;
	cass_lmon_counters_init(hw);

	return 0;
}

void cass_port_del_port_db(struct cass_dev *hw)
{
	if (hw->port) {
		cass_lmon_kill_all(hw);
		cass_lmon_counters_term(hw);
		kfree(hw->port);
		hw->port = NULL;
	}
}

/*
 * text output helpers
 */
const char *cass_port_subtype_str(enum cass_port_subtype subtype)
{
	switch (subtype) {
	case CASS_PORT_SUBTYPE_IEEE:    return "ieee";
	case CASS_PORT_SUBTYPE_CASSINI: return "cassini";
	case CASS_PORT_SUBTYPE_LOCAL:   return "local";
	case CASS_PORT_SUBTYPE_GLOBAL:  return "global";
	default:                        return "unknown";
	}
}

const char *cass_pause_type_str(enum cass_pause_type type)
{
	switch (type) {
	case CASS_PAUSE_TYPE_INVALID: return "invalid";
	case CASS_PAUSE_TYPE_NONE:    return "none";
	case CASS_PAUSE_TYPE_GLOBAL:  return "global/802.3x";
	case CASS_PAUSE_TYPE_PFC:     return "pfc/802.1qbb";
	default:                      return "unrecognised";
	}
}

/*
 * return the time (s) that we have been running for
 * if we are not running return 0;
 */
static time64_t cass_port_uptime_get(struct cass_dev *hw)
{
	if (hw->port->lstate == CASS_LINK_STATUS_UP)
		return  ktime_get_seconds() - hw->port->start_time;

	return 0;
}

static int cass_port_uptime_str(time64_t time, char *buf, int len)
{
	int days;
	int hours;
	int mins;
	int secs;
	int bytes;

	/* divide time by seconds per day to get days */
	days  = time / (24*60*60);
	time %= 24*60*60;

	/* divide remainder by seconds per hour to get hours */
	hours = time / (60*60);
	time %= 60*60;

	/* divide remainder by seconds per minute to get minutes */
	mins  = time / 60;
	time %= 60;

	/* remainder in seconds */
	secs  = time;

	if (days)
		bytes = snprintf(buf, len, "%dd %dh %dm %ds", days, hours, mins, secs);
	else if (hours)
		bytes = snprintf(buf, len, "%dh %dm %ds", hours, mins, secs);
	else if (mins)
		bytes = snprintf(buf, len, "%dm %ds", mins, secs);
	else
		bytes = snprintf(buf, len, "%ds", secs);

	if (bytes > len)
		return -ENOSPC;
	else
		return 0;
}

void cass_uptime_debugfs_print(struct cass_dev *hw, struct seq_file *s)
{
	time64_t uptime;
	char uptime_str[64];
	int err;

	uptime = cass_port_uptime_get(hw);
	if (!uptime)
		return;

	err = cass_port_uptime_str(uptime, uptime_str, sizeof(uptime_str));
	if (err) {
		cxidev_err(&hw->cdev, "get uptime str failed [%d]\n", err);
		return;
	}

	seq_printf(s, "uptime: %lld (%s)\n", uptime, uptime_str);
}
