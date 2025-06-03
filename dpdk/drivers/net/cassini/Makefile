# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 Google LLC

# objs-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) += rte_eth_cassini.o
# objs-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) += cassini_ethdev.o
# objs-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) += cassini_rxtx.o

# CFLAGS_rte_eth_cassini.o += -O3
# CFLAGS_cassini_ethdev.o += -O3
# CFLAGS_cassini_rxtx.o += -O3

# CFLAGS += -DALLOW_EXPERIMENTAL_API

# LIBABIVER := 1

# EXPORT_MAP := rte_pmd_cassini_version.map

# Versioning
# RTE_PMD_CASSINI_EXPORT_VERSION := RTE_PMD_CASSINI_VERSION

# $(eval $(call RTE_INIT_DRIVER,librte_pmd_cassini,pmd_cassini_drv))
# $(eval $(call RTE_INIT_VERSION,librte_pmd_cassini,RTE_PMD_CASSINI_VERSION))

# .PHONY: $(LIB_INSTALL_DEV_DEP_TARGETS) $(LIB_INSTALL_SHARED_DEP_TARGETS)
# $(LIB_INSTALL_DEV_DEP_TARGETS):
# $(LIB_INSTALL_SHARED_DEP_TARGETS):

# include $(RTE_SDK)/mk/rte.lib.mk
# include $(RTE_SDK)/mk/rte.vars.mk

# Allow a C++ compiler to be used.
# ifeq ($(CONFIG_RTE_ARCH_X86_64),y)
# CXXFLAGS += -std=c++11
# endif

# Allow the use of C11 atomics.
# CFLAGS += -std=c11

SRCS-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) := rte_eth_cassini.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) += cassini_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_CASSINI) += cassini_rxtx.c

# Basic CFLAGS
CFLAGS += -O3
CFLAGS += -std=c11
CFLAGS += -DALLOW_EXPERIMENTAL_API

# Include files from the parent directory
# CFLAGS += -I$(RTE_SDK)/drivers/net/cassini

# Versioning
# Not needed for skeleton

# Export map
# Not needed for skeleton

# Driver name
DRIVER = librte_pmd_cassini

# Build rules
include $(RTE_SDK)/mk/rte.extobj.mk
