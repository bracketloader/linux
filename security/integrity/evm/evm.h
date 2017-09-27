/*
 * Copyright (C) 2005-2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: evm.h
 *
 */

#ifndef __INTEGRITY_EVM_H
#define __INTEGRITY_EVM_H

#include <linux/xattr.h>
#include <linux/security.h>

#include "../integrity.h"

#define EVM_INIT_HMAC	0x0001
#define EVM_INIT_X509	0x0002

extern int evm_initialized;
extern char *evm_hmac;
extern char *evm_hash;

/* Extended attributes */
#define EVM_SELINUX (1L << 0)
#define EVM_SMACK (1L << 1)
#define EVM_SMACKEXEC (1L << 2)
#define EVM_SMACKTRANSMUTE (1L << 3)
#define EVM_SMACKMMAP (1L << 4)
#define EVM_IMA (1L << 5)
#define EVM_CAPS (1L << 6)
/* Other metadata */
#define EVM_INODE (1L << 32)
#define EVM_OWNERSHIP (1L << 33)
#define EVM_MODE (1L << 34)
#define EVM_FSUUID (1L << 35)
/* Behavioural flags */
#define EVM_HMAC_CONVERT (1L << 63)

extern u64 evm_default_flags;

extern struct crypto_shash *hmac_tfm;
extern struct crypto_shash *hash_tfm;

/* List of EVM protected security xattrs */
extern char *evm_config_xattrnames[];

int evm_init_key(void);
int evm_update_evmxattr(struct dentry *dentry,
			const char *req_xattr_name,
			const char *req_xattr_value,
			size_t req_xattr_value_len, u64 flags);
int evm_calc_hmac(struct dentry *dentry, const char *req_xattr_name,
		  const char *req_xattr_value,
		  size_t req_xattr_value_len, u64 flags, char *digest);
int evm_calc_hash(struct dentry *dentry, const char *req_xattr_name,
		  const char *req_xattr_value,
		  size_t req_xattr_value_len, u64 flags, char *digest);
int evm_init_hmac(struct inode *inode, const struct xattr *xattr,
		  char *hmac_val);
int evm_init_secfs(void);

#endif
