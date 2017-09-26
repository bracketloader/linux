/*
 * Copyright (C) 2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: evm_secfs.c
 *	- Used to signal when key is on keyring
 *	- Get the key and enable EVM
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>
#include <linux/module.h>
#include "evm.h"

static struct dentry *evm_init_tpm;
static struct dentry *evm_init_flags;

/**
 * evm_read_key - read() for <securityfs>/evm
 *
 * @filp: file pointer, not actually used
 * @buf: where to put the result
 * @count: maximum to send along
 * @ppos: where to start
 *
 * Returns number of bytes read or error code, as appropriate
 */
static ssize_t evm_read_key(struct file *filp, char __user *buf,
			    size_t count, loff_t *ppos)
{
	char temp[80];
	ssize_t rc;

	if (*ppos != 0)
		return 0;

	sprintf(temp, "%d", evm_initialized);
	rc = simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));

	return rc;
}

/**
 * evm_write_key - write() for <securityfs>/evm
 * @file: file pointer, not actually used
 * @buf: where to get the data from
 * @count: bytes sent
 * @ppos: where to start
 *
 * Used to signal that key is on the kernel key ring.
 * - get the integrity hmac key from the kernel key ring
 * - create list of hmac protected extended attributes
 * Returns number of bytes written or error code, as appropriate
 */
static ssize_t evm_write_key(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char temp[80];
	int i;

	if (!capable(CAP_SYS_ADMIN) || (evm_initialized & EVM_INIT_HMAC))
		return -EPERM;

	if (count >= sizeof(temp) || count == 0)
		return -EINVAL;

	if (copy_from_user(temp, buf, count) != 0)
		return -EFAULT;

	temp[count] = '\0';

	if ((sscanf(temp, "%d", &i) != 1) || (i != 1))
		return -EINVAL;

	evm_init_key();

	return count;
}

static const struct file_operations evm_key_ops = {
	.read		= evm_read_key,
	.write		= evm_write_key,
};

/**
 * evm_read_flags - read() for <securityfs>/evm_flags
 *
 * @filp: file pointer, not actually used
 * @buf: where to put the result
 * @count: maximum to send along
 * @ppos: where to start
 *
 * Returns number of bytes read or error code, as appropriate
 */
static ssize_t evm_read_flags(struct file *filp, char __user *buf,
			      size_t count, loff_t *ppos)
{
	char temp[19];
	ssize_t rc;

	if (*ppos != 0)
		return 0;

	sprintf(temp, "0x%llx", evm_default_flags);
	rc = simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));

	return rc;
}

/**
 * evm_write_flags - write() for <securityfs>/evm_flags
 * @file: file pointer, not actually used
 * @buf: where to get the data from
 * @count: bytes sent
 * @ppos: where to start
 *
 * - sets the components that will be measured in the EVM hash
 * Returns number of bytes written or error code, as appropriate
 */
static ssize_t evm_write_flags(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	int err;

	if (!capable(CAP_SYS_ADMIN) || (evm_initialized & EVM_INIT_HMAC))
		return -EPERM;

	if (evm_initialized & EVM_INIT_HMAC)
		return -EINVAL;

	err = kstrtoull_from_user(buf, count, 0, &evm_default_flags);
	if (err)
		return err;

	return count;
}

static const struct file_operations evm_flags_ops = {
	.read		= evm_read_flags,
	.write		= evm_write_flags,
};

int __init evm_init_secfs(void)
{
	evm_init_tpm = securityfs_create_file("evm", S_IRUSR | S_IRGRP,
					      NULL, NULL, &evm_key_ops);
	if (!evm_init_tpm || IS_ERR(evm_init_tpm))
		return -EFAULT;

	evm_init_flags = securityfs_create_file("evm_flags", S_IRUSR | S_IRGRP,
						NULL, NULL, &evm_flags_ops);

	if (!evm_init_flags || IS_ERR(evm_init_flags)) {
		securityfs_remove(evm_init_tpm);
		return -EFAULT;
	}

	return 0;
}
