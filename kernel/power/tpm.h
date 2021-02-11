/* SPDX-License-Identifier: GPL-2.0-only */
#include "swap.h"

#ifndef _POWER_TPM_H
#define _POWER_TPM_H

#ifdef CONFIG_SECURE_HIBERNATION
int secure_hibernation_available(void);
int swsusp_encrypt_digest(struct swsusp_header *header);
int swsusp_decrypt_digest(struct swsusp_header *header);
int swsusp_digest_setup(struct swap_map_handle *handle);
void swsusp_digest_update(struct swap_map_handle *handle, char *buf,
			  size_t size);
void swsusp_digest_final(struct swap_map_handle *handle);
#else
static inline int secure_hibernation_available(void)
{
	return -ENODEV;
};
static inline int swsusp_encrypt_digest(struct swsusp_header *header)
{
	return 0;
}
static inline int swsusp_decrypt_digest(struct swsusp_header *header)
{
	return 0;
}
static inline int swsusp_digest_setup(struct swap_map_handle *handle)
{
	return 0;
}
static inline void swsusp_digest_update(struct swap_map_handle *handle,
					char *buf, size_t size) {};
static inline void swsusp_digest_final(struct swap_map_handle *handle) {};
#endif

#endif /* _POWER_TPM_H */
