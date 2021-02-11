/* SPDX-License-Identifier: GPL-2.0-only */
#include <keys/trusted-type.h>
#include <crypto/sha2.h>

#ifndef _POWER_SWAP_H
#define _POWER_SWAP_H 1
/**
 *	The swap_map_handle structure is used for handling swap in
 *	a file-alike way
 */

struct swap_map_handle {
	struct swap_map_page *cur;
	struct swap_map_page_list *maps;
	struct shash_desc *desc;
	sector_t cur_swap;
	sector_t first_sector;
	unsigned int k;
	unsigned long reqd_free_pages;
	u32 crc32;
	u8 digest[SHA256_DIGEST_SIZE];
};

struct swsusp_header {
	char reserved[PAGE_SIZE - 20 - sizeof(sector_t) - sizeof(int) -
		      sizeof(u32) - SHA256_DIGEST_SIZE - MAX_BLOB_SIZE -
		      sizeof(u32)];
	u32	blob_len;
	u8	blob[MAX_BLOB_SIZE];
	u8      digest[SHA256_DIGEST_SIZE];
	u32     crc32;
	sector_t image;
	unsigned int flags;     /* Flags to pass to the "boot" kernel */
	char    orig_sig[10];
	char    sig[10];
} __packed;

#endif /* _POWER_SWAP_H */
