/*
 * Copyright (C) 2017 Google, Inc.
 *     Thiebaud Weksteen <tweek@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/efi.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/tpm_eventlog.h>

#include <asm/early_ioremap.h>

int efi_tpm_final_log_size;
EXPORT_SYMBOL(efi_tpm_final_log_size);

static int tpm2_calc_event_log_size(void *data, int count, void *size_info)
{
	struct tcg_pcr_event2_head *header;
	int event_size, size = 0;

	while (count > 0) {
		header = data + size;
		event_size = __calc_tpm2_event_size(header, size_info, true);
		if (event_size == 0)
			return -1;
		size += event_size;
	}

	return size;
}

/*
 * Reserve the memory associated with the TPM Event Log configuration table.
 */
int __init efi_tpm_eventlog_init(void)
{
	struct linux_efi_tpm_eventlog *log_tbl;
	struct efi_tcg2_final_events_table *final_tbl;
	unsigned int tbl_size;

	if (efi.tpm_log == EFI_INVALID_TABLE_ADDR) {
		/*
		 * We can't calculate the size of the final events without the
		 * first entry in the TPM log, so bail here.
		 */
		return 0;
	}

	log_tbl = early_memremap(efi.tpm_log, sizeof(*log_tbl));
	if (!log_tbl) {
		pr_err("Failed to map TPM Event Log table @ 0x%lx\n",
		       efi.tpm_log);
		efi.tpm_log = EFI_INVALID_TABLE_ADDR;
		return -ENOMEM;
	}

	tbl_size = sizeof(*log_tbl) + log_tbl->size;
	memblock_reserve(efi.tpm_log, tbl_size);
	early_memunmap(log_tbl, sizeof(*log_tbl));

	if (efi.tpm_final_log == EFI_INVALID_TABLE_ADDR)
		return 0;

	final_tbl = early_memremap(efi.tpm_final_log, sizeof(*final_tbl));

	if (!final_tbl) {
		pr_err("Failed to map TPM Final Event Log table @ 0x%lx\n",
		       efi.tpm_final_log);
		efi.tpm_final_log = EFI_INVALID_TABLE_ADDR;
		return -ENOMEM;
	}

	tbl_size = tpm2_calc_event_log_size(final_tbl->events,
					    final_tbl->nr_events,
					    (void *)efi.tpm_log);
	memblock_reserve((unsigned long)final_tbl,
			 tbl_size + sizeof(*final_tbl));
	early_memunmap(final_tbl, sizeof(*final_tbl));
	efi_tpm_final_log_size = tbl_size;

	return 0;
}

