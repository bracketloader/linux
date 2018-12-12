/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_TPM_EVENTLOG_H__
#define __LINUX_TPM_EVENTLOG_H__

#include <crypto/hash_info.h>

#define TCG_EVENT_NAME_LEN_MAX	255
#define MAX_TEXT_EVENT		1000	/* Max event string length */
#define ACPI_TCPA_SIG		"TCPA"	/* 0x41504354 /'TCPA' */
#define TPM2_ACTIVE_PCR_BANKS	3

#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2 0x1
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2   0x2

#ifdef CONFIG_PPC64
#define do_endian_conversion(x) be32_to_cpu(x)
#else
#define do_endian_conversion(x) x
#endif

enum bios_platform_class {
	BIOS_CLIENT = 0x00,
	BIOS_SERVER = 0x01,
};

struct tcpa_event {
	u32 pcr_index;
	u32 event_type;
	u8 pcr_value[20];	/* SHA1 */
	u32 event_size;
	u8 event_data[0];
};

enum tcpa_event_types {
	PREBOOT = 0,
	POST_CODE,
	UNUSED,
	NO_ACTION,
	SEPARATOR,
	ACTION,
	EVENT_TAG,
	SCRTM_CONTENTS,
	SCRTM_VERSION,
	CPU_MICROCODE,
	PLATFORM_CONFIG_FLAGS,
	TABLE_OF_DEVICES,
	COMPACT_HASH,
	IPL,
	IPL_PARTITION_DATA,
	NONHOST_CODE,
	NONHOST_CONFIG,
	NONHOST_INFO,
};

struct tcpa_pc_event {
	u32 event_id;
	u32 event_size;
	u8 event_data[0];
};

enum tcpa_pc_event_ids {
	SMBIOS = 1,
	BIS_CERT,
	POST_BIOS_ROM,
	ESCD,
	CMOS,
	NVRAM,
	OPTION_ROM_EXEC,
	OPTION_ROM_CONFIG,
	OPTION_ROM_MICROCODE = 10,
	S_CRTM_VERSION,
	S_CRTM_CONTENTS,
	POST_CONTENTS,
	HOST_TABLE_OF_DEVICES,
};

/* http://www.trustedcomputinggroup.org/tcg-efi-protocol-specification/ */

struct tcg_efi_specid_event_algs {
	u16 alg_id;
	u16 digest_size;
} __packed;

struct tcg_efi_specid_event {
	u8 signature[16];
	u32 platform_class;
	u8 spec_version_minor;
	u8 spec_version_major;
	u8 spec_errata;
	u8 uintnsize;
	u32 num_algs;
	struct tcg_efi_specid_event_algs digest_sizes[TPM2_ACTIVE_PCR_BANKS];
	u8 vendor_info_size;
	u8 vendor_info[0];
} __packed;

struct tcg_pcr_event {
	u32 pcr_idx;
	u32 event_type;
	u8 digest[20];
	u32 event_size;
	u8 event[0];
} __packed;

struct tcg_event_field {
	u32 event_size;
	u8 event[0];
} __packed;

struct tpm2_digest_hdr {
	u16 alg_id;
	u8 digest[0];
} __packed;

struct tcg_pcr_event2_hdr {
	u32 pcr_idx;
	u32 event_type;
	u32 count;
	struct tpm2_digest_hdr digests[0];
} __packed;

struct tcg_algorithm_size {
	u16 algorithm_id;
	u16 algorithm_size;
};

struct tcg_algorithm_info {
	u8 signature[16];
	u32 platform_class;
	u8 spec_version_minor;
	u8 spec_version_major;
	u8 spec_errata;
	u8 uintn_size;
	u32 number_of_algorithms;
	struct tcg_algorithm_size digest_sizes[];
};

/*
 * This can be called in two contexts - when the event is already mapped,
 * and when it isn't. In the latter case we don't know how much space we
 * need to map in advance so need to jump through this repeated map/unmap
 * dance as we learn more about the size of the event.
 */
static inline int _calc_tpm2_event_size(struct tcg_pcr_event2_hdr *event,
					struct tcg_pcr_event *event_header,
				 void *(*map)(resource_size_t, unsigned long),
					void(*unmap)(void *, unsigned long))
{
	struct tcg_efi_specid_event *efispecid;
	struct tcg_event_field *event_field;
	void *mapping = NULL;
	int mapping_size;
	void *marker;
	void *marker_start;
	u32 halg_size;
	size_t size;
	u16 halg;
	int i;
	int j;

	marker = event;
	marker_start = marker;
	marker = marker + sizeof(event->pcr_idx) + sizeof(event->event_type)
		+ sizeof(event->count);

	/* Map the event header */
	if (map) {
		mapping_size = marker - marker_start;
		mapping = map((unsigned long)marker_start, mapping_size);
		if (!mapping) {
			size = 0;
			goto out;
		}
	}

	efispecid = (struct tcg_efi_specid_event *)event_header->event;

	/* Check if event is malformed. */
	if (event->count > efispecid->num_algs) {
		size = 0;
		goto out;
	}

	for (i = 0; i < event->count; i++) {
		halg_size = sizeof(event->digests[i].alg_id);
		marker = marker + halg_size;

		/* Map the digest's algorithm identifier */
		if (map && unmap) {
			unmap(mapping, mapping_size);
			mapping_size = marker - marker_start;
			mapping = map((unsigned long)marker_start,
				      mapping_size);
			if (!mapping) {
				size = 0;
				goto out;
			}
		}

		memcpy(&halg, marker, halg_size);

		for (j = 0; j < efispecid->num_algs; j++) {
			if (halg == efispecid->digest_sizes[j].alg_id) {
				marker +=
					efispecid->digest_sizes[j].digest_size;

				/* Map the digest content itself */
				if (map && unmap) {
					unmap(mapping, mapping_size);
					mapping_size = marker - marker_start;
					mapping = map((unsigned long)marker_start,
						      mapping_size);
					if (!mapping) {
						size = 0;
						goto out;
					}
				}
				break;
			}
		}
		/* Algorithm without known length. Such event is unparseable. */
		if (j == efispecid->num_algs) {
			size = 0;
			goto out;
		}
	}

	event_field = (struct tcg_event_field *)marker;

	/*
	 * Map the event size - we don't read from the event itself, so
	 * we don't need to map it
	 */
	if (map && unmap) {
		unmap(marker_start, mapping_size);
		mapping_size += sizeof(event_field->event_size);
		mapping = map((unsigned long)marker_start, mapping_size);
		if (!mapping) {
			size = 0;
			goto out;
		}
	}

	marker = marker + sizeof(event_field->event_size)
		+ event_field->event_size;
	size = marker - marker_start;

	if ((event->event_type == 0) && (event_field->event_size == 0))
		size = 0;
out:
	if (unmap)
		unmap(mapping, mapping_size);
	return size;
}

#endif
