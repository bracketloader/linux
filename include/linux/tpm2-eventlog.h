#include <linux/types.h>
#include <crypto/sha.h>
#include <crypto/sm3.h>

#define TPM_ALG_SHA1	0x0004
#define TPM_ALG_SHA256	0x000B
#define TPM_ALG_SHA384	0x000C
#define TPM_ALG_SHA512	0x000D
#define TPM_ALG_SM3_256	0x0012

#define TPM_ALGO_COUNT 5

struct tpm_hash_size {
	uint16_t id;
	uint16_t size;
};

static struct tpm_hash_size tpm_hash_sizes[] = {
  {TPM_ALG_SHA1,	SHA1_DIGEST_SIZE},
  {TPM_ALG_SHA256,	SHA256_DIGEST_SIZE},
  {TPM_ALG_SM3_256,	SM3_DIGEST_SIZE},
  {TPM_ALG_SHA384,	SHA384_DIGEST_SIZE},
  {TPM_ALG_SHA512,	SHA512_DIGEST_SIZE},
};

struct tcg_event {
	uint32_t size;
	uint8_t data[];
};

struct tcg_event_digest {
	uint16_t algorithm;
	uint8_t data[];
};

struct tcg_event_digests_header {
	uint32_t count;
	struct tcg_event_digest digests[];
};

struct tcg_event_log_header {
	uint32_t pcr;
	uint32_t event_type;
	struct tcg_event_digests_header digests[];
};

static inline int tpm2_event_log_length(void *data, int count,
				  void *(*map)(resource_size_t, unsigned long),
				  void(*unmap)(void *, unsigned long)) {
	struct tcg_event_digests_header *digest_header;
	struct tcg_event_log_header *header;
	struct tcg_event_digest *digest;
	struct tcg_event *event;
	resource_size_t base = (resource_size_t)data;
	void *mapping = NULL;
	size_t size = 0;
	int i, j;

	while (count > 0) {
		header = data + size;
		if (mapping && unmap)
			unmap(mapping, size);
		size += sizeof(*header);
		if (map)
			mapping = map(base, size);

		digest_header = header->digests;
		if (unmap)
			unmap(mapping, size);
		size += sizeof(*digest_header);
		if (map)
			mapping = map(base, size);
		
		for (i = 0; i < digest_header->count; i++) {
			int found = 0;

			digest = (struct tcg_event_digest *)(data + size);
			if (unmap)
				unmap(mapping, size);
			size += sizeof(*digest);
			if (map)
				mapping = map(base, size);
			for (j = 0; j < TPM_ALGO_COUNT; j++) {
				if (tpm_hash_sizes[j].id == digest->algorithm) {
					if (unmap)
						unmap(mapping, size);
					size += tpm_hash_sizes[j].size;
					if (map)
						mapping = map(base, size);
					found = 1;
					break;
				}
			}
			if (found == 0) {
				unmap(mapping, size);
				return -1;
			}
		}

		event = (struct tcg_event *)(data + size);
		if (unmap)
			unmap(mapping, size);
		size += sizeof(*event);
		size += event->size;
		if (map)
			mapping = map(base, size);

		count--;
	}

	if (mapping && unmap)
		unmap(mapping, size);
	return size;
}
