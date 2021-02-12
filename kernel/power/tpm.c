// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/key-type.h>
#include <linux/scatterlist.h>

#include "swap.h"
#include "tpm.h"

/* sha256("To sleep, perchance to dream") */
static struct tpm_digest digest = { .alg_id = TPM_ALG_SHA256,
	.digest = {0x92, 0x78, 0x3d, 0x79, 0x2d, 0x00, 0x31, 0xb0, 0x55, 0xf9,
		   0x1e, 0x0d, 0xce, 0x83, 0xde, 0x1d, 0xc4, 0xc5, 0x8e, 0x8c,
		   0xf1, 0x22, 0x38, 0x6c, 0x33, 0xb1, 0x14, 0xb7, 0xec, 0x05,
		   0x5f, 0x49}};

/* sha256(sha256(empty_pcr | digest)) */
static char expected_digest[] = {0x2f, 0x96, 0xf2, 0x1b, 0x70, 0xa9, 0xe8,
	0x42, 0x25, 0x8e, 0x66, 0x07, 0xbe, 0xbc, 0xe3, 0x1f, 0x2c, 0x84, 0x4a,
	0x3f, 0x85, 0x17, 0x31, 0x47, 0x9a, 0xa5, 0x53, 0xbb, 0x23, 0x0c, 0x32,
	0xf3};

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};

static int sha256_data(char *buf, int size, char *output)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kmalloc(sizeof(struct shash_desc) +
			       crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;
	ret = crypto_shash_init(desc);
	if (ret != 0) {
		crypto_free_shash(tfm);
		kfree(desc);
		return ret;
	}

	crypto_shash_update(desc, buf, size);
	crypto_shash_final(desc, output);
	crypto_free_shash(desc->tfm);
	kfree(desc);

	return 0;
}

static int swsusp_enc_dec(struct trusted_key_payload *payload, char *buf,
			  int enc)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	int ret;

	skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
	if (IS_ERR(skcipher))
		return PTR_ERR(skcipher);

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done,
				      &sk.wait);

	/* AES 256 */
	if (crypto_skcipher_setkey(skcipher, payload->key, 32)) {
		ret = -EAGAIN;
		goto out;
	}

	/* Key will never be re-used, just fix the IV to 0 */
	ivdata = kzalloc(16, GFP_KERNEL);
	if (!ivdata) {
		ret = -ENOMEM;
		goto out;
	}

	sk.tfm = skcipher;
	sk.req = req;

	sg_init_one(&sk.sg, buf, 32);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
	crypto_init_wait(&sk.wait);

	/* perform the operation */
	if (enc)
		ret = crypto_wait_req(crypto_skcipher_encrypt(sk.req),
				     &sk.wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(sk.req),
				     &sk.wait);

	if (ret)
		pr_info("skcipher encrypt returned with result %d\n", ret);

	goto out;

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	kfree(ivdata);
	return ret;
}

static int tpm_certify_creationdata(struct tpm_chip *chip,
				    struct trusted_key_payload *payload)
{
	struct tpm_header *head;
	struct tpm_buf buf;
	int rc;

	rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_CERTIFYCREATION);
	if (rc)
		return rc;

	/* Use TPM_RH_NULL for signHandle */
	tpm_buf_append_u32(&buf, 0x40000007);

	/* Object handle */
	tpm_buf_append_u32(&buf, payload->blob_handle);

	/* Auth */
	tpm_buf_append_u32(&buf, 9);
	tpm_buf_append_u32(&buf, TPM2_RS_PW);
	tpm_buf_append_u16(&buf, 0);
	tpm_buf_append_u8(&buf, 0);
	tpm_buf_append_u16(&buf, 0);

	/* Qualifying data */
	tpm_buf_append_u16(&buf, 0);

	/* Creation data hash */
	tpm_buf_append_u16(&buf, payload->creation_hash_len);
	tpm_buf_append(&buf, payload->creation_hash,
		       payload->creation_hash_len);

	/* signature scheme */
	tpm_buf_append_u16(&buf, TPM_ALG_NULL);

	/* creation ticket */
	tpm_buf_append(&buf, payload->tk, payload->tk_len);

	rc = tpm_send(chip, buf.data, tpm_buf_length(&buf));
	if (rc)
		goto out;

	head = (struct tpm_header *)buf.data;

	if (head->return_code != 0)
		rc = -EINVAL;
out:
	tpm_buf_destroy(&buf);

	return rc;
}

int swsusp_encrypt_digest(struct swsusp_header *header)
{
	const struct cred *cred = current_cred();
	struct trusted_key_payload *payload;
	struct tpm_digest *digests = NULL;
	struct tpm_chip *chip;
	struct key *key;
	int ret, i;

	char *keyinfo = "new\t32\tkeyhandle=0x81000001\tcreationpcrs=0x00800000";

	chip = tpm_default_chip();

	if (!chip)
		return -ENODEV;

	if (!(tpm_is_tpm2(chip)))
		return -ENODEV;

	ret = tpm_pcr_reset(chip, 23);
	if (ret != 0)
		return ret;

	digests = kcalloc(chip->nr_allocated_banks, sizeof(struct tpm_digest),
			  GFP_KERNEL);
	if (!digests) {
		ret = -ENOMEM;
		goto reset;
	}

	for (i = 0; i <= chip->nr_allocated_banks; i++) {
		digests[i].alg_id = chip->allocated_banks[i].alg_id;
		if (digests[i].alg_id == digest.alg_id)
			memcpy(&digests[i], &digest, sizeof(digest));
	}

	ret = tpm_pcr_extend(chip, 23, digests);
	if (ret != 0)
		goto reset;

	key = key_alloc(&key_type_trusted, "swsusp", GLOBAL_ROOT_UID,
			GLOBAL_ROOT_GID, cred, 0, KEY_ALLOC_NOT_IN_QUOTA,
			NULL);

	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto reset;
	}

	ret = key_instantiate_and_link(key, keyinfo, strlen(keyinfo) + 1, NULL,
				       NULL);
	if (ret < 0)
		goto error;

	payload = key->payload.data[0];

	ret = swsusp_enc_dec(payload, header->digest, 1);
	if (ret)
		goto error;

	memcpy(header->blob, payload->blob, payload->blob_len);
	header->blob_len = payload->blob_len;

error:
	key_revoke(key);
	key_put(key);
reset:
	kfree(digests);
	tpm_pcr_reset(chip, 23);
	return ret;
}

int swsusp_decrypt_digest(struct swsusp_header *header)
{
	const struct cred *cred = current_cred();
	char *keytemplate = "load\t%s\tkeyhandle=0x81000001";
	struct trusted_key_payload *payload;
	struct tpm_digest *digests = NULL;
	char certhash[SHA256_DIGEST_SIZE];
	char *blobstring = NULL;
	char *keyinfo = NULL;
	struct tpm_chip *chip;
	struct key *key;
	int i, ret;

	chip = tpm_default_chip();

	if (!chip)
		return -ENODEV;

	if (!(tpm_is_tpm2(chip)))
		return -ENODEV;

	ret = tpm_pcr_reset(chip, 23);
	if (ret != 0)
		return ret;

	digests = kcalloc(chip->nr_allocated_banks, sizeof(struct tpm_digest),
			  GFP_KERNEL);
	if (!digests) {
		ret = -ENOMEM;
		goto reset;
	}

	for (i = 0; i <= chip->nr_allocated_banks; i++) {
		digests[i].alg_id = chip->allocated_banks[i].alg_id;
		if (digests[i].alg_id == digest.alg_id)
			memcpy(&digests[i], &digest, sizeof(digest));
	}

	ret = tpm_pcr_extend(chip, 23, digests);
	if (ret != 0)
		goto reset;

	blobstring = kmalloc(header->blob_len * 2, GFP_KERNEL);
	if (!blobstring) {
		ret = -ENOMEM;
		goto reset;
	}

	bin2hex(blobstring, header->blob, header->blob_len);

	keyinfo = kasprintf(GFP_KERNEL, keytemplate, blobstring);
	if (!keyinfo) {
		ret = -ENOMEM;
		goto reset;
	}

	key = key_alloc(&key_type_trusted, "swsusp", GLOBAL_ROOT_UID,
			GLOBAL_ROOT_GID, cred, 0, KEY_ALLOC_NOT_IN_QUOTA,
			NULL);

	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto out;
	}

	ret = key_instantiate_and_link(key, keyinfo, strlen(keyinfo) + 1, NULL,
				       NULL);
	if (ret < 0)
		goto out;

	payload = key->payload.data[0];

	ret = sha256_data(payload->creation, payload->creation_len, certhash);
	if (ret < 0)
		goto out;

	if (memcmp(payload->creation_hash, certhash, SHA256_DIGEST_SIZE) != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = tpm_certify_creationdata(chip, payload);
	if (ret != 0) {
		ret = -EINVAL;
		goto out;
	}

	/* We now know that the creation data is authentic - parse it */

	/* TPML_PCR_SELECTION.count */
	if (be32_to_cpu(*(int *)payload->creation) != 1) {
		ret = -EINVAL;
		goto out;
	}

	if (be16_to_cpu(*(u16 *)&payload->creation[4]) != TPM_ALG_SHA256) {
		ret = -EINVAL;
		goto out;
	}

	if (*(char *)&payload->creation[6] != 3) {
		ret = -EINVAL;
		goto out;
	}

	/* PCR 23 selected */
	if (be32_to_cpu(*(int *)&payload->creation[6]) != 0x03000080) {
		ret = -EINVAL;
		goto out;
	}

	if (be16_to_cpu(*(u16 *)&payload->creation[10]) !=
	    SHA256_DIGEST_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	if (memcmp(&payload->creation[12], expected_digest,
		   SHA256_DIGEST_SIZE) != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = swsusp_enc_dec(payload, header->digest, 0);
out:
	key_revoke(key);
	key_put(key);
reset:
	kfree(keyinfo);
	kfree(blobstring);
	kfree(digests);
	tpm_pcr_reset(chip, 23);
	return ret;
}

int swsusp_digest_setup(struct swap_map_handle *handle)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	handle->desc = kmalloc(sizeof(struct shash_desc) +
			       crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!handle->desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	handle->desc->tfm = tfm;
	ret = crypto_shash_init(handle->desc);
	if (ret != 0) {
		crypto_free_shash(tfm);
		kfree(handle->desc);
		return ret;
	}

	return 0;
}

void swsusp_digest_update(struct swap_map_handle *handle, char *buf,
			  size_t size)
{
	crypto_shash_update(handle->desc, buf, size);
}

void swsusp_digest_final(struct swap_map_handle *handle)
{
	crypto_shash_final(handle->desc, handle->digest);
	crypto_free_shash(handle->desc->tfm);
	kfree(handle->desc);
}

int secure_hibernation_available(void)
{
	struct tpm_chip *chip = tpm_default_chip();

	if (!chip)
		return -ENODEV;

	if (!(tpm_is_tpm2(chip)))
		return -ENODEV;

	return 0;
}
