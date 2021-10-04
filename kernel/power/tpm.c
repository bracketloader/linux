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

static int tpm_setup_policy(struct tpm_chip *chip, int *session_handle)
{
	struct tpm_header *head;
	struct tpm_buf buf;
	char nonce[32] = {0x00};
	int rc;

	rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS,
			  TPM2_CC_START_AUTH_SESSION);
	if (rc)
		return rc;

	/* Decrypt key */
	tpm_buf_append_u32(&buf, TPM2_RH_NULL);

	/* Auth entity */
	tpm_buf_append_u32(&buf, TPM2_RH_NULL);

	/* Nonce - blank is fine here */
	tpm_buf_append_u16(&buf, sizeof(nonce));
	tpm_buf_append(&buf, nonce, sizeof(nonce));

	/* Encrypted secret - empty */
	tpm_buf_append_u16(&buf, 0);

	/* Policy type - session */
	tpm_buf_append_u8(&buf, 0x01);

	/* Encryption type - NULL */
	tpm_buf_append_u16(&buf, TPM_ALG_NULL);

	/* Hash type - SHA256 */
	tpm_buf_append_u16(&buf, TPM_ALG_SHA256);

	rc = tpm_send(chip, buf.data, tpm_buf_length(&buf));

	if (rc)
		goto out;

	head = (struct tpm_header *)buf.data;

	if (be32_to_cpu(head->length) != sizeof(struct tpm_header) +
	    sizeof(int) + sizeof(u16) + sizeof(nonce)) {
		rc = -EINVAL;
		goto out;
	}

	*session_handle = be32_to_cpu(*(int *)&buf.data[10]);
	memcpy(nonce, &buf.data[16], sizeof(nonce));

	tpm_buf_destroy(&buf);

	rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_PCR);
	if (rc)
		return rc;

	tpm_buf_append_u32(&buf, *session_handle);

	/* PCR digest - read from the PCR, we'll verify creation data later */
	tpm_buf_append_u16(&buf, 0);

	/* One bank of PCRs */
	tpm_buf_append_u32(&buf, 1);

	/* SHA256 banks */
	tpm_buf_append_u16(&buf, TPM_ALG_SHA256);

	/* Select PCRs 5 and 23 */
	tpm_buf_append_u32(&buf, 0x03200080);

	rc = tpm_send(chip, buf.data, tpm_buf_length(&buf));

	if (rc)
		goto out;

out:
	tpm_buf_destroy(&buf);
	return rc;
}

static int tpm_policy_get_digest(struct tpm_chip *chip, int handle,
				 char *digest)
{
	struct tpm_header *head;
	struct tpm_buf buf;
	int rc;

	rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_GET_DIGEST);
	if (rc)
		return rc;

	tpm_buf_append_u32(&buf, handle);

	rc = tpm_send(chip, buf.data, tpm_buf_length(&buf));

	if (rc)
		goto out;

	head = (struct tpm_header *)buf.data;
	if (be32_to_cpu(head->length) != sizeof(struct tpm_header) +
	    sizeof(u16) + SHA256_DIGEST_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	memcpy(digest, &buf.data[12], SHA256_DIGEST_SIZE);
out:
	tpm_buf_destroy(&buf);

	return rc;
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
	char policy[SHA256_DIGEST_SIZE];
	char *policydigest = NULL;
	struct tpm_chip *chip;
	struct key *key;
	int session_handle;
	int ret, i;
	char *keyinfo = NULL;
	char *keytemplate = "new\t32\tkeyhandle=0x81000001\tcreationpcrs=0x00800000\tpolicydigest=%s";

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

	policydigest = kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
	if (!policydigest) {
		ret = -ENOMEM;
		goto reset;
	}

	ret = tpm_pcr_extend(chip, 23, digests);
	if (ret != 0)
		goto reset;

	ret = tpm_setup_policy(chip, &session_handle);

	if (ret != 0)
		goto reset;

	ret = tpm_policy_get_digest(chip, session_handle, policy);

	if (ret != 0)
		goto reset;

	bin2hex(policydigest, policy, SHA256_DIGEST_SIZE);
	policydigest[64] = '\0';

	keyinfo = kasprintf(GFP_KERNEL, keytemplate, policydigest);
	if (!keyinfo) {
		ret = -ENOMEM;
		goto reset;
	}

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
	kfree(keyinfo);
	kfree(policydigest);
	kfree(digests);
	tpm_pcr_reset(chip, 23);
	return ret;
}

int swsusp_decrypt_digest(struct swsusp_header *header)
{
	const struct cred *cred = current_cred();
	char *keytemplate = "load\t%s\tkeyhandle=0x81000001\tpolicyhandle=0x%x";
	struct trusted_key_payload *payload;
	struct tpm_digest *digests = NULL;
	struct tpm_digest pcr5, pcr23;
	char overall_digest[SHA256_DIGEST_SIZE * 2] = {0,};
	char compound_digest[SHA256_DIGEST_SIZE];
	char certhash[SHA256_DIGEST_SIZE];
	char *blobstring = NULL;
	char *keyinfo = NULL;
	struct tpm_chip *chip;
	int session_handle;
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

	ret = tpm_setup_policy(chip, &session_handle);

	if (ret != 0)
		goto reset;

	blobstring = kmalloc(header->blob_len * 2 + 1, GFP_KERNEL);
	if (!blobstring) {
		ret = -ENOMEM;
		goto reset;
	}

	bin2hex(blobstring, header->blob, header->blob_len);
	blobstring[header->blob_len * 2] = '\0';

	keyinfo = kasprintf(GFP_KERNEL, keytemplate, blobstring,
			    session_handle);
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

	/* Expect 3 bytes of selected PCRs */
	if (*(char *)&payload->creation[6] != 3) {
		ret = -EINVAL;
		goto out;
	}

	/* PCRs 11 and 23 selected */
	if (be32_to_cpu(*(int *)&payload->creation[6]) != 0x03200080) {
		ret = -EINVAL;
		goto out;
	}

	if (be16_to_cpu(*(u16 *)&payload->creation[10]) !=
	    SHA256_DIGEST_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Calculate what the expected digests are - PCR 5 and PCR 23 should
	 * have been identical at creation time and now
	 */
	pcr5.alg_id = pcr23.alg_id = TPM_ALG_SHA256;

	ret = tpm_pcr_read(chip, 5, &pcr5);
	if (ret != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = tpm_pcr_read(chip, 23, &pcr23);
	if (ret != 0) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(overall_digest, pcr5.digest, SHA256_DIGEST_SIZE);
	memcpy(overall_digest + SHA256_DIGEST_SIZE, pcr23.digest,
	       SHA256_DIGEST_SIZE);

	ret = sha256_data(overall_digest, SHA256_DIGEST_SIZE * 2,
			  compound_digest);
	if (ret < 0)
		goto out;

	/*
	 * And, finally, verify that the key was generated with the same PCR
	 * values - that tells us it was generated with a kernel that supports
	 * restricting access to PCR 23 (PCR 5 would be different otherwise)
	 * and that the image was created by the kernel (PCR 23 would be
	 * different otherwise). If these digests match, we're good to go.
	 */
	if (memcmp(&payload->creation[12], compound_digest,
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
