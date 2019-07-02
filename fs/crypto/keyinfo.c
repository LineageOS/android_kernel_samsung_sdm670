/*
 * key management facility for FS encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#include <keys/user-type.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>
#include "fscrypt_private.h"
#include "fscrypt_ice.h"

#ifdef CONFIG_FSCRYPT_SDP
static int derive_fek(struct inode *inode,
		const struct fscrypt_context *ctx,
		struct fscrypt_info *crypt_info,
		u8 *fek, u32 fek_len);
#endif

static struct crypto_shash *essiv_hash_tfm;

/**
 * derive_key_aes() - Derive a key using AES-128-ECB
 * @deriving_key: Encryption key used for derivation.
 * @source_key:   Source key to which to apply derivation.
 * @derived_raw_key:  Derived raw key.
 *
 * Return: Zero on success; non-zero otherwise.
 */
static int derive_key_aes(u8 deriving_key[FS_AES_128_ECB_KEY_SIZE],
				const struct fscrypt_key *source_key,
				u8 derived_raw_key[FS_MAX_KEY_SIZE])
{
	int res = 0;
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist src_sg, dst_sg;
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);

	if (IS_ERR(tfm)) {
		res = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}
	crypto_skcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		res = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);
	res = crypto_skcipher_setkey(tfm, deriving_key,
					FS_AES_128_ECB_KEY_SIZE);
	if (res < 0)
		goto out;

	sg_init_one(&src_sg, source_key->raw, source_key->size);
	sg_init_one(&dst_sg, derived_raw_key, source_key->size);
	skcipher_request_set_crypt(req, &src_sg, &dst_sg, source_key->size,
				   NULL);
	res = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
out:
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return res;
}

static int validate_user_key(struct fscrypt_info *crypt_info,
			struct fscrypt_context *ctx,
			const char *prefix, int min_keysize)
{
	char *description;
	struct key *keyring_key;
	struct fscrypt_key *master_key;
	const struct user_key_payload *ukp;
	int res;

	description = kasprintf(GFP_NOFS, "%s%*phN", prefix,
				FS_KEY_DESCRIPTOR_SIZE,
				ctx->master_key_descriptor);
	if (!description)
		return -ENOMEM;

	keyring_key = request_key(&key_type_logon, description, NULL);
	kfree(description);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);
	down_read(&keyring_key->sem);

	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
				"%s: key type must be logon\n", __func__);
		res = -ENOKEY;
		goto out;
	}
	ukp = user_key_payload_locked(keyring_key);
	if (!ukp) {
		/* key was revoked before we acquired its semaphore */
		res = -EKEYREVOKED;
		goto out;
	}
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		res = -EINVAL;
		goto out;
	}
	master_key = (struct fscrypt_key *)ukp->data;
	BUILD_BUG_ON(FS_AES_128_ECB_KEY_SIZE != FS_KEY_DERIVATION_NONCE_SIZE);

	if (master_key->size < min_keysize || master_key->size > FS_MAX_KEY_SIZE
	    || master_key->size % AES_BLOCK_SIZE != 0) {
		printk_once(KERN_WARNING
				"%s: key size incorrect: %d\n",
				__func__, master_key->size);
		res = -ENOKEY;
		goto out;
	}
	res = derive_key_aes(ctx->nonce, master_key, crypt_info->ci_raw_key);
	/* If we don't need to derive, we still want to do everything
	 * up until now to validate the key. It's cleaner to fail now
	 * than to fail in block I/O.
	if (!is_private_data_mode(crypt_info)) {
		res = derive_key_aes(ctx->nonce, master_key,
				crypt_info->ci_raw_key);
	} else {
		 * Inline encryption: no key derivation required because IVs are
		 * assigned based on iv_sector.

		BUILD_BUG_ON(sizeof(crypt_info->ci_raw_key) !=
				sizeof(master_key->raw));
		memcpy(crypt_info->ci_raw_key,
			master_key->raw, sizeof(crypt_info->ci_raw_key));
		res = 0;
	}
	 */
out:
	up_read(&keyring_key->sem);
	key_put(keyring_key);
	return res;
}

static const struct {
	const char *cipher_str;
	int keysize;
} available_modes[] = {
	[FS_ENCRYPTION_MODE_AES_256_XTS] = { "xts(aes)",
					     FS_AES_256_XTS_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_256_CTS] = { "cts(cbc(aes))",
					     FS_AES_256_CTS_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_128_CBC] = { "cbc(aes)",
					     FS_AES_128_CBC_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_128_CTS] = { "cts(cbc(aes))",
					     FS_AES_128_CTS_KEY_SIZE },
	[FS_ENCRYPTION_MODE_SPECK128_256_XTS] = { "xts(speck128)",	64 },
	[FS_ENCRYPTION_MODE_SPECK128_256_CTS] = { "cts(cbc(speck128))",	32 },
	[FS_ENCRYPTION_MODE_PRIVATE]	 = { "bugon",
					     FS_AES_256_XTS_KEY_SIZE },
};

static int determine_cipher_type(struct fscrypt_info *ci, struct inode *inode,
		const char **cipher_str_ret, int *keysize_ret, int *fname)
{
	u32 mode;

	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode)) {
		pr_warn_ratelimited("fscrypt: inode %lu uses unsupported encryption modes (contents mode %d, filenames mode %d)\n",
				    inode->i_ino,
				    ci->ci_data_mode, ci->ci_filename_mode);
		return -EINVAL;
	}

	if (S_ISREG(inode->i_mode)) {
		ci->ci_mode = CI_DATA_MODE;
		mode = ci->ci_data_mode;
	} else if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		ci->ci_mode = CI_FNAME_MODE;
		mode = ci->ci_filename_mode;
		*fname = 1;
	} else {
		WARN_ONCE(1, "fscrypt: filesystem tried to load encryption info for inode %lu, which is not encryptable (file type %d)\n",
			  inode->i_ino, (inode->i_mode & S_IFMT));
		return -EINVAL;
	}

	*cipher_str_ret = available_modes[mode].cipher_str;
	*keysize_ret = available_modes[mode].keysize;
	return 0;
}

static void put_crypt_info(struct fscrypt_info *ci)
{
	if (!ci)
		return;
#ifdef CONFIG_FSCRYPT_SDP
	fscrypt_sdp_put_sdp_info(ci->ci_sdp_info);
#endif
	crypto_free_skcipher(ci->ci_ctfm);
	crypto_free_cipher(ci->ci_essiv_tfm);
	memset(ci, 0, sizeof(*ci)); /* sanitizes ->ci_raw_key */
	kmem_cache_free(fscrypt_info_cachep, ci);
}

static int derive_essiv_salt(const u8 *key, int keysize, u8 *salt)
{
	struct crypto_shash *tfm = READ_ONCE(essiv_hash_tfm);

	/* init hash transform on demand */
	if (unlikely(!tfm)) {
		struct crypto_shash *prev_tfm;

		tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(tfm)) {
			pr_warn_ratelimited("fscrypt: error allocating SHA-256 transform: %ld\n",
					    PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		prev_tfm = cmpxchg(&essiv_hash_tfm, NULL, tfm);
		if (prev_tfm) {
			crypto_free_shash(tfm);
			tfm = prev_tfm;
		}
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		desc->flags = 0;

		return crypto_shash_digest(desc, key, keysize, salt);
	}
}

static int init_essiv_generator(struct fscrypt_info *ci, const u8 *raw_key,
				int keysize)
{
	int err;
	struct crypto_cipher *essiv_tfm;
	u8 salt[SHA256_DIGEST_SIZE];

	essiv_tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(essiv_tfm))
		return PTR_ERR(essiv_tfm);

	ci->ci_essiv_tfm = essiv_tfm;

	err = derive_essiv_salt(raw_key, keysize, salt);
	if (err)
		goto out;

	/*
	 * Using SHA256 to derive the salt/key will result in AES-256 being
	 * used for IV generation. File contents encryption will still use the
	 * configured keysize (AES-128) nevertheless.
	 */
	err = crypto_cipher_setkey(essiv_tfm, salt, sizeof(salt));
	if (err)
		goto out;

out:
	memzero_explicit(salt, sizeof(salt));
	return err;
}

void __exit fscrypt_essiv_cleanup(void)
{
	crypto_free_shash(essiv_hash_tfm);
}

static int fscrypt_data_encryption_mode(struct inode *inode)
{
	return fscrypt_is_ice_capable(inode->i_sb) ?
	FS_ENCRYPTION_MODE_PRIVATE : FS_ENCRYPTION_MODE_AES_256_XTS;
}

int fscrypt_get_encryption_info(struct inode *inode)
{
	struct fscrypt_info *crypt_info;
	struct fscrypt_context ctx;
	struct crypto_skcipher *ctfm;
	const char *cipher_str;
#ifdef CONFIG_FSCRYPT_SDP
	u8 temp_raw_key[FS_MAX_KEY_SIZE];
#endif
	int keysize;
	int res;
	int fname = 0;

	if (inode->i_crypt_info)
		return 0;

	res = fscrypt_initialize(inode->i_sb->s_cop->flags);
	if (res)
		return res;

	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (res < 0) {
		if (!fscrypt_dummy_context_enabled(inode) ||
		    IS_ENCRYPTED(inode))
			return res;
		/* Fake up a context for an unencrypted directory */
		memset(&ctx, 0, sizeof(ctx));
		ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
		ctx.contents_encryption_mode =
			fscrypt_data_encryption_mode(inode);
		ctx.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
		memset(ctx.master_key_descriptor, 0x42, FS_KEY_DESCRIPTOR_SIZE);
	} else if (res != sizeof(ctx)) {
		return -EINVAL;
	}

	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;

	if (ctx.flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	crypt_info = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!crypt_info)
		return -ENOMEM;

	crypt_info->ci_flags = ctx.flags;
	crypt_info->ci_data_mode = ctx.contents_encryption_mode;
	crypt_info->ci_filename_mode = ctx.filenames_encryption_mode;
	crypt_info->ci_ctfm = NULL;
	crypt_info->ci_essiv_tfm = NULL;
	memcpy(crypt_info->ci_master_key, ctx.master_key_descriptor,
				sizeof(crypt_info->ci_master_key));
#ifdef CONFIG_FSCRYPT_SDP
	crypt_info->ci_sdp_info = NULL;
	memset(temp_raw_key, 0, FS_MAX_KEY_SIZE);
#endif
	res = determine_cipher_type(crypt_info, inode, &cipher_str, &keysize,
				&fname);
	if (res)
		goto out;

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;

#ifdef CONFIG_FSCRYPT_SDP
	if ((FSCRYPT_SDP_PARSE_FLAG_SDP_ONLY(ctx.knox_flags) & FSCRYPT_KNOX_FLG_SDP_MASK)) {
		crypt_info->ci_sdp_info = fscrypt_sdp_alloc_sdp_info();
		if (!crypt_info->ci_sdp_info) {
			res = -ENOMEM;
			goto out;
		}

		res = fscrypt_sdp_update_sdp_info(inode, &ctx, crypt_info);
		if (res)
			goto out;

		if (fscrypt_sdp_is_classified(crypt_info)) {
			res = derive_fek(inode, &ctx, crypt_info, crypt_info->ci_raw_key, keysize);
			if (res)
				goto out;
			fscrypt_sdp_update_conv_status(crypt_info);
			goto sdp_dek;
		}
	}
#endif

	res = validate_user_key(crypt_info, &ctx, FS_KEY_DESC_PREFIX,
				keysize);
	if (res && inode->i_sb->s_cop->key_prefix) {
		int res2 = validate_user_key(crypt_info, &ctx,
					     inode->i_sb->s_cop->key_prefix,
					     keysize);
		if (res2) {
			if (res2 == -ENOKEY)
				res = -ENOKEY;
			goto out;
		}
		res = 0;
	} else if (res) {
		goto out;
	}

#ifdef CONFIG_FSCRYPT_SDP
sdp_dek:
	memcpy(temp_raw_key, crypt_info->ci_raw_key, keysize);
#endif

	if (is_private_data_mode(crypt_info)) {
		if (!fscrypt_is_ice_capable(inode->i_sb)) {
			pr_warn("%s: ICE support not available\n",
					__func__);
			res = -EINVAL;
			goto out;
		}
		/* Let's encrypt/decrypt by ICE */
		goto do_ice;
	}


	ctfm = crypto_alloc_skcipher(cipher_str, 0, 0);
	if (!ctfm || IS_ERR(ctfm)) {
		res = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		pr_debug("%s: error %d (inode %lu) allocating crypto tfm\n",
			 __func__, res, inode->i_ino);
		goto out;
	}
	crypt_info->ci_ctfm = ctfm;
	crypto_skcipher_clear_flags(ctfm, ~0);
	crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_REQ_WEAK_KEY);
	/*
	 * if the provided key is longer than keysize, we use the first
	 * keysize bytes of the derived key only
	 */
	res = crypto_skcipher_setkey(ctfm, crypt_info->ci_raw_key, keysize);
	if (res)
		goto out;

	if (S_ISREG(inode->i_mode) &&
	    crypt_info->ci_data_mode == FS_ENCRYPTION_MODE_AES_128_CBC) {
		res = init_essiv_generator(crypt_info, crypt_info->ci_raw_key,
						keysize);
		if (res) {
			pr_debug("%s: error %d (inode %lu) allocating essiv tfm\n",
				 __func__, res, inode->i_ino);
			goto out;
		}
	}
	memzero_explicit(crypt_info->ci_raw_key,
		sizeof(crypt_info->ci_raw_key));
do_ice:
	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)
		crypt_info = NULL;
#ifdef CONFIG_FSCRYPT_SDP
	if (crypt_info == NULL) //Call only when i_crypt_info is loaded initially
		fscrypt_sdp_finalize_tasks(inode, temp_raw_key, (res ? res : keysize));
	memzero_explicit(temp_raw_key, sizeof(temp_raw_key));
#endif
out:
	if (res == -ENOKEY)
		res = 0;
	put_crypt_info(crypt_info);
	return res;
}
EXPORT_SYMBOL(fscrypt_get_encryption_info);

void fscrypt_put_encryption_info(struct inode *inode)
{
#ifdef CONFIG_FSCRYPT_SDP
	fscrypt_sdp_cache_remove_inode_num(inode);
#endif
	put_crypt_info(inode->i_crypt_info);
	inode->i_crypt_info = NULL;
}
EXPORT_SYMBOL(fscrypt_put_encryption_info);

#ifdef CONFIG_FSCRYPT_SDP
static inline int __find_and_derive_fskey2(const struct inode *inode,
						const struct fscrypt_context *ctx,
						struct fscrypt_key *fskey, unsigned int min_keysize,
						const char *prefix)
{
	char *description;
	struct key *keyring_key;
	struct fscrypt_key *master_key;
	const struct user_key_payload *ukp;
	int res;

	description = kasprintf(GFP_NOFS, "%s%*phN", prefix,
				FS_KEY_DESCRIPTOR_SIZE,
				ctx->master_key_descriptor);
	if (!description)
		return -ENOMEM;

	keyring_key = request_key(&key_type_logon, description, NULL);
	kfree(description);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);
	down_read(&keyring_key->sem);

	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
				"%s: key type must be logon\n", __func__);
		res = -ENOKEY;
		goto out;
	}
	ukp = user_key_payload_locked(keyring_key);
	if (!ukp) {
		/* key was revoked before we acquired its semaphore */
		res = -EKEYREVOKED;
		goto out;
	}
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		res = -EINVAL;
		goto out;
	}
	master_key = (struct fscrypt_key *)ukp->data;
	BUILD_BUG_ON(FS_AES_128_ECB_KEY_SIZE != FS_KEY_DERIVATION_NONCE_SIZE);

	if (master_key->size < min_keysize || master_key->size > FS_MAX_KEY_SIZE
	    || master_key->size % AES_BLOCK_SIZE != 0) {
		printk_once(KERN_WARNING
				"%s: key size incorrect: %d\n",
				__func__, master_key->size);
		res = -ENOKEY;
		goto out;
	}
//	res = derive_key_aes(ctx->nonce, master_key, crypt_info->ci_raw_key);
	memcpy(fskey, master_key, sizeof(struct fscrypt_key));
	res = 0;
	/* If we don't need to derive, we still want to do everything
	 * up until now to validate the key. It's cleaner to fail now
	 * than to fail in block I/O.
	if (!is_private_data_mode(crypt_info)) {
		res = derive_key_aes(ctx->nonce, master_key,
				crypt_info->ci_raw_key);
	} else {
		 * Inline encryption: no key derivation required because IVs are
		 * assigned based on iv_sector.

		BUILD_BUG_ON(sizeof(crypt_info->ci_raw_key) !=
				sizeof(master_key->raw));
		memcpy(crypt_info->ci_raw_key,
			master_key->raw, sizeof(crypt_info->ci_raw_key));
		res = 0;
	}
	 */
out:
	up_read(&keyring_key->sem);
	key_put(keyring_key);
	return res;







//	struct key *key;
//	const struct fscrypt_key *payload;
//
//	key = find_and_lock_process_key(FS_KEY_DESC_PREFIX,
//					ctx->master_key_descriptor,
//					min_keysize, &payload);
//	if (key == ERR_PTR(-ENOKEY) && inode->i_sb->s_cop->key_prefix) {
//		key = find_and_lock_process_key(inode->i_sb->s_cop->key_prefix,
//						ctx->master_key_descriptor,
//						min_keysize, &payload);
//	}
//	if (IS_ERR(key))
//		return PTR_ERR(key);
//	memcpy(fskey, payload, sizeof(struct fscrypt_key));
//	up_read(&key->sem);
//	key_put(key);
//	return 0;
}

static inline int __find_and_derive_fskey(const struct inode *inode,
						const struct fscrypt_context *ctx,
						struct fscrypt_key *fskey, unsigned int min_keysize)
{
	int res;
	res = __find_and_derive_fskey2(inode, ctx, fskey, min_keysize,
									FS_KEY_DESC_PREFIX);
	if (res && inode->i_sb->s_cop->key_prefix) {
		int res2 = __find_and_derive_fskey2(inode, ctx, fskey, min_keysize,
									inode->i_sb->s_cop->key_prefix);
		if (res2) {
			if (res2 == -ENOKEY)
				res = -ENOKEY;
			goto out;
		}
		res = 0;
	} else if (res) {
		goto out;
	}

out:
	return res;
}

/* The function is only for regular files */
static int derive_fek(struct inode *inode,
						const struct fscrypt_context *ctx,
						struct fscrypt_info *crypt_info,
						u8 *fek, u32 fek_len)
{
	int res = 0;
	/*
	 * 1. [ Native / Uninitialized / To_sensitive ]  --> Plain fek
	 * 2. [ Native / Uninitialized / Non_sensitive ] --> Plain fek
	 */
	if (fscrypt_sdp_is_uninitialized(crypt_info))
	{
		res = fscrypt_sdp_derive_uninitialized_dek(crypt_info, fek, fek_len);
	}
	/*
	 * 3. [ Native / Initialized / Sensitive ]     --> { fek }_SDPK
	 * 4. [ Non_native / Initialized / Sensitive ] --> { fek }_SDPK
	 */
	else if (fscrypt_sdp_is_sensitive(crypt_info))
	{
		res = fscrypt_sdp_derive_dek(crypt_info, fek, fek_len);
	}
	/*
	 * 5. [ Native / Initialized / Non_sensitive ] --> { fek }_cekey
	 */
	else if (fscrypt_sdp_is_native(crypt_info))
	{
		res = fscrypt_sdp_derive_fek(inode, crypt_info, fek, fek_len);
	}
	/*
	 * else { N/A }
	 *
	 * Not classified file.
	 * 6. [ Non_native / Initialized / Non_sensitive ]
	 * 7. [ Non_native / Initialized / To_sensitive ]
	 */
	return res;
}

int fscrypt_get_encryption_key(struct inode *inode, struct fscrypt_key *key)
{
	struct fscrypt_info *crypt_info;
	struct fscrypt_context ctx;
	const char *cipher_str;
	int keysize;
	int res;
	int fname = 0;

	if (!inode->i_crypt_info)
		return -EINVAL;
	crypt_info = inode->i_crypt_info;

	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (res < 0) {
		return res;
	} else if (res != sizeof(ctx)) {
		return -EINVAL;
	}

	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;

	if (ctx.flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	res = determine_cipher_type(crypt_info, inode, &cipher_str, &keysize,
				&fname);
	if (res)
		goto out;

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;
	res = validate_user_key(crypt_info, &ctx, FS_KEY_DESC_PREFIX,
				keysize);
	if (res && inode->i_sb->s_cop->key_prefix) {
		int res2 = validate_user_key(crypt_info, &ctx,
					     inode->i_sb->s_cop->key_prefix,
					     keysize);
		if (res2) {
			if (res2 == -ENOKEY)
				res = -ENOKEY;
			goto out;
		}
		res = 0;
	} else if (res) {
		goto out;
	}

	memcpy(key->raw, crypt_info->ci_raw_key, sizeof(crypt_info->ci_raw_key));
	key->size = sizeof(crypt_info->ci_raw_key);

out:
	return res;
}
EXPORT_SYMBOL(fscrypt_get_encryption_key);

int fscrypt_get_encryption_kek(struct inode *inode,
							struct fscrypt_info *crypt_info,
							struct fscrypt_key *kek)
{
	struct fscrypt_context ctx;
	const char *cipher_str;
	int keysize;
	int res;
	int fname = 0;

	if (!crypt_info)
		return -EINVAL;

	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (res < 0) {
		return res;
	} else if (res != sizeof(ctx)) {
		return -EINVAL;
	}

	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;

	if (ctx.flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	res = determine_cipher_type(crypt_info, inode, &cipher_str, &keysize,
				&fname);
	if (res)
		goto out;

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;
	res = __find_and_derive_fskey(inode, &ctx, kek, keysize);

out:
	return res;
}
EXPORT_SYMBOL(fscrypt_get_encryption_kek);
#endif
