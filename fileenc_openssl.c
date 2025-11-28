/*
 ---------------------------------------------------------------------------
 OpenSSL-based file encryption for minizip

 This file implements password based file encryption and authentication
 using AES in CTR mode, HMAC-SHA1 authentication and RFC2898 password
 based key derivation via OpenSSL APIs.

 This replaces the original aes/ directory implementation.
 ---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "fileenc_openssl.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/* Helper function to get the appropriate AES-ECB cipher based on key length */
/* ECB mode is used for manual CTR implementation (WinZip AES compatible) */
static const EVP_CIPHER* get_aes_ecb_cipher(unsigned int key_len)
{
    switch (key_len)
    {
        case 16:
            return EVP_aes_128_ecb();
        case 24:
            return EVP_aes_192_ecb();
        case 32:
            return EVP_aes_256_ecb();
        default:
            return NULL;
    }
}

/* Manual CTR mode implementation (WinZip AES compatible) */
static void encr_data(unsigned char data[], unsigned int d_len, fcrypt_ctx cx[1])
{
    unsigned int i = 0;
    unsigned int pos = cx->encr_pos;
    int outlen;

    while (i < d_len)
    {
        if (pos == 16)  /* AES_BLOCK_SIZE */
        {
            unsigned int j = 0;
            /* increment encryption nonce (little-endian, first 8 bytes) */
            while (j < 8 && !++cx->nonce[j])
                ++j;
            /* encrypt the nonce to form next xor buffer */
            outlen = 0;
            EVP_EncryptUpdate(cx->encr_ctx, cx->encr_bfr, &outlen, cx->nonce, 16);
            if (outlen != 16) {
                /* Error: Expected 16 bytes output */
                return;
            }
            pos = 0;
        }

        data[i++] ^= cx->encr_bfr[pos++];
    }

    cx->encr_pos = pos;
}

int fcrypt_init(
    int mode,                               /* the mode to be used (input)          */
    const unsigned char pwd[],              /* the user specified password (input)  */
    unsigned int pwd_len,                   /* the length of the password (input)   */
    const unsigned char salt[],             /* the salt (input)                     */
#ifdef PASSWORD_VERIFIER
    unsigned char pwd_ver[PWD_VER_LENGTH],  /* 2 byte password verifier (output)    */
#endif
    fcrypt_ctx      cx[1])                  /* the file encryption context (output) */
{
    unsigned char kbuf[2 * MAX_KEY_LENGTH + PWD_VER_LENGTH];
    unsigned int key_len;
    unsigned int salt_len;
    const EVP_CIPHER *cipher;
    int ret;

    if (pwd_len > MAX_PWD_LENGTH)
        return PASSWORD_TOO_LONG;

    if (mode < 1 || mode > 3)
        return BAD_MODE;

    cx->mode = mode;
    cx->pwd_len = pwd_len;

    key_len = KEY_LENGTH(mode);
    salt_len = SALT_LENGTH(mode);

    /* derive the encryption and authentication keys and the password verifier */
    /* using PBKDF2-HMAC-SHA1 */
    ret = PKCS5_PBKDF2_HMAC_SHA1((const char*)pwd, (int)pwd_len,
                                  salt, (int)salt_len,
                                  KEYING_ITERATIONS,
                                  (int)(2 * key_len + PWD_VER_LENGTH),
                                  kbuf);
    if (ret != 1)
        return BAD_MODE;

    /* initialise the encryption nonce and buffer position */
    cx->encr_pos = 16;  /* Start from block boundary */
    memset(cx->nonce, 0, 16);
    memset(cx->encr_bfr, 0, 16);  /* Initialize encryption buffer */

    /* initialise for encryption using key 1 (ECB mode for manual CTR) */
    cipher = get_aes_ecb_cipher(key_len);
    if (cipher == NULL)
        return BAD_MODE;

    cx->encr_ctx = EVP_CIPHER_CTX_new();
    if (cx->encr_ctx == NULL)
        return BAD_MODE;

    ret = EVP_EncryptInit_ex(cx->encr_ctx, cipher, NULL, kbuf, NULL);
    if (ret != 1)
    {
        EVP_CIPHER_CTX_free(cx->encr_ctx);
        cx->encr_ctx = NULL;
        return BAD_MODE;
    }

    /* Disable padding for ECB mode (manual CTR implementation) */
    EVP_CIPHER_CTX_set_padding(cx->encr_ctx, 0);

    /* initialise for authentication using key 2 (HMAC-SHA1) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    {
        /* OpenSSL 3.0+ API */
        EVP_MAC *mac;
        OSSL_PARAM params[2];

        mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (mac == NULL)
        {
            EVP_CIPHER_CTX_free(cx->encr_ctx);
            cx->encr_ctx = NULL;
            return BAD_MODE;
        }

        cx->auth_ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);

        if (cx->auth_ctx == NULL)
        {
            EVP_CIPHER_CTX_free(cx->encr_ctx);
            cx->encr_ctx = NULL;
            return BAD_MODE;
        }

        params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA1", 0);
        params[1] = OSSL_PARAM_construct_end();

        ret = EVP_MAC_init(cx->auth_ctx, kbuf + key_len, key_len, params);
        if (ret != 1)
        {
            EVP_MAC_CTX_free(cx->auth_ctx);
            cx->auth_ctx = NULL;
            EVP_CIPHER_CTX_free(cx->encr_ctx);
            cx->encr_ctx = NULL;
            return BAD_MODE;
        }
    }
#else
    {
        /* OpenSSL 1.x API */
        cx->auth_ctx = HMAC_CTX_new();
        if (cx->auth_ctx == NULL)
        {
            EVP_CIPHER_CTX_free(cx->encr_ctx);
            cx->encr_ctx = NULL;
            return BAD_MODE;
        }

        ret = HMAC_Init_ex(cx->auth_ctx, kbuf + key_len, (int)key_len, EVP_sha1(), NULL);
        if (ret != 1)
        {
            HMAC_CTX_free(cx->auth_ctx);
            cx->auth_ctx = NULL;
            EVP_CIPHER_CTX_free(cx->encr_ctx);
            cx->encr_ctx = NULL;
            return BAD_MODE;
        }
    }
#endif

#ifdef PASSWORD_VERIFIER
    memcpy(pwd_ver, kbuf + 2 * key_len, PWD_VER_LENGTH);
#endif

    /* Clear sensitive data */
    memset(kbuf, 0, sizeof(kbuf));

    return GOOD_RETURN;
}

/* perform 'in place' encryption and authentication */

void fcrypt_encrypt(unsigned char data[], unsigned int data_len, fcrypt_ctx cx[1])
{
    /* Encrypt data using manual CTR mode */
    encr_data(data, data_len, cx);

    /* Update HMAC with encrypted data */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_update(cx->auth_ctx, data, data_len);
#else
    HMAC_Update(cx->auth_ctx, data, data_len);
#endif
}

/* perform 'in place' authentication and decryption */

void fcrypt_decrypt(unsigned char data[], unsigned int data_len, fcrypt_ctx cx[1])
{
    /* Update HMAC with encrypted data (before decryption) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_update(cx->auth_ctx, data, data_len);
#else
    HMAC_Update(cx->auth_ctx, data, data_len);
#endif

    /* Decrypt data using manual CTR mode (same as encryption in CTR) */
    encr_data(data, data_len, cx);
}

/* close encryption/decryption and return the MAC value */

int fcrypt_end(unsigned char mac[], fcrypt_ctx cx[1])
{
    unsigned int mac_len;
    unsigned char full_mac[20]; /* SHA1 produces 20 bytes */
    int ret_len;

    ret_len = MAC_LENGTH(cx->mode);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    {
        size_t out_len = sizeof(full_mac);
        EVP_MAC_final(cx->auth_ctx, full_mac, &out_len, out_len);
        mac_len = (unsigned int)out_len;
    }
#else
    HMAC_Final(cx->auth_ctx, full_mac, &mac_len);
#endif

    /* Copy only the required MAC length */
    memcpy(mac, full_mac, ret_len);

    /* Cleanup */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_CTX_free(cx->auth_ctx);
#else
    HMAC_CTX_free(cx->auth_ctx);
#endif
    EVP_CIPHER_CTX_free(cx->encr_ctx);

    cx->auth_ctx = NULL;
    cx->encr_ctx = NULL;

    return ret_len;
}

/* Random number generation using OpenSSL */

void prng_init(void* fun, prng_ctx ctx[1])
{
    /* OpenSSL RAND is automatically initialized */
    /* fun parameter is ignored for compatibility */
    (void)fun;
    ctx->initialized = 1;
}

void prng_rand(unsigned char data[], unsigned int data_len, prng_ctx ctx[1])
{
    (void)ctx; /* unused */
    RAND_bytes(data, (int)data_len);
}

void prng_end(prng_ctx ctx[1])
{
    /* No cleanup needed for OpenSSL RAND */
    ctx->initialized = 0;
}

#if defined(__cplusplus)
}
#endif
