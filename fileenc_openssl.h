/*
 ---------------------------------------------------------------------------
 OpenSSL-based file encryption for minizip

 This file implements password based file encryption and authentication
 using AES in CTR mode, HMAC-SHA1 authentication and RFC2898 password
 based key derivation via OpenSSL APIs.

 This replaces the original aes/ directory implementation.
 ---------------------------------------------------------------------------
*/

#ifndef _FENC_OPENSSL_H
#define _FENC_OPENSSL_H

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define PASSWORD_VERIFIER

#define MAX_KEY_LENGTH        32
#define MAX_PWD_LENGTH       128
#define MAX_SALT_LENGTH       16
#define KEYING_ITERATIONS   1000

#ifdef  PASSWORD_VERIFIER
#define PWD_VER_LENGTH         2
#else
#define PWD_VER_LENGTH         0
#endif

#define GOOD_RETURN            0
#define PASSWORD_TOO_LONG   -100
#define BAD_MODE            -101

/*
    Field lengths (in bytes) versus File Encryption Mode (0 < mode < 4)

    Mode Key Salt  MAC Overhead
       1  16    8   10       18
       2  24   12   10       22
       3  32   16   10       26

   The following macros assume that the mode value is correct.
*/

#define KEY_LENGTH(mode)        (8 * (mode & 3) + 8)
#define SALT_LENGTH(mode)       (4 * (mode & 3) + 4)
#define MAC_LENGTH(mode)        (10)

/* the context for file encryption   */

#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct
{
    unsigned char   nonce[16];              /* the CTR nonce          */
    unsigned char   encr_bfr[16];           /* encrypt buffer         */
    EVP_CIPHER_CTX  *encr_ctx;              /* encryption context     */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_CTX     *auth_ctx;              /* authentication context (OpenSSL 3.0+) */
#else
    HMAC_CTX        *auth_ctx;              /* authentication context (OpenSSL 1.x) */
#endif
    unsigned int    encr_pos;               /* block position (enc)   */
    unsigned int    pwd_len;                /* password length        */
    unsigned int    mode;                   /* File encryption mode   */
} fcrypt_ctx;

/* initialise file encryption or decryption */

int fcrypt_init(
    int mode,                               /* the mode to be used (input)          */
    const unsigned char pwd[],              /* the user specified password (input)  */
    unsigned int pwd_len,                   /* the length of the password (input)   */
    const unsigned char salt[],             /* the salt (input)                     */
#ifdef PASSWORD_VERIFIER
    unsigned char pwd_ver[PWD_VER_LENGTH],  /* 2 byte password verifier (output)    */
#endif
    fcrypt_ctx      cx[1]);                 /* the file encryption context (output) */

/* perform 'in place' encryption or decryption and authentication               */

void fcrypt_encrypt(unsigned char data[], unsigned int data_len, fcrypt_ctx cx[1]);
void fcrypt_decrypt(unsigned char data[], unsigned int data_len, fcrypt_ctx cx[1]);

/* close encryption/decryption and return the MAC value */
/* the return value is the length of the MAC            */

int fcrypt_end(unsigned char mac[],     /* the MAC value (output)   */
               fcrypt_ctx cx[1]);       /* the context (input)      */

/* Random number generation for salt values */

typedef struct
{
    int initialized; /* dummy field for compatibility */
} prng_ctx;

void prng_init(void* fun, prng_ctx ctx[1]);
void prng_rand(unsigned char data[], unsigned int data_len, prng_ctx ctx[1]);
void prng_end(prng_ctx ctx[1]);

#if defined(__cplusplus)
}
#endif

#endif
