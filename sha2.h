#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>

/************** PRIVATE **************/

/* PRIVATE: use only to declare struct sha2_variety_t and struct sha2_ctx_t.
 * Don't peep inside: use the methods after the string "PUBLIC API".
 */

#define SHA2_MAX_BLOCK_LENGTH 128

struct sha2_variety_t {
    uint64_t *iv;
    int bits,words_out;
    int v_flags;
};

struct sha2_ctx_t {
    int variety_idx;
    struct sha2_variety_t *variety;
    uint64_t h64[8];
    uint8_t pending[SHA2_MAX_BLOCK_LENGTH];
    int pending_len;
    uint64_t length;
    int flags;
    uint8_t k_prime[SHA2_MAX_BLOCK_LENGTH]; /* For HMAC */
};

/************** PUBLIC API **************/

/* Example usage:

    struct sha2_ctx_t ctx;
    uint8_t out[32];

    sha2_init(&ctx,SHA2_VARIETY_512);
    sha2_more(&ctx,"abc",3);
    sha2_more(&ctx,"def",3);
    sha2_finish(&ctx,out,32);


*/

/* Here are the varieties you can choose */
#define SHA2_VARIETY_224 0
#define SHA2_VARIETY_256 1
#define SHA2_VARIETY_384 2
#define SHA2_VARIETY_512 3
#define SHA2_VARIETY_512_256 4
#define SHA2_VARIETY_512_224 5

/* Internal use only */
#define SHA2_VARIETY_END 6

/* Largest digest this API can generate */
#define SHA2_MAX_DIGEST_SIZE  64

/* Pass a struct sha2_ctx_t to initialise with a variety from the above. This
 * will eventually yield a raw hash of that variety.
 */
void sha2_init(struct sha2_ctx_t *ctx, int sha2_variety);

/* Pass a struct sha2_ctx_t to initialise with a variety from the above. This
 * will eventually yield an HMAC with the given key.
 */
void sha2_init_hmac(struct sha2_ctx_t *ctx, int sha2_variety,
                    uint8_t *key, int key_len);

/* Some more data for this hash or HMAC. */
void sha2_more(struct sha2_ctx_t *ctx, uint8_t *data, int len);

/* Fill up the buffer provided with the digest, upto maxlen bytes */
int sha2_finish(struct sha2_ctx_t *ctx, uint8_t *out, int maxlen);

#endif
