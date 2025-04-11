#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha2.h"

uint64_t sha256_h_init[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

uint64_t sha224_h_init[8] = {
     0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
     0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

uint64_t sha384_h_init[8] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 
    0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

uint64_t sha512_h_init[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

uint64_t sha512_224_h_init[8] = {
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 
    0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304C48942,
    0x3f9d85a86a1d36C8, 0x1112e6ad91d692a1
};

uint64_t sha512_256_h_init[8] = {
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
    0x2393b86b6f53b151, 0x963877195940eabd, 
    0x96283ee2a88effe3, 0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa, 0x0eb72ddC81c52ca2
};

uint64_t sha256_k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
   0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
   0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
   0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
   0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
   0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint64_t sha512_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static inline int min(int a,int b) { return a<b?a:b; }

static inline uint32_t rot32(uint32_t v, int amt) {
    return (v>>amt) | (v<<(32-amt));
}

static inline uint64_t rot64(uint64_t v, int amt) {
    return (v>>amt) | (v<<(64-amt));
}

static inline uint64_t bepack(uint8_t **src,int num) {
    int i;
    uint64_t out=0;

    for(i=0;i<num;i++) {
        out <<= 8;
        out |= *((*src)++);
    }
    return out;
}

static inline int be_unpack(uint64_t in, uint8_t **out, int n_in, int n_out,
                             int *maxlen) {
    int i;

    if(maxlen) {
        n_out = min(n_out,*maxlen);
        *maxlen -= n_out;
    }
    if(n_out < n_in) {
        in >>= (8*(n_in-n_out));
    }
    for(i=n_out-1;i>=0;i--) {
        *((*out)+i) = (uint8_t)in;
        in >>= 8;
    }
    *out += n_in;
    return n_out;
}

#define FLAG_HALFWORD 1  /* Curse you, 512-224 */
#define FLAG_HMAC     2

struct sha2_variety_t sha2_variety_def[SHA2_VARIETY_END] = {
    {sha224_h_init,32,7,0},  /* SHA224 */
    {sha256_h_init,32,8,0},  /* SHA256 */
    {sha384_h_init,64,6,0}, /* SHA384 */
    {sha512_h_init,64,8,0},  /* SHA512 */
    {sha512_256_h_init,64,4,0}, /* SHA512-256 */
    {sha512_224_h_init,64,4,FLAG_HALFWORD}  /* SHA512-224 */
};

static int block_length(struct sha2_variety_t *var) {
    return var->bits*2;
}

void sha2_init(struct sha2_ctx_t *ctx, int sha2_variety) {
    ctx->variety_idx = sha2_variety;
    ctx->variety = &sha2_variety_def[sha2_variety];
    memcpy(&(ctx->h64),ctx->variety->iv,64);
    ctx->pending_len = 0;
    ctx->length = 0;
    ctx->flags = ctx->variety->v_flags;
}

static inline uint32_t sigma32(uint32_t src,int a,int b,int c) {
    return rot32(src,a) ^ rot32(src,b) ^ rot32(src,c);
}

static inline uint64_t sigma64(uint64_t src,int a,int b,int c) {
    return rot64(src,a) ^ rot64(src,b) ^ rot64(src,c);
}

static inline uint64_t maj(uint64_t a, uint64_t b, uint64_t c) {
    return (a&b) ^ (a&c) ^ (b&c);
}

static inline uint64_t choose(uint64_t a, uint64_t b, uint64_t c) {
    return (a&b)^((~a)&c);
}

static inline uint64_t shr32(uint64_t in, int amt) {
    return (in&0xFFFFFFFF)>>amt;
}

static void hash32(struct sha2_ctx_t *ctx) {
    uint64_t j[8],m[8],w[64],s0,s1,t1;
    uint8_t *src;
    int i;

    src = ctx->pending;
    for(i=0;i<16;i++) {
        w[i] = bepack(&src,4);
    }
    memcpy(j,ctx->h64,64);
    for(i=16;i<64;i++) {
        s0 = rot32(w[i-15],7) ^ rot32(w[i-15],18) ^ shr32(w[i-15],3);
        s1 = rot32(w[i-2],17) ^ rot32(w[i-2],19) ^ shr32(w[i-2],10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    for(i=0;i<64;i++) {
        memcpy(m+1,j,56);
        t1 = j[7] + sigma32(j[4],6,11,25) + choose(j[4],j[5],j[6]) +
            sha256_k[i] + w[i];
        m[4] += t1;
        m[0] = t1 + sigma32(j[0],2,13,22) + maj(j[0],j[1],j[2]);
        memcpy(j,m,64);
    }
    for(i=0;i<8;i++) {
        ctx->h64[i] += j[i];
    }
}

static void hash64(struct sha2_ctx_t *ctx) {
    uint64_t w[80],j[8],m[8],t1,s0,s1;
    uint8_t *src;
    int i;

    src = ctx->pending;
    for(i=0;i<16;i++) {
        w[i] = bepack(&src,8);
    }
    for(i=16;i<80;i++) {
        s0 = rot64(w[i-15],1) ^ rot64(w[i-15],8) ^ (w[i-15]>>7);
        s1 = rot64(w[i-2],19) ^ rot64(w[i-2],61) ^ (w[i-2]>>6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    memcpy(j,ctx->h64,64);
    for(i=0;i<80;i++) {
        memcpy(m+1,j,56);
        t1 = j[7] + sigma64(j[4],14,18,41) + choose(j[4],j[5],j[6]) + 
            sha512_k[i] + w[i];
        m[4] += t1;
        m[0] = t1 + sigma64(j[0],28,34,39) + maj(j[0],j[1],j[2]);
        memcpy(j,m,64);
    }
    for(i=0;i<8;i++) {
        ctx->h64[i] += j[i];
    }
}

static void sha_hash(struct sha2_ctx_t *ctx) {
    if(ctx->variety->bits>32)
        hash64(ctx);
    else
        hash32(ctx);
}

void sha2_more(struct sha2_ctx_t *ctx, uint8_t *data, int len) {
    int here,plen;

    ctx->length += len;
    plen = 2*ctx->variety->bits;
    while(len>0) {
        here = min(len, plen - ctx->pending_len);
        memcpy(ctx->pending + ctx->pending_len, data, here);
        data += here;
        len -= here;
        ctx->pending_len += here;
        if(ctx->pending_len == plen) {  
            sha_hash(ctx);
            ctx->pending_len = 0;
        }
    }
}

static int sha2_finish_main(struct sha2_ctx_t *ctx, uint8_t *out, int maxlen) {
    int i, half_here, space_needed, len_len, block_size,bits,len;
    signed int pad_length;
    uint8_t terminal[SHA2_MAX_BLOCK_LENGTH*2],*len_pos;

    bits = ctx->variety->bits;
    block_size = 2*bits;
    len_len = bits/4; /* Length of length field: 32bit => 8by; 64bit => 16by */
    space_needed = 1 + len_len; /* Need room for 0x80 and the length field */
    pad_length = block_size - ctx->pending_len - space_needed;
    if(pad_length<0) { /* Oops, add a block */
        pad_length += block_size;
    }
    memset(terminal,0,SHA2_MAX_BLOCK_LENGTH*2);
    terminal[0] = 0x80;
    len_pos = terminal + pad_length + 1; /* gets clobbered by be_unpack */
    be_unpack(ctx->length*8,&len_pos,len_len,len_len,NULL);
    sha2_more(ctx,terminal,space_needed + pad_length);
    len = 0;
    for(i=0;i<ctx->variety->words_out;i++) {
        half_here = (i==ctx->variety->words_out-1 && ctx->flags&FLAG_HALFWORD);
        len += 
            be_unpack(ctx->h64[i],&out,bits/8,half_here?bits/16:bits/8,&maxlen);
    }
    return len;
}

static void xor_blit(uint8_t *data, int v, int n) {
    int i;

    for(i=0;i<n;i++)
        data[i] ^= v;
}

int sha2_finish(struct sha2_ctx_t *ctx, uint8_t *out, int max_len) {
    uint8_t tmp[SHA2_MAX_BLOCK_LENGTH];
    struct sha2_ctx_t outer;
    int block_size,len;

    block_size = block_length(ctx->variety);
    if(ctx->flags&FLAG_HMAC) {
        sha2_init(&outer,ctx->variety_idx);
        memcpy(tmp,ctx->k_prime,block_size);
        xor_blit(tmp,0x5C,block_size);
        sha2_more(&outer,tmp,block_size);
        len = sha2_finish_main(ctx,tmp,SHA2_MAX_BLOCK_LENGTH);
        sha2_more(&outer,tmp,len);
        return sha2_finish_main(&outer,out,max_len);
    } else {
        return sha2_finish_main(ctx,out,max_len);
    }
}

static void derive_key(uint8_t *out, int sha2_variety, uint8_t *key, int key_len) {
    struct sha2_ctx_t ctx;
    int block_size;

    block_size = block_length(&sha2_variety_def[sha2_variety]);
    memset(out,0,block_size);
    if(key_len > block_size) {
        sha2_init(&ctx,sha2_variety);
        sha2_more(&ctx,key,key_len);
        sha2_finish(&ctx,out,SHA2_MAX_BLOCK_LENGTH);
    } else {
        memcpy(out,key,key_len);
    }
}

void sha2_init_hmac(struct sha2_ctx_t *ctx, int sha2_variety,
                    uint8_t *key, int key_len) {
    uint8_t i_pad[SHA2_MAX_BLOCK_LENGTH];
    int block_size;

    block_size = block_length(&sha2_variety_def[sha2_variety]);
    sha2_init(ctx,sha2_variety);
    derive_key(ctx->k_prime,sha2_variety,key,key_len);
    memcpy(i_pad,ctx->k_prime,block_size);
    xor_blit(i_pad,0x36,block_size);
    sha2_more(ctx,i_pad,block_size);
    ctx->flags |= FLAG_HMAC;
}
