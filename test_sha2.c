#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha2.h"

static void to_hex(char *hex, uint8_t *data, int len) {
    int i;
    char *h;

    h = hex;
    for(i=0;i<len;i++) {
        snprintf(h,3,"%2.2x",data[i]);
        h += 2;
    }
    *h = '\0';
}

static void compare(char * test_name, int variety, char *input, char *value, char *key) {
    struct sha2_ctx_t ctx;
    int len;
    uint8_t out[SHA2_MAX_DIGEST_SIZE];
    char hex[SHA2_MAX_DIGEST_SIZE*2+1];

    if(key) {
        sha2_init_hmac(&ctx,variety,(uint8_t *)key,strlen(key));
    } else {
        sha2_init(&ctx,variety);
    }
    sha2_more(&ctx,(uint8_t *)input,strlen(input));
    len = sha2_finish(&ctx,out,SHA2_MAX_DIGEST_SIZE);
    to_hex(hex,out,len);
    if(strcmp(hex,value)) {
        printf("test '%s' failed: expected='%s' got='%s'\n",test_name,value,hex);
        exit(1);
    }
    printf("ok %s\n",test_name);
}

static void test_trunc() {
    struct sha2_ctx_t ctx;
    uint8_t out[SHA2_MAX_DIGEST_SIZE+1];
    char hex[SHA2_MAX_DIGEST_SIZE*2+1];
    int len,got;
    char *expect_all = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    char expect[SHA2_MAX_DIGEST_SIZE*2+1];

    for(len=0;len<SHA2_MAX_DIGEST_SIZE;len++) {
        sha2_init(&ctx,SHA2_VARIETY_512);
        out[len] = len&0xFF;
        got = sha2_finish(&ctx,out,len);
        to_hex(hex,out,got);
        memcpy(expect,expect_all,len*2);
        expect[len*2] = '\0';
        if(strcmp(hex,expect)) {
            printf("test trunc failed at len=%d: expected='%s' got='%s'\n",
                    len,expect,hex);
            exit(1);
        }
        if(out[len] != (len&0xFF)) {
            printf("test trunc failed with overrun at len=%d\n",len);
            exit(1);
        }
    }
    printf("ok test-trunc\n");
}

int main() {
    char *dog = "The quick brown fox jumps over the lazy dog";
    char *k = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";

    compare("empty-512",SHA2_VARIETY_512,"","cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",NULL);
    compare("empty-384",SHA2_VARIETY_384,"","38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",NULL);
    compare("empty-256",SHA2_VARIETY_256,"","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",NULL);
    compare("empty-256",SHA2_VARIETY_224,"","d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",NULL);
    compare("empty-512/256",SHA2_VARIETY_512_256,"","c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",NULL);
    compare("empty-512/224",SHA2_VARIETY_512_224,"","6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",NULL);
    compare("dog-512",SHA2_VARIETY_512,dog,"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",NULL);
    compare("dog-384",SHA2_VARIETY_384,dog,"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",NULL);
    compare("dog-256",SHA2_VARIETY_256,dog,"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",NULL);
    compare("dog-224",SHA2_VARIETY_224,dog,"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",NULL);
    compare("hmac-512",SHA2_VARIETY_512,dog,"2a31d580d74d604de3dce055477d0a5633411adeafa044e10a2c6cfee6e38df49ed336cb53e3e7fa6bbbf3f107a3067296560be3deb09afcaff9cb98d2169433",k);
    compare("hmac-224",SHA2_VARIETY_224,dog,"610d38da56e06cf7d15bdf1ad83e250ae77ada28b5648036bba614ee",k);
    test_trunc();
    return 0;
}
