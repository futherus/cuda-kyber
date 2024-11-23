#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"

#define NTESTS 1

static void print_key( const char* descr, uint8_t* key, int key_sz)
{
  printf("%s:\n", descr);
  for ( int i = 0; i < key_sz; i++ )
  {
    printf("%hhX ", key[i]);
  }
  printf("\n");
}

static int test_keys(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0}; // 1184 bytes
  uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0}; // 2400 bytes
  // uint8_t ct[CRYPTO_CIPHERTEXTBYTES]; // 1088 bytes
  // uint8_t key_a[CRYPTO_BYTES]; // 32 bytes
  // uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  print_key( "Public key", pk, CRYPTO_PUBLICKEYBYTES);
  print_key( "Secret key", sk, CRYPTO_SECRETKEYBYTES);

  //Bob derives a secret key and creates a response
  //crypto_kem_enc(ct, key_b, pk);

  //Alice uses Bobs response to get her shared key
  //crypto_kem_dec(key_a, ct, sk);

  // if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
  //   printf("ERROR keys\n");
  //   return 1;
  // }

  return 0;
}

#if 0
static int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}
#endif

#if 0
static int test_invalid_ciphertext(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b;
  size_t pos;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}
#endif

int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
//    r |= test_invalid_sk_a();
//    r |= test_invalid_ciphertext();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}
