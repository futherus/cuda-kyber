#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#include <cuda.h>

// #define zetas KYBER_NAMESPACE(zetas)
// extern const int16_t zetas[128];

#define ntt KYBER_NAMESPACE(ntt)
__device__ void ntt(int16_t poly[256]);

#define invntt KYBER_NAMESPACE(invntt)
__device__ void invntt(int16_t poly[256]);

#define basemul KYBER_NAMESPACE(basemul)
__device__ void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
