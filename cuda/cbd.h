#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#include <cuda.h>

#define poly_cbd_eta1 KYBER_NAMESPACE(poly_cbd_eta1)
__device__ void poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]);

#define poly_cbd_eta2 KYBER_NAMESPACE(poly_cbd_eta2)
__device__ void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);

#endif
