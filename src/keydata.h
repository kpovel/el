#ifndef KEYDATA_H
#define KEYDATA_H

#include <stddef.h>
#include <stdint.h>

extern const size_t KEYDATA_SIZE;
const uint8_t *keydata_get8bytes(size_t pos);

#endif
