#ifndef KEYDATA_H
#define KEYDATA_H

#include <stddef.h>
#include <stdint.h>

/* Total size of the lookup table in bytes. */
extern const size_t KEYDATA_SIZE;

/* Return pointer to 8 bytes starting at offset pos within the table. */
const uint8_t *keydata_get8bytes(size_t pos);

#endif /* KEYDATA_H */
