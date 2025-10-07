#ifndef __UTF8_MAGIC
#define __UTF8_MAGIC

#include <stdbool.h>

enum CONVERSION_ERROR {
	CE_OK = 0,
	CE_ICONV_OPEN_ERRNO,
	CE_CANT_CONVERT_COMB,
	CE_INVALID_SEQ,
	CE_INCOMPLETE_SEQ,
	CE_UNKOWN_ICONV_ERRNO,
	CE_BUFFER_SIZE
};

enum CONVERSION_ERROR local_to_utf8(const char *buf, size_t bufbc, char **out, size_t *outbc);

enum CONVERSION_ERROR utf8_to_local(const char *buf, size_t bufbc, char **out, size_t *outbc);

#endif