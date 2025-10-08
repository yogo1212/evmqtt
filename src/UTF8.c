#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "UTF8.h"


#define UTF8_ENC_STRING "UTF-8"

static enum CONVERSION_ERROR _encode_magic(const char *from, const char *to, const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	if (strcmp(to, from) == 0) {
		size_t want = bufbc + 1;
		if (*out == NULL) {
			*out = malloc(want);
		} else if (*outbc < want) {
			return CE_BUFFER_SIZE;
		}
		(*out)[bufbc] = '\0';
		*outbc = bufbc;
		return CE_OK;
	}

	iconv_t ic = iconv_open(to, from);

	if (ic == (iconv_t) - 1) {
		if (errno == EINVAL) {
			return CE_CANT_CONVERT_COMB;
		}
		else {
			return CE_ICONV_OPEN_ERRNO;
		}
	}

	enum CONVERSION_ERROR res = CE_OK;

	size_t rem_out = *outbc;
	if (*out == NULL) {
		// i just hope no encoding exceeds this..
		rem_out = bufbc * 4 + 1;
		*out = malloc(rem_out);
	}

	char *bufcpy = (char *) buf;
	char *outcpy = *out;

	if (iconv(ic, &bufcpy, &bufbc, &outcpy, &rem_out) == (size_t) - 1) {
		switch (errno) {
			case EILSEQ:
				res = CE_INVALID_SEQ;
				break;

			case EINVAL:
				res = CE_INCOMPLETE_SEQ;
				break;

			case E2BIG:
				res = CE_BUFFER_SIZE;
				break;

			default:
				res = CE_UNKOWN_ICONV_ERRNO;
		}

		goto end;
	}

	*outbc = (uintptr_t) outcpy - (uintptr_t) *out;

	// because we're nice...
	// we'll add a terminating zero
	if (rem_out < 1) {
		res = CE_BUFFER_SIZE;
		goto end;
	}

	(*out)[*outbc] = '\0';;

end:
	iconv_close(ic);

	if (res != CE_OK) {
		free(*out);
	}

	return res;
}

enum CONVERSION_ERROR local_to_utf8(const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	char *encoding = nl_langinfo(CODESET);

	return _encode_magic(encoding, UTF8_ENC_STRING, buf, bufbc, out, outbc);
}

enum CONVERSION_ERROR utf8_to_local(const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	char *encoding = nl_langinfo(CODESET);

	return _encode_magic(UTF8_ENC_STRING, encoding, buf, bufbc, out, outbc);
}
