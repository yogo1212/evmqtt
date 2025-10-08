#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "UTF8.h"


#define UTF8_ENC_STRING "UTF-8"

// assume the locale doesn't change over the lifetime of the evmqtt_t object.
// if the first byte is '\0', no conversion is done.
static char local_encoding[32] = { '\0', };

bool probe_local_encoding(void)
{
	// TODO this is not thread-safe
	char *encoding = nl_langinfo(CODESET);
	size_t l = strlen(encoding);
	if (l >= sizeof(local_encoding))
		return false;

	if (strcmp(encoding, UTF8_ENC_STRING) == 0)
		local_encoding[0] = '\0';
	else
		memcpy(local_encoding, encoding, l + 1);

	return true;
}

static enum CONVERSION_ERROR _encode_magic(const char *from, const char *to, const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	if (local_encoding[0] == '\0') {
		if (*out == NULL) {
			*out = malloc(bufbc);
		} else if (*outbc < bufbc) {
			return CE_BUFFER_SIZE;
		}

		memcpy(*out, buf, bufbc);
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

end:
	iconv_close(ic);

	if (res != CE_OK) {
		free(*out);
	}

	return res;
}

enum CONVERSION_ERROR local_to_utf8(const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	return _encode_magic(local_encoding, UTF8_ENC_STRING, buf, bufbc, out, outbc);
}

enum CONVERSION_ERROR utf8_to_local(const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	return _encode_magic(UTF8_ENC_STRING, local_encoding, buf, bufbc, out, outbc);
}
