#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "UTF8.h"


#define UTF8_ENC_STRING "UTF-8"

static bool _utf8_is_continuation(uint8_t byte)
{
	return (byte & 0xC0) == 0x80;
}

size_t get_utf8_char_count(const void *buf, size_t bytecount)
{
	// either look at the first bits and skip using an array (potentially faster?)
	// or count every byte that is not a continuation:
	const uint8_t *raw = buf;
	size_t res = 0;

	while (bytecount > 0) {
		if (!_utf8_is_continuation(*raw)) {
			res++;
		}

		raw++;
		bytecount--;
	}

	return res;
}

size_t get_utf8_byte_count(const void *buf, size_t charcount)
{
	const uint8_t *raw = buf;
	size_t res = 0;

	if (charcount == 0) {
		return 0;
	}

	while (charcount > 0) {
		if (!_utf8_is_continuation(*raw)) {
			charcount--;
		}

		res++;
		raw++;
	}

	raw--;

	// we are now standing on the last character
	// there might be t(h)ree more bytes
	if (*raw & 0x80) {
		res++;

		if (*raw & 0x40) {
			res++;

			if (*raw & 0x20) {
				res++;

				if (*raw & 0x10) {
					res++;
				}
			}
		}
	}

	return res;
}

static enum CONVERSION_ERROR _encode_magic(const char *from, const char *to, const char *buf, size_t bufbc, char **out, size_t *outbc)
{
	if (strcmp(to, from) == 0) {
		*out = malloc(bufbc + 1);
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
	// i just hope no encoding exceeds this..
	size_t outsize = bufbc * 4;
	*out = malloc(outsize);
	char *outcpy = *out;

	char *bufcpy = (char *) buf;

	if (iconv(ic, &bufcpy, &bufbc, &outcpy, &outsize) == (size_t) - 1) {
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

	*outbc = (uintptr_t) outcpy - (uintptr_t) * out;
	// because we're nice...
	// we'll add a terminating zero
	*out = realloc(*out, *outbc + 1);
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
