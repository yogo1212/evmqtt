#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "UTF8.h"

#include "mqtt_proto.h"

const char *mqtt_connack_code_str(enum MQTT_CONNACK_CODE code)
{
	char *res = "UNKNOWN_CONACK_VALUE";

	switch (code) {
		case MQTT_CONNACK_ACCEPTED:
			res = "MQTT_CONNACK_ACCEPTED";
			break;

		case MQTT_CONNACK_UNACC_PROTO_VERSION:
			res = "MQTT_HEADER_CONNACK_UNACC_PROTO_VERSION";

			break;

		case MQTT_CONNACK_ID_REJECT:
			res = "MQTT_HEADER_CONNACK_ID_REJECT";
			break;

		case MQTT_HEADER_CONNACK_SERVER_UNAVAIL:
			res = "MQTT_HEADER_CONNACK_SERVER_UNAVAIL";
			break;

		case MQTT_HEADER_CONNACK_BAD_USER_PASS:
			res = "MQTT_HEADER_CONNACK_BAD_USER_PASS";
			break;

		case MQTT_HEADER_CONNACK_NOT_AUTHORIZED:
			res = "MQTT_HEADER_CONNACK_NOT_AUTHORIZED";
			break;
	}

	return res;
}

static enum MQTT_MESSAGE_TYPE get_header_type(uint8_t buf)
{
	return (buf >> 4) & 0xF;
}

static void set_header_type(uint8_t *buf, enum MQTT_MESSAGE_TYPE type)
{
	*buf &= ~0xF0;
	*buf |= ((type << 4) & 0xF0);
}

static bool get_header_dup_flag(uint8_t buf)
{
	return (buf >> 3) & 0x1;
}

static void set_header_dup_flag(uint8_t *buf, bool dup)
{
	*buf &= ~0x8;
	*buf |= (((dup ? 1 : 0) << 3) & 0x8);
}

static uint8_t get_header_qos(uint8_t buf)
{
	return (buf >> 1) & 0x3;
}

static void set_header_qos(uint8_t *buf, uint8_t qos)
{
	*buf &= ~0x6;
	*buf |= ((qos << 1) & 0x6);
}


static bool get_header_retain_flag(uint8_t buf)
{
	return buf & 0x1;
}

static void set_header_retain_flag(uint8_t *buf, bool retain)
{
	*buf &= ~0x1;
	*buf |= ((retain ? 1 : 0) & 0x1);
}

bool read_remaining_size(void **buf, size_t *out, size_t max_bytes)
{
	uint8_t *byte = *buf;
	size_t len = 0;
	uint32_t mul = 1;

	do {
		if ((((uintptr_t) byte) - ((uintptr_t) *buf)) > max_bytes) {
			return false;
		}

		len += (size_t) ((*byte) & 0x7F) * mul;
		mul *= 0x80; // << 7

		if (((*byte) & 0x80) != 0) {
			byte++;
		}
		else {
			break;
		}
	}
	while (true);

	byte++;

	*buf = byte;
	*out = len;
	return true;
}

bool write_remaining_size(void **buf, size_t size)
{
	uint8_t *byte = *buf;

	do {
		if ((((uintptr_t) byte) - ((uintptr_t) *buf)) > 4) {
			return false;
		}

		*byte = size % 128;// size & 0x7F
		size = size / 128;// >> 7

		// if there are more digits to encode, set the top bit of this digit
		if (size > 0) {
			*byte |= 0x80;
		}

		byte++;
	}
	while (size > 0);

	*buf = byte;
	return true;
}

void mqtt_read_header(void **buf, mqtt_proto_header_t *hdr)
{
	uint8_t *pnt = *buf;
	hdr->dup = get_header_dup_flag(*pnt);
	hdr->msg_type = get_header_type(*pnt);
	hdr->qos = get_header_qos(*pnt);
	hdr->retain = get_header_retain_flag(*pnt);
	pnt++;
	*buf = pnt;
}


void mqtt_write_header(void **buf, mqtt_proto_header_t *hdr, size_t remaining_size)
{
	uint8_t *pnt = *buf;
	*pnt = 0;
	set_header_dup_flag(pnt, hdr->dup);
	set_header_type(pnt, hdr->msg_type);
	set_header_qos(pnt, hdr->qos);
	set_header_retain_flag(pnt, hdr->retain);
	pnt++;
	write_remaining_size((void **) &pnt, remaining_size);
	*buf = pnt;
}

void mqtt_read_connect_data(uint8_t **buf, mqtt_connect_data_t *data)
{
	// TODO
	(void) buf;
	(void) data;
}

static void copy_to(void **buf, void *from, size_t len)
{
	memcpy(*buf, from, len);
	uint8_t *pnt = *buf;
	pnt += len;
	*buf = pnt;
}

bool mqtt_write_connect_data(mqtt_connect_data_t *data, char **out, size_t *outlen)
{
	bool res = true;

	size_t proto_name_len;
	char *proto_name;

	if (!mqtt_write_string(data->proto_name.buf, data->proto_name.len, &proto_name, &proto_name_len)) {
		*out = malloc(proto_name_len + 512);
		*outlen = sprintf(*out, "couldn't write proto_name:\n\t%.*s", (int) proto_name_len, proto_name);
		res = false;
		goto cleanup_proto_name;
	}

	uint8_t proto_version = data->proto_version;

	uint8_t connect_flags = 0;
	connect_flags |= ((data->clean_session ? 1 : 0) << 1);
	connect_flags |= ((data->will_flag ? 1 : 0) << 2);
	connect_flags |= ((data->will_qos & 2) << 3);
	connect_flags |= ((data->will_retain ? 1 : 0) << 5);
	connect_flags |= ((data->password.buf ? 1 : 0) << 6);
	connect_flags |= ((data->username.buf ? 1 : 0) << 7);

	uint16_t keep_alive = htons(data->keep_alive);

	size_t cid_len;
	char *cid;

	if (!mqtt_write_string(data->id.buf, data->id.len, &cid, &cid_len)) {
		*out = malloc(cid_len + 512);
		*outlen = sprintf(*out, "couldn't write id:\n\t%.*s", (int) cid_len, cid);
		res = false;
		goto cleanup_id;
	}

	if ((cid_len - 2 > 23) || (cid_len - 2 < 1)) {
		*out = malloc(cid_len + 512);
		*outlen = sprintf(*out, "id must be 1-23 UTF-8 characters long (%zu)", cid_len);
		res = false;
		goto cleanup_id;
	}

	size_t will_topic_len = 0;
	char *will_topic = NULL;
	size_t will_message_len = 0;
	char *will_message = NULL;

	if (data->will_flag) {
		if ((!data->will_topic.buf) || (data->will_topic.len == 0)) {
			*out = malloc(512);
			*outlen = sprintf(*out, "missing will_topic");
			res = false;
			goto cleanup_id;
		}

		if (!mqtt_write_string(data->will_topic.buf, data->will_topic.len, &will_topic, &will_topic_len)) {
			*out = malloc(will_topic_len + 512);
			*outlen = sprintf(*out, "couldn't write will_topic:\n\t%.*s", (int) will_topic_len, will_topic);
			res = false;
			goto cleanup_will_topic;
		}

		if ((!data->will_message.buf) || (data->will_message.len == 0)) {
			*out = malloc(512);
			*outlen = sprintf(*out, "missing will_message");
			res = false;
			goto cleanup_will_topic;
		}

		if (!mqtt_write_string(data->will_message.buf, data->will_message.len, &will_message, &will_message_len)) {
			*out = malloc(will_message_len + 512);
			*outlen = sprintf(*out, "couldn't write will_message:\n\t%.*s", (int) will_message_len, will_message);
			res = false;
			goto cleanup_will_message;
		}
	}

	size_t username_len = 0;
	char *username = NULL;
	size_t password_len = 0;
	char *password = NULL;

	if ((!data->username.buf) || (data->username.len == 0)) {
		goto assemble;
	}

	if (!mqtt_write_string(data->username.buf, data->username.len, &username, &username_len)) {
		*out = malloc(username_len + 512);
		*outlen = sprintf(*out, "couldn't write username:\n\t%.*s", (int) username_len, username);
		res = false;
		goto cleanup_username;
	}

	if ((!data->password.buf) || (data->password.len == 0)) {
		goto assemble;
	}

	if (!mqtt_write_string(data->password.buf, data->password.len, &password, &password_len)) {
		*out = malloc(password_len + 512);
		*outlen = sprintf(*out, "couldn't write password:\n\t%.*s", (int) password_len, password);
		res = false;
		goto cleanup_password;
	}

assemble:
	*outlen = proto_name_len
	          + sizeof(proto_version)
	          + sizeof(connect_flags)
	          + sizeof(keep_alive)
	          + cid_len
	          + will_topic_len
	          + will_message_len
	          + username_len
	          + password_len;
	*out = malloc(*outlen);

	void *out_pnt = *out;
	copy_to(&out_pnt, proto_name, proto_name_len);
	copy_to(&out_pnt, &proto_version, sizeof(proto_version));
	copy_to(&out_pnt, &connect_flags, sizeof(connect_flags));
	copy_to(&out_pnt, &keep_alive, sizeof(keep_alive));
	copy_to(&out_pnt, cid, cid_len);
	copy_to(&out_pnt, will_topic, will_topic_len);
	copy_to(&out_pnt, will_message, will_message_len);
	copy_to(&out_pnt, username, username_len);
	copy_to(&out_pnt, password, password_len);


cleanup_password:
	free(password);

cleanup_username:
	free(username);

cleanup_will_message:
	free(will_message);

cleanup_will_topic:
	free(will_topic);

cleanup_id:
	free(cid);

cleanup_proto_name:
	free(proto_name);

	return res;
}

void mqtt_read_connack_data(void **buf, mqtt_connack_data_t *data)
{
	uint8_t *pnt = *buf;
	//First byte is reserved
	pnt++;
	data->return_code = *pnt;
	pnt++;
	*buf = pnt;
}

uint16_t mqtt_read_uint16(void **buf)
{
	uint16_t *pnt = *buf;
	uint16_t res = ntohs(*pnt);
	pnt++;
	*buf = pnt;
	return res;
}

void mqtt_write_uint16(void **buf, uint16_t val)
{
	uint16_t *pnt = *buf;
	*pnt = htons(val);
	pnt++;
	*buf = pnt;
}

bool mqtt_write_string(const char *string, size_t stringlen, char **out, size_t *outlen)
{
	if (!string) {
		*out = malloc(1024);
		*outlen = sprintf(*out, "conv-err: input NULL");
		return false;
	}

	char *data;
	size_t data_len;
	enum CONVERSION_ERROR err = local_to_utf8(string, stringlen, &data, &data_len);

	if (err != CE_OK) {
		*out = malloc(1024);
		*outlen = sprintf(*out, "to utf8 conv-err: %d", (int) err);
		return false;
	}

	*outlen = data_len + 2;
	*out = malloc(*outlen);
	void *bufpnt = *out;
	mqtt_write_uint16(&bufpnt, get_utf8_char_count(data, data_len));

	memcpy(bufpnt, data, data_len);
	free(data);
	return true;
}

bool mqtt_read_string(void **buf, size_t *remaining, char **out, size_t *outlen)
{
	//utf8 char count!!
	if (*remaining < 2) {
		*out = malloc(1024);
		*outlen = sprintf(*out, "illegal utf8 with not even two-byte prefix");
		return false;
	}

	uint16_t stringlen = mqtt_read_uint16(buf);
	*remaining -= 2;

	size_t bc = get_utf8_byte_count(*buf, stringlen);

	if (bc > *remaining) {
		*out = malloc(1024);
		*outlen = sprintf(*out, "illegal utf8-bc: %zu (remaining: %zu)", bc, *remaining);
		return false;
	}

	*remaining -= bc;

	enum CONVERSION_ERROR err;
	char *localstr;

	if ((err = utf8_to_local((char *) *buf,  bc, &localstr, outlen)) != CE_OK) {
		*out = malloc(1024);
		*outlen = sprintf(*out, "to local conv-err: %d", (int) err);
		return false;
	}

	*buf = (uint8_t *)(*buf) + bc;

	*out = localstr;
	return true;
}
