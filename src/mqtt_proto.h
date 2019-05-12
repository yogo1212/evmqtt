#ifndef __MQTT_PROTO_H
#define __MQTT_PROTO_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define MQTT_PROTOCOL_LEVEL 4
#define MQTT_PROTOCOL_VERSION "MQTT/3.1.1"
/* THIS SOURCE FILE MUST BE UTF-8 ENCODED!! */
#define MQTT_PROTOCOL_MAGIC "MQTT"

// max size 32,767
#define MAX_TOPIC_SIZE (0x8000)
#define MQTT_MAX_FIXED_HEADER_SIZE (5)

enum MQTT_MESSAGE_TYPE {
	MQTT_MESSAGE_TYPE_Reserved1 = 0, // Reserved
	MQTT_MESSAGE_TYPE_CONNECT = 1, // Client request to connect to Server
	MQTT_MESSAGE_TYPE_CONNACK = 2, // Connect Acknowledgment
	MQTT_MESSAGE_TYPE_PUBLISH = 3, // Publish message
	MQTT_MESSAGE_TYPE_PUBACK = 4, // Publish Acknowledgment
	MQTT_MESSAGE_TYPE_PUBREC = 5, // Publish Received (assured delivery part 1)
	MQTT_MESSAGE_TYPE_PUBREL = 6, // Publish Release (assured delivery part 2)
	MQTT_MESSAGE_TYPE_PUBCOMP = 7, // Publish Complete (assured delivery part 3)
	MQTT_MESSAGE_TYPE_SUBSCRIBE = 8, // Client Subscribe request
	MQTT_MESSAGE_TYPE_SUBACK = 9, // Subscribe Acknowledgment
	MQTT_MESSAGE_TYPE_UNSUBSCRIBE = 10, // Client Unsubscribe request
	MQTT_MESSAGE_TYPE_UNSUBACK = 11, // Unsubscribe Acknowledgment
	MQTT_MESSAGE_TYPE_PINGREQ = 12, // PING Request
	MQTT_MESSAGE_TYPE_PINGRESP = 13, // PING Response
	MQTT_MESSAGE_TYPE_DISCONNECT = 14, // Client is Disconnecting
	MQTT_MESSAGE_TYPE_Reserved2 = 15 // Reserved
};

typedef struct {
	uint8_t msg_type, qos;
	bool retain, dup;
} mqtt_proto_header_t;

void mqtt_read_header(void **buf, mqtt_proto_header_t *hdr);
void mqtt_write_header(void **buf, mqtt_proto_header_t *hdr, size_t remaining_size);
bool read_remaining_size(void **buf, size_t *out, size_t max_bytes);
bool write_remaining_size(void **buf, size_t size);

typedef struct {
	void *buf;
	size_t len;
} memchunk_t;

typedef struct {
	// ok - size prefix are great but annoying in C.
	// since some of these fields might contain zeros
	memchunk_t proto_name;
	uint8_t proto_level, will_qos;
	bool will_retain, will_flag, clean_session;
	uint16_t keep_alive;
	memchunk_t id, will_topic, will_message, username, password;
} mqtt_connect_data_t;

void mqtt_read_connect_data(uint8_t **buf, mqtt_connect_data_t *data);
bool mqtt_write_connect_data(mqtt_connect_data_t *data, char **out, size_t *outlen);
size_t mqtt_get_connect_data_wire_size(mqtt_connect_data_t *data);

#define MQTT_CONNACK_FLAGS_SESSION_PRESENT 0x01

enum MQTT_CONNACK_CODE {
	MQTT_CONNACK_ACCEPTED = 0,
	MQTT_CONNACK_UNACC_PROTO_VERSION = 1,
	MQTT_CONNACK_ID_REJECT = 2,
	MQTT_HEADER_CONNACK_SERVER_UNAVAIL = 3,
	MQTT_HEADER_CONNACK_BAD_USER_PASS = 4,
	MQTT_HEADER_CONNACK_NOT_AUTHORIZED = 5
};

const char *mqtt_connack_code_str(enum MQTT_CONNACK_CODE code);

typedef struct {
	uint8_t flags;
	uint8_t return_code;
} __attribute__((packed)) mqtt_connack_data_t;

void mqtt_read_connack_data(void **buf, mqtt_connack_data_t *data);


uint16_t mqtt_read_uint16(void **buf);
void mqtt_write_uint16(void **buf, uint16_t val);

bool mqtt_read_string(void **buf, size_t *remaining, char **out, size_t *outlen);
bool mqtt_write_string(const char *string, size_t stringlen, char **out, size_t *outlen);

#endif
