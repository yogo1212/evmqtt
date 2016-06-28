#ifndef EVMQTT_H
#define EVMQTT_H

#include <stdbool.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

struct evmqtt;
typedef struct evmqtt evmqtt_t;

enum evmqtt_error {
	MQTT_ERROR_PROTOCOL,
	MQTT_ERROR_NETWORK,
	MQTT_ERROR_CONNECT,
	MQTT_ERROR_STATE,
	MQTT_ERROR_HARD,
	MQTT_ERROR_UNKNOWN
};

enum evmqtt_event {
	MQTT_EVENT_CONNECTED,
	MQTT_EVENT_DISCONNECTED
};


typedef void (*evmqtt_event_handler_t)(evmqtt_t *mc, enum evmqtt_event evt);
void evmqtt_set_event_cb(evmqtt_t *mc, evmqtt_event_handler_t cb);

/**
 * @param topic a UTF-8 encoded topic-name
 */
typedef void (*evmqtt_message_handler_t)(evmqtt_t *mc, const char *topic, const void *message, size_t len, bool retain, uint8_t qos, void *arg);
typedef void (*evmqtt_error_handler_t)(evmqtt_t *mc, enum evmqtt_error err, char *msg);


evmqtt_t *evmqtt_create(struct event_base *base, evmqtt_error_handler_t err_handler, void *userdata);
void evmqtt_free(evmqtt_t *mc);

/**
 * @param topic a UTF-8 encoded topic-name
 */
void evmqtt_will_set(evmqtt_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain);
void evmqtt_set_msg_cb(evmqtt_t *mc, evmqtt_message_handler_t msg_handler, void *msg_arg);

void evmqtt_setup(evmqtt_t *mc, char *id, uint16_t keep_alive, char *username, char *password);
void evmqtt_connect(evmqtt_t *mc, struct bufferevent *bev, bool clean_session);
void evmqtt_disconnect(evmqtt_t *mc);

void *evmqtt_userdata(evmqtt_t *mc);

/**
 * Publish a message.
 * @param topic a UTF-8 encoded topic-name
 */
void evmqtt_pub(evmqtt_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain);

/**
 * @param topic a UTF-8 encoded topic-name
 */
void evmqtt_sub(evmqtt_t *mc, const char *topic, int qos);
/**
 * @param topic a UTF-8 encoded topic-name
 */
void evmqtt_unsub(evmqtt_t *mc, const char *topic);

typedef void (*evmqtt_notification_handler_t)(evmqtt_t *mc, const char *str);
void evmqtt_set_notification_cb(evmqtt_t *mc, evmqtt_notification_handler_t cb);

struct event_base *evmqtt_get_base(evmqtt_t *mc);

#endif
