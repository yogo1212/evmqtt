#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>

#include <uthash.h>

#include "mqtt_proto.h"

#include "evmqtt/mqtt.h"
#include "UTF8.h"

enum MQTT_STATE {
	//MQTT_STATE_INVALID = 0,
	MQTT_STATE_PREPARING,
	MQTT_STATE_CONNECTING,
	MQTT_STATE_CONNECTED,
	MQTT_STATE_DISCONNECTING,
	MQTT_STATE_DISCONNECTED,
};

struct mqtt_retransmission;
typedef struct mqtt_retransmission mqtt_retransmission_t;

struct mqtt_qos2msg;
typedef struct mqtt_qos2msg mqtt_qos2msg_t;

struct evmqtt {
	struct event_base *base;
	struct bufferevent *bev;

	void *userdata;
	bool awaiting_ping;
	struct event *timeout_evt;
	enum MQTT_STATE state;
	uint16_t next_mid;
	mqtt_retransmission_t *active_transmissions;

	struct event *qos2_cleanup_evt;
	mqtt_qos2msg_t *incoming_qos2;
	mqtt_connect_data_t data;
	evmqtt_message_handler_t msg_cb;
	void *msg_cb_arg;
	evmqtt_error_handler_t error_cb;
	evmqtt_notification_handler_t debug_cb;
	evmqtt_event_handler_t event_cb;
};

struct mqtt_retransmission {
	void *buffer;
	size_t len;
	uint16_t mid;
	struct event *evt;
	struct timeval tvl;
	evmqtt_t *session;

	UT_hash_handle hh;
};

struct mqtt_qos2msg {
	uint16_t mid;
	time_t last;
	UT_hash_handle hh;
};

static uint16_t next_mid(evmqtt_t *mc)
{
	uint16_t res = htons(mc->next_mid++);
	if (res == 0)
		res = htons(mc->next_mid++);
	return res;
}

static void retransmission_timeout(int fd, short evt, void *arg)
{
	(void) fd;
	(void) evt;
	mqtt_retransmission_t *r = arg;

	r->tvl.tv_usec = 0;

	if (r->session->state == MQTT_STATE_CONNECTED) {
		bufferevent_write(r->session->bev, r->buffer, r->len);

		// set the dup-flag
		uint8_t *cpyptr = r->buffer;
		// TODO ? shift + and ?
		*cpyptr |= ((1 << 3) & 0x8);

		// TODO this is not good for big messages...
		// it might be worth it for mc to monitor the actual throughput and have this wait for e.g. 1.5 times the expected time.
		r->tvl.tv_sec = r->tvl.tv_sec + 1;

		if (r->tvl.tv_sec >= 12) {
			r->tvl.tv_sec = 1;
		}
	}
	else {
		r->tvl.tv_sec = 1;
	}

	event_add(r->evt, &r->tvl);
}

static mqtt_retransmission_t *mqtt_retransmission_new(evmqtt_t *session, void *data, size_t datalen, uint16_t mid)
{
	mqtt_retransmission_t *res = malloc(sizeof(mqtt_retransmission_t));

	res->session = session;

	res->len = datalen;
	res->buffer = malloc(datalen);
	memcpy(res->buffer, data, datalen);

	res->evt = event_new(session->base, -1, EV_TIMEOUT, retransmission_timeout, res);
	res->tvl.tv_usec = 10;
	res->tvl.tv_sec = 0;

	res->mid = mid;

	if (res->session->state == MQTT_STATE_CONNECTED) {
		event_add(res->evt, &res->tvl);
	}

	return res;
}

static void mqtt_retransmission_free(mqtt_retransmission_t *r)
{
	free(r->buffer);
	event_free(r->evt);

	free(r);
}

static void mqtt_retransmission_resume(mqtt_retransmission_t *r)
{
	if (r->session->state == MQTT_STATE_CONNECTED) {
		event_add(r->evt, &r->tvl);
	}
}

static void mqtt_retransmission_pause(mqtt_retransmission_t *r)
{
	event_del(r->evt);
}

static void add_retransmission(evmqtt_t *mc, struct evbuffer *evb, uint16_t mid)
{
	size_t evblen = evbuffer_get_length(evb);
	void *evbbuf = alloca(evblen);
	evbuffer_copyout(evb, evbbuf, evblen);
	mqtt_retransmission_t *r = mqtt_retransmission_new(mc, evbbuf, evblen, mid);

	if (mc->state != MQTT_STATE_CONNECTED) {
		mqtt_retransmission_pause(r);
	}

	mqtt_retransmission_t *tmp;
	HASH_REPLACE(hh, mc->active_transmissions, mid, sizeof(mid), r, tmp);

	if (tmp != NULL) {
		mqtt_retransmission_free(tmp);
	}
}

static void delete_retransmission(evmqtt_t *mc, uint16_t mid)
{
	mqtt_retransmission_t *r;
	HASH_FIND(hh, mc->active_transmissions, &mid, sizeof(mid), r);

	if (r != NULL) {
		HASH_DEL(mc->active_transmissions, r);
		mqtt_retransmission_free(r);
	}
}

static void _evmqtt_disconnect(evmqtt_t *mc, bool graceful);

static void call_error_cb(evmqtt_t *mc, enum evmqtt_error err, const char *errstr)
{
	_evmqtt_disconnect(mc, false);

	char *error = alloca(strlen(errstr) + 1);
	strcpy(error, errstr);

	if (mc->error_cb) {
		mc->error_cb(mc, err, error);
	}
}

static void call_debug_cb(evmqtt_t *mc, const char *msg)
{
	if (mc->debug_cb) {
		mc->debug_cb(mc, msg);
	}
}

static void mqtt_send_connect(evmqtt_t *mc)
{
	char *databuf;
	size_t datalen;

	if (!mqtt_write_connect_data(&mc->data, &databuf, &datalen)) {
		call_error_cb(mc, MQTT_ERROR_CONNECT, databuf);
		free(databuf);
		return;
	}

	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_CONNECT, 0, false, false };

	mqtt_write_header(&bufpnt, &hdr, datalen);
	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);
	bufferevent_write(mc->bev, databuf, datalen);

	free(databuf);

	call_debug_cb(mc, "sending connect");
}

static void mqtt_send_pingreq(evmqtt_t *mc)
{
	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PINGREQ, 0, false, false };
	mqtt_write_header(&bufpnt, &hdr, 0);


	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);
	bufferevent_flush(mc->bev, EV_WRITE, BEV_FLUSH);

	call_debug_cb(mc, "sending pingreq");
}

static void mqtt_send_disconnect(evmqtt_t *mc)
{
	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_DISCONNECT, 0, false, false };
	mqtt_write_header(&bufpnt, &hdr, 0);

	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

	call_debug_cb(mc, "sending disconnect");
}

static void mqtt_send_subscribe(evmqtt_t *mc, const char *topic, uint8_t qos)
{
	char *buf = NULL;
	size_t bufsize = 0;

	if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
		call_error_cb(mc, MQTT_ERROR_PROTOCOL, buf);
		free(buf);
		return;
	}

	char *bufcpy = alloca(bufsize);
	memcpy(bufcpy, buf, bufsize);
	free(buf);

	uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *hdrbufpnt = hdrbuf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_SUBSCRIBE, 1, false, false };
	mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(mc->next_mid) + sizeof(qos));

	struct evbuffer *evb = evbuffer_new();

	evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
	uint16_t mid = next_mid(mc);
	evbuffer_add(evb, &mid, sizeof(mid));
	evbuffer_add(evb, bufcpy, bufsize);
	evbuffer_add(evb, &qos, sizeof(qos));

	add_retransmission(mc, evb, ntohs(mid));

	evbuffer_free(evb);

	call_debug_cb(mc, "sending subscribe");
}

static void mqtt_send_unsubscribe(evmqtt_t *mc, const char *topic)
{
	char *buf = NULL;
	size_t bufsize = 0;

	if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
		call_error_cb(mc, MQTT_ERROR_PROTOCOL, buf);
		free(buf);
		return;
	}

	char *bufcpy = alloca(bufsize);
	memcpy(bufcpy, buf, bufsize);
	free(buf);

	uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *hdrbufpnt = hdrbuf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_UNSUBSCRIBE, 1, false, false };
	mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(mc->next_mid));

	struct evbuffer *evb = evbuffer_new();

	evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
	uint16_t mid = next_mid(mc);
	evbuffer_add(evb, &mid, sizeof(mid));
	evbuffer_add(evb, bufcpy, bufsize);

	add_retransmission(mc, evb, ntohs(mid));

	evbuffer_free(evb);

	call_debug_cb(mc, "sending unsubscribe");
}

static void mqtt_send_publish(evmqtt_t *mc, const char *topic, const void *data, size_t datalen, uint8_t qos, bool retain)
{
	char *topicbuf = NULL;
	size_t topicbufsize = 0;

	if (!mqtt_write_string(topic, strlen(topic), &topicbuf, &topicbufsize)) {
		call_error_cb(mc, MQTT_ERROR_PROTOCOL, topicbuf);
		free(topicbuf);
		return;
	}

	uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *hdrbufpnt = hdrbuf;
	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBLISH, qos, retain, false };
	mqtt_write_header(&hdrbufpnt, &hdr, topicbufsize + (qos > 0 ? sizeof(mc->next_mid) : 0) + datalen);

	struct evbuffer *evb = evbuffer_new();

	evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
	evbuffer_add(evb, topicbuf, topicbufsize);
	free(topicbuf);

	// this increases even for qos=0
	uint16_t mid;
	if (qos > 0) {
		mid = next_mid(mc);
		evbuffer_add(evb, &mid, sizeof(mid));
	}

	evbuffer_add(evb, data, datalen);

	if (qos > 0) {
		add_retransmission(mc, evb, ntohs(mid));
	}
	else {
		bufferevent_write_buffer(mc->bev, evb);
	}

	evbuffer_free(evb);

	call_debug_cb(mc, "sending publish");
}

static void mqtt_send_puback(evmqtt_t *mc, uint16_t mid)
{
	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBACK, 1, false, false };
	mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
	mqtt_write_uint16(&bufpnt, mid);

	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

	call_debug_cb(mc, "sending puback");
}

static void mqtt_send_pubrec(evmqtt_t *mc, uint16_t mid)
{
	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBREC, 1, false, false };
	mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
	mqtt_write_uint16(&bufpnt, mid);

	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

	call_debug_cb(mc, "sending pubrec");
}

static void mqtt_send_pubrel(evmqtt_t *mc, uint16_t mid)
{
	uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
	void *hdrbufpnt = hdrbuf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBREL, 1, false, false };
	mqtt_write_header(&hdrbufpnt, &hdr, sizeof(mid));

	struct evbuffer *evb = evbuffer_new();

	evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
	evbuffer_add(evb, &mid, sizeof(mid));

	add_retransmission(mc, evb, mid);

	evbuffer_free(evb);

	call_debug_cb(mc, "sending pubrel");
}

static void mqtt_send_pubcomp(evmqtt_t *mc, uint16_t mid)
{
	uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
	void *bufpnt = buf;

	mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBCOMP, 1, false, false };
	mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
	mqtt_write_uint16(&bufpnt, mid);

	bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

	call_debug_cb(mc, "sending pubcomp");
}

static void handle_connack(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	mqtt_connack_data_t data;
	mqtt_read_connack_data(&buf, &data);

	if (data.return_code != MQTT_CONNACK_ACCEPTED) {
		call_error_cb(mc, MQTT_ERROR_CONNECT, mqtt_connack_code_str(data.return_code));
		return;
	}

	// TODO data.flags == MQTT_CONNACK_FLAGS_SESSION_PRESENT

	mc->state = MQTT_STATE_CONNECTED;
	if (mc->event_cb) {
		mc->event_cb(mc, MQTT_EVENT_CONNECTED);
	}

	mc->awaiting_ping = false;

	struct timeval interval = { mc->data.keep_alive, 0 };
	event_add(mc->timeout_evt, &interval);
	interval.tv_sec = 60;
	event_add(mc->qos2_cleanup_evt, &interval);

	mqtt_retransmission_t *r, *tmp;

	HASH_ITER(hh, mc->active_transmissions, r, tmp) {
		mqtt_retransmission_resume(r);
	}

	call_debug_cb(mc, "received connack");
}

static void handle_pingresp(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) buf;
	(void) len;

	mc->awaiting_ping = false;

	call_debug_cb(mc, "received pingresp");
}

static void handle_publish(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	char *topic;
	size_t topic_len;

	if (!mqtt_read_string(&buf, &len, &topic, &topic_len)) {
		call_error_cb(mc, MQTT_ERROR_PROTOCOL, topic);
		free(topic);
		return;
	}

	uint16_t mid;

	if (hdr->qos > 0) {
		mid = mqtt_read_uint16(&buf);
		len -= 2;

		if (hdr->qos == 1) {
			mqtt_send_puback(mc, mid);
			goto call;
		}

		if (hdr->qos == 2) {
			mqtt_qos2msg_t *q;
			HASH_FIND(hh, mc->incoming_qos2, &mid, sizeof(mid), q);

			if (!q) {
				q = malloc(sizeof(mqtt_qos2msg_t));
				q->mid = mid;
				HASH_ADD(hh, mc->incoming_qos2, mid, sizeof(mid), q);

				goto call;
			}

			q->last = time(NULL);
			mqtt_send_pubrec(mc, mid);

			goto out;
		}
	}

call:
	if (mc->msg_cb)
		mc->msg_cb(mc, topic, buf, len, hdr->retain, hdr->qos, mc->msg_cb_arg);

out:
	free(topic);

	call_debug_cb(mc, "received publish");
}

static void handle_puback(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	uint16_t mid = mqtt_read_uint16(&buf);
	delete_retransmission(mc, mid);

	call_debug_cb(mc, "received puback");
}

static void handle_pubrec(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	uint16_t mid = mqtt_read_uint16(&buf);
	delete_retransmission(mc, mid);

	mqtt_send_pubrel(mc, mid);

	call_debug_cb(mc, "received pubrec");
}

static void handle_pubrel(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	uint16_t mid = mqtt_read_uint16(&buf);
	mqtt_qos2msg_t *q;
	HASH_FIND(hh, mc->incoming_qos2, &mid, sizeof(mid), q);

	if (q) {
		HASH_DEL(mc->incoming_qos2, q);
		free(q);
	}

	mqtt_send_pubcomp(mc, mid);

	call_debug_cb(mc, "received pubrel");
}

static void handle_pubcomp(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	uint16_t mid = mqtt_read_uint16(&buf);
	delete_retransmission(mc, mid);

	call_debug_cb(mc, "received pubcomp");
}

static void handle_suback(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;

	uint16_t mid = mqtt_read_uint16(&buf);
	len -= sizeof(mid);
	delete_retransmission(mc, mid);

	// TODO buf contains byte for each subscription
	// either QoS (0,1,2) or failure (0x80)

	call_debug_cb(mc, "received suback");
}

static void handle_unsuback(evmqtt_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
	(void) hdr;
	(void) len;

	uint16_t mid = mqtt_read_uint16(&buf);
	delete_retransmission(mc, mid);

	call_debug_cb(mc, "received unsuback");
}

static void qos2_cleanup(evutil_socket_t fd, short events, void *arg)
{
	(void) fd;
	(void) events;

	evmqtt_t *mc = (evmqtt_t *) arg;

	// TODO configurable interval
	time_t expired = time(NULL) - 600;

	mqtt_qos2msg_t *q, *tmp;
	HASH_ITER(hh, mc->incoming_qos2, q, tmp) {
		if (q->last > expired)
			continue;

		HASH_DEL(mc->incoming_qos2, q);
		free(q);
	}

	if (!mc->incoming_qos2)
		event_del(mc->qos2_cleanup_evt);
}

static void _evmqtt_disconnect(evmqtt_t *mc, bool graceful)
{
	char buf[1024];

	switch (mc->state) {
		case MQTT_STATE_CONNECTED:
			if (!graceful)
				break;

			mc->state = MQTT_STATE_DISCONNECTING;
			if (mc->event_cb) {
				mc->event_cb(mc, MQTT_EVENT_DISCONNECTED);
			}
			mqtt_send_disconnect(mc);
			struct timeval interval = { 1, 0 };
			event_add(mc->timeout_evt, &interval);
			return;

		case MQTT_STATE_PREPARING:
		case MQTT_STATE_DISCONNECTED:
			return;

		case MQTT_STATE_CONNECTING:
		case MQTT_STATE_DISCONNECTING:
			break;

		default:
			sprintf(buf, "can't disconnect from this state: %d", mc->state);
			call_error_cb(mc, MQTT_ERROR_STATE, buf);
	}

	if (mc->bev) {
		bufferevent_free(mc->bev);
		mc->bev = NULL;
	}

	event_del(mc->timeout_evt);
	mc->state = MQTT_STATE_DISCONNECTED;
}

static void mqtt_timeout(evutil_socket_t fd, short events, void *arg)
{
	(void) fd;
	(void) events;

	evmqtt_t *mc = (evmqtt_t *) arg;

	// TODO
	switch (mc->state) {
		case MQTT_STATE_CONNECTING:
			call_error_cb(mc, MQTT_ERROR_NETWORK, "timeout waiting for CONACK");
			break;

		case MQTT_STATE_CONNECTED:
			if (mc->awaiting_ping) {
				goto timeout;
			}

			mqtt_send_pingreq(mc);
			mc->awaiting_ping = true;
			break;

		case MQTT_STATE_DISCONNECTING:
			_evmqtt_disconnect(mc, false);
			break;

		default:
			event_del(mc->timeout_evt);
			call_error_cb(mc, MQTT_ERROR_UNKNOWN, "checking for timeout in unknown state!");
	}

	return;

timeout:
	call_error_cb(mc, MQTT_ERROR_NETWORK, "timeout waiting for PINGRESP");
}

static void event_callback(struct bufferevent *bev, short what, void *ctx)
{
	(void) bev;

	evmqtt_t *mc = (evmqtt_t *) ctx;

	if (what & BEV_EVENT_EOF) {
		if ((mc->state == MQTT_STATE_DISCONNECTING) || (mc->state == MQTT_STATE_DISCONNECTED)) {
			return;
		}

		call_error_cb(mc, MQTT_ERROR_NETWORK, "socket closed");
	}

	if (what & BEV_EVENT_ERROR) {
		char buf[1024];
		sprintf(buf, "bev-error(%d): %s", what, strerror(errno));

		call_error_cb(mc, MQTT_ERROR_NETWORK, buf);
	}

	if (what & BEV_EVENT_TIMEOUT) {
		call_error_cb(mc, MQTT_ERROR_NETWORK, "bev-timeout");
	}
}

static void read_callback(struct bufferevent *bev, void *ctx)
{
	evmqtt_t *mc = (evmqtt_t *) ctx;
	struct evbuffer *inbuf = bufferevent_get_input(bev);

	mqtt_proto_header_t hdr;
	uint8_t buf[5];
	void *bufpnt;
	//look into the buffer
	size_t remaining_length;
	ssize_t headerlen = evbuffer_copyout(inbuf, buf, sizeof(buf));

	if (headerlen < 0) {
		bufferevent_setwatermark(bev, EV_READ, 2, 0);
		return;
	}

	bufpnt = buf;
	//OK, maybe my api-design sucks for this...
	mqtt_read_header(&bufpnt, &hdr);

	// check whether we can read the whole 'remaining length'-field
	bufpnt = buf + 1;

	if (!read_remaining_size(&bufpnt, &remaining_length, headerlen - 1)) {
		if (headerlen >= MQTT_MAX_FIXED_HEADER_SIZE) {
			// protocol allows a maximum of 4 bytes for that field
			call_error_cb(mc, MQTT_ERROR_PROTOCOL, "remaining length faulty");
			return;
		}

		// request one more byte than we were able to read
		bufferevent_setwatermark(bev, EV_READ, headerlen + 1, 0);
		return;
	}

	headerlen = ((uintptr_t) bufpnt - (uintptr_t) buf);

	size_t framelen = remaining_length + headerlen;
	ssize_t readlen;

	if (evbuffer_get_length(inbuf) < framelen) {
		bufferevent_setwatermark(bev, EV_READ, framelen, 0);
		return;
	}

	// TODO stack is cool and shit.. but
	if (framelen >= 0x400000) {
		call_debug_cb(mc, "got really big publish");
		evbuffer_drain(inbuf, framelen);
		return;
	}

	void *buffer = alloca(framelen);

	if ((readlen = evbuffer_copyout(inbuf, buffer, framelen)) == -1) {
		call_error_cb(mc, MQTT_ERROR_NETWORK, "evbuffer_copyout -1");
		return;
	}

	if ((size_t) readlen < framelen) {
		bufferevent_setwatermark(bev, EV_READ, framelen, 0);
		return;
	}

	// this actually removes data from the buffer
	evbuffer_drain(inbuf, readlen);

	bufpnt = (uint8_t *) buffer + headerlen;

	switch (hdr.msg_type) {
		case MQTT_MESSAGE_TYPE_CONNACK:
			handle_connack(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PUBLISH:
			handle_publish(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PINGRESP:
			handle_pingresp(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PUBACK:
			handle_puback(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_SUBACK:
			handle_suback(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_UNSUBACK:
			handle_unsuback(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PUBREC:
			handle_pubrec(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PUBREL:
			handle_pubrel(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PUBCOMP:
			handle_pubcomp(mc, &hdr, bufpnt, remaining_length);
			break;

		case MQTT_MESSAGE_TYPE_PINGREQ:
		case MQTT_MESSAGE_TYPE_DISCONNECT:
		case MQTT_MESSAGE_TYPE_CONNECT:
		case MQTT_MESSAGE_TYPE_SUBSCRIBE:
		case MQTT_MESSAGE_TYPE_UNSUBSCRIBE:
			break;

		default:
			call_error_cb(mc, MQTT_ERROR_PROTOCOL, "unkonwn message type");
	}

	// we got a whole message - the next thing we want to read is a header
	bufferevent_setwatermark(bev, EV_READ, 2, 0);
	bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);
}

void evmqtt_will_set(evmqtt_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain)
{
	if (mc->data.will_topic.buf) {
		free(mc->data.will_topic.buf);
	}

	mc->data.will_topic.buf = strdup(topic);
	mc->data.will_topic.len = strlen(topic);

	if (mc->data.will_message.buf) {
		free(mc->data.will_message.buf);
	}

	if (payloadlen > 0) {
		mc->data.will_message.buf = malloc(payloadlen);
		memcpy(mc->data.will_message.buf, payload, payloadlen);
	} else {
		mc->data.will_message.buf = NULL;
	}
	mc->data.will_message.len = payloadlen;

	mc->data.will_retain = retain;
	mc->data.will_qos = qos;
	mc->data.will_flag = true;
}

void evmqtt_set_event_cb(evmqtt_t *mc, evmqtt_event_handler_t cb)
{
	mc->event_cb = cb;
}

void evmqtt_set_msg_cb(evmqtt_t *mc, evmqtt_message_handler_t msg_handler, void *msg_arg)
{
	mc->msg_cb = msg_handler;
	mc->msg_cb_arg = msg_arg;
}

void evmqtt_set_notification_cb(evmqtt_t *mc, evmqtt_notification_handler_t cb)
{
	mc->debug_cb = cb;
}

void *evmqtt_userdata(evmqtt_t *mc)
{
	return mc->userdata;
}

struct event_base *evmqtt_get_base(evmqtt_t *mc)
{
	return mc->base;
}

evmqtt_t *evmqtt_create(struct event_base *base, evmqtt_error_handler_t err_handler, void *userdata)
{
	if (!probe_local_encoding()) {
		if (err_handler)
			err_handler(NULL, MQTT_ERROR_HARD, "couldn't determine local codeset");
		return NULL;
	}

	evmqtt_t *res = malloc(sizeof(evmqtt_t));
	res->state = MQTT_STATE_PREPARING;
	res->base = base;
	res->error_cb = err_handler;
	res->userdata = userdata;
	res->timeout_evt = event_new(res->base, -1, EV_TIMEOUT | EV_PERSIST, mqtt_timeout, res);
	res->qos2_cleanup_evt = event_new(res->base, -1, EV_TIMEOUT | EV_PERSIST, qos2_cleanup, res);

	memset(&res->data, 0, sizeof(res->data));

	res->data.proto_name.buf = strdup(MQTT_PROTOCOL_MAGIC);
	res->data.proto_name.len = strlen(MQTT_PROTOCOL_MAGIC);
	res->data.proto_level = MQTT_PROTOCOL_LEVEL;

	res->event_cb = NULL;
	res->debug_cb = NULL;
	res->msg_cb = NULL;

	res->bev = NULL;

	res->next_mid = 0;

	res->active_transmissions = NULL;
	res->incoming_qos2 = NULL;

	return res;
}

static void mqtt_clear_incoming(evmqtt_t *mc)
{
	mqtt_qos2msg_t *q, *tmp;

	HASH_ITER(hh, mc->incoming_qos2, q, tmp) {
		HASH_DEL(mc->incoming_qos2, q);
		free(q);
	}
}

static void mqtt_clear_retransmissions(evmqtt_t *mc)
{
	mqtt_retransmission_t *r, *tmp;

	HASH_ITER(hh, mc->active_transmissions, r, tmp) {
		HASH_DEL(mc->active_transmissions, r);
		mqtt_retransmission_free(r);
	}

	mc->active_transmissions = NULL;
}

static void mqtt_clear_inflight(evmqtt_t *mc)
{
	mqtt_clear_incoming(mc);
	mqtt_clear_retransmissions(mc);
}

void evmqtt_setup(evmqtt_t *mc, char *id, uint16_t keep_alive, char *username, char *password)
{
	if (mc->state != MQTT_STATE_PREPARING) {
		call_error_cb(mc, MQTT_ERROR_STATE, "can't use evmqtt_setup after connecting");
		return;
	}

	mc->awaiting_ping = false;

	mc->data.keep_alive = keep_alive;

	if (mc->data.id.buf) {
		free(mc->data.id.buf);
	}

	if (id) {
		// TODO error if id is longer than that
		mc->data.id.len = strnlen(id, 23) + 1;
		mc->data.id.buf = malloc(mc->data.id.len);
		memcpy(mc->data.id.buf, id, mc->data.id.len);
		((char *) mc->data.id.buf)[mc->data.id.len - 1] = '\0';
	}
	else {
		mc->data.id.buf = strdup("");
		mc->data.id.len = 0;
	}

	if (username) {
		if (mc->data.username.buf) {
			free(mc->data.username.buf);
		}

		mc->data.username.buf = strdup(username);
		mc->data.username.len = strlen(username);
	}

	if (password) {
		if (mc->data.password.buf) {
			free(mc->data.password.buf);
		}

		mc->data.password.len = strlen(password);
		if (mc->data.password.len > 0)
			mc->data.password.buf = strdup(password);
		else
			mc->data.password.buf = NULL;
	}
}

void evmqtt_connect(evmqtt_t *mc, struct bufferevent *bev, bool clean_session)
{
	_evmqtt_disconnect(mc, false);

	if (!bev) {
		call_error_cb(mc, MQTT_ERROR_HARD, "got a NULL bufferevent");
		return;
	}

	mc->state = MQTT_STATE_CONNECTING;

	mc->bev = bev;

	bufferevent_setwatermark(mc->bev, EV_READ, 2, 0);
	bufferevent_setcb(mc->bev, read_callback, NULL, event_callback, mc);
	bufferevent_enable(mc->bev, EV_READ | EV_WRITE);

	mc->data.clean_session = clean_session;
	if (clean_session) {
		mqtt_clear_inflight(mc);
	}

	mqtt_send_connect(mc);
	struct timeval interval = { mc->data.keep_alive, 0 };
	event_add(mc->timeout_evt, &interval);
}

void evmqtt_disconnect(evmqtt_t *mc)
{
	_evmqtt_disconnect(mc, true);
}

void evmqtt_free(evmqtt_t *mc)
{
	mqtt_clear_inflight(mc);

	if (mc->bev) {
		bufferevent_flush(mc->bev, EV_WRITE, BEV_FLUSH);
		bufferevent_free(mc->bev);
	}

	event_free(mc->timeout_evt);
	event_free(mc->qos2_cleanup_evt);

	free(mc->data.username.buf);
	free(mc->data.password.buf);
	free(mc->data.id.buf);
	free(mc->data.will_topic.buf);
	free(mc->data.will_message.buf);

	free(mc->data.proto_name.buf);

	free(mc);
}

void evmqtt_sub(evmqtt_t *mc, const char *topic, int qos)
{
	mqtt_send_subscribe(mc, topic, qos);
}

void evmqtt_unsub(evmqtt_t *mc, const char *topic)
{
	mqtt_send_unsubscribe(mc, topic);
}

void evmqtt_pub(evmqtt_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain)
{
	mqtt_send_publish(mc, topic, payload, payloadlen, qos, retain);
}
