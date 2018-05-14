#include <pcre.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <uthash.h>

#include "evmqtt/mqtt.h"

#include "evmqtt/util.h"

struct mqtt_subscription;
typedef struct mqtt_subscription mqtt_subscription_t;

struct mqtt_subscription_engine {
	evmqtt_t *evm;
	mqtt_subscription_t *subs;
};

struct mqtt_subscription_handler;
typedef struct mqtt_subscription_handler mqtt_subscription_handler_t;

struct mqtt_subscription_handler {
	evmqtt_message_handler_t cb;
	void *ctx;
};

struct mqtt_subscription {
	mqtt_subscription_engine_t *se;
	char *topic;
	uint8_t qos;

	pcre *topic_regex;
	pcre_extra *topic_regex_extra;

	size_t handlers_size;
	mqtt_subscription_handler_t *handlers;

	UT_hash_handle hh;
};

static char *dull_replace(const char *in, const char *pattern, const char *by)
{
	size_t outsize = strlen(in) + 1;
	// TODO maybe avoid reallocing by counting the non-overlapping occurences of pattern
	char *res = malloc(outsize);
	// use this to iterate over the output
	size_t resoffset = 0;

	char *needle;

	while ((needle = strstr(in, pattern))) {
		// copy everything up to the pattern
		memcpy(res + resoffset, in, needle - in);
		resoffset += needle - in;

		// skip the pattern in the input-string
		in = needle + strlen(pattern);

		// adjust space for replacement
		outsize = outsize - strlen(pattern) + strlen(by);
		res = realloc(res, outsize);

		// copy the pattern
		memcpy(res + resoffset, by, strlen(by));
		resoffset += strlen(by);
	}

	// copy the remaining input
	strcpy(res + resoffset, in);

	return res;
}

static bool subscription_matches_topic(mqtt_subscription_t *sub, const char *topic)
{
	int pcreExecRet;
	int subStrVec[3 * 10];

	pcreExecRet = pcre_exec(sub->topic_regex,
		        sub->topic_regex_extra,
		        topic,
		        strlen(topic),  // length of string
		        0,	        // Start looking at this point
		        0,	        // OPTIONS
		        subStrVec,
		        sizeof(subStrVec)); // Length of subStrVec

	// Report what happened in the pcre_exec call..
	if (pcreExecRet < -1) { // Something dreadful happened..
		fprintf(stderr, "got pcreExecRet %d", pcreExecRet);
		return false;
	}
	else if (pcreExecRet == PCRE_ERROR_NOMATCH) {
		return false;
	}
	else {
		// we aren't using groups anyway, so we can ignore pcreExecRet == 0
		return true;
	}
}

static void mqtt_subscription_notify_handlers(mqtt_subscription_t *sub, mqtt_subscription_engine_t *se, const char *topic, const void *message, size_t len, bool retain, uint8_t qos)
{
	size_t pos;
	for (pos = 0; pos < sub->handlers_size; pos++) {
		sub->handlers[pos].cb(se->evm, topic, message, len, retain, qos, sub->handlers[pos].ctx);
	}
}

static void mqtt_subscription_add_handler(mqtt_subscription_t *sub, evmqtt_message_handler_t cb, void *ctx)
{
	size_t pos;
	for (pos = 0; pos < sub->handlers_size; pos++) {
		if ((sub->handlers[pos].cb == cb) && (sub->handlers[pos].ctx == ctx))
			return;
	}

	sub->handlers_size += 1;
	sub->handlers = realloc(sub->handlers, sub->handlers_size);

	sub->handlers[sub->handlers_size - 1].cb = cb;
	sub->handlers[sub->handlers_size - 1].ctx = ctx;
}

static bool mqtt_subscription_has_handlers(mqtt_subscription_t *sub)
{
	return sub->handlers_size != 0;
}

static void mqtt_subscription_remove_handler(mqtt_subscription_t *sub, evmqtt_message_handler_t cb, void *ctx)
{
	size_t pos;
	for (pos = 0; pos < sub->handlers_size; pos++) {
		if ((sub->handlers[pos].cb == cb) && (sub->handlers[pos].ctx == ctx))
			break;
	}

	if (pos == sub->handlers_size)
		return;

	sub->handlers_size -= 1;

	sub->handlers[pos].cb = sub->handlers[sub->handlers_size].cb;
	sub->handlers[pos].ctx = sub->handlers[sub->handlers_size].ctx;

	sub->handlers = realloc(sub->handlers, sub->handlers_size);
}

static mqtt_subscription_t *mqtt_subscription_new(mqtt_subscription_engine_t *se, const char *topic, uint8_t qos)
{
	if (((topic == NULL) || (strlen(topic) == 0))) {
		return NULL;
	}

	char *regex = NULL, *tmp;
	tmp = dull_replace(topic, "+", "[^/\\x00]*");
	regex = dull_replace(tmp, "#", ".*");
	free(tmp);

	size_t rexlen = strlen(regex);
	tmp = alloca(rexlen + 3);
	memcpy(&tmp[1], regex, rexlen);
	tmp[0] = '^';
	tmp[rexlen + 1] = '$';
	tmp[rexlen + 2] = '\0';

	free(regex);

	regex = tmp;

	mqtt_subscription_t *res = malloc(sizeof(mqtt_subscription_t));

	res->topic = strdup(topic);
	res->qos = qos;
	res->se = se;

	const char *pcreErrorStr = NULL;
	int pcreErrorOffset = 0;

	// First, the regex string must be compiled.
	res->topic_regex = pcre_compile(regex, 0, &pcreErrorStr, &pcreErrorOffset, NULL);

	// pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr
	if (res->topic_regex == NULL) {
		fprintf(stderr, "regex: Could not compile '%s': %s (%d)", regex, pcreErrorStr, pcreErrorOffset);
		goto error;
	}

	// Optimize the regex
	res->topic_regex_extra = pcre_study(res->topic_regex, 0, &pcreErrorStr);

	/*
	 * pcre_study() returns NULL for both errors and when it can not optimize the regex.
	 * The last argument is how one checks for errors
	 * it is NULL if everything works, and points to an error string otherwise.
	 */
	if (pcreErrorStr != NULL) {
		fprintf(stderr, "regex: Could not study '%s': %s", regex, pcreErrorStr);
	}

	res->handlers_size = 0;
	res->handlers = NULL;

	return res;

error:
	free(res->topic);

	free(res);

	return NULL;
}


static void mqtt_subscription_free(mqtt_subscription_t *sub)
{
	evmqtt_unsub(sub->se->evm, sub->topic);

	free(sub->handlers);

	// free the EXTRA PCRE value (may be NULL at this point)
	if (sub->topic_regex_extra != NULL) {
		pcre_free(sub->topic_regex_extra);
	}

	// free the regular expression.
	pcre_free(sub->topic_regex);

	free(sub->topic);
	free(sub);
}

static void _mqtt_subscription_engine_msg_handler(evmqtt_t *mc, const char *topic, const void *message, size_t len, bool retain, uint8_t qos, void *arg)
{
	(void) mc;

	mqtt_subscription_engine_t *se = arg;

	mqtt_subscription_t *sub, *tmp;
	HASH_ITER(hh, se->subs, sub, tmp) {
		if (subscription_matches_topic(sub, topic)) {
			mqtt_subscription_notify_handlers(sub, se, topic, message, len, retain, qos);
		}
	}
}

mqtt_subscription_engine_t *mqtt_subscription_engine_new(evmqtt_t *evm)
{
	mqtt_subscription_engine_t *res = malloc(sizeof(mqtt_subscription_engine_t));
	res->evm = evm;
	res->subs = NULL;

	evmqtt_set_msg_cb(evm, _mqtt_subscription_engine_msg_handler, res);

	return res;
}

bool mqtt_subscription_engine_add_sub(mqtt_subscription_engine_t *se, const char *topic, uint8_t qos, evmqtt_message_handler_t cb, void *ctx)
{
	if (!cb || !topic)
		return false;

	mqtt_subscription_t *sub;
	HASH_FIND_STR(se->subs, topic, sub);

	if (!sub) {
		sub = mqtt_subscription_new(se, topic, qos);

		if (!sub) {
			return false;
		}

		HASH_ADD_KEYPTR(hh, se->subs, topic, strlen(topic), sub);
	}

	mqtt_subscription_add_handler(sub, cb, ctx);

	return true;
}

void mqtt_subscription_engine_remove_sub(mqtt_subscription_engine_t *se, const char *topic, evmqtt_message_handler_t cb, void *ctx)
{
	mqtt_subscription_t *sub;
	HASH_FIND_STR(se->subs, topic, sub);

	if (sub) {
		mqtt_subscription_remove_handler(sub, cb, ctx);

		if (!mqtt_subscription_has_handlers(sub)) {
			HASH_DEL(se->subs, sub);
			mqtt_subscription_free(sub);
		}
	}
}

void mqtt_subscription_engine_activate(mqtt_subscription_engine_t *se)
{
	mqtt_subscription_t *sub, *tmp;
	HASH_ITER(hh, se->subs, sub, tmp) {
		evmqtt_sub(se->evm, sub->topic, sub->qos);
	}
}

void mqtt_subscription_engine_free(mqtt_subscription_engine_t *se)
{
	evmqtt_set_msg_cb(se->evm, NULL, NULL);

	mqtt_subscription_t *sub, *tmp;
	HASH_ITER(hh, se->subs, sub, tmp) {
		HASH_DEL(se->subs, sub);
		mqtt_subscription_free(sub);
	}

	free(se);
}


/*
 * The topic-tokenizer can be used to traverse a topic
 */

/*
 * The maximum topic-length is implicitly and explicitly limited to HIGH(uint16_t).
 * There is no restriction for particles.
 */
#define MQTT_MAX_TOPIC_SIZE 0xFFFF
#define MQTT_MAX_PARTICLE_SIZE 0xFFFF

struct topic_tokenizer {
	char *topic_pnt;
	/* need space for zero-termination */
	char topic[MQTT_MAX_TOPIC_SIZE + 1];

	char current[MQTT_MAX_PARTICLE_SIZE + 1];
};

topic_tokenizer_t *topic_tokenizer_create(const char *topic)
{
	topic_tokenizer_t *res = malloc(sizeof(topic_tokenizer_t));

	strncpy(res->topic, topic, sizeof(res->topic) - 1);
	res->topic[sizeof(res->topic) - 1] = '\0';
	res->topic_pnt = res->topic;

	res->current[0] = '\0';

	return res;
}

void topic_tokenizer_free(topic_tokenizer_t *tokenizer)
{
	free(tokenizer);
}

void topic_tokenizer_reset(topic_tokenizer_t *tokenizer)
{
	tokenizer->topic_pnt = tokenizer->topic;
	tokenizer->current[0] = '\0';
}

char *topic_tokenizer_get_next_particle(topic_tokenizer_t *from)
{
	if (*from->topic_pnt == '\0') {
		return NULL;
	}

	char *dpos = strstr(from->topic_pnt, "/");

	if (dpos) {
		uintptr_t cnt = dpos - from->topic_pnt;
		memcpy(from->current, from->topic_pnt, cnt);
		from->current[cnt] = '\0';
		from->topic_pnt += cnt + 1;
	}
	else {
		strcpy(from->current, from->topic_pnt);
		from->topic_pnt = &from->topic[sizeof(from->topic) - 1];
	}

	return from->current;
}
