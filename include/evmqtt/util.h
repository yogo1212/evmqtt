#ifndef EVMQTT_UTIL_H
#define EVMQTT_UTIL_H

#include <evmqtt/mqtt.h>

struct mqtt_subscription_engine;
typedef struct mqtt_subscription_engine mqtt_subscription_engine_t;


mqtt_subscription_engine_t *mqtt_subscription_engine_new(evmqtt_t *evm);
void mqtt_subscription_engine_free(mqtt_subscription_engine_t *se);

bool mqtt_subscription_engine_add_sub(mqtt_subscription_engine_t *se, const char *topic, uint8_t qos, evmqtt_message_handler_t cb, void *ctx);
void mqtt_subscription_engine_remove_sub(mqtt_subscription_engine_t *se, const char *topic, evmqtt_message_handler_t cb, void *ctx);

void mqtt_subscription_engine_activate(mqtt_subscription_engine_t *se);

struct topic_tokenizer;
typedef struct topic_tokenizer topic_tokenizer_t;

topic_tokenizer_t *topic_tokenizer_create(const char *topic);
void topic_tokenizer_free(topic_tokenizer_t *tokenizer);

void topic_tokenizer_reset(topic_tokenizer_t *tokenizer);
/**
 * extracts the next particle from the topic.
 * @return the extracted particle or NULL if no particle could be read
 */
char *topic_tokenizer_get_next_particle(topic_tokenizer_t *from);

#endif
