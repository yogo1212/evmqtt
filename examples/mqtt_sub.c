#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <evtssl.h>

#include "evmqtt/mqtt.h"
#include "evmqtt/util.h"

typedef struct {
	const char *host;
	unsigned long port;
	const char *cafile;
	const char *cadir;
	const char *key;
	const char *cert;
	bool ssl;
	int family;
	bool verbose;
} ms_opts_t;

typedef struct {
	struct event_base *base;
	struct event *sig_event;

	evt_ssl_t *essl;
	evmqtt_t *evm;
	mqtt_subscription_engine_t *mse;

	ms_opts_t mo;
} mqtt_sub_t;

static void handle_interrupt(int fd, short events, void *arg)
{
	(void) fd;
	(void) events;

	mqtt_sub_t *sc = arg;

	event_base_loopbreak(sc->base);
}

static void ssl_error_cb(evt_ssl_t *essl, evt_ssl_error_t error)
{
	mqtt_sub_t *sc = evt_ssl_get_ctx(essl);

	fprintf(stderr, "ssl error(%d): %s\n", error, evt_ssl_get_error_str(essl));

	event_base_loopbreak(sc->base);
}

enum option_repr {
	opt_host = 1,
	opt_port,
	opt_cafile,
	opt_cadir,
	opt_key,
	opt_cert,
	opt_ssl,
	opt_family,
	opt_verbose,
};
static struct option options[] = {
	{ "host", 1, NULL, opt_host },
	{ "port", 1, NULL, opt_port },
	{ "cafile", 1, NULL, opt_cafile },
	{ "cadir", 1, NULL, opt_cadir },
	{ "key", 1, NULL, opt_key },
	{ "cert", 1, NULL, opt_cert },
	{ "ssl", 0, NULL, opt_ssl },
	{ "family", 1, NULL, opt_family },
	{ "verbose", 0, NULL, opt_verbose },
	{ NULL, 0, NULL, 0 }
};

static void print_help(void)
{
	struct option *opt = &options[0];
	while (opt->name) {
		fputs("--", stdout);
		fputs(opt->name, stdout);
		if (opt->has_arg > 0) {
			fputs(" ", stdout);
			if (opt->has_arg > 1)
				fputs("[", stdout);
			fputs("arg", stdout);
			if (opt->has_arg > 1)
				fputs("]", stdout);
		}
		puts("");
		opt++;
	}
	puts("family can be either 4 or 6 (unspec elsewise)");
	puts("-t TOPIC specifies the topic for a new subscription");
	puts("-q 0-2 sets the QoS for the next subscription (default: 1)");
}

void mqtt_msgcb(evmqtt_t *conn, const char *topic, const void *message, size_t len, bool retain, uint8_t qos, void *arg)
{
	(void) retain;
	(void) qos;

	ms_opts_t *cfg = evmqtt_userdata(conn);

	if (arg) {
		printf("%s|", (char *) arg);
	}

	if (cfg->verbose) {
		printf("%s: ", topic);
	}

	printf("%.*s\n", (int) len, (char *) message);
}

// TODO option, arg, param... naming?

static bool parse_args(ms_opts_t *mo, int argc, char *argv[], mqtt_subscription_engine_t *mse)
{
	int c;
	memset(mo, 0, sizeof(ms_opts_t));

	uint8_t last_qos = 1;

	while ((c = getopt_long(argc, argv, "q:t:", options, NULL)) != -1) {
		if ((c == '?') || (c == ':')) {
			fprintf(stderr, "getopt failed (%c)\n", c);
			break;
		}

		switch (c) {
		case opt_host:
			mo->host = optarg;
			break;
		case opt_port:
			errno = 0;
			mo->port = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "can't convert port: %s\n", strerror(errno));
				return false;
			}
			break;
		case opt_cafile:
			mo->cafile = optarg;
			break;
		case opt_cadir:
			mo->cadir = optarg;
			break;
		case opt_key:
			mo->key = optarg;
			break;
		case opt_cert:
			mo->cert = optarg;
			break;
		case opt_ssl:
			mo->ssl = true;
			break;
		case opt_family:
			if (strcmp(optarg, "4") == 0)
				mo->family = AF_INET;
			else if (strcmp(optarg, "6") == 0)
				mo->family = AF_INET6;
			break;
		case opt_verbose:
			mo->verbose = true;
			break;
		case 'q':
			errno = 0;
			last_qos = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "can't convert port: %s\n", strerror(errno));
				return false;
			}
			if (last_qos > 2) {
				last_qos = 1;
			}
			break;
		case 't':
			if (!mqtt_subscription_engine_add_sub(mse, optarg, last_qos, mqtt_msgcb, optarg)) {
				fprintf(stderr, "couldn't add topic \"%s\" (%u)\n", optarg, last_qos);
			}
			last_qos = 1;
			break;
		default:
			fprintf(stderr, "getopt_long huh? (%d)\n", c);
			break;
		}
	}

	return true;
}

static const char *config_ssl(evt_ssl_t *essl, SSL_CTX *ssl_ctx)
{
	mqtt_sub_t *ms = evt_ssl_get_ctx(essl);

	if (ms->mo.cafile || ms->mo.cadir) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, ms->mo.cafile, ms->mo.cadir) < 1) {
			return "ca-error!";
		}
	}

	if (ms->mo.cert) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, ms->mo.cert, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set certificate!";
		}
	}

	if (ms->mo.key) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ms->mo.key, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set private key!";
		}

		if (SSL_CTX_check_private_key(ssl_ctx) < 1) {
		  return "invalid private key!";
		}
	}

	return NULL;
}

void mqtt_errorcb(evmqtt_t *conn, enum evmqtt_error err, char *errormsg)
{
	(void) conn;

	fprintf(stderr, "mqtt-error %d: %s\n", err, errormsg);
}

void mqtt_evtcb(evmqtt_t *conn, enum evmqtt_event evt)
{
  mqtt_sub_t *ms = evmqtt_userdata(conn);

	switch (evt) {
		case MQTT_EVENT_CONNECTED:
			mqtt_subscription_engine_activate(ms->mse);
			break;

		case MQTT_EVENT_DISCONNECTED:
			// TODO reconnect-logic?
			fprintf(stderr, "disconnected\n");
			event_base_loopbreak(ms->base);
			break;

		default:
			;
	}
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		print_help();
		return EXIT_SUCCESS;
	}

	mqtt_sub_t ms;
	ms.base = event_base_new();
	if (!ms.base) {
		fprintf(stderr, "no evbase.. aborting\n");
		return EXIT_FAILURE;
	}

	ms.evm = evmqtt_create(ms.base, mqtt_errorcb, &ms);
	ms.mse = mqtt_subscription_engine_new(ms.evm);

	if (!parse_args(&ms.mo, argc, argv, ms.mse)) {
		fprintf(stderr, "couldn't parse args\n");
		return EXIT_FAILURE;
	}

	int res = EXIT_SUCCESS;

	ms.essl = evt_ssl_create(
	                         ms.base,
	                         ms.mo.host,
	                         ms.mo.port,
	                         &ms,
	                         config_ssl,
	                         ssl_error_cb
	                        );

	if (!ms.essl) {
		fprintf(stderr, "failed to init essl\n");
		res = EXIT_FAILURE;
		goto base_cleanup;
	}

	if (!ms.mo.ssl)
		evt_ssl_dont_really_ssl(ms.essl);

	if (ms.mo.family != 0)
		evt_ssl_set_family(ms.essl, ms.mo.family);


	evmqtt_setup(ms.evm, "some-evmqtt-client", 30, NULL /* user */, NULL /* pw */);
	struct bufferevent *bev = evt_ssl_connect(ms.essl);
	if (!bev) {
		fprintf(stderr, "evt_ssl_connect failed");
		goto ouch;
	}
	evmqtt_connect(ms.evm, bev, true);
	evmqtt_set_event_cb(ms.evm, mqtt_evtcb);

	ms.sig_event = evsignal_new(ms.base, SIGINT, handle_interrupt, &ms);

	event_add(ms.sig_event, NULL);
	event_base_dispatch(ms.base);
	event_free(ms.sig_event);

ouch:
	mqtt_subscription_engine_free(ms.mse);

	evmqtt_free(ms.evm);

	evt_ssl_free(ms.essl);

base_cleanup:
	event_base_free(ms.base);

	return res;
}
