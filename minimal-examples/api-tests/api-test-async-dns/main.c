/*
 * lws-api-test-async-dns
 *
 * Written in 2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms various kinds of async dns apis
 */

#include <libwebsockets.h>
#include <signal.h>

static int interrupted, dtest, ok, fail;

/*
 * These are used to test the apis to parse and print ipv4 / ipv6 literal
 * address strings for various cases.
 *
 * Expected error cases are not used to test the ip data -> string api.
 */

static const struct ipparser_tests {
	const char	*test;
	int		rlen;
	const char	*emit_test;
	int		emit_len;
	uint8_t		b[16];
} ipt[] = {
	{ "2001:db8:85a3:0:0:8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "2001:db8:85a3::8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "::1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "::",  16, "::", 2,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },

	{ "::ffff:192.0.2.128", 16,  "::ffff:192.0.2.128", 18,
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x80 } },

	{ "cats", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ ":::1", -8, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "0:0::0:1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.2.3.4", 4, "1.2.3.4", 7, { 1, 2, 3, 4 } },
};

static const struct async_dns_tests {
	const char *dns_name;
	int recordtype;
	int addrlen;
	uint8_t ads[16];
} adt[] = {
	{ "warmcat.com", LWS_ADNS_RECORD_A, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "libwebsockets.org", LWS_ADNS_RECORD_A, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "warmcat.com", LWS_ADNS_RECORD_AAAA, 16, /* check ipv6 */
		{ 0x20, 0x01, 0x41, 0xd0, 0x00, 0x02, 0xee, 0x93,
				0, 0, 0, 0, 0, 0, 0, 0, } },
};


struct lws *
cb1(struct lws *wsi_unused, const char *ads, struct addrinfo *a, int n,
    void *opaque)
{
	int alen = a->ai_addrlen == sizeof(struct sockaddr_in) ? 4 : 16;
	uint8_t *addr;
	char buf[64];
	int m;

	if (alen == 4)
		addr = (uint8_t *)&(((struct sockaddr_in *)a->ai_addr)->
							sin_addr.s_addr);
	else
		addr = (uint8_t *)&(((struct sockaddr_in6 *)a->ai_addr)->
							sin6_addr.s6_addr);

	strcpy(buf, "unknown");
	lws_write_numeric_address(addr, alen, buf, sizeof(buf));

	lwsl_info("%s: %s %d %s\n", __func__, ads, alen, buf);

	dtest++;

	if (alen != adt[dtest - 1].addrlen) {
		lwsl_warn("%s: dns test %d: alen mismatch %d %d\n", __func__,
			  dtest, alen, adt[dtest - 1].addrlen);
		fail++;
		goto next;
	}

	if (memcmp(adt[dtest - 1].ads, addr, alen)) {
		lwsl_warn("%s: dns test %d: addr mismatch\n", __func__, dtest);
		lwsl_hexdump_notice(addr, alen);
		lwsl_hexdump_notice(adt[dtest - 1].ads, alen);
		fail++;
		goto next;
	}

	ok++;

next:
	if (dtest == (int)LWS_ARRAY_SIZE(adt))
		interrupted = 1;
	else {
		m = lws_async_dns_query((struct lws_context *)opaque, 0,
					adt[dtest].dns_name,
					adt[dtest].recordtype, cb1, NULL,
					opaque);
		if (m != LADNS_RET_CONTINUING) {
			lwsl_err("%s: adns 1 failed: %d\n", __func__, m);
			fail++;
			interrupted = 1;
		}
	}

	return NULL;
}


void sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	int m, n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;

	/* the normal lws init */

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: Async DNS\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}


	/* ip address parser tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		uint8_t u[16];
		int m = lws_parse_numeric_address(ipt[n].test, u, sizeof(u));

		if (m != ipt[n].rlen) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (memcmp(ipt[n].b, u, m)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(u, m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* ip address formatter tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		char buf[64];
		int m;

		/* don't attempt to reverse the ones that are meant to fail */
		if (ipt[n].rlen < 0)
			continue;

		m = lws_write_numeric_address(ipt[n].b, ipt[n].rlen, buf,
						sizeof(buf));
		if (m != ipt[n].emit_len) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].emit_test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (strcmp(ipt[n].emit_test, buf)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(buf, m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* kick off the async dns tests */

	m = lws_async_dns_query(context, 0, adt[0].dns_name,
				adt[0].recordtype, cb1, NULL, context);
	if (m != LADNS_RET_CONTINUING) {
		lwsl_err("%s: adns 1 failed: %d\n", __func__, m);
		goto bail;
	}

	/* the usual lws event loop */

	n = 1;
	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", ok, fail);

	return !(ok && !fail);
}
