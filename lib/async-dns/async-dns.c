/*
 * Adapted from tadns 1.1, from http://adns.sourceforge.net/
 * Original license -->
 *
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 *
 * Integrated into lws, extended and more or less completely rewritten and
 * relicensed (as allowed above)
 *
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"
#include "private-lib-async-dns.h"

static struct canned_q {
	lws_adns_q_t		q;
	char			n[16];
} q_localhost = {
	{
		.addr		= { 127, 0, 0, 1 },
		.addrlen	= 4,
		.ret		= LADNS_RET_FOUND,
		.qtype		= LWS_ADNS_RECORD_A,
		.sent		= 1
	},
	.n			= "localhost"
}
#if defined(LWS_WITH_IPV6)
, q_localhost6 = {
	{
		.addr		= { 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 1 },
		.addrlen	= 16,
		.ret		= LADNS_RET_FOUND,
		.qtype		= LWS_ADNS_RECORD_AAAA,
		.sent		= 1
	},
	.n			= "localhost6"
}
#endif
;


void
lws_adns_q_destroy(lws_adns_q_t *q)
{
	lws_dll2_remove(&q->sul.list);
	lws_dll2_remove(&q->list);
	lws_free(q);
}

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   lws_dll2_owner_t *owner, uint16_t tid, const char *name)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(owner)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		if (!name && tid == q->tid)
			return q;

		if (name && q->qtype == qtype &&
		    !strcasecmp(name, (const char *)&q[1])) {
			if (owner == &dns->cached) {
				/* Keep sorted by LRU: move to the head */
				lws_dll2_remove(&q->list);
				lws_dll2_add_head(&q->list, &dns->cached);
			}

			return q;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

int
lws_async_dns_done(lws_adns_q_t *q, struct lws *wsi, lws_async_dns_retcode_t r)
{
	struct addrinfo ai, *rai = NULL;
	int n = -1, alen;
	struct sockaddr_in sai;
	struct sockaddr_in6 sai6;
	char buf[64];

	q->ret = r;

	if (r != LADNS_RET_FAILED && r != LADNS_RET_TIMEDOUT &&
	    r != LADNS_RET_NXDOMAIN) {

		memset(&sai, 0, sizeof sai);
		memset(&sai6, 0, sizeof sai6);
		memset(&ai, 0, sizeof ai);

		rai = &ai;
		n = 0;

		if (q->qtype == LWS_ADNS_RECORD_AAAA) {
			sai6.sin6_family = AF_INET6;
			sai6.sin6_port = 0;
			memcpy(&sai6.sin6_addr, q->addr, sizeof(sai6.sin6_addr));
			ai.ai_addrlen = sizeof(sai6);//q->addrlen;
			ai.ai_addr = (struct sockaddr *)&sai6;
			alen = 16;
		} else {
			sai.sin_family = AF_INET;
			sai.sin_port = 0;
			memcpy(&sai.sin_addr, q->addr, sizeof(sai.sin_addr));
			ai.ai_addrlen = sizeof(sai);//q->addrlen;
			ai.ai_addr = (struct sockaddr *)&sai;
			alen = 4;
		}
		ai.ai_flags = 0;
		ai.ai_family = AF_INET;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol = IPPROTO_UDP;

		ai.ai_canonname = (char *)&q[1];

		if (lws_write_numeric_address(q->addr, alen, buf, sizeof(buf)) > 0)
			lwsl_info("%s: result %d, %s\n", __func__, r, buf);

	} else
		lwsl_info("%s: result %d\n", __func__, r);

	if (wsi)
		return !wsi->adns_cb(wsi, (const char*)&q[1], rai, n, q->opaque);

	/* inform all of the parent wsi that were interested in us */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = lws_container_of(d, struct lws, adns);

		lws_dll2_remove(d);
		w->adns_cb(w, (const char*)&q[1], rai, n, q->opaque);
	} lws_end_foreach_dll_safe(d, d1);

	if (q->standalone_cb)
		q->standalone_cb(NULL, (const char*)&q[1], rai, n, q->opaque);

	return 0;
}

void
lws_async_dns_drop_server(struct lws_context *context)
{
	context->async_dns.dns_server_set = 0;
	lws_set_timeout(context->async_dns.wsi, 1, LWS_TO_KILL_ASYNC);
	context->async_dns.wsi = NULL;
}


static void
sul_cb_timeout(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	lws_async_dns_done(q, NULL, LADNS_RET_TIMEDOUT);
	lws_adns_q_destroy(q);

	/*
	 * our policy is to force reloading the dns server info if our
	 * connection ever timed out, in case it or the routing state changed
	 */

	lws_async_dns_drop_server(q->context);
}

static int
callback_async_dns(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_async_dns *dns = &(lws_get_context(wsi)->async_dns);
	uint8_t pkt[LWS_PRE + DNS_PACKET_LEN], *p;
	int fd;

	switch (reason) {

	/* callbacks related to raw socket descriptor */

        case LWS_CALLBACK_RAW_ADOPT:
		// lwsl_user("LWS_CALLBACK_RAW_ADOPT\n");
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		// lwsl_user("LWS_CALLBACK_RAW_CLOSE\n");
		break;

	case LWS_CALLBACK_RAW_RX:
		// lwsl_user("LWS_CALLBACK_RAW_RX (%d)\n", (int)len);
		//lwsl_hexdump_level(LLL_NOTICE, in, len);
		lws_adns_parse_udp(dns, in, len);

		return 0;

	case LWS_CALLBACK_RAW_WRITEABLE:

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&dns->active)) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);
			int did = 0, m;

			if (!q->sent) {
				const char *s, *name = (const char *)&q[1];
				int i, n, name_len;

				if (did) {
					/* we used up our budget of one send */
					lws_callback_on_writable(wsi);

					return 0;
				}

				p = &pkt[LWS_PRE];

				memset(p, 0, DHO_SIZEOF);

				lws_ser_wu16be(&p[DHO_TID], q->tid);
				lws_ser_wu16be(&p[DHO_FLAGS], 0x100);
				lws_ser_wu16be(&p[DHO_NQUERIES], 1);

				name_len = strlen(name);
				p += DHO_SIZEOF;

				do {
					if ((s = strchr(name, '.')) == NULL)
						s = name + name_len;

					n = s - name;
					*p++ = n;
					for (i = 0; i < n; i++)
						*p++ = name[i];

					if (*s == '.')
						n++;

					name += n;
					name_len -= n;

				} while (*s);

				*p++ = 0;
				*p++ = 0;
				*p++ = (uint8_t)q->qtype;

				*p++ = 0;
				*p++ = 1;

				assert(p < pkt + sizeof(pkt) - LWS_PRE);
				n = lws_ptr_diff(p, pkt + LWS_PRE);

				fd = lws_get_socket_fd(wsi);
				if (fd < 0)
					break;

				m = send(fd, pkt + LWS_PRE, n, 0);
				if (m != n) {
					lwsl_notice("%s: dns write failed %d %d\n",
							__func__, m, n);
					lws_async_dns_done(q, NULL,
							   LADNS_RET_FAILED);
					lws_adns_q_destroy(q);
				} else
					q->sent = 1;
				did = 1;
			}
		} lws_end_foreach_dll_safe(d, d1);
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols lws_async_dns_protocol = {
	"lws-async-dns", callback_async_dns, 0, 0
};

int
lws_async_dns_init(struct lws_context *context)
{
	char ads[20];
	uint32_t be;
	int n;

	memset(&context->async_dns.sa, 0, sizeof(context->async_dns.sa));

	n = lws_plat_asyncdns_init(context, &context->async_dns.sa);
	if (n < 0) {
		lwsl_warn("%s: no valid dns server, retry\n", __func__);

		return 1;
	}

	be = ntohl(context->async_dns.sa.sin_addr.s_addr);

	context->async_dns.sa.sin_family = AF_INET;
	context->async_dns.sa.sin_port = htons(53);
	lws_snprintf(ads, sizeof(ads), "%u.%u.%u.%u",
			(uint8_t)(be >> 24),
			(uint8_t)(be >> 16),
			(uint8_t)(be >> 8),
			(uint8_t)be);
	context->async_dns.wsi = lws_create_adopt_udp(context->vhost_list, ads,
				       53, 0, lws_async_dns_protocol.name, NULL);
	if (!context->async_dns.wsi) {
		lwsl_err("%s: foreign socket adoption failed\n", __func__);
		return 1;
	}

	context->async_dns.dns_server_set = 1;

	return 0;
}

static int
clean(struct lws_dll2 *d, void *user)
{
	lws_adns_q_destroy(lws_container_of(d, lws_adns_q_t, list));

	return 0;
}

void
lws_async_dns_deinit(lws_async_dns_t *dns)
{
	lws_dll2_foreach_safe(&dns->active, NULL, clean);
	lws_dll2_foreach_safe(&dns->cached, NULL, clean);
}

void
lws_async_dns_cancel(struct lws *wsi)
{
	lws_async_dns_t *dns = &wsi->context->async_dns;
	struct lws *w;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->active)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, d3, d4,
					   lws_dll2_get_head(&q->wsi_adns)) {
			w = lws_container_of(d3, struct lws, adns);

			if (wsi == w) {
				lws_dll2_remove(d3);
				if (!q->wsi_adns.count)
					lws_adns_q_destroy(q);
				return;
			}
		} lws_end_foreach_dll_safe(d3, d4);

	} lws_end_foreach_dll_safe(d, d1);
}

lws_async_dns_retcode_t
lws_async_dns_query(struct lws_context *context, int tsi, const char *name,
		    adns_query_type_t qtype, lws_async_dns_cb_t cb,
		    struct lws *wsi, void *opaque)
{
	lws_async_dns_t *dns = &context->async_dns;
	size_t nlen = strlen(name);
	uint8_t ads[16];
	lws_adns_q_t *q;
	char *p;
	int m;

	/*
	 * It's a 1.2.3.4 type IP address already?  We don't need a dns
	 * server set up to be able to return that...
	 */

	m = lws_parse_numeric_address(name, ads, sizeof(ads));
	if (m == 4) {
		struct sockaddr_in sai;
		struct addrinfo ai;
		size_t addrlen = sizeof(struct sockaddr_in);

		memset(&sai, 0, sizeof sai);
		memset(&ai, 0, sizeof ai);

		ai.ai_flags = 0;
		ai.ai_family = AF_INET;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol = 0;
		ai.ai_addrlen = addrlen;
		ai.ai_addr = (struct sockaddr *)&sai;
		sai.sin_family = AF_INET;
		sai.sin_port = 0;
		memcpy(&sai.sin_addr, ads, sizeof(sai.sin_addr));
		ai.ai_canonname = (char *)name;

		cb(wsi, name, &ai, 0, opaque);

		return LADNS_RET_FOUND;
	}

#if defined(LWS_WITH_IPV6)
	if (m == 16) {
		struct sockaddr_in6 sai;
		struct addrinfo ai;
		size_t addrlen = sizeof(struct sockaddr_in6);

		memset(&sai, 0, sizeof sai);
		memset(&ai, 0, sizeof ai);

		ai.ai_flags = 0;
		ai.ai_family = AF_INET;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol = 0;
		ai.ai_addrlen = addrlen;
		ai.ai_addr = (struct sockaddr *)&sai;
		sai.sin6_family = AF_INET6;
		sai.sin6_port = 0;
		memcpy(&sai.sin_addr, ads, sizeof(sai.sin_addr));
		ai.ai_canonname = (char *)name;

		cb(wsi, name, &ai, 0, opaque);

		return LADNS_RET_FOUND;
	}
#endif

	if (wsi)
		wsi->adns_cb = cb;

	/*
	 * we magically know 'localhost'
	 */

	if (!strcmp(name, q_localhost.n)) {
		if (lws_async_dns_done(&q_localhost.q, wsi, LADNS_RET_FOUND))
			return LADNS_RET_FAILED_WSI_CLOSED;
		return LADNS_RET_FOUND;
	}

#if defined(LWS_WITH_IPV6)
	if (!strcmp(name, q_localhost6.n)) {
		if (lws_async_dns_done(&q_localhost6.q, wsi, LADNS_RET_FOUND))
			return LADNS_RET_FAILED_WSI_CLOSED;
		return LADNS_RET_FOUND;
	}
#endif

	/*
	 * to try anything else we need a remote server configured...
	 */

	if (!context->async_dns.dns_server_set &&
	    lws_async_dns_init(context)) {
		lwsl_notice("%s: init failed\n", __func__);
		return LADNS_RET_FAILED;
	}

	/* there's a done, cached query we can just reuse? */

	q = lws_adns_get_query(dns, qtype, &dns->cached, 0, name);
	if (q) {
		lwsl_debug("%s: reusing cached result\n", __func__);
		if (lws_async_dns_done(q, wsi, q->ret))
			return LADNS_RET_FAILED_WSI_CLOSED;
		return LADNS_RET_FOUND;
	}

	/* there's an ongoing query we can share the result of */

	q = lws_adns_get_query(dns, qtype, &dns->active, 0, name);
	if (q) {
		lwsl_debug("%s: dns piggybacking: %d:%s\n", __func__,
				qtype, name);
		if (wsi)
			lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

		return LADNS_RET_CONTINUING;
	}

	/* Allocate new query */

	q = (lws_adns_q_t *)lws_zalloc(sizeof(*q) + nlen + 1, __func__);
	if (!q) {
		cb(wsi, NULL, NULL, LADNS_RET_FAILED, opaque);

		return LADNS_RET_FAILED;
	}

	if (wsi)
		lws_dll2_add_head(&wsi->adns, &q->wsi_adns);
	q->qtype = (uint16_t)qtype;
	q->tid = ++dns->tid;
	q->context = context;
	q->tsi = tsi;
	q->opaque = opaque;

	if (!wsi)
		q->standalone_cb = cb;

	lws_sul_schedule(context, tsi, &q->sul, sul_cb_timeout,
			 lws_now_usecs() +
			 (DNS_QUERY_TIMEOUT * LWS_US_PER_SEC));

	p = (char *)&q[1];
	while (nlen--)
		*p++ = tolower(*name++);
	*p = '\0';

	lws_callback_on_writable(dns->wsi);

	lws_dll2_add_head(&q->list, &dns->active);

	lwsl_debug("%s: created new query\n", __func__);

	return LADNS_RET_CONTINUING;
}
