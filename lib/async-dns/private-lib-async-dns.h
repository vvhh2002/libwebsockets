/*
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


#define	DNS_MAX			128	/* Maximum host name		*/
#define	DNS_PACKET_LEN		1400	/* Buffer size for DNS packet	*/
#define	MAX_CACHE_ENTRIES	10	/* Dont cache more than that	*/
#define	DNS_QUERY_TIMEOUT	30	/* Query timeout, seconds	*/

typedef struct {
	uint8_t			addr[64];
	lws_sorted_usec_list_t	sul;
	lws_dll2_t		list;
	lws_dll2_owner_t	wsi_adns;
	lws_async_dns_cb_t	standalone_cb;	/* if not associated to wsi */
	struct lws_context	*context;
	void			*opaque;
	size_t			addrlen;
	lws_async_dns_retcode_t	ret;
	uint16_t		tid;
	uint16_t		qtype;
	char			sent;
	uint8_t			tsi;

	/* name overallocated here */
} lws_adns_q_t;

enum {
	DHO_TID,
	DHO_FLAGS = 2,
	DHO_NQUERIES = 4,
	DHO_NANSWERS = 6,
	DHO_NAUTH = 8,
	DHO_NOTHER = 10,

	DHO_SIZEOF = 12 /* last */
};

void
lws_adns_q_destroy(lws_adns_q_t *q);

int
lws_async_dns_done(lws_adns_q_t *q, struct lws *wsi, lws_async_dns_retcode_t r);

void
lws_adns_parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, size_t len);

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   lws_dll2_owner_t *owner, uint16_t tid, const char *name);
