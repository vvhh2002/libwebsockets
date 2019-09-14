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

#include "private-lib-core.h"
#include "private-lib-async-dns.h"

static void
sul_cb_expire(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	lws_adns_q_destroy(q);
}

/* updates *dest, returns chars used from ls directly, else -1 for fail */

static int
lws_adns_parse_label(const uint8_t *pkt, int len, const uint8_t *ls, int budget,
		     char **dest, int dl)
{
	const uint8_t *e = pkt + len, *ols = ls;
	char pointer = 0, first = 1;
	uint8_t ll;
	int n;

	if (budget < 1)
		return 0;

	/* caller must catch end of labels */
	assert(*ls);

again1:
	if (ls >= e)
		return -1;

	if (((*ls) & 0xc0) == 0xc0) {
		if (budget < 2)
			return -1;
		/* pointer into message pkt to name to actually use */
		n = lws_ser_ru16be(ls) & 0x3fff;
		if (n >= len) {
			lwsl_notice("%s: illegal name pointer\n", __func__);

			return -1;
		}

		/* dereference the label pointer */
		ls = pkt + n;

		/* are we being fuzzed or messed with? */
		if (((*ls) & 0xc0) == 0xc0) {
			/* ... pointer to pointer is unreasonable */
			lwsl_notice("%s: label ptr to ptr invalid\n", __func__);

			return -1;
		}
		pointer = 1;
	}

again:
	if (ls >= e)
		return -1;
	ll = *ls++;
	if (ls + ll + 4 > e || ll > budget) {
		lwsl_notice("%s: label len invalid\n", __func__);

		return -1;
	}

	if (ll + 2 > dl) {
		lwsl_notice("%s: qname too large\n", __func__);

		return -1;
	}

	/* copy the label content into place */

	memcpy(*dest, ls, ll);
	(*dest)[ll] = '.';
	(*dest)[ll + 1] = '\0';
	*dest += ll + 1;
	ls += ll;

	if (pointer) {
		if (*ls)
			goto again;

		/*
		 * special fun rule... if whole qname was a pointer label,
		 * it has no 00 terminator afterwards
		 */
		if (first)
			return 2; /* we just took the 16-bit pointer */

		return 3;
	}

	first = 0;

	if (*ls)
		goto again1;

	ls++;

	return ls - ols;
}

/* locally query the response packet */

struct label_stack {
	char name[64];
	int enl;
	const uint8_t *p;
};

/*
 * Able to recurse without stack recursion to resolve CNAME usages
 *
 * Return -1: unexpectedly failed
 *         0: found
 *         1: didn't find anything matching
 */

static int
lws_adns_find(const uint8_t *pkt, int len, uint16_t qtype, const char *expname,
	      uint32_t *ttl, uint8_t *result)
{
	struct label_stack stack[4];
	const uint8_t *e = pkt + len, *p, *pay;
	uint16_t rrtype, rrpaylen;
	int n = 0, stp = 0, ansc;
	char *sp, inq;

	lws_strncpy(stack[stp].name, expname, sizeof(stack[stp].name));
	stack[stp].enl = strlen(expname);

start:
	ansc = lws_ser_ru16be(pkt + DHO_NANSWERS);
	p = pkt + DHO_SIZEOF;
	inq = 1;

	/*
	 * The response also includes the query... and we have to parse it
	 * so we can understand we reached the response... there's a QNAME
	 * made up of labels and then 2 x 16-bit fields, for query type and
	 * query class
	 */

resume:
	while (p + 14 < e && (inq || ansc)) {

		if (!inq)
			ansc--;

		/*
		 * First is the name the query applies to... two main
		 * formats can appear here, one is a pointer to
		 * elsewhere in the message, the other separately
		 * provides len / data for each dotted "label", so for
		 * "warmcat.com" warmcat and com are given each with a
		 * prepended length byte.  Any of those may be a pointer
		 * to somewhere else in the packet :-/
		 *
		 * Paranoia is appropriate since the name length must be
		 * parsed out before the rest of the RR can be used and
		 * we can be attacked with absolutely any crafted
		 * content easily via UDP.
		 *
		 * So parse the name and additionally confirm it matches
		 * what the query the TID belongs to actually asked for.
		 */

		sp = stack[0].name;

		/* while we have more labels */

		n = lws_adns_parse_label(pkt, len, p, len, &sp,
					 sizeof(stack[0].name) -
					 lws_ptr_diff(sp, stack[0].name));
		/* includes case name won't fit */
		if (n < 0)
			return -1;

		p += n;

		if (p + (inq ? 5 : 14) > e)
			return -1;

		/* p is now just after the decoded RR name, pointing at: type */

		if (!inq) {
			lwsl_debug("%s: RR name '%s', type 0x%x\n", __func__,
				stack[0].name, lws_ser_ru16be(&p[0]));
		}

		/* sent class = 1 = IN query... response must match */

		if (lws_ser_ru16be(&p[2]) != 1) {
			lwsl_debug("%s: non-IN response 0x%x\n", __func__,
						lws_ser_ru16be(&p[2]));

			return -1;
		}

		if (inq) {
			lwsl_debug("%s: reached end of inq\n", __func__);
			inq = 0;
			p += 4;
			continue;
		}

		/* carefully validate the claimed RR payload length */

		rrpaylen = lws_ser_ru16be(&p[8]);
		if (p + 10 + rrpaylen > e) { /* it may be == e */
			lwsl_notice("%s: invalid RR data length\n", __func__);

			return -1;
		}

		*ttl = lws_ser_ru32be(&p[4]);

		rrtype = lws_ser_ru16be(&p[0]);
		p += 10; /* point to the payload */
		pay = p;

		/*
		 * Compare the RR names, allowing for the decoded labelname
		 * to have an extra '.' at the end.
		 */

		n = lws_ptr_diff(sp, stack[0].name);
		if (stack[0].name[n - 1] == '.')
			n--;

		if (n < 1 || n != stack[stp].enl ||
		    strcmp(stack[0].name, stack[stp].name)) {
			lwsl_debug("%s: skipping %s vs %s\n", __func__,
					stack[0].name, stack[stp].name);
			goto skip;
		}

		/*
		 * It's something we could be interested in...
		 *
		 * We can skip RRs we don't understand.  But we need to deal
		 * with at least these and their payloads:
		 *
		 *    A:      4: ipv4 address
		 *    AAAA:  16: ipv6 address (if asked for AAAA)
		 *    CNAME:  ?: labelized name
		 *
		 * If we hit a CNAME we need to try to dereference it with
		 * stuff that is in the same response packet and judge it
		 * from that, without losing our place here.  CNAMEs may
		 * point to CNAMEs to whatever depth we're willing to handle.
		 */

		switch (rrtype) {
		case LWS_ADNS_RECORD_A:
			if (rrpaylen != 4)
				return -1;
			lwsl_debug("%s: seen A\n", __func__);
			if (qtype == LWS_ADNS_RECORD_A) {
				memcpy(result, pay, 4);

				return 0;
			}
			break;
		case LWS_ADNS_RECORD_AAAA:
			if (rrpaylen != 16)
				return -1;
			if (qtype == LWS_ADNS_RECORD_AAAA) {
				memcpy(result, pay, 16);

				return 0;
			}
			break;
		case LWS_ADNS_RECORD_CNAME:
			/*
			 * The name the CNAME refers to should itself be
			 * included elsewhere in the response packet.
			 *
			 * So switch tack, stack where to resume from and
			 * search for the decoded CNAME label name definition
			 * instead.
			 *
			 * First decode the CNAME label payload into the next
			 * stack level buffer for it.
			 */

			if (++stp == (int)LWS_ARRAY_SIZE(stack)) {
				lwsl_notice("%s: CNAMEs too deep\n", __func__);

				return -1;
			}
			sp = stack[stp].name;
			n = lws_adns_parse_label(pkt, len, p, rrpaylen, &sp,
						 sizeof(stack[stp].name) -
						 lws_ptr_diff(sp, stack[stp].name));
			/* includes case name won't fit */
			if (n < 0)
				return -1;

			p += n;

			if (p + 14 > e)
				return -1;

			/* it should have exactly reached rrpaylen */

			if (p != pay + rrpaylen) {
				lwsl_err("%s: cname name bad len\n", __func__);

				return -1;
			}

			stack[stp].enl = lws_ptr_diff(sp, stack[stp].name);
			/* when we unstack, resume from here */
			stack[stp].p = pay + rrpaylen;
			goto start;

		default:
			break;
		}

skip:
		p += rrpaylen;
	}

	if (!stp)
		return 1; /* we didn't find anything, but we didn't error */

	/*
	 * This implies there wasn't any usable definition for the
	 * CNAME in the end, eg, only AAAA when we needed and A.
	 *
	 * Short-circuit the whole stack and resume from after the
	 * original CNAME reference.
	 */
	p = stack[1].p;
	stp = 0;
	goto resume;
}


/*
 * If asked for A, return the first A.
 *
 * If asked for AAAA, return the first AAAA if any, but if none, return first
 * A in ipv6 form
 */

void
lws_adns_parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, size_t len)
{
	lws_async_dns_retcode_t ret;
	lws_adns_q_t *q, *qc;
	const char *nm;
	uint32_t ttl;
	int n;

	// lwsl_hexdump_notice(pkt, len);

	/* we have to at least have the header */

	if (len < DHO_SIZEOF)
		return;


	if (lws_ser_ru16be(pkt + DHO_NQUERIES) != 1)
		return;

	q = lws_adns_get_query(dns, 0, &dns->active,
			       lws_ser_ru16be(pkt + DHO_TID), NULL);
	if (!q) {
		lwsl_notice("%s: dropping unknown query\n", __func__);

		return;
	}

	nm = (const char *)&q[1];
	qc = lws_adns_get_query(dns, q->qtype, &dns->cached, 0, nm);
	if (qc) {
		lwsl_debug("%s: finishing with already cached\n", __func__);
		lws_async_dns_done(q, NULL, qc->ret);
		lws_adns_q_destroy(q);
		return;
	}

	/* If no answers, the domain doesn't exist */

	if (!lws_ser_ru16be(pkt + DHO_NANSWERS)) {
		q->addrlen = 0;

		lwsl_debug("%s: nxdomain, no answers\n", __func__);
		ret = LADNS_RET_NXDOMAIN;
		goto save_for_ttl;
	}

	if (q->qtype == LWS_ADNS_RECORD_AAAA &&
	    !lws_adns_find(pkt, len, LWS_ADNS_RECORD_AAAA, nm, &ttl, q->addr)) {
		/* we did get the desired AAAA as the result */
		q->addrlen = 16;
		goto okay;
	}

	n = lws_adns_find(pkt, len, LWS_ADNS_RECORD_A, nm, &ttl, q->addr);
	lwsl_debug("%s: find A: %d\n", __func__, n);
	if (!n) {
		/* we found an A */
		if (q->qtype == LWS_ADNS_RECORD_AAAA) {
			/* he really wanted ipv6, promote it to encap ipv4 */

			q->addr[12] = q->addr[0];
			q->addr[13] = q->addr[1];
			q->addr[14] = q->addr[2];
			q->addr[15] = q->addr[3];
			memset(q->addr, 0, 10);
			q->addr[10] = 0xff;
			q->addr[11] = 0xff;

			q->addrlen = 16;
			goto okay;
		}

		if (q->qtype == LWS_ADNS_RECORD_A) {
			q->addrlen = 4;
			goto okay;
		}
	}

	/* no usable result */

	lwsl_debug("%s: nxdomain, nothing usable\n", __func__);
	ret = LADNS_RET_NXDOMAIN;
	goto save_for_ttl;

okay:

	/* Add to the cache */

//	if (q->wsi_adns.count) {
//	w = lws_container_of(lws_dll2_get_head(&q->wsi_adns), struct lws, adns);
	lws_sul_schedule(q->context, 0, &q->sul, sul_cb_expire,
			 lws_now_usecs() + (ttl * LWS_US_PER_SEC));

	ret = LADNS_RET_FOUND;

save_for_ttl:
	lws_dll2_remove(&q->list);
	lws_dll2_add_head(&q->list, &dns->cached);

	lws_async_dns_done(q, NULL, ret);

	if (dns->cached.count >= MAX_CACHE_ENTRIES) {
		q = lws_container_of(lws_dll2_get_tail(&dns->cached),
					 lws_adns_q_t, list);
		lws_adns_q_destroy(q);
	}
}

