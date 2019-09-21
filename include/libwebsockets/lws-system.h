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
 *
 * This provides a clean way to interface lws user code to be able to
 * work unchanged on different systems for fetching common system information,
 * and performing common system operations like reboot.
 *
 * An ops struct with the system-specific implementations is set at
 * context creation time, and apis are provided that call through to
 * those where they exist.
 */

typedef enum {
	LWS_SYSI_HRS_DEVICE_MODEL = 1,
	LWS_SYSI_HRS_DEVICE_SERIAL,
	LWS_SYSI_HRS_FIRMWARE_VERSION,

	LWS_SYSI_USER_BASE = 100
} lws_system_item_t;

typedef union {
	const char	*hrs;	/* human readable string */
	void		*data;
	time_t		t;
} lws_system_arg_t;

/*
 * Lws view of system state... normal operation from user code perspective is
 * dependent on implicit (eg, knowing the date for cert validation) and
 * explicit dependencies.
 *
 * Bit of lws and user code can register notification handlers that can enforce
 * dependent operations before state transitions can complete.
 */

typedef enum {
	LWS_SYSTATE_CONTEXT_CREATED = 8, /* context was just created */
	LWS_SYSTATE_INITIALIZED = 16,	 /* protocols initialized.  Lws itself
					  * can operate normally */
	LWS_SYSTATE_TIME_VALID = 24,	 /* ntpclient ran, or hw time valid...
					  * tls cannot work until we reach here
					  */
	LWS_SYSTATE_POLICY_VALID = 32,	 /* user code knows how to operate... it
					  * can set up prerequisites */
	LWS_SYSTATE_OPERATIONAL = 40,	 /* user code can operate normally */

	LWS_SYSTATE_POLICY_INVALID = 48, /* user code is changing its policies
					  * drop everything done with old
					  * policy, switch to new then enter
					  * LWS_SYSTATE_POLICY_VALID */
} lws_system_states_t;

typedef int (*lws_system_notify_t)(struct lws_context *context,
				   lws_system_states_t current,
				   lws_system_states_t target);

typedef struct lws_system_notify_link {
	lws_dll2_t		list;
	lws_system_notify_t	notify_cb;
	lws_system_states_t	objected;
} lws_system_notify_link_t;

typedef struct lws_system_ops {
	int (*get_info)(lws_system_item_t i, lws_system_arg_t arg, size_t *len);
	int (*reboot)(void);
	int (*set_clock)(lws_usec_t us);
} lws_system_ops_t;

/**
 * lws_system_reg_notifier() - add dep handler for system state notifications
 *
 * \param context: the lws_context
 * \param notify_link: the handler to add to the notifier linked-list
 *
 * Add \p notify_link to the context's list of notification handlers for system
 * state changes.  The handlers can defeat or take over responsibility for
 * retrying the change after they have initiated some dependency.
 */

LWS_EXTERN LWS_VISIBLE void
lws_system_reg_notifier(struct lws_context *context,
			lws_system_notify_link_t *notify_link);

/**
 * lws_system_try_state_transition() - move to state via starting any deps
 *
 * \param context: the lws_context
 * \param target: the state we wish to move to
 *
 * If there is nothing on the notify list, this simply moves to the target
 * state.  If there are notify functions but all return 0 when queried about the
 * change, again the context just moves to the target state.
 *
 * However if any notified function recognizes the requested state is dependent
 * on it having done something, it can stop the change by returning nonzero, and
 * take on responsibility for retrying the change when it has succeeded to do
 * whatever its dependency is.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_try_state_transition(struct lws_context *context,
				lws_system_states_t target);


LWS_EXTERN LWS_VISIBLE lws_system_states_t
lws_system_state(struct lws_context *context);

/* wrappers handle NULL members or no ops struct set at all cleanly */

/**
 * lws_system_get_info() - get standardized system information
 *
 * \param context: the lws_context
 * \param item: which information to fetch
 * \param arg: where to place the result
 * \param len: incoming: max length of result, outgoing: used length of result
 *
 * This queries a standardized information-fetching ops struct that can be
 * applied to the context... the advantage is it allows you to get common items
 * of information like a device serial number writing the code once, even if the
 * actual serial number muse be fetched in wildly different ways depending on
 * the exact platform it's running on.
 *
 * Set arg and *len on entry to be the result location and the max length that
 * can be used there, on seccessful exit *len is set to the actual length and
 * 0 is returned.  On error, 1 is returned.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_get_info(struct lws_context *context, lws_system_item_t item,
		    lws_system_arg_t arg, size_t *len);


/**
 * lws_system_reboot() - if provided, use the lws_system ops to reboot
 *
 * \param context: the lws_context
 *
 * If possible, the system will reboot.  Otherwise returns 1.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_reboot(struct lws_context *context);
