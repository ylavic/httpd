/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * http_request.c: functions to get and process requests
 *
 * Rob McCool 3/21/93
 *
 * Thoroughly revamped by rst for Apache.  NB this file reads
 * best from the bottom up.
 *
 */

#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "http_connection.h"
#include "mpm_common.h"
#include "util_filter.h"
#include "util_charset.h"
#include "scoreboard.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif

APLOG_USE_MODULE(http);

/*****************************************************************
 *
 * Mainline request processing...
 */

/* XXX A cleaner and faster way to do this might be to pass the request_rec
 * down the filter chain as a parameter.  It would need to change for
 * subrequest vs. main request filters; perhaps the subrequest filter could
 * make the switch.
 */
static void update_r_in_filters(ap_filter_t *f,
                                request_rec *from,
                                request_rec *to)
{
    while (f) {
        if (f->r == from) {
            f->r = to;
        }
        f = f->next;
    }
}

static void ap_die_r(int type, request_rec *r, int recursive_error)
{
    char *custom_response;
    request_rec *r_1st_err = r;

    if (type == OK || type == DONE) {
        ap_finalize_request_protocol(r);
        return;
    }

    /*
     * if we have already passed the final response down the
     * output filter chain, we cannot generate a second final
     * response here.
     */
    if (r->final_resp_passed) {
        return;
    }

    if (!ap_is_HTTP_VALID_RESPONSE(type)) {
        if (type != AP_FILTER_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01579)
                          "Invalid response status %i", type);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02831)
                          "Response from AP_FILTER_ERROR");
        }
        type = HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * The following takes care of Apache redirects to custom response URLs
     * Note that if we are already dealing with the response to some other
     * error condition, we just report on the original error, and give up on
     * any attempt to handle the other thing "intelligently"...
     */
    if (recursive_error != HTTP_OK) {
        while (r_1st_err->prev && (r_1st_err->prev->status != HTTP_OK))
            r_1st_err = r_1st_err->prev;  /* Get back to original error */

        if (r_1st_err != r) {
            /* The recursive error was caused by an ErrorDocument specifying
             * an internal redirect to a bad URI.  ap_internal_redirect has
             * changed the filter chains to point to the ErrorDocument's
             * request_rec.  Back out those changes so we can safely use the
             * original failing request_rec to send the canned error message.
             *
             * ap_send_error_response gets rid of existing resource filters
             * on the output side, so we can skip those.
             */
            update_r_in_filters(r_1st_err->proto_output_filters, r, r_1st_err);
            update_r_in_filters(r_1st_err->input_filters, r, r_1st_err);
            recursive_error = type;
        }

        custom_response = NULL; /* Do NOT retry the custom thing! */
    }
    else {
        int error_index = ap_index_of_response(type);
        custom_response = ap_response_code_string(r, error_index);
        recursive_error = 0;
    }

    r->status = type;

    /*
     * This test is done here so that none of the auth modules needs to know
     * about proxy authentication.  They treat it like normal auth, and then
     * we tweak the status.
     */
    if (HTTP_UNAUTHORIZED == r->status && PROXYREQ_PROXY == r->proxyreq) {
        r->status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
    }

    /* If we don't want to keep the connection, make sure we mark that the
     * connection is not eligible for keepalive.  If we want to keep the
     * connection, be sure that the request body (if any) has been read.
     */
    if (ap_status_drops_connection(r->status)) {
        r->connection->keepalive = AP_CONN_CLOSE;
    }

    /*
     * Two types of custom redirects --- plain text, and URLs. Plain text has
     * a leading '"', so the URL code, here, is triggered on its absence
     */

    if (custom_response && custom_response[0] != '"') {

        if (ap_is_url(custom_response)) {
            /*
             * The URL isn't local, so lets drop through the rest of this
             * apache code, and continue with the usual REDIRECT handler.
             * But note that the client will ultimately see the wrong
             * status...
             */
            r->status = HTTP_MOVED_TEMPORARILY;
            apr_table_setn(r->headers_out, "Location", custom_response);
        }
        else if (custom_response[0] == '/') {
            const char *error_notes, *original_method;
            int original_method_number;
            r->no_local_copy = 1;       /* Do NOT send HTTP_NOT_MODIFIED for
                                         * error documents! */
            /*
             * This redirect needs to be a GET no matter what the original
             * method was.
             */
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);

            /*
             * Provide a special method for modules to communicate
             * more informative (than the plain canned) messages to us.
             * Propagate them to ErrorDocuments via the ERROR_NOTES variable:
             */
            if ((error_notes = apr_table_get(r->notes,
                                             "error-notes")) != NULL) {
                apr_table_setn(r->subprocess_env, "ERROR_NOTES", error_notes);
            }
            original_method = r->method;
            original_method_number = r->method_number;
            r->method = "GET";
            r->method_number = M_GET;
            ap_internal_redirect(custom_response, r);
            /* preserve ability to see %<m in the access log */
            r->method = original_method;
            r->method_number = original_method_number;
            return;
        }
        else {
            /*
             * Dumb user has given us a bad url to redirect to --- fake up
             * dying with a recursive server error...
             */
            recursive_error = HTTP_INTERNAL_SERVER_ERROR;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01580)
                        "Invalid error redirection directive: %s",
                        custom_response);
        }
    }
    ap_send_error_response(r_1st_err, recursive_error);
}

AP_DECLARE(void) ap_die(int type, request_rec *r)
{
    ap_die_r(type, r, r->status);
}

AP_DECLARE(apr_status_t) ap_check_pipeline(conn_rec *c, apr_bucket_brigade *bb,
                                           unsigned int max_blank_lines)
{
    apr_status_t rv = APR_EOF;
    ap_input_mode_t mode = AP_MODE_SPECULATIVE;
    unsigned int num_blank_lines = 0;
    apr_size_t cr = 0;
    char buf[2];

    while (c->keepalive != AP_CONN_CLOSE && !c->aborted) {
        apr_size_t len = cr + 1;

        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c->input_filters, bb, mode,
                            APR_NONBLOCK_READ, len);
        if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
            if (mode == AP_MODE_READBYTES) {
                /* Unexpected error, stop with this connection */
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c, APLOGNO(02967)
                              "Can't consume pipelined empty lines");
                c->keepalive = AP_CONN_CLOSE;
                rv = APR_EGENERAL;
            }
            else if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
                /* Pipe is dead */
                c->keepalive = AP_CONN_CLOSE;
            }
            else {
                /* Pipe is up and empty */
                rv = APR_EAGAIN;
            }
            break;
        }
        if (!max_blank_lines) {
            apr_off_t n = 0;
            /* Single read asked, (non-meta-)data available? */
            rv = apr_brigade_length(bb, 0, &n);
            if (rv == APR_SUCCESS && n <= 0) {
                rv = APR_EAGAIN;
            }
            break;
        }

        /* Lookup and consume blank lines */
        rv = apr_brigade_flatten(bb, buf, &len);
        if (rv != APR_SUCCESS || len != cr + 1) {
            int log_level;
            if (mode == AP_MODE_READBYTES) {
                /* Unexpected error, stop with this connection */
                c->keepalive = AP_CONN_CLOSE;
                log_level = APLOG_ERR;
                rv = APR_EGENERAL;
            }
            else {
                /* Let outside (non-speculative/blocking) read determine
                 * where this possible failure comes from (metadata,
                 * morphed EOF socket, ...). Debug only here.
                 */
                log_level = APLOG_DEBUG;
                rv = APR_SUCCESS;
            }
            ap_log_cerror(APLOG_MARK, log_level, rv, c, APLOGNO(02968)
                          "Can't check pipelined data");
            break;
        }

        if (mode == AP_MODE_READBYTES) {
            /* [CR]LF consumed, try next */
            mode = AP_MODE_SPECULATIVE;
            cr = 0;
        }
        else if (cr) {
            AP_DEBUG_ASSERT(len == 2 && buf[0] == APR_ASCII_CR);
            if (buf[1] == APR_ASCII_LF) {
                /* consume this CRLF */
                mode = AP_MODE_READBYTES;
                num_blank_lines++;
            }
            else {
                /* CR(?!LF) is data */
                break;
            }
        }
        else {
            if (buf[0] == APR_ASCII_LF) {
                /* consume this LF */
                mode = AP_MODE_READBYTES;
                num_blank_lines++;
            }
            else if (buf[0] == APR_ASCII_CR) {
                cr = 1;
            }
            else {
                /* Not [CR]LF, some data */
                break;
            }
        }
        if (num_blank_lines > max_blank_lines) {
            /* Enough blank lines with this connection,
             * stop and don't recycle it.
             */
            c->keepalive = AP_CONN_CLOSE;
            rv = APR_NOTFOUND;
            break;
        }
    }

    return rv;
}

AP_DECLARE(void) ap_process_request_after_handler(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    conn_rec *c = r->connection;

    bb = ap_acquire_brigade(c);

    /* Send an EOR bucket through the output filter chain.  When
     * this bucket is destroyed, the request will be logged and
     * its pool will be freed
     */
    b = ap_bucket_eor_create(c->bucket_alloc, r);
    APR_BRIGADE_INSERT_HEAD(bb, b);

    /* Find the last request, taking into account internal
     * redirects. We want to send the EOR bucket at the end of
     * all the buckets so it does not jump the queue.
     */
    while (r->next) {
        r = r->next;
    }

    /* All the request filters should have bailed out on EOS, and in any
     * case they shouldn't have to handle this EOR which will destroy the
     * request underneath them. So go straight to the connection filters.
     */
    ap_pass_brigade(c->output_filters, bb);

    /* The EOR bucket has either been handled by an output filter (eg.
     * deleted or moved to a buffered_bb => no more in bb), or an error
     * occurred before that (eg. c->aborted => still in bb) and we ought
     * to destroy it now. So cleanup any remaining bucket along with
     * the orphan request (if any).
     */
    apr_brigade_cleanup(bb);

    /* From here onward, it is no longer safe to reference r
     * or r->pool, because r->pool may have been destroyed
     * already by the EOR bucket's cleanup function.
     */

    /* Check pipeline consuming blank lines, they must not be interpreted as
     * the next pipelined request, otherwise we would block on the next read
     * without flushing data, and hence possibly delay pending response(s)
     * until the next/real request comes in or the keepalive timeout expires.
     */
    (void)ap_check_pipeline(c, bb, DEFAULT_LIMIT_BLANK_LINES);

    ap_release_brigade(c, bb);

    if (c->cs) {
        if (c->aborted) {
            c->cs->state = CONN_STATE_LINGER;
        }
        else {
            /* If we have still data in the output filters here it means that
             * the last (recent) nonblocking write was EAGAIN, so tell the MPM
             * to not try another useless/stressful one but to go straight to
             * POLLOUT.
            */
            c->cs->state = CONN_STATE_WRITE_COMPLETION;
        }
    }
    AP_PROCESS_REQUEST_RETURN((uintptr_t)r, r->uri, r->status);
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, STOP_PREQUEST);
    }
}

/* Whether the MPM can wait for requests (AP_MPMQ_CAN_REGISTER_WAIT), set by
 * ap_request_async_post_config()
 */
static int request_can_wait = 0;

AP_CORE_DECLARE(void) ap_request_async_post_config(apr_pool_t *ptemp,
                                                   server_rec *s)
{
    apr_array_header_t *timeouts;

    if (ap_mpm_query(AP_MPMQ_CAN_REGISTER_WAIT, &request_can_wait)
            != APR_SUCCESS) {
        request_can_wait = 0;
    }
    if (!request_can_wait) {
        return;
    }

    /* The servers' Timeout, the default of the waits for the client's output
     * and of the waits for other targets (AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT),
     * declared to the MPM (which ignores the duplicates)
     */
    timeouts = apr_array_make(ptemp, 4, sizeof(apr_interval_time_t));
    for (; s; s = s->next) {
        APR_ARRAY_PUSH(timeouts, apr_interval_time_t) = s->timeout;
    }
    (void)ap_mpm_register_timeouts(timeouts);
}

/* The asynchronous state of r, if it's the top-level request it was made for
 * (ap_process_async_request()), else NULL
 */
static ap_request_async_t *request_async_get(request_rec *r)
{
    core_request_config *req_cfg = ap_get_core_module_config(r->request_config);
    ap_request_async_t *async = (req_cfg) ? req_cfg->async : NULL;

    return (async && async->r == r) ? async : NULL;
}

AP_DECLARE(int) ap_request_can_suspend(request_rec *r)
{
    ap_request_async_t *async;

    if (!request_can_wait || r->main || r->prev || r->connection->master) {
        return 0;
    }
    async = request_async_get(r);
    return (async && async->phase == AP_REQUEST_PHASE_HANDLER);
}

/*
 * Requests' waits (ap_request_wait()): a wait context per target, the state
 * of the request's waits in its ap_request_async_t.
 */

/* The kinds of targets */
typedef enum {
    REQUEST_WAITCTX_CLIENT,
    REQUEST_WAITCTX_TIMER
} request_waitctx_kind_e;

/* Their names in the logs */
static const char *const request_waitctx_kind_names[] = {
    "client", "timer"
};

/* The state of a context's waits in a direction */
typedef struct {
    int waits;         /* registered so far, the next ones keep the pfd */
    int pending_ready; /* answered OK for the filters' pending input, see
                        * request_waitctx_check_ready() */
} request_waitctx_dir_t;

/* A wait context: the public part first */
typedef struct {
    ap_request_waitctx_t pub;
    request_waitctx_kind_e kind;
    apr_pool_t *pool;             /* allocated from (the constructor's) */
    conn_rec *c;                  /* whose filters are checked, if any */
    apr_pollfd_t pfd;             /* the target's descriptor, if any */
    request_waitctx_dir_t dirs[2];   /* AP_WAIT_IN, AP_WAIT_OUT */
    apr_interval_time_t timeout;  /* of the wait in flight, resolved */
    unsigned int ready;           /* AP_WAIT_* of the last wait */
    unsigned int waiting  :1,     /* in the wait in flight */
                 kept     :1,     /* its pfd may be kept by the MPM */
                 released :1;     /* ap_request_waitctx_release()d */
} request_waitctx_t;

/* APLOG_MARK for a wait context's module */
#define WAITCTX_LOG_MARK(ctx) __FILE__, __LINE__, (ctx)->pub.module_index

#define REQUEST_WAITCTX_DIR(direction) (((direction) & AP_WAIT_OUT) ? 1 : 0)

/* The state of a request's waits (ap_request_async_t->waitset) */
struct ap_request_waitset {
    request_rec *r;
    request_waitctx_t *client;   /* the client's context, if created */
    apr_array_header_t *pfds;     /* of the wait, reused */
    request_waitctx_t **ctxs;    /* of the wait in flight */
    unsigned int *directions;     /* of ctxs */
    int nctx, nalloc;             /* ctxs used, allocated */
    apr_interval_time_t timeout;  /* of the wait in flight */
    ap_request_continuation_fn *fn;
    void *baton;
    int ending;                   /* r->pool is being destroyed */
};

/* The request's pool is being destroyed (its pre-cleanups run before its
 * subpools are destroyed): the contexts' cleanups know that the request
 * ends with them.
 */
static apr_status_t request_waitset_cleanup(void *data)
{
    struct ap_request_waitset *w = data;

    w->ending = 1;
    return APR_SUCCESS;
}

static struct ap_request_waitset *request_waitset_get(ap_request_async_t *async)
{
    struct ap_request_waitset *w = async->waitset;

    if (!w) {
        request_rec *r = async->r;
        w = apr_pcalloc(r->pool, sizeof(*w));
        w->r = r;
        w->pfds = apr_array_make(r->pool, 2, sizeof(apr_pollfd_t));
        apr_pool_pre_cleanup_register(r->pool, w, request_waitset_cleanup);
        async->waitset = w;
    }
    return w;
}

static void request_waitctx_release_pfd(request_waitctx_t *ctx);

/* The pool of a context (but the client's) is being cleaned up: the context
 * is released, unless the request ends with the pool (the MPM dropped what
 * it kept for the request when it resumed or closed the connection).
 * Destroying the pool while a wait on the context is in flight is a bug of
 * the caller: the context is detached from the wait (which completes
 * without it), its descriptor left to its own pool's cleanup if the MPM
 * keeps it (it can't be released while waited for).
 */
static apr_status_t request_waitctx_cleanup(void *data)
{
    request_waitctx_t *ctx = data;
    request_rec *r = ctx->pub.r;
    ap_request_async_t *async;
    struct ap_request_waitset *w;
    int i;

    async = request_async_get(r);
    w = (async) ? async->waitset : NULL;
    if (ctx->pool == r->pool || (w && w->ending)) {
        ctx->released = 1;
        ctx->kept = 0;
        return APR_SUCCESS;
    }

    if (ctx->waiting) {
        ap_log_rerror(WAITCTX_LOG_MARK(ctx), APLOG_ERR,
                      0, r, APLOGNO()
                      "the pool of a %s wait context destroyed while it "
                      "waits", request_waitctx_kind_names[ctx->kind]);
        AP_DEBUG_ASSERT(0);
        for (i = 0; w && i < w->nctx; i++) {
            if (w->ctxs[i] == ctx) {
                w->ctxs[i] = NULL;
            }
        }
        ctx->waiting = 0;
        ctx->released = 1;
        ctx->kept = 0;
        return APR_SUCCESS;
    }

    if (!ctx->released) {
        ctx->released = 1;
        request_waitctx_release_pfd(ctx);
    }
    return APR_SUCCESS;
}

/* A context allocated from p, released when p is cleaned up but for the
 * client's (in r->pool, for the whole request)
 */
static request_waitctx_t *request_waitctx_make(request_rec *r,
                                               apr_pool_t *p,
                                               request_waitctx_kind_e kind,
                                               int module_index)
{
    request_waitctx_t *ctx = apr_pcalloc(p, sizeof(*ctx));

    ctx->pub.r = r;
    ctx->pub.module_index = module_index;
    ctx->pub.timeout = AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT;
    ctx->pub.delay = 0;
    ctx->kind = kind;
    ctx->pool = p;
    ctx->pfd.p = p;
    if (kind != REQUEST_WAITCTX_CLIENT) {
        apr_pool_pre_cleanup_register(p, ctx, request_waitctx_cleanup);
    }
    return ctx;
}

AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_client_(request_rec *r,
                                                              int module_index)
{
    ap_request_async_t *async = request_async_get(r);
    struct ap_request_waitset *w = (async) ? request_waitset_get(async) : NULL;
    request_waitctx_t *ctx = (w) ? w->client : NULL;

    /* A request that can't suspend gets a context whose waits decline */
    if (!ctx) {
        ctx = request_waitctx_make(r, r->pool, REQUEST_WAITCTX_CLIENT,
                                   module_index);
        ctx->c = r->connection;
        ctx->pfd.desc_type = APR_POLL_SOCKET;
        ctx->pfd.desc.s = ap_get_conn_socket(r->connection);
        if (w) {
            w->client = ctx;
        }
    }
    ctx->pub.module_index = module_index;
    return &ctx->pub;
}

AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_timer_(request_rec *r,
                                                             apr_pool_t *p,
                                                             int module_index)
{
    request_waitctx_t *ctx;

    ctx = request_waitctx_make(r, p, REQUEST_WAITCTX_TIMER, module_index);
    ctx->pub.timeout = -1;
    return &ctx->pub;
}

/* Whether the context waits for a descriptor */
#define REQUEST_WAITCTX_HAS_PFD(ctx) ((ctx)->pfd.desc_type != APR_NO_DESC)

/* Release the context's pfd kept by the MPM, if any */
static void request_waitctx_release_pfd(request_waitctx_t *ctx)
{
    apr_status_t rv;

    if (!ctx->kept) {
        return;
    }
    ctx->kept = 0;
    rv = ap_mpm_release_pfd(&ctx->pfd);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_ENOTIMPL(rv)) {
        ap_log_rerror(WAITCTX_LOG_MARK(ctx), APLOG_DEBUG,
                      rv, ctx->pub.r, APLOGNO()
                      "can't release the %s from the MPM",
                      request_waitctx_kind_names[ctx->kind]);
    }
}

AP_DECLARE(void) ap_request_waitctx_release(ap_request_waitctx_t *pub)
{
    request_waitctx_t *ctx = (request_waitctx_t *)pub;

    if (ctx->released) {
        return;
    }
    ctx->released = 1;

    /* The MPM can't release a pfd while it waits: at the continuation */
    if (!ctx->waiting) {
        request_waitctx_release_pfd(ctx);
    }

    if (ctx->kind == REQUEST_WAITCTX_CLIENT) {
        ap_request_async_t *async = request_async_get(ctx->pub.r);
        if (async && async->waitset && async->waitset->client == ctx) {
            async->waitset->client = NULL;
        }
    }
}

AP_DECLARE(unsigned int) ap_request_waitctx_ready(const ap_request_waitctx_t *pub)
{
    return ((const request_waitctx_t *)pub)->ready;
}

/* A direction's name in the logs */
static const char *request_waitctx_dir_name(const request_waitctx_t *ctx,
                                            unsigned int directions)
{
    if (!REQUEST_WAITCTX_HAS_PFD(ctx)) {
        return "";
    }
    switch (directions & (AP_WAIT_IN | AP_WAIT_OUT)) {
    case AP_WAIT_IN:
        return " (in)";
    case AP_WAIT_OUT:
        return " (out)";
    default:
        return " (in/out)";
    }
}

/* The directions of a context ready in its connection's filters already:
 * input pending (or an error the read will report), no output pending (or
 * an error).
 */
static unsigned int request_waitctx_check_ready(request_waitctx_t *ctx,
                                                unsigned int directions)
{
    unsigned int ready = 0;

    if (!ctx->c) {
        return 0;
    }
    if (directions & AP_WAIT_IN) {
        request_waitctx_dir_t *d = &ctx->dirs[REQUEST_WAITCTX_DIR(AP_WAIT_IN)];

        /* Input kept by the filters after the caller's last read said EAGAIN
         * (e.g. mod_ssl's part of a line) is pending but not readable: after
         * an OK for it, the next wait in this direction polls the socket.
         */
        if (ap_check_input_pending(ctx->c) != OK && !d->pending_ready) {
            d->pending_ready = 1;
            ready |= AP_WAIT_IN;
        }
        else {
            d->pending_ready = 0;
        }
    }
    if (directions & AP_WAIT_OUT) {
        if (ap_check_output_pending(ctx->c) != AGAIN) {
            ready |= AP_WAIT_OUT;
        }
    }
    return ready;
}

/* The directions of a context ready from the rtnevents of its pfd: an error
 * or a hangup lets the caller's I/O report it
 */
static unsigned int ready_directions(apr_int16_t rtnevents,
                                     unsigned int directions)
{
    unsigned int ready = 0;

    if ((directions & AP_WAIT_IN)
        && (rtnevents & (APR_POLLIN | APR_POLLPRI | APR_POLLHUP
                         | APR_POLLERR | APR_POLLNVAL))) {
        ready |= AP_WAIT_IN;
    }
    if ((directions & AP_WAIT_OUT)
        && (rtnevents & (APR_POLLOUT | APR_POLLHUP
                         | APR_POLLERR | APR_POLLNVAL))) {
        ready |= AP_WAIT_OUT;
    }
    return ready;
}

/* The timeout of a context's wait, AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT resolved */
static apr_interval_time_t request_waitctx_timeout(request_waitctx_t *ctx,
                                                   unsigned int directions)
{
    request_rec *r = ctx->pub.r;

    if (ctx->pub.timeout != AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT) {
        return ctx->pub.timeout;
    }
    if (ctx->kind == REQUEST_WAITCTX_CLIENT && (directions & AP_WAIT_IN)) {
        return ap_get_connection_timeout(ctx->c, r->server);
    }
    return r->server->timeout;
}

static void request_waitset_continuation(conn_rec *c, request_rec *mpm_r,
                                         ap_mpm_wait_result_e why,
                                         const apr_array_header_t *pfds,
                                         void *baton)
{
    struct ap_request_waitset *w = baton;
    request_rec *r = w->r;
    ap_request_continuation_fn *fn = w->fn;
    void *fn_baton = w->baton;
    apr_status_t rv;
    int i, j;

    AP_DEBUG_ASSERT(mpm_r == r);
    switch (why) {
    case AP_MPM_WAIT_READY:
        rv = APR_SUCCESS;
        break;
    case AP_MPM_WAIT_TIMEOUT:
        rv = APR_TIMEUP; /* or a timer's success, below */
        break;
    default:
        rv = APR_EGENERAL;
        break;
    }

    /* The pfds are the wait's, in the order of the contexts having one */
    for (i = 0, j = 0; i < w->nctx; i++) {
        request_waitctx_t *ctx = w->ctxs[i];
        unsigned int directions = w->directions[i];

        ctx->ready = 0;
        if (REQUEST_WAITCTX_HAS_PFD(ctx)) {
            if (why == AP_MPM_WAIT_READY && pfds && j < pfds->nelts) {
                const apr_pollfd_t *pfd = &APR_ARRAY_IDX(pfds, j,
                                                         apr_pollfd_t);
                ctx->ready = ready_directions(pfd->rtnevents,
                                              directions);
            }
            j++;
        }
        else if (ctx->kind == REQUEST_WAITCTX_TIMER
                 && why == AP_MPM_WAIT_TIMEOUT
                 && ctx->timeout == w->timeout) {
            ctx->ready = AP_WAIT_IN | AP_WAIT_OUT;
            rv = APR_SUCCESS;
        }
        ctx->waiting = 0;
        if (ctx->released) {
            request_waitctx_release_pfd(ctx);
        }
    }

    for (i = 0; i < w->nctx; i++) {
        request_waitctx_t *ctx = w->ctxs[i];
        const char *name = request_waitctx_kind_names[ctx->kind];
        const char *dir = request_waitctx_dir_name(ctx, w->directions[i]);

        if (rv == APR_EGENERAL) {
            ap_log_rerror(WAITCTX_LOG_MARK(ctx),
                          APLOG_DEBUG, 0, r, APLOGNO()
                          "waiting for the %s%s interrupted (async, %i)",
                          name, dir, (int)why);
        }
        ap_log_rerror(WAITCTX_LOG_MARK(ctx),
                      APLOG_TRACE5, rv, r,
                      "done waiting for the %s%s (async)", name, dir);
    }
    w->nctx = 0;

    fn(r, rv, fn_baton);
}

/* Wait for the targets of nctx contexts, the first ready completing the
 * wait (ap_request_wait()).
 */
static int request_wait(request_waitctx_t **ctxs,
                        const unsigned int *directions, int nctx,
                        unsigned int flags,
                        ap_request_continuation_fn *fn, void *baton)
{
    request_rec *r = ctxs[0]->pub.r;
    struct ap_request_waitset *w;
    apr_interval_time_t timeout = -1, delay = -1;
    unsigned int mpm_flags = 0, ready = 0;
    int i, npfds = 0, keep = 1, polled = 0;
    apr_status_t rv;

    if (!ap_request_can_suspend(r)) {
        return DECLINED;
    }
    w = request_waitset_get(request_async_get(r));

    /* Ready in the connections' filters already? */
    for (i = 0; i < nctx; i++) {
        request_waitctx_t *ctx = ctxs[i];

        AP_DEBUG_ASSERT(ctx->pub.r == r && !ctx->released && !ctx->waiting);
        if (ctx->pub.r != r || ctx->released || ctx->waiting) {
            return DECLINED;
        }
        if (REQUEST_WAITCTX_HAS_PFD(ctx)) {
            AP_DEBUG_ASSERT(directions[i] & (AP_WAIT_IN | AP_WAIT_OUT));
            if (!(directions[i] & (AP_WAIT_IN | AP_WAIT_OUT))
                || !ctx->pfd.desc.s) {
                return DECLINED;
            }
        }
        ctx->ready = request_waitctx_check_ready(ctx, directions[i]);
        ready |= ctx->ready;
    }
    if (ready) {
        return OK;
    }

    /* The descriptors to poll and wait for, the smallest timeout and delay;
     * the MPM keeps the descriptors registered from their second wait in
     * the same direction.
     */
    apr_array_clear(w->pfds);
    for (i = 0; i < nctx; i++) {
        request_waitctx_t *ctx = ctxs[i];
        apr_interval_time_t t = request_waitctx_timeout(ctx, directions[i]);

        ctx->timeout = t;
        if (t >= 0 && (timeout < 0 || t < timeout)) {
            timeout = t;
        }
        if (REQUEST_WAITCTX_HAS_PFD(ctx)) {
            apr_pollfd_t *pfd = apr_array_push(w->pfds);

            *pfd = ctx->pfd;
            pfd->reqevents = 0;
            if (directions[i] & AP_WAIT_IN) {
                pfd->reqevents |= APR_POLLIN;
                if (!ctx->dirs[REQUEST_WAITCTX_DIR(AP_WAIT_IN)].waits) {
                    keep = 0;
                }
            }
            if (directions[i] & AP_WAIT_OUT) {
                pfd->reqevents |= APR_POLLOUT;
                if (!ctx->dirs[REQUEST_WAITCTX_DIR(AP_WAIT_OUT)].waits) {
                    keep = 0;
                }
            }
            pfd->rtnevents = 0;
            pfd->client_data = NULL;
            if (delay < 0 || ctx->pub.delay < delay) {
                delay = ctx->pub.delay;
            }
            npfds++;
        }
    }

    /* Ready within the delay: no need to wait. Anything but a timeout lets
     * the caller do its I/O as usual: readiness, an error the I/O will
     * report, or the poll's own failure (e.g. EINTR, which must not fail
     * the request).
     */
    if (npfds && delay > 0) {
        apr_int32_t nready = 0;

        rv = apr_poll((apr_pollfd_t *)w->pfds->elts, npfds, &nready, delay);
        if (!APR_STATUS_IS_TIMEUP(rv)) {
            for (i = 0, npfds = 0; i < nctx; i++) {
                request_waitctx_t *ctx = ctxs[i];

                if (!REQUEST_WAITCTX_HAS_PFD(ctx)) {
                    continue;
                }
                if (rv == APR_SUCCESS) {
                    apr_pollfd_t *pfd = &APR_ARRAY_IDX(w->pfds, npfds,
                                                       apr_pollfd_t);
                    ctx->ready = ready_directions(pfd->rtnevents,
                                                  directions[i]);
                }
                else {
                    ctx->ready = directions[i] & (AP_WAIT_IN | AP_WAIT_OUT);
                }
                npfds++;
            }
            if (rv != APR_SUCCESS) {
                ap_log_rerror(WAITCTX_LOG_MARK(ctxs[0]),
                              APLOG_TRACE2, rv, r,
                              "polling the %s failed, going on",
                              request_waitctx_kind_names[ctxs[0]->kind]);
            }
            return OK;
        }
        /* Not ready, so drained */
        polled = 1;
    }

    /* A readiness the MPM saw for the last wait of a kept pfd was consumed
     * since if the caller says so, or if the poll above found none.
     */
    if (npfds && keep) {
        mpm_flags = AP_MPM_WAIT_KEEP_PFDS;
        if ((flags & AP_REQUEST_WAIT_DRAINED) || polled) {
            mpm_flags |= AP_MPM_WAIT_DRAINED;
        }
    }
    rv = ap_mpm_register_wait(r->connection, r->pool, w->pfds, timeout, NULL,
                              mpm_flags, request_waitset_continuation, w);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(WAITCTX_LOG_MARK(ctxs[0]),
                      APLOG_DEBUG, rv, r, APLOGNO()
                      "can't wait for the %s%s asynchronously",
                      request_waitctx_kind_names[ctxs[0]->kind],
                      request_waitctx_dir_name(ctxs[0], directions[0]));
        return DECLINED; /* the caller waits synchronously */
    }

    if (w->nalloc < nctx) {
        w->nalloc = (nctx > 2) ? nctx : 2;
        w->ctxs = apr_palloc(r->pool, w->nalloc * sizeof(*w->ctxs));
        w->directions = apr_palloc(r->pool,
                                   w->nalloc * sizeof(*w->directions));
    }
    for (i = 0; i < nctx; i++) {
        request_waitctx_t *ctx = ctxs[i];

        w->ctxs[i] = ctx;
        w->directions[i] = directions[i];
        ctx->waiting = 1;
        if (REQUEST_WAITCTX_HAS_PFD(ctx)) {
            if (directions[i] & AP_WAIT_IN) {
                ctx->dirs[REQUEST_WAITCTX_DIR(AP_WAIT_IN)].waits++;
            }
            if (directions[i] & AP_WAIT_OUT) {
                ctx->dirs[REQUEST_WAITCTX_DIR(AP_WAIT_OUT)].waits++;
            }
            if (mpm_flags & AP_MPM_WAIT_KEEP_PFDS) {
                ctx->kept = 1;
            }
        }
        ap_log_rerror(WAITCTX_LOG_MARK(ctx),
                      APLOG_TRACE5, 0, r, "waiting for the %s%s (async)",
                      request_waitctx_kind_names[ctx->kind],
                      request_waitctx_dir_name(ctx, directions[i]));
    }
    w->nctx = nctx;
    w->timeout = timeout;
    w->fn = fn;
    w->baton = baton;
    return SUSPENDED;
}

AP_DECLARE(int) ap_request_wait(ap_request_waitctx_t *pub,
                                ap_wait_direction_e direction,
                                unsigned int flags,
                                ap_request_continuation_fn *fn, void *baton)
{
    request_waitctx_t *ctx = (request_waitctx_t *)pub;
    unsigned int directions = (unsigned int)direction;

    /* One direction for a descriptor */
    if (REQUEST_WAITCTX_HAS_PFD(ctx)
        && directions != AP_WAIT_IN && directions != AP_WAIT_OUT) {
        ap_log_rerror(WAITCTX_LOG_MARK(ctx), APLOG_ERR,
                      0, ctx->pub.r, APLOGNO() "can't wait for the %s in "
                      "both directions (or none) with ap_request_wait()",
                      request_waitctx_kind_names[ctx->kind]);
        AP_DEBUG_ASSERT(!REQUEST_WAITCTX_HAS_PFD(ctx)
                        || directions == AP_WAIT_IN
                        || directions == AP_WAIT_OUT);
        return DECLINED;
    }
    return request_wait(&ctx, &directions, 1, flags, fn, baton);
}

void ap_process_async_request(request_rec *r)
{
    conn_rec *c = r->connection;
    core_request_config *req_cfg = ap_get_core_module_config(r->request_config);
    int access_status;

    /* The state of the request's asynchronous processing, in no phase that
     * can suspend until the handlers run (ap_invoke_handler())
     */
    if (req_cfg && !r->main && !r->prev) {
        req_cfg->async = apr_pcalloc(r->pool, sizeof(*req_cfg->async));
        req_cfg->async->r = r;
        req_cfg->async->phase = AP_REQUEST_PHASE_NONE;
    }

    /* Give quick handlers a shot at serving the request on the fast
     * path, bypassing all of the other Apache hooks.
     *
     * This hook was added to enable serving files out of a URI keyed
     * content cache ( e.g., Mike Abbott's Quick Shortcut Cache,
     * described here: http://oss.sgi.com/projects/apache/mod_qsc.html )
     *
     * It may have other uses as well, such as routing requests directly to
     * content handlers that have the ability to grok HTTP and do their
     * own access checking, etc (e.g. servlet engines).
     *
     * Use this hook with extreme care and only if you know what you are
     * doing.
     */
    AP_PROCESS_REQUEST_ENTRY((uintptr_t)r, r->uri);
    if (ap_extended_status) {
        ap_time_process_request(r->connection->sbh, START_PREQUEST);
    }

    if (APLOGrtrace4(r)) {
        int i;
        const apr_array_header_t *t_h = apr_table_elts(r->headers_in);
        const apr_table_entry_t *t_elt = (apr_table_entry_t *)t_h->elts;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                      "Header received from client:");
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s", r->the_request);
        for (i = 0; i < t_h->nelts; i++, t_elt++) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s: %s",
                          ap_escape_logitem(r->pool, t_elt->key),
                          ap_escape_logitem(r->pool, t_elt->val));
        }
    }

#if APR_HAS_THREADS
    apr_thread_mutex_create(&r->invoke_mtx, APR_THREAD_MUTEX_DEFAULT, r->pool);
    apr_thread_mutex_lock(r->invoke_mtx);
#endif
    access_status = ap_run_quick_handler(r, 0);  /* Not a look-up request */
    if (access_status == DECLINED) {
        access_status = ap_process_request_internal(r);
        if (access_status == OK) {
            access_status = ap_invoke_handler(r);
        }
    }

    if (access_status == SUSPENDED) {
        /* TODO: Should move these steps into a generic function, so modules
         * working on a suspended request can also call _ENTRY again.
         */
        AP_PROCESS_REQUEST_RETURN((uintptr_t)r, r->uri, access_status);
        if (ap_extended_status) {
            ap_time_process_request(c->sbh, STOP_PREQUEST);
        }
        if (c->cs)
            c->cs->state = CONN_STATE_SUSPENDED;
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(r->invoke_mtx);
#endif
        return;
    }
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(r->invoke_mtx);
#endif

    ap_die_r(access_status, r, HTTP_OK);

    ap_process_request_after_handler(r);
}

AP_DECLARE(void) ap_request_finish_suspended(request_rec *r, int status)
{
    conn_rec *c = r->connection;
    ap_request_async_t *async = request_async_get(r);

    if (async) {
        async->phase = AP_REQUEST_PHASE_DONE;
    }

    /* This run on a worker is timed as one, stopped by
     * ap_process_request_after_handler() (its STOP_PREQUEST)
     */
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, START_PREQUEST);
    }

    /* As ap_process_async_request() would have if the handler had returned
     * this status: an error is not a recursive one.
     */
    ap_die_r(status, r, HTTP_OK);
    ap_process_request_after_handler(r);
    /* don't dereference r from here! */

    if (c->keepalive == AP_CONN_CLOSE || c->aborted) {
        c->cs->state = CONN_STATE_LINGER;
    }
    else {
        c->cs->state = CONN_STATE_WRITE_COMPLETION;
    }
    ap_mpm_resume_suspended(c);
}

AP_DECLARE(void) ap_process_request(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    conn_rec *c = r->connection;
    apr_status_t rv;

    ap_process_async_request(r);

    if (ap_check_input_pending(c) != AGAIN) {
        bb = ap_acquire_brigade(c);
        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(bb, b);
        rv = ap_pass_brigade(c->output_filters, bb);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            /*
             * Notice a timeout as an error message. This might be
             * valuable for detecting clients with broken network
             * connections or possible DoS attacks.
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(01581)
                          "flushing data to the client");
        }
        ap_release_brigade(c, bb);
    }
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, STOP_PREQUEST);
    }
}

static apr_table_t *rename_original_env(apr_pool_t *p, apr_table_t *t)
{
    const apr_array_header_t *env_arr = apr_table_elts(t);
    const apr_table_entry_t *elts = (const apr_table_entry_t *) env_arr->elts;
    apr_table_t *new = apr_table_make(p, env_arr->nalloc);
    int i;

    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;
        apr_table_setn(new, apr_pstrcat(p, "REDIRECT_", elts[i].key, NULL),
                  elts[i].val);
    }

    return new;
}

static request_rec *internal_internal_redirect(const char *new_uri,
                                               request_rec *r) {
    int access_status;
    request_rec *new;
    const char *vary_header;

    if (ap_is_recursion_limit_exceeded(r)) {
        ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
        return NULL;
    }

    new = (request_rec *) apr_pcalloc(r->pool, sizeof(request_rec));

    new->connection = r->connection;
    new->server     = r->server;
    new->pool       = r->pool;

    /*
     * A whole lot of this really ought to be shared with http_protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */

    new->method          = r->method;
    new->method_number   = r->method_number;
    new->allowed_methods = ap_make_method_list(new->pool, 2);
    ap_parse_uri(new, new_uri);
    new->parsed_uri.port_str = r->parsed_uri.port_str;
    new->parsed_uri.port = r->parsed_uri.port;

    new->request_config = ap_create_request_config(r->pool);

    new->per_dir_config = r->server->lookup_defaults;

    new->prev = r;
    r->next   = new;

    new->useragent_addr = r->useragent_addr;
    new->useragent_ip = r->useragent_ip;

    /* Must have prev and next pointers set before calling create_request
     * hook.
     */
    ap_run_create_request(new);

    /* Inherit the rest of the protocol info... */

    new->the_request = r->the_request;

    new->allowed         = r->allowed;

    new->status          = r->status;
    new->assbackwards    = r->assbackwards;
    new->header_only     = r->header_only;
    new->protocol        = r->protocol;
    new->proto_num       = r->proto_num;
    new->hostname        = r->hostname;
    new->request_time    = r->request_time;
    new->main            = r->main;

    new->headers_in      = r->headers_in;
    new->trailers_in     = r->trailers_in;
    new->headers_out     = apr_table_make(r->pool, 12);
    if (ap_is_HTTP_REDIRECT(new->status)) {
        const char *location = apr_table_get(r->headers_out, "Location");
        if (location)
            apr_table_setn(new->headers_out, "Location", location);
    }

    /* A module (like mod_rewrite) can force an internal redirect
     * to carry over the Vary header (if present).
     */
    if (apr_table_get(r->notes, "redirect-keeps-vary")) {
        if((vary_header = apr_table_get(r->headers_out, "Vary"))) {
            apr_table_setn(new->headers_out, "Vary", vary_header);
        }
    }

    new->err_headers_out = r->err_headers_out;
    new->trailers_out    = apr_table_make(r->pool, 5);
    new->subprocess_env  = rename_original_env(r->pool, r->subprocess_env);
    new->notes           = apr_table_make(r->pool, 5);

    new->htaccess        = r->htaccess;
    new->no_cache        = r->no_cache;
    new->expecting_100   = r->expecting_100;
    new->no_local_copy   = r->no_local_copy;
    new->read_length     = r->read_length;     /* We can only read it once */
    new->vlist_validator = r->vlist_validator;

    new->proto_output_filters  = r->proto_output_filters;
    new->proto_input_filters   = r->proto_input_filters;

    new->input_filters   = new->proto_input_filters;

    if (new->main) {
        ap_filter_t *f, *nextf;

        /* If this is a subrequest, the filter chain may contain a
         * mixture of filters specific to the old request (r), and
         * some inherited from r->main.  Here, inherit that filter
         * chain, and remove all those which are specific to the old
         * request; ensuring the subreq filter is left in place. */
        new->output_filters = r->output_filters;

        f = new->output_filters;
        do {
            nextf = f->next;

            if (f->r == r && f->frec != ap_subreq_core_filter_handle) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01582)
                              "dropping filter '%s' in internal redirect from %s to %s",
                              f->frec->name, r->unparsed_uri, new_uri);

                /* To remove the filter, first set f->r to the *new*
                 * request_rec, so that ->output_filters on 'new' is
                 * changed (if necessary) when removing the filter. */
                f->r = new;
                ap_remove_output_filter(f);
            }

            f = nextf;

            /* Stop at the protocol filters.  If a protocol filter has
             * been newly installed for this resource, better leave it
             * in place, though it's probably a misconfiguration or
             * filter bug to get into this state. */
        } while (f && f != new->proto_output_filters);
    }
    else {
        /* If this is not a subrequest, clear out all
         * resource-specific filters. */
        new->output_filters  = new->proto_output_filters;
    }

    update_r_in_filters(new->input_filters, r, new);
    update_r_in_filters(new->output_filters, r, new);

    apr_table_setn(new->subprocess_env, "REDIRECT_STATUS",
                   apr_itoa(r->pool, r->status));

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    new->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

#if APR_HAS_THREADS
    new->invoke_mtx = r->invoke_mtx;
#endif

    /*
     * XXX: hmm.  This is because mod_setenvif and mod_unique_id really need
     * to do their thing on internal redirects as well.  Perhaps this is a
     * misnamed function.
     */
    if ((access_status = ap_post_read_request(new))) {
        ap_die(access_status, new);
        return NULL;
    }

    return new;
}

/* XXX: Is this function is so bogus and fragile that we deep-6 it? */
AP_DECLARE(void) ap_internal_fast_redirect(request_rec *rr, request_rec *r)
{
    /* We need to tell POOL_DEBUG that we're guaranteeing that rr->pool
     * will exist as long as r->pool.  Otherwise we run into troubles because
     * some values in this request will be allocated in r->pool, and others in
     * rr->pool.
     */
    apr_pool_join(r->pool, rr->pool);
    r->proxyreq = rr->proxyreq;
    r->no_cache = (r->no_cache && rr->no_cache);
    r->no_local_copy = (r->no_local_copy && rr->no_local_copy);
    r->mtime = rr->mtime;
    r->uri = rr->uri;
    r->filename = rr->filename;
    r->canonical_filename = rr->canonical_filename;
    r->path_info = rr->path_info;
    r->args = rr->args;
    r->finfo = rr->finfo;
    r->handler = rr->handler;
    ap_set_content_type_ex(r, rr->content_type, AP_REQUEST_IS_TRUSTED_CT(rr));
    r->content_encoding = rr->content_encoding;
    r->content_languages = rr->content_languages;
    r->per_dir_config = rr->per_dir_config;
    /* copy output headers from subrequest, but leave negotiation headers */
    r->notes = apr_table_overlay(r->pool, rr->notes, r->notes);
    r->headers_out = apr_table_overlay(r->pool, rr->headers_out,
                                       r->headers_out);
    r->err_headers_out = apr_table_overlay(r->pool, rr->err_headers_out,
                                           r->err_headers_out);
    r->trailers_out = apr_table_overlay(r->pool, rr->trailers_out,
                                           r->trailers_out);
    r->subprocess_env = apr_table_overlay(r->pool, rr->subprocess_env,
                                          r->subprocess_env);

    r->output_filters = rr->output_filters;
    r->input_filters = rr->input_filters;

    /* If any filters pointed at the now-defunct rr, we must point them
     * at our "new" instance of r.  In particular, some of rr's structures
     * will now be bogus (say rr->headers_out).  If a filter tried to modify
     * their f->r structure when it is pointing to rr, the real request_rec
     * will not get updated.  Fix that here.
     */
    update_r_in_filters(r->input_filters, rr, r);
    update_r_in_filters(r->output_filters, rr, r);

    if (r->main) {
        ap_filter_t *next = r->output_filters;
        while (next && (next != r->proto_output_filters)) {
            if (next->frec == ap_subreq_core_filter_handle) {
                break;
            }
            next = next->next;
        }
        if (!next || next == r->proto_output_filters) {
            ap_add_output_filter_handle(ap_subreq_core_filter_handle,
                                        NULL, r, r->connection);
        }
    }
    else {
        /*
         * We need to check if we now have the SUBREQ_CORE filter in our filter
         * chain. If this is the case we need to remove it since we are NO
         * subrequest. But we need to keep in mind that the SUBREQ_CORE filter
         * does not necessarily need to be the first filter in our chain. So we
         * need to go through the chain. But we only need to walk up the chain
         * until the proto_output_filters as the SUBREQ_CORE filter is below the
         * protocol filters.
         */
        ap_filter_t *next;

        next = r->output_filters;
        while (next && (next->frec != ap_subreq_core_filter_handle)
               && (next != r->proto_output_filters)) {
                next = next->next;
        }
        if (next && (next->frec == ap_subreq_core_filter_handle)) {
            ap_remove_output_filter(next);
        }
    }
}

AP_DECLARE(void) ap_internal_redirect(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = internal_internal_redirect(new_uri, r);

    AP_INTERNAL_REDIRECT(r->uri, new_uri);

    /* ap_die was already called, if an error occurred */
    if (!new) {
        return;
    }

    access_status = ap_run_quick_handler(new, 0);  /* Not a look-up request */
    if (access_status == DECLINED) {
        access_status = ap_process_request_internal(new);
        if (access_status == OK) {
            access_status = ap_invoke_handler(new);
        }
    }
    ap_die(access_status, new);
}

/* This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 */
AP_DECLARE(void) ap_internal_redirect_handler(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = internal_internal_redirect(new_uri, r);

    /* ap_die was already called, if an error occurred */
    if (!new) {
        return;
    }

    /* Propagate the content type, but never the "trusted" flag: the
     * type is carried across the redirect for the benefit of AddType
     * style configuration of the *original* URI, and must not be used
     * as the handler for the target if no handler is determined for it
     * by ap_process_request_internal() below.
     */
    if (r->handler)
        ap_set_content_type_ex(new, r->content_type, 0);
    access_status = ap_process_request_internal(new);
    if (access_status == OK) {
        access_status = ap_invoke_handler(new);
    }
    ap_die(access_status, new);
}

AP_DECLARE(void) ap_allow_methods(request_rec *r, int reset, ...)
{
    const char *method;
    va_list methods;

    /*
     * Get rid of any current settings if requested; not just the
     * well-known methods but any extensions as well.
     */
    if (reset) {
        ap_clear_method_list(r->allowed_methods);
    }

    va_start(methods, reset);
    while ((method = va_arg(methods, const char *)) != NULL) {
        ap_method_list_add(r->allowed_methods, method);
    }
    va_end(methods);
}

AP_DECLARE(void) ap_allow_standard_methods(request_rec *r, int reset, ...)
{
    int method;
    va_list methods;
    ap_method_mask_t mask;

    /*
     * Get rid of any current settings if requested; not just the
     * well-known methods but any extensions as well.
     */
    if (reset) {
        ap_clear_method_list(r->allowed_methods);
    }

    mask = 0;
    va_start(methods, reset);
    while ((method = va_arg(methods, int)) != -1) {
        mask |= (AP_METHOD_BIT << method);
    }
    va_end(methods);

    r->allowed_methods->method_mask |= mask;
}
