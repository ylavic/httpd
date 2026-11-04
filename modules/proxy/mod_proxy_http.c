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

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"
#include "ap_regex.h"
#include "ap_mpm.h"
#include "mpm_common.h"

module AP_MODULE_DECLARE_DATA proxy_http_module;

/* A request is processed by the same steps whether it can be suspended or
 * not: either way it gets the same results (statuses, timeouts, logs, backend
 * connection reuse), it just doesn't hold a thread while waiting when it can
 * be suspended (the waits in the MPM, and their continuations).
 *
 * Whether the request can be suspended to wait asynchronously is
 * ap_proxy_request_can_suspend()'s answer. Should the MPM refuse a wait
 * still, req->can_suspend is cleared and the rest of the request blocks.
 */

static int (*ap_proxy_clear_connection_fn)(request_rec *r, apr_table_t *headers) =
        NULL;


static const char *get_url_scheme(const char **url, int *is_ssl)
{
    const char *u = *url;

    switch (u[0]) {
    case 'h':
    case 'H':
        if (strncasecmp(u + 1, "ttp", 3) == 0) {
            if (u[4] == ':') {
                *is_ssl = 0;
                *url = u + 5;
                return "http";
            }
            if (apr_tolower(u[4]) == 's' && u[5] == ':') {
                *is_ssl = 1;
                *url = u + 6;
                return "https";
            }
        }
        break;

    case 'w':
    case 'W':
        if (apr_tolower(u[1]) == 's') {
            if (u[2] == ':') {
                *is_ssl = 0;
                *url = u + 3;
                return "ws";
            }
            if (apr_tolower(u[2]) == 's' && u[3] == ':') {
                *is_ssl = 1;
                *url = u + 4;
                return "wss";
            }
        }
        break;
    }

    *is_ssl = 0;
    return NULL;
}

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 */
static int proxy_http_canon(request_rec *r, char *url)
{
    const char *base_url = url;
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;
    int is_ssl = 0;

    scheme = get_url_scheme((const char **)&url, &is_ssl);
    if (!scheme) {
        return DECLINED;
    }
    port = def_port = (is_ssl) ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "HTTP: canonicalising URL %s", base_url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01083)
                      "error parsing URL %s: %s", base_url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path.
     *
     * In a reverse proxy, our URL has been processed, so canonicalise
     * unless proxy-nocanon is set to say it's raw
     * In a forward proxy, we have and MUST NOT MANGLE the original.
     */
    switch (r->proxyreq) {
    default: /* wtf are we doing here? */
    case PROXYREQ_REVERSE:
        if (apr_table_get(r->notes, "proxy-nocanon")) {
            path = url;   /* this is the raw path */
        }
        else if (apr_table_get(r->notes, "proxy-noencode")) {
            path = url;   /* this is the encoded path already */
            search = r->args;
        }
        else {
            core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
            int flags = d->allow_encoded_slashes && !d->decode_encoded_slashes ? PROXY_CANONENC_NOENCODEDSLASHENCODING : 0;

            path = ap_proxy_canonenc_ex(r->pool, url, strlen(url), enc_path,
                                        flags, r->proxyreq);
            if (!path) {
                return HTTP_BAD_REQUEST;
            }
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }
    /*
     * If we have a raw control character or a ' ' in nocanon path or
     * r->args, correct encoding was missed.
     */
    if (path == url && *ap_scan_vchar_obstext(path)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10415)
                      "To be forwarded path contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
    }
    if (search && *ap_scan_vchar_obstext(search)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10408)
                      "To be forwarded query string contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
    }

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }

    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport,
                              "/", path, (search) ? "?" : "", search, NULL);
    return OK;
}

/* Clear all connection-based headers from the incoming headers table */
typedef struct header_dptr {
    apr_pool_t *pool;
    apr_table_t *table;
    apr_time_t time;
} header_dptr;
static ap_regex_t *warn_rx;
static int clean_warning_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    char *warning;
    char *date;
    apr_time_t warn_time;
    const int nmatch = 3;
    ap_regmatch_t pmatch[3];

    if (headers == NULL) {
        ((header_dptr*)data)->table = headers = apr_table_make(pool, 2);
    }
/*
 * Parse this, suckers!
 *
 *    Warning    = "Warning" ":" 1#warning-value
 *
 *    warning-value = warn-code SP warn-agent SP warn-text
 *                                             [SP warn-date]
 *
 *    warn-code  = 3DIGIT
 *    warn-agent = ( host [ ":" port ] ) | pseudonym
 *                    ; the name or pseudonym of the server adding
 *                    ; the Warning header, for use in debugging
 *    warn-text  = quoted-string
 *    warn-date  = <"> HTTP-date <">
 *
 * Buggrit, use a bloomin' regexp!
 * (\d{3}\s+\S+\s+\".*?\"(\s+\"(.*?)\")?)  --> whole in $1, date in $3
 */
    while (!ap_regexec(warn_rx, val, nmatch, pmatch, 0)) {
        warning = apr_pstrndup(pool, val+pmatch[0].rm_so,
                               pmatch[0].rm_eo - pmatch[0].rm_so);
        warn_time = 0;
        if (pmatch[2].rm_eo > pmatch[2].rm_so) {
            /* OK, we have a date here */
            date = apr_pstrndup(pool, val+pmatch[2].rm_so,
                                pmatch[2].rm_eo - pmatch[2].rm_so);
            warn_time = apr_date_parse_http(date);
        }
        if (!warn_time || (warn_time == ((header_dptr*)data)->time)) {
            apr_table_addn(headers, key, warning);
        }
        val += pmatch[0].rm_eo;
    }
    return 1;
}
static apr_table_t *ap_proxy_clean_warnings(apr_pool_t *p, apr_table_t *headers)
{
   header_dptr x;
   x.pool = p;
   x.table = NULL;
   x.time = apr_date_parse_http(apr_table_get(headers, "Date"));
   apr_table_do(clean_warning_headers, &x, headers, "Warning", NULL);
   if (x.table != NULL) {
       apr_table_unset(headers, "Warning");
       return apr_table_overlay(p, headers, x.table);
   }
   else {
        return headers;
   }
}

static void add_te_chunked(apr_pool_t *p,
                           apr_bucket_alloc_t *bucket_alloc,
                           apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;
    char *buf;
    const char te_hdr[] = "Transfer-Encoding: chunked" CRLF;

    buf = apr_pmemdup(p, te_hdr, sizeof(te_hdr)-1);
    ap_xlate_proto_to_ascii(buf, sizeof(te_hdr)-1);

    e = apr_bucket_pool_create(buf, sizeof(te_hdr)-1, p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static void add_cl(apr_pool_t *p,
                   apr_bucket_alloc_t *bucket_alloc,
                   apr_bucket_brigade *header_brigade,
                   const char *cl_val)
{
    apr_bucket *e;
    char *buf;

    buf = apr_pstrcat(p, "Content-Length: ",
                      cl_val,
                      CRLF,
                      NULL);
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}


#define MAX_MEM_SPOOL 16384

typedef enum {
    RB_INIT = 0,
    RB_STREAM_CL,
    RB_STREAM_CHUNKED,
    RB_SPOOL_CL
} rb_methods;

typedef struct {
    apr_pool_t *p;
    request_rec *r;
    const char *proto;
    proxy_worker *worker;
    proxy_dir_conf *dconf;
    proxy_server_conf *sconf;
    char server_portstr[32];

    proxy_conn_rec *backend;
    conn_rec *origin;

    apr_bucket_alloc_t *bucket_alloc;
    apr_bucket_brigade *header_brigade;
    apr_bucket_brigade *input_brigade;

    char *old_cl_val, *old_te_val;
    apr_off_t cl_val;

    rb_methods rb_method;

    const char *upgrade;
    proxy_tunnel_rec *tunnel;

    ap_request_waitctx_t *connect_wait; /* of the connect in progress */
    apr_pool_t *connect_pool;            /* its pool, cleared per attempt */
    apr_interval_time_t idle_timeout;

    /* The response body's streaming state (proxy_http_response_body()) */
    apr_bucket_brigade *response_bb, *response_pass_bb;
    apr_read_type_e response_mode;

    /* The request's sending state (stream_reqbody()) */
    apr_off_t bytes_streamed;

    /* The response heads, read (without blocking when async) by
     * proxy_http_response_read_heads() with ap_h1_head_parse(), then
     * processed in order by ap_proxy_http_process_response().
     */
    ap_h1_head_parser_t *head_parser;
    apr_array_header_t *heads;  /* ap_h1_head_t *, as read */
    int head_next;              /* the next one to process */
    int head_interims;          /* the interim ones read */
    int head_rc;                /* the parsing's DONE or error, if failed */
    ap_h1_head_t *head_failed;  /* the head failed, as parsed (if any) */

    /* The state of the steps run by proxy_http_process(), including a
     * connect in progress (proxy_http_connect())
     */
    char *url, *locurl;
    apr_uri_t *uri;
    const char *proxyname;
    apr_port_t proxyport;
    int retry;
    ap_proxy_connect_state connect;

    unsigned int connecting             :1,
                 handshaking            :1,
                 toclose                :1,
                 can_suspend            :1, /* cleared if the MPM refuses */
                 direction              :2, /* ap_proxy_direction_e */
                 backend_broke          :1,
                 request_timed_out         :1, /* the wait for the client did */
                 request_eos               :1,
                 head_final             :1, /* the final head is read */
                 do_100_continue        :1,
                 prefetch_nonblocking   :1,
                 force10                :1,
                 upgraded               :1;
} proxy_http_req_t;

/* The state of a request across the runs of proxy_http_handler(): after
 * waiting for the client's body or for a backend connection (the same
 * attempt), and for each attempt (balancer failover). In mod_proxy_http's
 * request_config, see proxy_http_rctx().
 */
typedef struct {
    proxy_http_req_t *req;              /* The current attempt, if any */
    apr_bucket_brigade *input;          /* The request body read so far */
    struct proxy_http_preread *preread; /* See proxy_http_request_preread() */
} proxy_http_rctx_t;

/* Get (or create) the request's proxy_http_rctx_t */
static proxy_http_rctx_t *proxy_http_rctx(request_rec *r)
{
    proxy_http_rctx_t *rctx = ap_get_module_config(r->request_config,
                                                   &proxy_http_module);
    if (!rctx) {
        rctx = apr_pcalloc(r->pool, sizeof(*rctx));
        ap_set_module_config(r->request_config, &proxy_http_module, rctx);
    }
    return rctx;
}

static void proxy_http_async_finish(proxy_http_req_t *req, int status);

/* The end of a tunnel (after a 101 Switching Protocols), with its status:
 * account for the bytes exchanged by the backend, and we are done with both
 * connections.
 */
static void proxy_http_tunnel_end(proxy_http_req_t *req, int status)
{
    proxy_conn_rec *backend = req->backend;

    if (status == HTTP_GATEWAY_TIME_OUT) {
        /* ap_proxy_tunnel_run{,_ex}() didn't log this */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req->r, APLOGNO()
                      "proxy: %s tunneling timed out", req->proto);
    }

    backend->worker->s->read +=
        ap_proxy_tunnel_conn_bytes_in(req->tunnel->origin);
    backend->worker->s->transferred +=
        ap_proxy_tunnel_conn_bytes_out(req->tunnel->origin);

    req->r->connection->keepalive = AP_CONN_CLOSE;
    backend->close = 1;
}

/* The end of a tunnel run asynchronously (ap_proxy_tunnel_run_ex()):
 * proxy_http_tunnel_end(), then finish the request as any async one
 * (proxy_http_async_finish()) with DONE, the status of a tunnel's end.
 */
static void proxy_http_tunnel_done(proxy_tunnel_rec *tunnel, int status,
                                   void *baton)
{
    proxy_http_req_t *req = baton;

    proxy_http_tunnel_end(req, status);
    proxy_http_async_finish(req, DONE);
}

static int ap_proxy_http_process_response(proxy_http_req_t *req);

/* Finish a request whose processing was suspended (status as returned by
 * proxy_http_handler()): release the backend, finish the request and give
 * the client connection back to the MPM (ap_proxy_handler_done()).
 */
static void proxy_http_async_finish(proxy_http_req_t *req, int status)
{
    request_rec *r = req->r;

    /* Release the backend, which proxy_http_handler() didn't since it
     * returned SUSPENDED, unless ap_proxy_http_process_response() already
     * did (then req->backend is NULL).
     */
    if (req->backend) {
        proxy_run_detach_backend(r, req->backend);
        if (status != OK) {
            req->backend->close = 1;
        }
        ap_proxy_release_connection(req->proto, req->backend, r->server);
        req->backend = NULL;
    }
    ap_proxy_handler_done(r, status);
}

static int proxy_http_response_read_heads(proxy_http_req_t *req,
                                          int nonblocking);
static int proxy_http_response_suspend(proxy_http_req_t *req);

/* The continuation of proxy_http_response_head_wait(), called when the
 * backend's response is available (or on timeout or error): read its head,
 * process it and finish the request.
 */
static void proxy_http_response_head_continuation(request_rec *r,
                                                  apr_status_t rv,
                                                  void *baton)
{
    proxy_http_req_t *req = baton;
    proxy_conn_rec *backend = req->backend;
    int status;

    AP_DEBUG_ASSERT(req->r == r);
    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                      "proxy %s: response ready (async)", req->proto);
        if (proxy_http_response_read_heads(req, 1) == SUSPENDED) {
            return; /* waiting for the rest of the head */
        }
        status = ap_proxy_http_process_response(req);
    }
    else if (APR_STATUS_IS_TIMEUP(rv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "proxy %s: timeout waiting for the %sresponse of "
                      "%s:%d (async)", req->proto,
                      req->do_100_continue ? "100-continue " : "",
                      backend->hostname, backend->port);
        apr_table_setn(r->notes, "proxy_timedout", "1");
        if (req->do_100_continue) {
            /* 503, for the balancer to try another member (the body is
             * not sent yet).
             */
            status = ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE,
                                   "Timeout on 100-Continue");
        }
        else {
            status = HTTP_GATEWAY_TIME_OUT;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: can't wait for the response of %s:%d "
                      "(async)", req->proto, backend->hostname, backend->port);
        status = HTTP_BAD_GATEWAY;
    }
    if (status == SUSPENDED) {
        /* Streaming the response body is waiting,
         * proxy_http_response_body_continuation() continues, or sending the
         * body after a 100 Continue (then waiting for the final response),
         * proxy_http_request_forward_continuation() continues. Upgrades
         * (tunnels) don't take this path, see proxy_http_handler().
         */
        return;
    }
    proxy_http_async_finish(req, status);
}

/* Wait for the backend's response without holding the thread: read its head
 * without blocking (proxy_http_response_read_heads(), which waits for the
 * rest as needed), so that anything the filters already hold is read before any
 * poll. Returns OK if the response can be read now, or SUSPENDED if it's
 * waited for asynchronously (proxy_http_response_head_continuation() is
 * called then).
 */
static int proxy_http_response_head_wait(proxy_http_req_t *req)
{
    return proxy_http_response_read_heads(req, 1);
}

/* Wait until the backend is readable (ap_proxy_wait()), then read its
 * response head in proxy_http_response_head_continuation(). Returns
 * SUSPENDED, OK if readable within ProxyAsyncDelay (the caller goes on), or
 * DECLINED if we can't wait asynchronously (the caller then blocks).
 */
static int proxy_http_response_suspend(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    int rc;

    /* Waiting for the 100 Continue (or a final response) to send the body,
     * the worker's ping= applies if set.
     */
    rc = ap_proxy_wait(r, req->backend, AP_PROXY_BACKEND_IN,
                       AP_PROXY_WAIT_DRAINED, /* the parser's AGAIN */
                       (req->do_100_continue
                        && req->worker->s->ping_timeout_set)
                       ? req->worker->s->ping_timeout
                       : req->idle_timeout,
                       proxy_http_response_head_continuation, req);
    if (rc == SUSPENDED) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                      "proxy %s: waiting for the response (async)",
                      req->proto);
    }
    else if (rc == DECLINED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "proxy %s: can't wait for the response asynchronously",
                      req->proto);
    }
    return rc;
}

/* How long to wait for the client to send more of the body: the time left in
 * the connection's current stage if limited (mod_reqtimeout's
 * RequestReadTimeout, as of the last read, which extends it with minrate),
 * otherwise the server's Timeout (ap_get_connection_timeout()).
 */
static apr_interval_time_t proxy_http_request_read_timeout(request_rec *r)
{
    return ap_get_connection_timeout(r->connection, r->server);
}

/*
 * Limit the number of interim responses we sent back to the client. Otherwise
 * we suffer from a memory build up. Besides there is NO sense in sending back
 * an unlimited number of interim responses to the client. Thus if we cross
 * this limit send back a 502 (Bad Gateway).
 */
#ifndef AP_MAX_INTERIM_RESPONSES
#define AP_MAX_INTERIM_RESPONSES 10
#endif

/* Read the backend's response heads with ap_h1_head_parse() (the rules and
 * limits of ap_proxy_h1_head_opts()), keeping them in req for
 * ap_proxy_http_process_response(). Nonblocking (waiting for the rest as
 * needed): up to the final head, a 100 Continue for our Expect (the body is
 * sent first, then the reading goes on), a 101 (the upgraded protocol
 * follows) or AP_MAX_INTERIM_RESPONSES interim heads; blocking: the next
 * head only (each interim head is processed when it comes). A failure is
 * kept for the processing to report. Returns OK, or SUSPENDED if waiting for
 * the backend (proxy_http_response_head_continuation() is called then).
 */
static int proxy_http_response_read_heads(proxy_http_req_t *req,
                                          int nonblocking)
{
    apr_read_type_e block = (nonblocking) ? APR_NONBLOCK_READ
                                          : APR_BLOCK_READ;

    if (!req->head_parser) {
        ap_h1_head_opts_t opts;

        ap_proxy_h1_head_opts(&opts, req->r, req->worker, AP_H1_HEAD_RESPONSE);
        req->head_parser = ap_h1_head_parser_create(req->p, req->r, &opts);
        req->heads = apr_array_make(req->p, 2, sizeof(ap_h1_head_t *));
    }

    while (!req->head_final && !req->head_rc) {
        ap_h1_head_t *head;
        int rc;

        rc = ap_h1_head_parse(req->head_parser, req->origin->input_filters,
                              block, &head);
        if (rc == AGAIN) {
            rc = proxy_http_response_suspend(req);
            if (rc == SUSPENDED) {
                return SUSPENDED;
            }
            if (rc != OK) {
                block = APR_BLOCK_READ; /* can't wait: block (the parsing
                                         * state is kept) */
            }
            continue;
        }
        if (rc != OK) {
            req->head_rc = rc;
            req->head_failed = head;
            break;
        }

        APR_ARRAY_PUSH(req->heads, ap_h1_head_t *) = head;
        if (head->u.rsp.status >= 200) {
            req->head_final = 1;
            break;
        }
        ap_h1_head_parser_reset(req->head_parser);
        if (!nonblocking
            || head->u.rsp.status == HTTP_SWITCHING_PROTOCOLS
            || (head->u.rsp.status == HTTP_CONTINUE && req->do_100_continue)
            || ++req->head_interims >= AP_MAX_INTERIM_RESPONSES) {
            break;
        }
    }
    return OK;
}

/* The next response head to process, read now (blocking) if not read yet
 * (proxy_http_response_read_heads()). Returns OK with *head, or the
 * parsing's DONE or error with *head as parsed (or NULL).
 */
static int proxy_http_response_next_head(proxy_http_req_t *req,
                                         ap_h1_head_t **head)
{
    if (!req->heads || req->head_next >= req->heads->nelts) {
        proxy_http_response_read_heads(req, 0);
    }
    if (req->head_next < req->heads->nelts) {
        *head = APR_ARRAY_IDX(req->heads, req->head_next++, ap_h1_head_t *);
        return OK;
    }
    *head = req->head_failed;
    return (req->head_rc) ? req->head_rc : HTTP_INTERNAL_SERVER_ERROR;
}

static void proxy_http_request_forward_continuation(request_rec *r,
                                                    apr_status_t status,
                                                    void *baton);

/* The directions' names in the trace logs (ap_proxy_direction_e) */
static const char *const proxy_http_direction_names[] = {
    "client", "client (output)", "backend (input)", "backend"
};

/* While sending the request, wait for the backend or the client
 * (ap_proxy_direction_e) with ap_proxy_wait(). Returns SUSPENDED, AGAIN if
 * ready within ProxyAsyncDelay (the caller goes on), or OK if we can't wait
 * asynchronously (the caller then blocks).
 */
static int proxy_http_request_forward_wait(proxy_http_req_t *req,
                                           ap_proxy_direction_e wait,
                                           unsigned int flags)
{
    request_rec *r = req->r;
    apr_interval_time_t timeout;
    int rc;

    /* Wait for the backend with the proxy's timeout (ProxyAsyncIdleTimeout,
     * or else the backend's), for the client to take output with the server's
     * Timeout, and for it to send with the time left to read
     * (proxy_http_request_read_timeout()).
     */
    switch (wait) {
    case AP_PROXY_BACKEND_OUT:
        timeout = req->idle_timeout;
        break;
    case AP_PROXY_CLIENT_OUT:
        timeout = r->server->timeout;
        break;
    default:
        timeout = proxy_http_request_read_timeout(r);
        break;
    }
    rc = ap_proxy_wait(r, req->backend, wait, flags, timeout,
                       proxy_http_request_forward_continuation, req);
    if (rc == OK) {
        return AGAIN;
    }
    if (rc != SUSPENDED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "proxy %s: can't wait for the %s asynchronously",
                      req->proto, proxy_http_direction_names[wait]);
        return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy %s: request: waiting for the %s (async)",
                  req->proto, proxy_http_direction_names[wait]);
    req->direction = wait;
    return SUSPENDED;
}

/* Read some of the request body without blocking (for async sending).
 * Returns OK with the data in req->input_brigade, SUSPENDED if waiting in the
 * MPM for the backend to take what's pending or for the client to send more,
 * or an HTTP error.
 */
static int proxy_http_request_read_body(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = req->input_brigade;
    apr_status_t status;
    int rv;

    /* If the client waits for a 100 Continue, let HTTP_IN send it on this
     * nonblocking read (it does on blocking reads only by default, not to
     * send it before the backend agrees with 100-continue, which is done by
     * now), or the client and we would wait for each other.
     */
read_again:
    if (r->expecting_100) {
        r->expecting_100 |= AP_EXPECT_100_NONBLOCK;
    }
    status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, HUGE_STRING_LEN);
    if (r->expecting_100) {
        r->expecting_100 &= ~AP_EXPECT_100_NONBLOCK;
    }
    if (APR_STATUS_IS_EAGAIN(status)
        || (status == APR_SUCCESS && APR_BRIGADE_EMPTY(bb))) {
        ap_proxy_direction_e wait = AP_PROXY_CLIENT_IN;

        if (req->request_timed_out) {
            /* The wait for the client timed out and there is still nothing
             * to read (the server's Timeout, a deadline of mod_reqtimeout's
             * would have failed the read): a 408.
             */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                          "proxy %s: timeout reading the request body from "
                          "the client (async)", req->proto);
            return HTTP_REQUEST_TIME_OUT;
        }

        /* Nothing from the client yet: let the filters release what they
         * hold towards the backend without blocking (WC), then wait for the
         * backend to take what's pending if any, otherwise for the client to
         * take what's pending if any (the 100 Continue it waits for), or
         * else to send more.
         */
        apr_brigade_cleanup(bb);
        APR_BRIGADE_INSERT_TAIL(bb, ap_bucket_wc_create(bb->bucket_alloc));
        rv = ap_proxy_pass_brigade(req->bucket_alloc, r, req->backend,
                                   req->origin, bb, 0);
        if (rv != OK) {
            return rv;
        }
        if (ap_check_output_pending(req->origin) == AGAIN) {
            wait = AP_PROXY_BACKEND_OUT;
        }
        else {
            rv = ap_check_output_pending(c);
            if (rv == AGAIN) {
                wait = AP_PROXY_CLIENT_OUT;
            }
            else if (rv != OK) {
                return DONE; /* the client is gone */
            }
        }
        rv = proxy_http_request_forward_wait(req, wait,
                                             (wait == AP_PROXY_CLIENT_IN
                                              && APR_STATUS_IS_EAGAIN(status))
                                             ? AP_PROXY_WAIT_DRAINED : 0);
        if (rv == SUSPENDED) {
            return SUSPENDED;
        }
        if (rv == AGAIN) {
            goto read_again; /* ready within ProxyAsyncDelay */
        }
        req->can_suspend = 0; /* can't wait: block */
        if (wait == AP_PROXY_CLIENT_OUT) {
            /* The blocking read won't write what's pending for the client
             * (the 100 Continue it waits for), so flush it first.
             */
            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(bb->bucket_alloc));
            if (ap_pass_brigade(c->output_filters, bb) != APR_SUCCESS) {
                return DONE;
            }
            apr_brigade_cleanup(bb);
        }
        return ap_proxy_read_input(r, req->backend, bb, HUGE_STRING_LEN);
    }
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO()
                      "read request body failed to %pI (%s)"
                      " from %s (%s)", req->backend->addr,
                      req->backend->hostname ? req->backend->hostname : "",
                      c->client_ip, c->remote_host ? c->remote_host : "");
        return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
    }
    req->request_timed_out = 0; /* data came in the meantime */
    return OK;
}

static int stream_reqbody(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    int seen_eos = 0, rv = OK;
    apr_size_t hdr_len;
    char chunk_hdr[20];  /* must be here due to transient bucket. */
    conn_rec *origin = req->origin;
    proxy_conn_rec *p_conn = req->backend;
    apr_bucket_alloc_t *bucket_alloc = req->bucket_alloc;
    apr_bucket_brigade *header_brigade = req->header_brigade;
    apr_bucket_brigade *input_brigade = req->input_brigade;
    rb_methods rb_method = req->rb_method;
    apr_off_t bytes, bytes_streamed = req->bytes_streamed;
    apr_bucket *e;

    do {
        if (APR_BRIGADE_EMPTY(input_brigade)
                && APR_BRIGADE_EMPTY(header_brigade)) {
            if (req->can_suspend) {
                rv = proxy_http_request_read_body(req);
                if (rv == SUSPENDED) {
                    req->bytes_streamed = bytes_streamed;
                    return SUSPENDED;
                }
            }
            else {
                rv = ap_proxy_read_input(r, p_conn, input_brigade,
                                         HUGE_STRING_LEN);
            }
            if (rv != OK) {
                return rv;
            }
        }

        if (!APR_BRIGADE_EMPTY(input_brigade)) {
            /* If this brigade contains EOS, remove it and be done. */
            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
                seen_eos = 1;

                /* We can't pass this EOS to the output_filters. */
                e = APR_BRIGADE_LAST(input_brigade);
                apr_bucket_delete(e);
            }

            apr_brigade_length(input_brigade, 1, &bytes);
            bytes_streamed += bytes;

            if (rb_method == RB_STREAM_CHUNKED) {
                if (bytes) {
                    /*
                     * Prepend the size of the chunk
                     */
                    hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                           "%" APR_UINT64_T_HEX_FMT CRLF,
                                           (apr_uint64_t)bytes);
                    ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
                    e = apr_bucket_transient_create(chunk_hdr, hdr_len,
                                                    bucket_alloc);
                    APR_BRIGADE_INSERT_HEAD(input_brigade, e);

                    /*
                     * Append the end-of-chunk CRLF
                     */
                    e = apr_bucket_immortal_create(CRLF_ASCII, 2, bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(input_brigade, e);
                }
                if (seen_eos) {
                    ap_h1_add_end_chunk(input_brigade, NULL, r, r->trailers_in);
                }
            }
            else if (rb_method == RB_STREAM_CL
                     && (bytes_streamed > req->cl_val
                         || (seen_eos && bytes_streamed < req->cl_val))) {
                /* C-L != bytes streamed?!?
                 *
                 * Prevent HTTP Request/Response Splitting.
                 *
                 * We can't stream more (or less) bytes at the back end since
                 * they could be interpreted in separate requests (more bytes
                 * now would start a new request, less bytes would make the
                 * first bytes of the next request be part of the current one).
                 *
                 * It can't happen from the client connection here thanks to
                 * ap_http_filter(), but some module's filter may be playing
                 * bad games, hence the HTTP_INTERNAL_SERVER_ERROR.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01086)
                              "read %s bytes of request body than expected "
                              "(got %" APR_OFF_T_FMT ", expected "
                              "%" APR_OFF_T_FMT ")",
                              bytes_streamed > req->cl_val ? "more" : "less",
                              bytes_streamed, req->cl_val);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (seen_eos && apr_table_get(r->subprocess_env,
                                          "proxy-sendextracrlf")) {
                e = apr_bucket_immortal_create(CRLF_ASCII, 2, bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(input_brigade, e);
            }
        }

        /* If we never sent the header brigade, go ahead and take care of
         * that now by prepending it (once only since header_brigade will be
         * empty afterward).
         */
        APR_BRIGADE_PREPEND(input_brigade, header_brigade);

        if (req->can_suspend) {
            /* Don't block on the backend (WC). Wait for it in the MPM when
             * too much is pending (backpressure: nothing more is read from
             * the client meanwhile), and at EOS until it has taken
             * everything (the response is waited for afterward).
             */
            APR_BRIGADE_INSERT_TAIL(input_brigade,
                                    ap_bucket_wc_create(bucket_alloc));
            rv = ap_proxy_pass_brigade(bucket_alloc, r, p_conn, origin,
                                       input_brigade, 0);
            if (rv != OK) {
                return rv;
            }
            while (seen_eos
                   ? ap_check_output_pending(origin) == AGAIN
                   : ap_filter_should_yield(origin->output_filters)) {
                req->request_eos = seen_eos;
                req->bytes_streamed = bytes_streamed;
                rv = proxy_http_request_forward_wait(req, AP_PROXY_BACKEND_OUT,
                                                     0);
                if (rv == SUSPENDED) {
                    return SUSPENDED;
                }
                if (rv == AGAIN) {
                    /* Writable within ProxyAsyncDelay: write the rest at EOS,
                     * otherwise read more first.
                     */
                    if (seen_eos) {
                        continue;
                    }
                    break;
                }
                /* can't wait: block */
                req->can_suspend = 0;
                rv = ap_proxy_pass_brigade(bucket_alloc, r, p_conn, origin,
                                           input_brigade, 1);
                if (rv != OK) {
                    return rv;
                }
                break;
            }
        }
        else {
            /* Flush here on EOS because we won't ap_proxy_read_input() again. */
            rv = ap_proxy_pass_brigade(bucket_alloc, r, p_conn, origin,
                                       input_brigade, seen_eos);
            if (rv != OK) {
                return rv;
            }
        }
    } while (!seen_eos);

    req->request_eos = 1;
    req->bytes_streamed = bytes_streamed;
    return OK;
}

/* Once the request is sent (asynchronously), wait for the response and
 * process it (proxy_http_handler()'s Step Five). Returns SUSPENDED if
 * waiting in the MPM, otherwise the status to finish the request with.
 */
static int proxy_http_request_sent(proxy_http_req_t *req)
{
    int status;

    if (req->can_suspend) {
        status = proxy_http_response_head_wait(req);
        if (status == SUSPENDED) {
            return SUSPENDED;
        }
    }
    return ap_proxy_http_process_response(req);
}

/* The continuation of proxy_http_request_forward_wait(), called when the
 * backend can take more of the pending output or the client sent more of the
 * body (or on timeout or error): continue sending the request, then wait for
 * the response.
 */
static void proxy_http_request_forward_continuation(request_rec *r,
                                                    apr_status_t rv,
                                                    void *baton)
{
    proxy_http_req_t *req = baton;
    conn_rec *c = r->connection;
    int status;

    AP_DEBUG_ASSERT(req->r == r);
    if (APR_STATUS_IS_TIMEUP(rv) && req->direction == AP_PROXY_CLIENT_IN) {
        /* Read the body once more: the read fails on mod_reqtimeout's
         * deadline, or proxy_http_request_read_body() answers the timeout if
         * there's still nothing to read (a 408 either way), unless the client
         * sent some in the meantime.
         */
        req->request_timed_out = 1;
    }
    else if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: %s waiting for the %s while sending the "
                      "request (async)", req->proto,
                      APR_STATUS_IS_TIMEUP(rv) ? "timeout" : "error",
                      proxy_http_direction_names[req->direction]);
        if (req->direction == AP_PROXY_BACKEND_OUT) {
            apr_table_setn(r->notes, "proxy_timedout", "1");
            status = HTTP_GATEWAY_TIME_OUT;
        }
        else {
            status = HTTP_REQUEST_TIME_OUT;
        }
        proxy_http_async_finish(req, status);
        return;
    }

    if (req->direction == AP_PROXY_CLIENT_OUT) {
        /* Write what's pending to the client (the 100 Continue it waits
         * for) before reading more from it.
         */
        int rc;
        while ((rc = ap_check_output_pending(c)) == AGAIN) {
            apr_bucket_brigade *bb = req->input_brigade;

            rc = proxy_http_request_forward_wait(req, AP_PROXY_CLIENT_OUT, 0);
            if (rc == SUSPENDED) {
                return;
            }
            if (rc == AGAIN) {
                continue; /* writable within ProxyAsyncDelay */
            }
            /* can't wait: block */
            req->can_suspend = 0;
            apr_brigade_cleanup(bb);
            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(bb->bucket_alloc));
            rc = (ap_pass_brigade(c->output_filters, bb) == APR_SUCCESS) ? OK : DONE;
            apr_brigade_cleanup(bb);
            break;
        }
        if (rc != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                          "proxy %s: client gone while sending the request "
                          "(async)", req->proto);
            proxy_http_async_finish(req, DONE);
            return;
        }
    }
    else if (req->direction == AP_PROXY_BACKEND_OUT) {
        /* Write what's pending to the backend */
        int rc;
        while ((rc = ap_check_output_pending(req->origin)) == AGAIN) {
            rc = proxy_http_request_forward_wait(req, AP_PROXY_BACKEND_OUT, 0);
            if (rc == SUSPENDED) {
                return;
            }
            if (rc == AGAIN) {
                continue; /* writable within ProxyAsyncDelay */
            }
            /* can't wait: block */
            req->can_suspend = 0;
            apr_brigade_cleanup(req->input_brigade);
            rc = ap_proxy_pass_brigade(req->bucket_alloc, r, req->backend,
                                       req->origin, req->input_brigade, 1);
            break;
        }
        if (rc != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                          "proxy %s: pass request to %pI (%s) failed "
                          "(async)", req->proto, req->backend->addr,
                          req->backend->hostname);
            proxy_http_async_finish(req, HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (!req->request_eos) {
        status = stream_reqbody(req);
        if (status == SUSPENDED) {
            return; /* continued later */
        }
        if (status != OK) {
            proxy_http_async_finish(req, status);
            return;
        }
    }

    status = proxy_http_request_sent(req);
    if (status == SUSPENDED) {
        return; /* waiting for the response (or while streaming its body) */
    }
    proxy_http_async_finish(req, status);
}

static void terminate_headers(proxy_http_req_t *req)
{
    /*
     * Handle Connection: header if we do HTTP/1.1 request:
     * If we plan to close the backend connection sent Connection: close
     * otherwise sent Connection: Keep-Alive.
     */
    if (!req->force10) {
        if (req->upgrade) {
            /* Tell the backend that it can upgrade the connection. */
            ap_h1_append_header(req->header_brigade, req->p, "Connection", "Upgrade");
            ap_h1_append_header(req->header_brigade, req->p, "Upgrade", req->upgrade);
        }
        else if (ap_proxy_connection_reusable(req->backend)) {
            ap_h1_append_header(req->header_brigade, req->p, "Connection", "Keep-Alive");
        }
        else {
            ap_h1_append_header(req->header_brigade, req->p, "Connection", "close");
        }
    }

    /* add empty line at the end of the headers */
    ap_h1_terminate_header(req->header_brigade);
}

static int ap_proxy_http_prefetch(proxy_http_req_t *req,
                                  apr_uri_t *uri, char *url)
{
    apr_pool_t *p = req->p;
    request_rec *r = req->r;
    conn_rec *c = r->connection;
    proxy_conn_rec *p_conn = req->backend;
    apr_bucket_alloc_t *bucket_alloc = req->bucket_alloc;
    apr_bucket_brigade *header_brigade = req->header_brigade;
    apr_bucket_brigade *input_brigade = req->input_brigade;
    apr_bucket *e;
    apr_off_t bytes_read = 0;
    apr_off_t bytes;
    int rv;

    rv = ap_proxy_create_hdrbrgd(p, header_brigade, r, p_conn,
                                 req->worker, req->sconf,
                                 uri, url, req->server_portstr,
                                 &req->old_cl_val, &req->old_te_val);
    if (rv != OK) {
        return rv;
    }

    /* sub-requests never use keepalives, and mustn't pass request bodies.
     * Because the new logic looks at input_brigade, we will self-terminate
     * input_brigade and jump past all of the request body logic...
     * Reading anything with ap_get_brigade is likely to consume the
     * main request's body or read beyond EOS - which would be unpleasant.
     *
     * An exception: when a kept_body is present, then subrequest CAN use
     * pass request bodies, and we DONT skip the body.
     */
    if (!r->kept_body && r->main) {
        /* XXX: Why DON'T sub-requests use keepalives? */
        p_conn->close = 1;
        req->old_te_val = NULL;
        req->old_cl_val = NULL;
        req->rb_method = RB_STREAM_CL;
        e = apr_bucket_eos_create(input_brigade->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
        goto skip_body;
    }

    /* WE only understand chunked.  Other modules might inject
     * (and therefore, decode) other flavors but we don't know
     * that the can and have done so unless they remove
     * their decoding from the headers_in T-E list.
     * XXX: Make this extensible, but in doing so, presume the
     * encoding has been done by the extensions' handler, and
     * do not modify add_te_chunked's logic
     */
    if (req->old_te_val && ap_cstr_casecmp(req->old_te_val, "chunked") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01093)
                      "%s Transfer-Encoding is not supported",
                      req->old_te_val);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (req->old_cl_val && req->old_te_val) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01094)
                      "client %s (%s) requested Transfer-Encoding "
                      "chunked body with Content-Length (C-L ignored)",
                      c->client_ip, c->remote_host ? c->remote_host: "");
        req->old_cl_val = NULL;
        p_conn->close = 1;
    }

    rv = ap_proxy_prefetch_input(r, req->backend, input_brigade,
                                 req->prefetch_nonblocking ? APR_NONBLOCK_READ
                                                           : APR_BLOCK_READ,
                                 &bytes_read, MAX_MEM_SPOOL);
    if (rv != OK) {
        return rv;
    }

    /*
     * The request body is streamed by default, using either content-length
     * or chunked transfer-encoding, like this:
     *
     *   The whole body (including no body) was received on prefetch, i.e.
     *   the input brigade ends with EOS => RB_STREAM_CL.
     *
     *   C-L is known and reliable, i.e. only protocol filters in the input
     *   chain thus none should change the body => RB_STREAM_CL.
     *
     *   The administrator has not SetEnv "force-proxy-request-1.0" or
     *   "proxy-sendcl" which prevents T-E => RB_STREAM_CHUNKED.
     *
     * Otherwise we need to determine and set a content-length, so spool the
     * entire request body to memory or temporary file (above MAX_MEM_SPOOL),
     * such that we finally know its length => RB_SPOOL_CL.
     */
    if (!APR_BRIGADE_EMPTY(input_brigade)
        && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
        /* The whole thing fit, so our decision is trivial, use
         * the filtered bytes read from the client for the request
         * body Content-Length.
         *
         * If we expected no body, and read no body, do not set
         * the Content-Length.
         */
        if (req->old_cl_val || req->old_te_val || bytes_read) {
            req->old_cl_val = apr_off_t_toa(r->pool, bytes_read);
            req->cl_val = bytes_read;
        }
        req->rb_method = RB_STREAM_CL;
    }
    else if (req->old_cl_val && r->input_filters == r->proto_input_filters) {
        /* Streaming is possible by preserving the existing C-L */
        if (!ap_parse_strict_length(&req->cl_val, req->old_cl_val)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01085)
                          "could not parse request Content-Length (%s)",
                          req->old_cl_val);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        req->rb_method = RB_STREAM_CL;
    }
    else if (!req->force10 && !apr_table_get(r->subprocess_env,
                                             "proxy-sendcl")) {
        /* Streaming is possible using T-E: chunked */
        req->rb_method = RB_STREAM_CHUNKED;
    }
    else {
        /* No streaming, C-L is the only option so spool to memory/file */
        req->rb_method = RB_SPOOL_CL;
    }

    switch (req->rb_method) {
    case RB_STREAM_CHUNKED:
        add_te_chunked(req->p, bucket_alloc, header_brigade);
        break;

    case RB_STREAM_CL:
        if (req->old_cl_val) {
            add_cl(req->p, bucket_alloc, header_brigade, req->old_cl_val);
        }
        break;

    default: /* => RB_SPOOL_CL */
        /* Spool now, before connecting or reusing the backend connection
         * which could expire and be closed in the meantime.
         */
        rv = ap_proxy_spool_input(r, p_conn, input_brigade,
                                  &bytes, MAX_MEM_SPOOL);
        if (rv != OK) {
            return rv;
        }
        if (bytes || req->old_te_val || req->old_cl_val) {
            add_cl(p, bucket_alloc, header_brigade, apr_off_t_toa(p, bytes));
        }
    }

/* Yes I hate gotos.  This is the subrequest shortcut */
skip_body:
    terminate_headers(req);

    return OK;
}

/* With 100-continue, send the request's head only (the body follows the
 * backend's 100 Continue, see send_continue_body()). When async, without
 * blocking: if the backend doesn't take it all now, wait for it in the MPM,
 * then proxy_http_request_forward_continuation() flushes the rest and waits
 * for the response (req->request_eos, nothing more to send before the 100).
 * Returns OK, SUSPENDED or an error.
 */
static int send_continue_head(proxy_http_req_t *req)
{
    int rv;

    for (;;) {
        if (req->can_suspend) {
            /* Don't block on the backend (WC) */
            APR_BRIGADE_INSERT_TAIL(req->header_brigade,
                                    ap_bucket_wc_create(req->bucket_alloc));
        }
        /* (When blocking after a nonblocking pass, the brigade is empty and
         * this flushes what's pending.)
         */
        rv = ap_proxy_pass_brigade(req->bucket_alloc, req->r, req->backend,
                                   req->origin, req->header_brigade,
                                   !req->can_suspend);
        if (rv != OK || !req->can_suspend
            || ap_check_output_pending(req->origin) != AGAIN) {
            return rv;
        }
        req->request_eos = 1;
        rv = proxy_http_request_forward_wait(req, AP_PROXY_BACKEND_OUT, 0);
        if (rv == SUSPENDED) {
            return SUSPENDED;
        }
        if (rv != AGAIN) {
            req->can_suspend = 0; /* can't wait: block */
        }
    }
}

/* With 100-continue, send the request's body once the backend says so
 * (ap_proxy_http_process_response()): fully, or SUSPENDED if req->can_suspend
 * then proxy_http_request_forward_continuation() continues.
 */
static int send_continue_body(proxy_http_req_t *req)
{
    int status;

    /* The body is to be sent now, send_continue_head() may have left
     * req->request_eos set (nothing more to send before the 100) if it waited.
     */
    req->request_eos = 0;

    switch(req->rb_method) {
    case RB_SPOOL_CL:
    case RB_STREAM_CL:
    case RB_STREAM_CHUNKED:
        status = stream_reqbody(req);
        break;
    default:
        /* Shouldn't happen */
        status = HTTP_INTERNAL_SERVER_ERROR;
        break;
    }
    if (status != OK && status != SUSPENDED) {
        conn_rec *c = req->r->connection;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req->r,
                APLOGNO(10154) "pass request body failed "
                "to %pI (%s) from %s (%s) with status %i",
                req->backend->addr,
                req->backend->hostname ? req->backend->hostname : "",
                c->client_ip, c->remote_host ? c->remote_host : "",
                status);
        req->backend->close = 1;
    }
    return status;
}

/* With 100-continue pending, the backend may answer a final response instead
 * of the 100 Continue and keep the connection, reading (and discarding) the
 * body (RFC 9110 10.1.1), which must then be sent for the connection to be
 * reused, before the response is processed. When that final head is read
 * (proxy_http_response_read_heads()) and the client doesn't wait for a 100 itself
 * (its body is read then), send the body without blocking first, then the
 * processing has nothing more to send (it sends the body itself otherwise, see
 * ap_proxy_http_process_response()). Returns OK, SUSPENDED
 * (proxy_http_request_forward_continuation() continues, then
 * proxy_http_request_sent()) or an error.
 */
/* apr_table_do() callback: 0 (stop) on a "Connection: close" */
static int connection_not_close(void *r, const char *key, const char *val)
{
    return !ap_find_token(((request_rec *)r)->pool, val, "close");
}

static int send_continue_body_before_final(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    const ap_h1_head_t *head;
    int keepalive = 0;

    if (!req->do_100_continue || !req->head_final || r->expecting_100) {
        return OK;
    }

    /* Does the backend keep the connection: HTTP/1.1+ without
     * "Connection: close"?
     */
    head = APR_ARRAY_IDX(req->heads, req->heads->nelts - 1, ap_h1_head_t *);
    if (head->proto_num >= HTTP_VERSION(1, 1)) {
        keepalive = apr_table_do(connection_not_close, r, head->headers,
                                 "Connection", NULL);
    }
    if (!keepalive) {
        /* Not sent: ap_proxy_http_process_response() then closes the
         * backend connection (in either mode), not reusable without it.
         */
        return OK;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "HTTP: final response instead of 100 Continue, sending "
                  "the body before processing it");
    req->do_100_continue = 0;
    return send_continue_body(req);
}

static int ap_proxy_http_request(proxy_http_req_t *req)
{
    int rv;
    request_rec *r = req->r;

    /* send the request header/body, if any. */
    switch (req->rb_method) {
    case RB_SPOOL_CL:
    case RB_STREAM_CL:
    case RB_STREAM_CHUNKED:
        if (req->do_100_continue) {
            rv = send_continue_head(req);
        }
        else {
            rv = stream_reqbody(req);
        }
        break;

    default:
        /* shouldn't be possible */
        rv = HTTP_INTERNAL_SERVER_ERROR;
        break;
    }

    if (rv == SUSPENDED) {
        /* Continues in proxy_http_request_forward_continuation() */
        return SUSPENDED;
    }
    if (rv != OK) {
        conn_rec *c = r->connection;
        /* apr_status_t value has been logged in lower level method */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01097)
                      "pass request body failed to %pI<>%pI (%s) from %s (%s)",
                      req->origin->local_addr,
                      req->backend->addr,
                      req->backend->hostname ? req->backend->hostname: "",
                      c->client_ip, c->remote_host ? c->remote_host: "");
        return rv;
    }

    return OK;
}

/*
 * If the date is a valid RFC 850 date or asctime() date, then it
 * is converted to the RFC 1123 format.
 */
static const char *date_canon(apr_pool_t *p, const char *date)
{
    apr_status_t rv;
    char* ndate;

    apr_time_t time = apr_date_parse_http(date);
    if (!time) {
        return date;
    }

    ndate = apr_palloc(p, APR_RFC822_DATE_LEN);
    rv = apr_rfc822_date(ndate, time);
    if (rv != APR_SUCCESS) {
        return date;
    }

    return ndate;
}

static request_rec *make_fake_req(conn_rec *c, request_rec *r)
{
    apr_pool_t *pool;
    request_rec *rp;

    apr_pool_create(&pool, c->pool);
    apr_pool_tag(pool, "proxy_http_rp");

    rp = apr_pcalloc(pool, sizeof(*r));

    rp->pool            = pool;
    rp->status          = HTTP_OK;

    rp->headers_in      = apr_table_make(pool, 50);
    rp->trailers_in     = apr_table_make(pool, 5);

    rp->subprocess_env  = apr_table_make(pool, 50);
    rp->headers_out     = apr_table_make(pool, 12);
    rp->trailers_out    = apr_table_make(pool, 5);
    rp->err_headers_out = apr_table_make(pool, 5);
    rp->notes           = apr_table_make(pool, 5);

    rp->server = r->server;
    rp->log = r->log;
    rp->proxyreq = r->proxyreq;
    rp->request_time = r->request_time;
    rp->connection      = c;
    rp->output_filters  = c->output_filters;
    rp->input_filters   = c->input_filters;
    rp->proto_output_filters  = c->output_filters;
    rp->proto_input_filters   = c->input_filters;
    rp->useragent_ip = c->client_ip;
    rp->useragent_addr = c->client_addr;

    rp->request_config  = ap_create_request_config(pool);
    proxy_run_create_req(r, rp);

    return rp;
}

/* How process_proxy_header() rewrites a response header */
typedef enum {
    PROXY_HDR_ASIS = 0,
    PROXY_HDR_DATE,         /* date_canon() */
    PROXY_HDR_LOCATION,     /* ap_proxy_location_reverse_map() */
    PROXY_HDR_COOKIE        /* ap_proxy_cookie_reverse_map() */
} proxy_hdr_e;

/* The rewriting of the header named key: the names rewritten have distinct
 * lengths, so one comparison tells
 */
static proxy_hdr_e proxy_header_kind(const char *key)
{
    const char *name;
    proxy_hdr_e kind;

    switch (strlen(key)) {
    case 3:
        name = "URI";
        kind = PROXY_HDR_LOCATION;
        break;
    case 4:
        name = "Date";
        kind = PROXY_HDR_DATE;
        break;
    case 7:
        name = "Expires";
        kind = PROXY_HDR_DATE;
        break;
    case 8:
        name = "Location";
        kind = PROXY_HDR_LOCATION;
        break;
    case 10:
        name = "Set-Cookie";
        kind = PROXY_HDR_COOKIE;
        break;
    case 11:
        name = "Destination";
        kind = PROXY_HDR_LOCATION;
        break;
    case 13:
        name = "Last-Modified";
        kind = PROXY_HDR_DATE;
        break;
    case 16:
        name = "Content-Location";
        kind = PROXY_HDR_LOCATION;
        break;
    default:
        return PROXY_HDR_ASIS;
    }
    return ap_cstr_casecmp(key, name) ? PROXY_HDR_ASIS : kind;
}

/* Add a response header to r->headers_out, rewritten if need be; key and
 * value are the parsed head's, in r->pool
 */
static void process_proxy_header(request_rec *r, proxy_dir_conf *c,
                                 const char *key, const char *value)
{
    switch (proxy_header_kind(key)) {
    case PROXY_HDR_DATE:
        apr_table_add(r->headers_out, key, date_canon(r->pool, value));
        break;
    case PROXY_HDR_LOCATION:
        apr_table_add(r->headers_out, key,
                      ap_proxy_location_reverse_map(r, c, value));
        break;
    case PROXY_HDR_COOKIE:
        apr_table_add(r->headers_out, key,
                      ap_proxy_cookie_reverse_map(r, c, value));
        break;
    default:
        apr_table_addn(r->headers_out, key, value);
        break;
    }
}

/* Add the headers of a response head to r->headers_out, through
 * process_proxy_header() (canonical dates, ProxyPassReverse and family),
 * duplicates kept.
 */
static void proxy_http_response_headers(request_rec *r, proxy_dir_conf *dconf,
                                        const ap_h1_head_t *head)
{
    const apr_array_header_t *arr = apr_table_elts(head->headers);
    const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
    int i;

    r->headers_out = apr_table_make(r->pool, 20);
    r->trailers_out = apr_table_make(r->pool, 5);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                  "Headers received from backend:");
    for (i = 0; i < arr->nelts; i++) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "%s: %s",
                      elts[i].key, elts[i].val);
        process_proxy_header(r, dconf, elts[i].key, elts[i].val);
    }
}

static int addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static int add_trailers(void *data, const char *key, const char *val)
{
    if (val) {
        apr_table_add((apr_table_t*)data, key, val);
    }
    return 1;
}

static void proxy_http_response_body_continuation(request_rec *r,
                                                  apr_status_t status,
                                                  void *baton);

/* While streaming the response body, wait for the client to drain the pending
 * output (AP_PROXY_CLIENT_OUT), or for the backend to be readable
 * (AP_PROXY_BACKEND_IN), with ap_proxy_wait(). Returns AGAIN if ready within
 * ProxyAsyncDelay (the caller goes on), SUSPENDED, or OK if we can't wait
 * asynchronously (the caller then blocks).
 */
static int proxy_http_response_body_wait(proxy_http_req_t *req,
                                         ap_proxy_direction_e direction,
                                         unsigned int flags)
{
    int for_client = (direction == AP_PROXY_CLIENT_OUT);
    request_rec *r = req->r;
    int rc;

    /* Wait for the client with the server's Timeout, and for the backend with
     * the proxy's timeout (ProxyAsyncIdleTimeout, or else the backend's).
     */
    rc = ap_proxy_wait(r, req->backend, direction, flags,
                       for_client ? r->server->timeout : req->idle_timeout,
                       proxy_http_response_body_continuation, req);
    if (rc == OK) {
        return AGAIN;
    }
    if (rc != SUSPENDED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "proxy %s: can't wait for the %s asynchronously",
                      req->proto, for_client ? "client" : "backend");
        return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy %s: body: waiting for the %s (async)",
                  req->proto, for_client ? "client" : "backend");
    req->direction = direction;
    return SUSPENDED;
}

/* Stream the response body from the backend to the client, resuming where it
 * stopped (the state is in req). Returns OK once done (with
 * req->backend_broke set if the backend failed half way), or SUSPENDED if
 * waiting in the MPM (only when req->can_suspend;
 * proxy_http_response_body_continuation() continues then).
 */
static int proxy_http_response_body(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    conn_rec *c = r->connection;
    proxy_conn_rec *backend = req->backend;
    apr_bucket_brigade *bb = req->response_bb;
    apr_bucket_brigade *pass_bb = req->response_pass_bb;
    apr_bucket *e;
    int finish = FALSE;

    do {
        apr_off_t readbytes;
        apr_status_t rv;
        int rc;

        rv = ap_get_brigade(backend->r->input_filters, bb,
                            AP_MODE_READBYTES, req->response_mode,
                            req->sconf->io_buffer_size);

        /* ap_get_brigade will return success with an empty brigade
         * for a non-blocking read which would block: */
        if (req->response_mode == APR_NONBLOCK_READ
            && (APR_STATUS_IS_EAGAIN(rv)
                || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(bb)))) {
            if (req->can_suspend) {
                /* Nothing to read from the backend yet: let the filters
                 * release what they hold without blocking on the client
                 * (WC), then wait in the MPM for the client to drain what's
                 * pending if any, otherwise for the backend.
                 */
                apr_brigade_cleanup(bb);
                e = ap_bucket_wc_create(c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                if (ap_pass_brigade(r->output_filters, bb)
                    || c->aborted) {
                    backend->close = 1;
                    break;
                }
                apr_brigade_cleanup(bb);
                if (ap_filter_should_yield(c->output_filters)) {
                    rc = proxy_http_response_body_wait(req,
                                                       AP_PROXY_CLIENT_OUT, 0);
                }
                else {
                    rc = proxy_http_response_body_wait(req,
                                                       AP_PROXY_BACKEND_IN,
                                                       APR_STATUS_IS_EAGAIN(rv)
                                                       ? AP_PROXY_WAIT_DRAINED
                                                       : 0);
                }
                if (rc == SUSPENDED) {
                    return SUSPENDED;
                }
                if (rc == AGAIN) {
                    continue; /* ready within ProxyAsyncDelay */
                }
                req->can_suspend = 0; /* can't wait: block */
            }
            /* flush to the client and switch to blocking mode */
            e = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            if (ap_pass_brigade(r->output_filters, bb)
                || c->aborted) {
                backend->close = 1;
                break;
            }
            apr_brigade_cleanup(bb);
            req->response_mode = APR_BLOCK_READ;
            continue;
        }
        if (rv == APR_EOF) {
            backend->close = 1;
            break;
        }
        if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
            int error_status = HTTP_BAD_GATEWAY;
            if (rv == APR_ENOSPC) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02475)
                              "Response chunk/line was too large to parse");
            }
            else if (rv == APR_ENOTIMPL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02476)
                              "Response Transfer-Encoding was not recognised");
            }
            else if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01110)
                              "Network error reading response");
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10293)
                              "Unexpected empty data reading response");
                error_status = HTTP_INTERNAL_SERVER_ERROR;
            }

            /* In this case, we are in real trouble because
             * our backend bailed on us. Given we're half way
             * through a response, our only option is to
             * disconnect the client too.
             */
            apr_brigade_cleanup(bb);
            ap_proxy_fill_error_brigade(r, error_status, bb, 1);
            ap_pass_brigade(r->output_filters, bb);

            req->backend_broke = 1;
            backend->close = 1;
            break;
        }
        /* next time try a non-blocking read */
        req->response_mode = APR_NONBLOCK_READ;

        if (!apr_is_empty_table(backend->r->trailers_in)) {
            apr_table_do(add_trailers, r->trailers_out,
                    backend->r->trailers_in, NULL);
            apr_table_clear(backend->r->trailers_in);
        }

        apr_brigade_length(bb, 0, &readbytes);
        backend->worker->s->read += readbytes;
#if DEBUGGING
        {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01111)
                      "readbytes: %#x", readbytes);
        }
#endif

        /* Switch the allocator lifetime of the buckets */
        rv = ap_proxy_buckets_lifetime_transform(r, bb, pass_bb);
        if (rv != APR_SUCCESS) {
            /* Same, half way through a response, our only option is
             * to notice the output filters and then disconnect the
             * client and backend.
             */
            if (!APR_BRIGADE_EMPTY(pass_bb)) {
                /* Pass what we have still */
                ap_pass_brigade(r->output_filters, pass_bb);
                apr_brigade_cleanup(pass_bb);
            }
            ap_proxy_fill_error_brigade(r, HTTP_INTERNAL_SERVER_ERROR,
                                        pass_bb, 1);
            ap_pass_brigade(r->output_filters, pass_bb);
            apr_brigade_cleanup(pass_bb);

            req->backend_broke = 1;
            backend->close = 1;
            break;
        }

        /* found the last brigade? */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(pass_bb))) {

            /* signal that we must leave */
            finish = TRUE;

            /* the brigade may contain transient buckets that contain
             * data that lives only as long as the backend connection.
             * Force a setaside so these transient buckets become heap
             * buckets that live as long as the request.
             */
            for (e = APR_BRIGADE_FIRST(pass_bb); e
                    != APR_BRIGADE_SENTINEL(pass_bb); e
                    = APR_BUCKET_NEXT(e)) {
                apr_bucket_setaside(e, r->pool);
            }

            /* finally it is safe to clean up the brigade from the
             * connection pool, as we have forced a setaside on all
             * buckets.
             */
            apr_brigade_cleanup(bb);

            /* make sure we release the backend connection as soon
             * as we know we are done, so that the backend isn't
             * left waiting for a slow client to eventually
             * acknowledge the data.
             */
            proxy_run_detach_backend(r, backend);
            ap_proxy_release_connection(backend->worker->s->scheme,
                    backend, r->server);
            /* Ensure that the backend is not reused */
            req->backend = NULL;

        }
        else if (req->can_suspend) {
            /* Don't block on the client (WC), see below */
            e = ap_bucket_wc_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pass_bb, e);
        }

        /* try send what we read */
        if (ap_pass_brigade(r->output_filters, pass_bb) != APR_SUCCESS
            || c->aborted) {
            /* Ack! Phbtt! Die! User aborted! */
            /* Only close backend if we haven't got all from the
             * backend. Furthermore if req->backend is NULL it is no
             * longer safe to fiddle around with backend as it might
             * be already in use by another thread.
             */
            if (req->backend) {
                /* this causes socket close below */
                req->backend->close = 1;
            }
            finish = TRUE;
        }

        /* make sure we always clean up after ourselves */
        apr_brigade_cleanup(pass_bb);
        apr_brigade_cleanup(bb);

        if (!finish && req->can_suspend && ap_filter_should_yield(c->output_filters)) {
            /* The client is slower than the backend: wait for it to drain
             * the pending output before reading more (backpressure).
             */
            rc = proxy_http_response_body_wait(req, AP_PROXY_CLIENT_OUT, 0);
            if (rc == SUSPENDED) {
                return SUSPENDED;
            }
            if (rc != AGAIN) {
                req->can_suspend = 0; /* can't wait: block */
            }
        }
    } while (!finish);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "end body send");
    return OK;
}

/* The status of a response whose body was streamed (as returned by
 * ap_proxy_http_process_response()).
 */
static int proxy_http_response_body_status(proxy_http_req_t *req)
{
    /* We have to cleanup bb brigade, because buckets inserted to it could be
     * created from scpool and this pool can be freed before this brigade. */
    apr_brigade_cleanup(req->response_bb);

    /* If our connection with the client is to be aborted, return DONE. */
    if (req->r->connection->aborted || req->backend_broke) {
        return DONE;
    }
    return OK;
}

/* The continuation of proxy_http_response_body_wait(), called when the client
 * or the backend is ready (or on timeout or error): continue streaming the
 * response body, and finish the request once done.
 */
static void proxy_http_response_body_continuation(request_rec *r,
                                                  apr_status_t rv,
                                                  void *baton)
{
    proxy_http_req_t *req = baton;
    conn_rec *c = r->connection;
    int status;

    AP_DEBUG_ASSERT(req->r == r);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: %s waiting for the %s while streaming the "
                      "response body (async)", req->proto,
                      APR_STATUS_IS_TIMEUP(rv) ? "timeout" : "error",
                      (req->direction == AP_PROXY_CLIENT_OUT) ? "client"
                                                              : "backend");
        /* Half way through the response, our only option is to disconnect
         * the client (as for a backend failure).
         */
        apr_brigade_cleanup(req->response_bb);
        ap_proxy_fill_error_brigade(r, HTTP_GATEWAY_TIME_OUT, req->response_bb, 1);
        ap_pass_brigade(r->output_filters, req->response_bb);
        req->backend_broke = 1;
        if (req->backend) {
            req->backend->close = 1;
        }
        proxy_http_async_finish(req, proxy_http_response_body_status(req));
        return;
    }

    if (req->direction == AP_PROXY_CLIENT_OUT) {
        /* Write what's pending to the client */
        int rc = ap_check_output_pending(c);
        if (rc == AGAIN) {
            rc = proxy_http_response_body_wait(req, AP_PROXY_CLIENT_OUT, 0);
            if (rc == SUSPENDED) {
                return;
            }
            if (rc != AGAIN) {
                req->can_suspend = 0; /* can't wait: block */
            }
        }
        else if (rc != OK) {
            /* The client is gone */
            if (req->backend) {
                req->backend->close = 1;
            }
            proxy_http_async_finish(req, proxy_http_response_body_status(req));
            return;
        }
    }

    status = proxy_http_response_body(req);
    if (status == SUSPENDED) {
        return; /* continued later */
    }
    proxy_http_async_finish(req, proxy_http_response_body_status(req));
}

static
int ap_proxy_http_process_response(proxy_http_req_t *req)
{
    apr_pool_t *p = req->p;
    request_rec *r = req->r;
    conn_rec *c = r->connection;
    proxy_worker *worker = req->worker;
    proxy_conn_rec *backend = req->backend;
    conn_rec *origin = req->origin;
    int do_100_continue;
    int status;

    const char *buf;
    apr_bucket *e;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *pass_bb;
    int interim_response = 0; /* non-zero whilst interim 1xx responses
                               * are being read. */
    apr_table_t *save_table;
    ap_h1_head_opts_t trailers_opts;
    static const char *const hop_by_hop_hdrs[] =
        {"Keep-Alive", "Proxy-Authenticate", "TE", "Trailer", "Upgrade", NULL};
    int i;
    const char *te = NULL;
    int original_status = r->status;
    const char *original_status_line = r->status_line;
    const char *proxy_status_line = NULL;
    apr_interval_time_t old_timeout = 0;
    proxy_dir_conf *dconf = req->dconf;
    int proxy_status = OK;

    /* A final response instead of the 100 Continue may need the body to be
     * sent before processing it, without blocking.
     */
    status = send_continue_body_before_final(req);
    if (status != OK) {
        return status; /* SUSPENDED included */
    }
    do_100_continue = req->do_100_continue;

    bb = apr_brigade_create(p, c->bucket_alloc);
    pass_bb = apr_brigade_create(p, c->bucket_alloc);

    /* Setup for 100-Continue timeout if appropriate */
    if (do_100_continue && worker->s->ping_timeout_set) {
        apr_socket_timeout_get(backend->sock, &old_timeout);
        if (worker->s->ping_timeout != old_timeout) {
            apr_status_t rc;
            rc = apr_socket_timeout_set(backend->sock, worker->s->ping_timeout);
            if (rc != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01101)
                              "could not set 100-Continue timeout");
            }
        }
    }

    /* Get response from the remote server, and pass it up the
     * filter chain
     */

    backend->r = make_fake_req(origin, r);
    /* In case anyone needs to know, this is a fake request that is really a
     * response.
     */
    backend->r->proxyreq = PROXYREQ_RESPONSE;
    /* A chunked body's trailers are read with the response heads' rules */
    ap_proxy_h1_head_opts(&trailers_opts, r, worker, AP_H1_HEAD_TRAILERS);
    ap_h1_set_trailers_opts(backend->r, &trailers_opts);
    apr_table_setn(r->notes, "proxy-source-port", apr_psprintf(r->pool, "%hu",
                   origin->local_addr->port));
    do {
        ap_h1_head_t *head;
        const char *upgrade = NULL;
        int major = 0, minor = 0;
        int toclose = 0;
        int rc;

        apr_brigade_cleanup(bb);

        rc = proxy_http_response_next_head(req, &head);
        if (rc == DONE || rc == HTTP_GATEWAY_TIME_OUT) {
            /* Closed, failed or timed out before or within the head */
            apr_status_t rv = ap_h1_head_parser_status(req->head_parser);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01102)
                          "error reading status line from remote "
                          "server %s:%d", backend->hostname, backend->port);
            if (rc == HTTP_GATEWAY_TIME_OUT) {
                apr_table_setn(r->notes, "proxy_timedout", "1");
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01103) "read timeout");
                if (do_100_continue) {
                    return ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE,
                                         "Timeout on 100-Continue");
                }
                /* A gateway timeout, as when waiting asynchronously
                 * (proxy_http_response_head_continuation()).
                 */
                return ap_proxyerror(r, HTTP_GATEWAY_TIME_OUT,
                                     "Timeout reading from remote server");
            }
            /*
             * If we are a reverse proxy request shutdown the connection
             * WITHOUT ANY response to trigger a retry by the client
             * if allowed (as for idempotent requests).
             * BUT currently we should not do this if the request is the
             * first request on a keepalive connection as browsers like
             * seamonkey only display an empty page in this case and do
             * not do a retry. We should also not do this on a
             * connection which times out; instead handle as
             * we normally would handle timeouts
             */
            if (r->proxyreq == PROXYREQ_REVERSE && c->keepalives) {

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01104)
                              "Closing connection to client because"
                              " reading from backend server %s:%d failed."
                              " Number of keepalives %i", backend->hostname,
                              backend->port, c->keepalives);

                ap_proxy_fill_error_brigade(r, HTTP_BAD_GATEWAY, bb, 1);
                ap_pass_brigade(r->output_filters, bb);
                /* Mark the backend connection for closing */
                backend->close = 1;
                if (origin->keepalives) {
                    /* We already had a request on this backend connection and
                     * might just have run into a keepalive race. Hence we
                     * think positive and assume that the backend is fine and
                     * we do not need to signal an error on backend side.
                     */
                    return OK;
                }
                /*
                 * This happened on our first request on this connection to the
                 * backend. This indicates something fishy with the backend.
                 * Return HTTP_INTERNAL_SERVER_ERROR to signal an unrecoverable
                 * server error. We do not worry about r->status code and a
                 * possible error response here as the ap_http_outerror_filter
                 * will fix all of this for us.
                 */
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            if (!c->keepalives) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01105)
                              "NOT Closing connection to client"
                              " although reading from backend server %s:%d"
                              " failed.",
                              backend->hostname, backend->port);
            }
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc != OK && (!head || !head->u.rsp.status)) {
            /* Not an HTTP/1 status line (an HTTP/0.9 response, which
             * mod_proxy_http never asks for, so rather another protocol),
             * or one too long or malformed (the parsing logged why).
             */
            backend->close = 1;
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                        apr_pstrcat(p, "Corrupt status line returned "
                                    "by remote server: ",
                                    (head) ? head->start_line : "", NULL));
        }
        if (rc != OK) {
            /* The headers are invalid (the parsing logged why) */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01106)
                          "bad HTTP/%d.%d header returned by %s (%s)",
                          HTTP_VERSION_MAJOR(head->proto_num),
                          HTTP_VERSION_MINOR(head->proto_num),
                          r->uri, r->method);
            backend->close = 1;
            /*
             * ap_send_error relies on a headers_out to be present. we
             * are in a bad position here.. so force everything we send out
             * to have nothing to do with the incoming packet
             */
            r->headers_out = apr_table_make(r->pool,1);
            r->status = HTTP_BAD_GATEWAY;
            r->status_line = ap_get_status_line(r->status);
            return r->status;
        }
        backend->worker->s->read += head->length;

        major = HTTP_VERSION_MAJOR(head->proto_num);
        minor = HTTP_VERSION_MINOR(head->proto_num);
        proxy_status = head->u.rsp.status;
        apr_table_setn(r->notes, "proxy-status",
                       apr_psprintf(r->pool, "%03d", proxy_status));
        /* 2616 requires the space in Status-Line, even without a reason */
        proxy_status_line = apr_psprintf(p, "%03d %s", proxy_status,
                                         head->u.rsp.reason);

        /* The status out of the front is the same as the status coming in
         * from the back, until further notice.
         */
        r->status = proxy_status;
        r->status_line = proxy_status_line;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "Status from backend: %d", proxy_status);

        /* read the headers. */
        /* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers*/
        /* Also, take care with headers with multiple occurrences. */

        /* First, tuck away all already existing cookies */
        save_table = apr_table_make(r->pool, 2);
        apr_table_do(addit_dammit, save_table, r->headers_out,
                     "Set-Cookie", NULL);

        /* shove the headers direct into r->headers_out */
        proxy_http_response_headers(r, dconf, head);

        /* Now, add in the just read cookies */
        apr_table_do(addit_dammit, save_table, r->headers_out,
                     "Set-Cookie", NULL);

        /* and now load 'em all in */
        if (!apr_is_empty_table(save_table)) {
            apr_table_unset(r->headers_out, "Set-Cookie");
            r->headers_out = apr_table_overlay(r->pool,
                                               r->headers_out,
                                               save_table);
        }

        /*
         * Save a possible Transfer-Encoding header as we need it later for
         * ap_http_filter to know where to end.
         */
        te = apr_table_get(r->headers_out, "Transfer-Encoding");

        /* can't have both Content-Length and Transfer-Encoding */
        if (te && apr_table_get(r->headers_out, "Content-Length")) {
            /*
             * 2616 section 4.4, point 3: "if both Transfer-Encoding
             * and Content-Length are received, the latter MUST be
             * ignored";
             *
             * To help mitigate HTTP Splitting, unset Content-Length
             * and shut down the backend server connection
             * XXX: We aught to treat such a response as uncachable
             */
            apr_table_unset(r->headers_out, "Content-Length");
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01107)
                          "server %s:%d returned Transfer-Encoding"
                          " and Content-Length",
                          backend->hostname, backend->port);
            backend->close = 1;
        }

        upgrade = apr_table_get(r->headers_out, "Upgrade");
        if (proxy_status == HTTP_SWITCHING_PROTOCOLS) {
            if (!upgrade || !req->upgrade || (strcasecmp(req->upgrade,
                                                         upgrade) != 0)) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     apr_pstrcat(p, "Unexpected Upgrade: ",
                                                 upgrade ? upgrade : "n/a",
                                                 " (expecting ",
                                                 req->upgrade ? req->upgrade
                                                              : "n/a", ")",
                                                 NULL));
            }
            backend->close = 1;

            /* RFC 9110 7.8: a server receiving both Upgrade and Expect:
             * 100-continue MUST send the 100 before the 101. Switching
             * with the body still held for that 100 would need to send
             * it before tunneling (and the backend to read it as such),
             * so refuse (before forwarding the 101 to the client).
             */
            if (do_100_continue && ap_request_has_body(r)) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     "Switching Protocols before "
                                     "100 Continue");
            }
        }

        /* strip connection listed hop-by-hop headers from response */
        toclose = ap_proxy_clear_connection_fn(r, r->headers_out);
        if (toclose) {
            backend->close = 1;
            if (toclose < 0) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     "Malformed connection header");
            }
        }

        if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
            ap_set_content_type(r, apr_pstrdup(p, buf));
        }
        if (!ap_is_HTTP_INFO(proxy_status)) {
            ap_proxy_pre_http_request(origin, backend->r);
        }

        /* Clear hop-by-hop headers */
        for (i=0; hop_by_hop_hdrs[i]; ++i) {
            apr_table_unset(r->headers_out, hop_by_hop_hdrs[i]);
        }

        /* Delete warnings with wrong date */
        r->headers_out = ap_proxy_clean_warnings(p, r->headers_out);

        /* handle Via header in response */
        if (req->sconf->viaopt != via_off
                && req->sconf->viaopt != via_block) {
            const char *server_name = ap_get_server_name(r);
            /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
             * then the server name returned by ap_get_server_name() is the
             * origin server name (which does make too much sense with Via: headers)
             * so we use the proxy vhost's name instead.
             */
            if (server_name == r->hostname)
                server_name = r->server->server_hostname;
            /* create a "Via:" response header entry and merge it */
            apr_table_addn(r->headers_out, "Via",
                           (req->sconf->viaopt == via_full)
                                 ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                       HTTP_VERSION_MAJOR(r->proto_num),
                                       HTTP_VERSION_MINOR(r->proto_num),
                                       server_name,
                                       req->server_portstr,
                                       AP_SERVER_BASEVERSION)
                                 : apr_psprintf(p, "%d.%d %s%s",
                                       HTTP_VERSION_MAJOR(r->proto_num),
                                       HTTP_VERSION_MINOR(r->proto_num),
                                       server_name,
                                       req->server_portstr)
            );
        }

        /* cancel keepalive if HTTP/1.0 or less */
        if ((major < 1) || (minor < 1)) {
            backend->close = 1;
            origin->keepalive = AP_CONN_CLOSE;
        }
        else {
            /*
             * Keep track of the number of keepalives we processed on this
             * connection.
             */
            origin->keepalives++;
        }


        if (ap_is_HTTP_INFO(proxy_status)) {
            const char *policy = NULL;

            /* RFC2616 tells us to forward this.
             *
             * OTOH, an interim response here may mean the backend
             * is playing sillybuggers.  The Client didn't ask for
             * it within the defined HTTP/1.1 mechanisms, and if
             * it's an extension, it may also be unsupported by us.
             *
             * There's also the possibility that changing existing
             * behaviour here might break something.
             *
             * So let's make it configurable.
             *
             * We need to force "r->expecting_100 = 1" for RFC behaviour
             * otherwise ap_send_interim_response() does nothing when
             * the client did not ask for 100-continue.
             *
             * 101 Switching Protocol has its own configuration which
             * shouldn't be interfered by "proxy-interim-response".
             */
            if (proxy_status != HTTP_SWITCHING_PROTOCOLS) {
                policy = apr_table_get(r->subprocess_env,
                                       "proxy-interim-response");
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "HTTP: received interim %d response (policy: %s)",
                          r->status, policy ? policy : "n/a");
            if (!policy
                    || (!strcasecmp(policy, "RFC")
                        && (proxy_status != HTTP_CONTINUE
                            || (r->expecting_100 = 1)))) {
                apr_status_t rv;

                switch (proxy_status) {
                case HTTP_SWITCHING_PROTOCOLS:
                    AP_DEBUG_ASSERT(upgrade != NULL);
                    apr_table_setn(r->headers_out, "Connection", "Upgrade");
                    apr_table_setn(r->headers_out, "Upgrade",
                                   apr_pstrdup(p, upgrade));
                    break;
                }
                /* Async: what can't be written now is written before waiting
                 * for the client (see proxy_http_request_read_body()), or with
                 * the final response, or for a 101 by the tunnel before it
                 * forwards anything (it starts with the client's pending
                 * output, see ap_proxy_tunnel_create()).
                 */
                rv = ap_send_interim_response_ex(r, 1,
                                                 req->can_suspend
                                                 ? AP_SEND_INTERIM_NONBLOCK
                                                 : 0);
                /* A client gone is noticed by the final response's write,
                 * but there's none after a 101: don't tunnel for nobody
                 * (the backend connection is upgraded already, close it).
                 */
                if (proxy_status == HTTP_SWITCHING_PROTOCOLS
                    && rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, APLOGNO()
                                  "proxy: client gone while sending the 101 "
                                  "for %s", upgrade);
                    r->connection->keepalive = AP_CONN_CLOSE;
                    backend->close = 1;
                    return DONE;
                }
            }
            /* FIXME: refine this to be able to specify per-response-status
             * policies and maybe also add option to bail out with 502
             */
            else if (strcasecmp(policy, "Suppress")) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01108)
                              "undefined proxy interim response policy");
            }
            interim_response++;
        }
        else {
            interim_response = 0;
        }

        /* If we still do 100-continue (end-to-end or ping), either the
         * current response is the expected "100 Continue" and we are done
         * with this mode, or this is another interim response and we'll wait
         * for the next one, or this is a final response and hence the backend
         * did not honor our expectation.
         */
        if (do_100_continue && (!interim_response
                                || proxy_status == HTTP_CONTINUE)) {
            /* RFC 7231 - Section 5.1.1 - Expect - Requirement for servers
             *   A server that responds with a final status code before
             *   reading the entire message body SHOULD indicate in that
             *   response whether it intends to close the connection or
             *   continue reading and discarding the request message.
             *
             * So, if this response is not an interim 100 Continue, we can
             * avoid sending the request body if the backend responded with
             * "Connection: close" or HTTP < 1.1, and either let the core
             * discard it or the caller try another balancer member with the
             * same body (given status 503, though not implemented yet).
             * Nor if the client waits for a 100 Continue (end-to-end), which
             * won't come with a final response: its body can't be read, so
             * the backend connection is closed instead (below).
             *
             * When async, a final response keeping the connection had the
             * body sent before its processing, its head pre-read
             * (send_continue_body_before_final(), then this is not reached);
             * were the head not pre-read, the backend connection would be
             * closed too rather than sending the body blocking.
             */
            int do_send_body = (proxy_status == HTTP_CONTINUE
                                || (!toclose && major > 0 && minor > 0
                                    && !r->expecting_100
                                    && !req->can_suspend));

            /* Reset to old timeout iff we've adjusted it. */
            if (worker->s->ping_timeout_set) {
                apr_socket_timeout_set(backend->sock, old_timeout);
            }

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10153)
                          "HTTP: %s100 continue sent by %pI (%s): "
                          "%ssending body (response: HTTP/%i.%i %s)",
                          proxy_status != HTTP_CONTINUE ? "no " : "",
                          backend->addr,
                          backend->hostname ? backend->hostname : "",
                          do_send_body ? "" : "not ",
                          major, minor, proxy_status_line);

            if (do_send_body) {
                if (proxy_status == HTTP_CONTINUE) {
                    /* If the client still waits for a 100 Continue (the
                     * backend's not forwarded, e.g. "proxy-interim-response
                     * Suppress"), HTTP_IN sends it when reading the body, but
                     * only with a successful r->status: restore the original
                     * one, the next (final) response sets its own.
                     */
                    r->status = original_status;
                    r->status_line = original_status_line;

                    if (req->can_suspend) {
                        /* Send the body without blocking, then wait for the
                         * final response as after any async send
                         * (proxy_http_request_sent(), directly or from
                         * proxy_http_request_forward_continuation()), which
                         * processes it from the start: this call is done with
                         * the 100 Continue.
                         */
                        req->do_100_continue = 0;
                        status = send_continue_body(req);
                        if (status != OK) {
                            return status; /* SUSPENDED included */
                        }
                        return proxy_http_request_sent(req);
                    }
                }
                /* Otherwise a final response with the backend keeping the
                 * connection (and the client not waiting for a 100), when
                 * blocking: send the body before processing it.
                 */
                status = send_continue_body(req);
                if (status != OK) {
                    return status;
                }
            }
            else {
                /* If we don't read the client connection any further, since
                 * there are pending data it should be "Connection: close"d to
                 * prevent reuse. We don't exactly c->keepalive = AP_CONN_CLOSE
                 * here though, because error_override or a potential retry on
                 * another backend could finally read that data and finalize
                 * the request processing, making keep-alive possible. So what
                 * we do is leaving r->expecting_100 alone, ap_set_keepalive()
                 * will do the right thing according to the final response and
                 * any later update of r->expecting_100.
                 *
                 * The backend connection is out of sync if the backend keeps
                 * it for the body that we don't send, so close it.
                 */
                backend->close = 1;
            }

            /* Once only! */
            do_100_continue = 0;
        }

        if (proxy_status == HTTP_SWITCHING_PROTOCOLS) {
            apr_status_t rv;

            /* Still expecting the 100 Continue here means no body (a 101
             * before the 100 with a body is refused above): nothing more to
             * send before tunneling, the request's head was sent already.
             */
            if (do_100_continue) {
                r->expecting_100 = 0;
            }

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10239)
                          "HTTP: tunneling protocol %s", upgrade);

            rv = ap_proxy_tunnel_create(&req->tunnel, r, origin, upgrade);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10240)
                              "can't create tunnel for %s", upgrade);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            r->status = HTTP_SWITCHING_PROTOCOLS;
            req->proto = upgrade;
            req->upgraded = 1;

            /* Tunnel asynchronously as any wait (when the MPM can wait, see
             * ap_proxy_tunnel_run_ex()), a tunnel holding a thread for its
             * whole life otherwise, unless disabled (ProxyAsyncDelay -1):
             * with req->idle_timeout (ProxyAsyncIdleTimeout if set), this
             * thread forwards what's ready, then the MPM waits for the
             * connections, and proxy_http_tunnel_done() finishes. Otherwise
             * the whole tunneling happens now in this thread, with the
             * proxy's timeout.
             */
            status = ap_proxy_tunnel_run_ex(req->tunnel, req->idle_timeout,
                                            req->can_suspend ? proxy_http_tunnel_done
                                                             : NULL,
                                            req);
            if (status == SUSPENDED) {
                /* The MPM arms the wait once the handler returns SUSPENDED */
                return SUSPENDED;
            }
            proxy_http_tunnel_end(req, status);
            return DONE;
        }

        if (interim_response) {
            /* Already forwarded above, read next response */
            continue;
        }

        /* The fixups of Date headers and those affected by
         * ProxyPassReverse/etc are in proxy_http_response_headers()
         */

        /* PR 41646: get HEAD right with ProxyErrorOverride */
        if (ap_proxy_should_override(dconf, proxy_status)) {
            if (proxy_status == HTTP_UNAUTHORIZED) {
                const char *buf;
                const char *wa = "WWW-Authenticate";
                if ((buf = apr_table_get(r->headers_out, wa))) {
                    apr_table_set(r->err_headers_out, wa, buf);
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01109)
                                  "origin server sent 401 without "
                                  "WWW-Authenticate header");
                }
            }
            /* clear r->status for override error, otherwise ErrorDocument
             * thinks that this is a recursive error, and doesn't find the
             * custom error page
             */
            r->status = HTTP_OK;
            /* Discard body, if one is expected (not HEAD request) */
            if (!r->header_only) {
                const char *tmp;
                /* Add minimal headers needed to allow http_in filter
                 * detecting end of body without waiting for a timeout. */
                if ((tmp = apr_table_get(r->headers_out, "Transfer-Encoding"))) {
                    apr_table_set(backend->r->headers_in, "Transfer-Encoding", tmp);
                }
                else if ((tmp = apr_table_get(r->headers_out, "Content-Length"))) {
                    apr_table_set(backend->r->headers_in, "Content-Length", tmp);
                }
                else if (te) {
                    apr_table_set(backend->r->headers_in, "Transfer-Encoding", te);
                }
                ap_discard_request_body(backend->r);
            }
            /*
             * prevent proxy_handler() from treating this as an
             * internal error.
             */
            apr_table_setn(r->notes, "proxy-error-override", "1");
            return proxy_status;
        }

        /* Forward back Upgrade header if it matches the configured one(s), it
         * may be an HTTP_UPGRADE_REQUIRED response or some other status where
         * Upgrade makes sense to negotiate the protocol by other means.
         */
        if (upgrade && ap_proxy_worker_can_upgrade(p, worker, upgrade,
                                                   (*req->proto == 'w')
                                                   ? "WebSocket" : NULL)) {
            apr_table_setn(r->headers_out, "Connection", "Upgrade");
            apr_table_setn(r->headers_out, "Upgrade", apr_pstrdup(p, upgrade));
        }

        r->sent_bodyct = 1;
        /* send body - but only if a body is expected */
        if (!r->header_only && !AP_STATUS_IS_HEADER_ONLY(proxy_status)) {

            /* We need to copy the output headers and treat them as input
             * headers as well.  BUT, we need to do this before we remove
             * TE, so that they are preserved accordingly for
             * ap_http_filter to know where to end.
             */
            backend->r->headers_in = apr_table_clone(backend->r->pool, r->headers_out);
            /*
             * Restore Transfer-Encoding header from response if we saved
             * one before and there is none left. We need it for the
             * ap_http_filter. See above.
             */
            if (te && !apr_table_get(backend->r->headers_in, "Transfer-Encoding")) {
                apr_table_add(backend->r->headers_in, "Transfer-Encoding", te);
            }

            apr_table_unset(r->headers_out,"Transfer-Encoding");

            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "start body send");

            /* read the body, pass it to the output filters */

            /* Handle the case where the error document is itself reverse
             * proxied and was successful. We must maintain any previous
             * error status so that an underlying error (eg HTTP_NOT_FOUND)
             * doesn't become an HTTP_OK.
             */
            if (ap_proxy_should_override(dconf, original_status)) {
                r->status = original_status;
                r->status_line = original_status_line;
            }

            req->response_bb = bb;
            req->response_pass_bb = pass_bb;
            req->response_mode = APR_NONBLOCK_READ;
            /* Asynchronously when req->can_suspend, as when waiting for the
             * response head (see proxy_http_handler()).
             */
            status = proxy_http_response_body(req);
            if (status == SUSPENDED) {
                /* Continues in proxy_http_response_body_continuation() */
                return SUSPENDED;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "header only");

            /* make sure we release the backend connection as soon
             * as we know we are done, so that the backend isn't
             * left waiting for a slow client to eventually
             * acknowledge the data.
             */
            proxy_run_detach_backend(r, backend);
            ap_proxy_release_connection(backend->worker->s->scheme,
                    backend, r->server);
            /* Ensure that the backend is not reused */
            req->backend = NULL;

            /* Pass EOS bucket down the filter chain. */
            e = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            ap_pass_brigade(r->output_filters, bb);

            apr_brigade_cleanup(bb);
        }
    } while (interim_response && (interim_response < AP_MAX_INTERIM_RESPONSES));

    /* We have to cleanup bb brigade, because buckets inserted to it could be
     * created from scpool and this pool can be freed before this brigade. */
    apr_brigade_cleanup(bb);

    /* See define of AP_MAX_INTERIM_RESPONSES for why */
    if (interim_response >= AP_MAX_INTERIM_RESPONSES) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             apr_psprintf(p,
                             "Too many (%d) interim responses from origin server",
                             interim_response));
    }

    /* If our connection with the client is to be aborted, return DONE. */
    if (c->aborted || req->backend_broke) {
        return DONE;
    }

    return OK;
}

static int proxy_http_process(proxy_http_req_t *req);

/* Finish a request whose continuation ran before Step Five, cleaning up as
 * proxy_http_handler() does.
 */
static void proxy_http_continuation_finish(proxy_http_req_t *req, int status)
{
    if (req->backend) {
        if (status != OK) {
            req->backend->close = 1;
        }
        ap_proxy_release_connection(req->proto, req->backend,
                                    req->r->server);
        req->backend = NULL;
    }
    proxy_http_async_finish(req, status);
}

/* Release the wait context of the connect in progress, if any, then clear
 * the pool it was made from: released first, since destroying the context of
 * a wait in flight is a bug for the core.
 */
static void proxy_http_connect_wait_release(proxy_http_req_t *req)
{
    if (req->connect_wait) {
        ap_request_waitctx_release(req->connect_wait);
        req->connect_wait = NULL;
    }
    if (req->connect_pool) {
        apr_pool_clear(req->connect_pool);
    }
}

/* The continuation of proxy_http_connect(), called when the connect in
 * progress completes (or on timeout or error): go on with the steps from
 * there.
 */
static void proxy_http_connect_continuation(request_rec *r, apr_status_t rv,
                                            void *baton)
{
    proxy_http_req_t *req = baton;
    int status;

    AP_DEBUG_ASSERT(req->r == r);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(rv)) {
        ap_proxy_connect_backend_cancel(&req->connect);
        proxy_http_connect_wait_release(req);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: can't wait for the connection to %s:%d "
                      "(async)", req->proto,
                      req->backend->hostname, req->backend->port);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto finish;
    }
    /* A timeout fails this address: the next one is tried */
    req->connect.status = rv;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy %s: connect %s (async)", req->proto,
                  rv == APR_SUCCESS ? "ready" : "timeout");

    req->connecting = 1;
    status = proxy_http_process(req);
    if (status == SUSPENDED) {
        return;
    }

finish:
    proxy_http_continuation_finish(req, status);
}

/* Connect to the backend, without blocking when waiting asynchronously is
 * possible (ProxyAsyncDelay). Each connect in progress is polled first (for up
 * to ProxyAsyncDelay the first time, then without waiting, so that a connect
 * which has completed already doesn't suspend), then waited for with
 * ap_request_wait() and the connect timeout, on a descriptor context of its
 * socket made for each wait: never kept in the MPM, since the connect closes
 * the socket of an address that fails before trying the next one
 * (proxy_http_connect_continuation() continues then). The contexts are made
 * from a subpool of the request (created at the first wait), cleared at each
 * next attempt once the previous context is released.
 * Returns OK, SUSPENDED or DECLINED.
 */
static int proxy_http_connect(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    proxy_conn_rec *backend = req->backend;
    apr_pollfd_t pfd;
    apr_interval_time_t delay = 0;
    apr_int32_t nready;
    apr_status_t rv;
    int status;

    if (!req->connecting) {
        if (!req->can_suspend) {
            return ap_proxy_connect_backend(req->proto, backend, req->worker,
                                            r->server);
        }
        memset(&req->connect, 0, sizeof(req->connect));
        delay = req->dconf->async_delay;
    }
    req->connecting = 0;

    proxy_http_connect_wait_release(req);

    for (;;) {
        status = ap_proxy_connect_backend_ex(req->proto, backend, req->worker,
                                             r->server, &req->connect);
        if (status != SUSPENDED) {
            return status;
        }

        /* Poll for ProxyAsyncDelay the first time, then for 0: a nonblocking
         * connect is always in progress at first, even when it completes
         * right away (e.g. on loopback).
         */
        memset(&pfd, 0, sizeof(pfd));
        pfd.p = r->pool;
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = req->connect.sock;
        pfd.reqevents = req->connect.events;
        nready = 0;
        if (delay >= req->connect.timeout) {
            delay = req->connect.timeout;
        }
        rv = apr_poll(&pfd, 1, &nready, delay);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (delay < req->connect.timeout) {
                req->connect.timeout -= delay;
                break;
            }
            req->connect.status = APR_TIMEUP;
        }
        delay = 0;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = req->connect.sock;
    if (!req->connect_pool) {
        apr_pool_create(&req->connect_pool, r->pool);
        apr_pool_tag(req->connect_pool, "proxy_http_connect");
    }
    req->connect_wait = ap_request_waitctx_pfd(r, req->connect_pool, &pfd);
    req->connect_wait->timeout = req->connect.timeout;
    req->connect_wait->delay = 0; /* polled above */
    status = ap_request_wait(req->connect_wait,
                             (req->connect.events & APR_POLLOUT) ? AP_WAIT_OUT
                                                                 : AP_WAIT_IN,
                             0, proxy_http_connect_continuation, req);
    if (status != SUSPENDED) {
        /* We can't wait asynchronously: wait synchronously, for each address
         * as needed.
         */
        proxy_http_connect_wait_release(req);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "proxy %s: can't wait for the connection "
                      "asynchronously", req->proto);
        do {
            memset(&pfd, 0, sizeof(pfd));
            pfd.p = r->pool;
            pfd.desc_type = APR_POLL_SOCKET;
            pfd.desc.s = req->connect.sock;
            pfd.reqevents = req->connect.events;
            nready = 0;
            rv = apr_poll(&pfd, 1, &nready, req->connect.timeout);
            if (APR_STATUS_IS_TIMEUP(rv)) {
                req->connect.status = APR_TIMEUP;
            }
            status = ap_proxy_connect_backend_ex(req->proto, backend,
                                                 req->worker, r->server,
                                                 &req->connect);
        } while (status == SUSPENDED);
        return status;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy %s: connecting to %s:%d (async)", req->proto,
                  backend->hostname, backend->port);
    return SUSPENDED;
}

static void proxy_http_handshake_continuation(request_rec *r,
                                              apr_status_t status,
                                              void *baton);

/* Perform the TLS handshake with the backend before sending the request.
 * Without this, the handshake would happen (blocking) in the first write of
 * the request. Here it's driven by nonblocking reads (mod_ssl's AP_MODE_INIT
 * with APR_NONBLOCK_READ): when it would block, we wait with ap_proxy_wait()
 * (the backend's context of the request's later waits), which calls
 * proxy_http_handshake_continuation() once the backend is ready. Nothing is
 * done for a reused connection, whose handshake is complete already. Returns
 * OK, SUSPENDED, or an HTTP error. On error, the backend connection is marked
 * to be closed and nothing is written to it.
 */
static int proxy_http_handshake(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    conn_rec *origin = req->origin;
    proxy_conn_rec *backend = req->backend;
    apr_bucket_brigade *bb;
    ap_proxy_direction_e direction = AP_PROXY_BACKEND_IN;
    apr_status_t rv;
    int rc = OK;

    req->handshaking = 0;
    bb = apr_brigade_create(req->p, origin->bucket_alloc);
    for (;;) {
        rv = ap_get_brigade(origin->input_filters, bb, AP_MODE_INIT,
                            APR_NONBLOCK_READ, 0);
        apr_brigade_cleanup(bb);
        if (!APR_STATUS_IS_EAGAIN(rv)) {
            break;
        }
        /* Wait for the backend to be writable if the handshake left output
         * pending, otherwise for it to be readable: after EAGAIN either way.
         */
        direction = (ap_check_output_pending(origin) == AGAIN)
                    ? AP_PROXY_BACKEND_OUT : AP_PROXY_BACKEND_IN;
        rc = ap_proxy_wait(r, backend, direction, AP_PROXY_WAIT_DRAINED,
                           req->idle_timeout,
                           proxy_http_handshake_continuation, req);
        if (rc != OK) {
            break; /* waiting (SUSPENDED), or can't wait (DECLINED) */
        }
    }
    apr_brigade_destroy(bb);
    if (rv == APR_SUCCESS) {
        return OK;
    }
    if (!APR_STATUS_IS_EAGAIN(rv)) {
        const char *ssl_note;

        /* Fail the same way as when the handshake fails in the first write.
         * mod_ssl has shut the TLS layer down, so anything written to this
         * connection now would go out unencrypted: it must be closed.
         */
        backend->close = 1;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: TLS handshake with %pI (%s) failed",
                      req->proto, backend->addr, backend->hostname);
        if (origin->aborted
            && (ssl_note = apr_table_get(origin->notes, "SSL_connect_rv")) != NULL
            && strcmp(ssl_note, "err") == 0) {
            return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                 "Error during SSL Handshake with"
                                 " remote server");
        }
        return HTTP_BAD_GATEWAY;
    }

    if (rc != SUSPENDED) {
        /* We can't wait asynchronously, so the first write of the request
         * will finish the handshake (blocking).
         */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "proxy %s: can't wait for the TLS handshake "
                      "asynchronously", req->proto);
        return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy %s: TLS handshake with %s:%d: waiting to %s (async)",
                  req->proto, backend->hostname, backend->port,
                  direction == AP_PROXY_BACKEND_OUT ? "write" : "read");
    return SUSPENDED;
}

/* The continuation of proxy_http_handshake(), called by the MPM when the
 * backend is ready, or on timeout or error: continue the handshake, then the
 * remaining steps.
 */
static void proxy_http_handshake_continuation(request_rec *r,
                                              apr_status_t rv,
                                              void *baton)
{
    proxy_http_req_t *req = baton;
    int status;

    AP_DEBUG_ASSERT(req->r == r);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "proxy %s: %s during the TLS handshake with %s:%d "
                      "(async)", req->proto,
                      APR_STATUS_IS_TIMEUP(rv) ? "timeout" : "error",
                      req->backend->hostname, req->backend->port);
        req->backend->close = 1;
        /* A failed handshake (as ap_proxy_pass_brigade() reports it) */
        status = ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                               "Error during SSL Handshake with"
                               " remote server");
        proxy_http_continuation_finish(req, status);
        return;
    }

    req->handshaking = 1;
    status = proxy_http_process(req);
    if (status == SUSPENDED) {
        return;
    }
    proxy_http_continuation_finish(req, status);
}

/* Run Steps Two to Five of proxy_http_handler(): from Step Two (again for a
 * 100-continue retry), from the connect in progress when continued
 * (req->connecting, proxy_http_connect_continuation()), or from the TLS
 * handshake in progress (req->handshaking,
 * proxy_http_handshake_continuation()). Returns the status of the request, or
 * SUSPENDED.
 */
static int proxy_http_process(proxy_http_req_t *req)
{
    request_rec *r = req->r;
    proxy_conn_rec *backend = req->backend;
    const char *scheme = req->proto;
    int status = OK;

    while (req->retry < 2) {
        if (req->handshaking) {
            goto handshake; /* Steps Two and Three are done already */
        }
        if (req->retry && !req->connecting) {
            char *newurl = req->url;

            /* Step One (again): (Re)Determine Who To Connect To */
            if ((status = ap_proxy_determine_connection(req->p, r, req->sconf,
                            req->worker, backend, req->uri, &newurl,
                            req->proxyname, req->proxyport,
                            req->server_portstr, sizeof(req->server_portstr))))
                break;

            /* The code assumes locurl is not changed during the loop, or
             * ap_proxy_http_prefetch() would have to be called every time,
             * and header_brigade be changed accordingly...
             */
            AP_DEBUG_ASSERT(strcmp(newurl, req->locurl) == 0);
        }

        /* Step Two: Make the Connection */
        if (req->connecting
            || ap_proxy_check_connection(scheme, backend, r->server, 1, PROXY_CHECK_CONN_EMPTY)) {
            status = proxy_http_connect(req);
            if (status == SUSPENDED) {
                return SUSPENDED;
            }
            if (status != OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01114)
                              "HTTP: failed to make connection to backend: %s",
                              backend->hostname);
                status = HTTP_SERVICE_UNAVAILABLE;
                break;
            }
        }

        /* Step Three: Create conn_rec */
        if ((status = ap_proxy_connection_create_ex(scheme, backend, r)) != OK)
            break;
        req->origin = backend->connection;

        /* Don't recycle the connection if prefetch (above) told not to do so */
        if (req->toclose) {
            backend->close = 1;
            req->origin->keepalive = AP_CONN_CLOSE;
        }

handshake:
        /* Do the TLS handshake now, so that the first write below doesn't
         * block on it.
         */
        if (backend->is_ssl && req->can_suspend) {
            status = proxy_http_handshake(req);
            if (status == SUSPENDED) {
                return SUSPENDED;
            }
            if (status != OK) {
                break;
            }
        }

        /* Step Four: Send the Request
         * On the off-chance that we forced a 100-Continue as a
         * kinda HTTP ping test, allow for retries
         */
        /* Don't hold the thread while the client or the backend is slow
         * when req->can_suspend (as for the response, see Step Five below).
         * With 100-continue only the header is sent here (see
         * send_continue_head()), the body once the backend says so
         * (ap_proxy_http_process_response()).
         */
        req->request_eos = 0;
        req->bytes_streamed = 0;
        status = ap_proxy_http_request(req);
        if (status == SUSPENDED) {
            return SUSPENDED;
        }
        if (status != OK) {
            proxy_run_detach_backend(r, backend);
            if (req->do_100_continue && status == HTTP_SERVICE_UNAVAILABLE) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO(01115)
                              "HTTP: 100-Continue failed to %pI (%s:%d)",
                              backend->addr, backend->hostname, backend->port);
                backend->close = 1;
                req->retry++;
                continue;
            }
            break;
        }

        /* Step Five: Receive the Response... Fall thru to cleanup */
        if (req->can_suspend) {
            /* Don't hold the thread while the backend processes the request,
             * decides on 100-continue, or on an upgrade (the 101 then).
             */
            status = proxy_http_response_head_wait(req);
            if (status == SUSPENDED) {
                return SUSPENDED;
            }
        }
        status = ap_proxy_http_process_response(req);
        if (status == SUSPENDED) {
            return SUSPENDED;
        }
        if (req->backend) {
            proxy_run_detach_backend(r, req->backend);
        }

        break;
    }

    return status;
}

static int proxy_http_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname,
                              apr_port_t proxyport);

/* A request whose body is read before acquiring a backend connection
 * (proxy_http_request_preread()), with what it needs to run the handler again.
 */
typedef struct proxy_http_preread {
    apr_bucket_brigade *bb;     /* The request's rctx->input */
    apr_bucket_brigade *tmp_bb;
    ap_proxy_spool_state spool;
    apr_pool_t *wait_pool;
    proxy_worker *worker;
    proxy_server_conf *conf;
    char *url;
    const char *proxyname;
    apr_port_t proxyport;
    unsigned int spool_needed :1,
                 spooling     :1,
                 timed_out    :1, /* the wait for the client did */
                 done         :1;
} proxy_http_request_preread_t;

/* The continuation of proxy_http_request_preread(), called when the client
 * sent more of the body (or on timeout or error): run the handler again, which
 * continues reading where it stopped.
 */
static void proxy_http_request_preread_continuation(conn_rec *c, request_rec *r,
                                                    ap_mpm_wait_result_e why,
                                                    const apr_array_header_t *pfds,
                                                    void *baton)
{
    proxy_http_request_preread_t *pr = baton;
    int status;

    if (why == AP_MPM_WAIT_TIMEOUT) {
        /* Read the body once more: the read fails on mod_reqtimeout's
         * deadline, or proxy_http_request_preread() answers the timeout if
         * there's still nothing to read (a 408 either way), unless the client
         * sent some in the meantime.
         */
        pr->timed_out = 1;
    }
    else if (why != AP_MPM_WAIT_READY) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "proxy: error waiting for the client's request body "
                      "(async, %i)", (int)why);
        ap_proxy_handler_done(r, HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    status = proxy_http_handler(r, pr->worker, pr->conf, pr->url,
                                pr->proxyname, pr->proxyport);
    if (status == SUSPENDED) {
        return; /* waiting again (for the body, the pool, or in a later step) */
    }
    ap_proxy_handler_done(r, status);
}

/* Read the request body before acquiring a backend connection, so that a slow
 * client doesn't hold one: up to MAX_MEM_SPOOL bytes or EOS, or all of it when
 * it will have to be spooled (what ap_proxy_http_prefetch() reads), waiting
 * for the client in the MPM when waiting asynchronously is possible
 * (ProxyAsyncDelay). The body is saved as the request's rctx->input, where
 * ap_proxy_http_prefetch() starts from: finding enough there, it doesn't read
 * more. Returns OK, SUSPENDED (the handler then runs again from
 * proxy_http_request_preread_continuation()), or an HTTP error.
 */
static int proxy_http_request_preread(request_rec *r, proxy_dir_conf *dconf,
                                      proxy_worker *worker,
                                      proxy_server_conf *conf, char *url,
                                      const char *proxyname,
                                      apr_port_t proxyport)
{
    conn_rec *c = r->connection;
    proxy_http_rctx_t *rctx = proxy_http_rctx(r);
    proxy_http_request_preread_t *pr = rctx->preread;
    apr_array_header_t *pfds;
    apr_pollfd_t *pfd;
    apr_status_t rv;

    if (!pr) {
        const char *te, *cl;

        if (!ap_proxy_request_can_suspend(r)
            || r->expecting_100     /* the client waits for 100 */
            || !ap_request_has_body(r)
            || apr_table_get(r->headers_in, "Upgrade")
            || apr_table_get(r->subprocess_env, "proxy-prefetch-nonblocking")) {
            return OK;
        }
        if (rctx->input) {
            return OK; /* read already (e.g. balancer fallback) */
        }

        pr = apr_pcalloc(r->pool, sizeof(*pr));
        pr->bb = apr_brigade_create(r->pool, c->bucket_alloc);
        pr->tmp_bb = apr_brigade_create(r->pool, c->bucket_alloc);
        /* The body will be spooled (RB_SPOOL_CL) if it can't be streamed, as
         * ap_proxy_http_prefetch() decides when it couldn't prefetch all of
         * it.
         */
        te = apr_table_get(r->headers_in, "Transfer-Encoding");
        cl = apr_table_get(r->headers_in, "Content-Length");
        if (!(cl && !te && r->input_filters == r->proto_input_filters)
            && (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")
                || apr_table_get(r->subprocess_env, "proxy-sendcl"))
            && !apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
            pr->spool_needed = 1;
        }
        rctx->preread = pr;
        rctx->input = pr->bb;
    }
    else if (pr->done) {
        return OK;
    }
    pr->worker = worker;
    pr->conf = conf;
    pr->url = url;
    pr->proxyname = proxyname;
    pr->proxyport = proxyport;

    for (;;) {
        apr_off_t bytes = 0;

        if (pr->spooling) {
            int status = ap_proxy_spool_input_ex(r, NULL, pr->bb, &bytes,
                                                 MAX_MEM_SPOOL,
                                                 APR_NONBLOCK_READ,
                                                 &pr->spool);
            if (status != SUSPENDED) {
                pr->done = 1;
                return status;
            }
            break; /* wait */
        }

        if (!APR_BRIGADE_EMPTY(pr->bb) && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(pr->bb))) {
            pr->done = 1;
            return OK;
        }
        apr_brigade_length(pr->bb, 0, &bytes);
        if (bytes >= MAX_MEM_SPOOL - 80) {
            if (!pr->spool_needed) {
                pr->done = 1;
                return OK;
            }
            pr->spooling = 1;
            continue;
        }

        rv = ap_get_brigade(r->input_filters, pr->tmp_bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, MAX_MEM_SPOOL - bytes);
        if (APR_STATUS_IS_EAGAIN(rv) || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(pr->tmp_bb))) {
            apr_brigade_cleanup(pr->tmp_bb);
            break; /* wait */
        }
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "prefetch request body failed from %s (%s)",
                          c->client_ip, c->remote_host ? c->remote_host : "");
            pr->done = 1;
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }
        /* Set the buckets aside (they may be transient, e.g. with SSL) */
        rv = ap_save_brigade(NULL, &pr->bb, &pr->tmp_bb, r->pool);
        if (rv != APR_SUCCESS) {
            pr->done = 1;
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        pr->timed_out = 0; /* data came in the meantime */
    }

    if (pr->timed_out) {
        /* The wait for the client timed out and there is still nothing to
         * read (the server's Timeout, a deadline of mod_reqtimeout's would
         * have failed the read): a 408. (When spooling, a few bytes read at
         * that very moment don't save it.)
         */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                      "proxy: timeout reading the request body from the "
                      "client (async)");
        pr->done = 1;
        return HTTP_REQUEST_TIME_OUT;
    }

    /* Wait for the client with the time left to read
     * (proxy_http_request_read_timeout()).
     */
    if (pr->wait_pool) {
        apr_pool_clear(pr->wait_pool);
    }
    else {
        apr_pool_create(&pr->wait_pool, r->pool);
    }
    pfds = apr_array_make(pr->wait_pool, 1, sizeof(apr_pollfd_t));
    pfd = apr_array_push(pfds);
    memset(pfd, 0, sizeof(*pfd));
    pfd->p = pr->wait_pool;
    pfd->desc_type = APR_POLL_SOCKET;
    pfd->desc.s = ap_get_conn_socket(c);
    pfd->reqevents = APR_POLLIN;
    rv = ap_mpm_register_wait(c, pr->wait_pool, pfds, proxy_http_request_read_timeout(r), NULL, 0,
                              proxy_http_request_preread_continuation, pr);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO()
                      "proxy: can't wait for the request body "
                      "asynchronously");
        pr->done = 1;
        if (pr->spooling) {
            /* Finish spooling (blocking): the state holds what's spooled
             * already.
             */
            apr_off_t bytes = 0;
            return ap_proxy_spool_input_ex(r, NULL, pr->bb, &bytes,
                                           MAX_MEM_SPOOL, APR_BLOCK_READ,
                                           &pr->spool);
        }
        /* The handler's prefetch (or spool) continues, blocking */
        return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                  "proxy: %s the request body: waiting for the client "
                  "(async)", pr->spooling ? "spooling" : "prefetching");
    return SUSPENDED;
}

/*
 * This handles http:// URLs, and other URLs using a remote proxy over http
 * If proxyhost is NULL, then contact the server directly, otherwise
 * go via the proxy.
 * Note that if a proxy is used, then URLs other than http: can be accessed,
 * also, if we have trouble which is clearly specific to the proxy, then
 * we return DECLINED so that we can try another proxy. (Or the direct
 * route.)
 */
static int proxy_http_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname,
                              apr_port_t proxyport)
{
    int status;
    const char *scheme;
    const char *u = url;
    proxy_http_rctx_t *rctx;
    proxy_http_req_t *req = NULL;
    proxy_conn_rec *backend = NULL;
    apr_bucket_brigade *input_brigade = NULL;
    int is_ssl = 0;
    conn_rec *c = r->connection;
    proxy_dir_conf *dconf;
    char *locurl = url;
    /*
     * Use a shorter-lived pool to reduce memory usage
     * and avoid a memory leak
     */
    apr_pool_t *p = r->pool;
    apr_uri_t *uri;

    scheme = get_url_scheme(&u, &is_ssl);
    if (!scheme && proxyname && strncasecmp(url, "ftp:", 4) == 0) {
        u = url + 4;
        scheme = "ftp";
        is_ssl = 0;
    }
    if (!scheme || u[0] != '/' || u[1] != '/' || u[2] == '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01113)
                      "HTTP: declining URL %s", url);
        return DECLINED; /* only interested in HTTP, WS or FTP via proxy */
    }
    if (is_ssl && !ap_ssl_has_outgoing_handlers()) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01112)
                      "HTTP: declining URL %s (mod_ssl not configured?)", url);
        return DECLINED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "HTTP: serving URL %s", url);

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    /* The state kept across the runs of this handler (a new attempt, or
     * after waiting for the client or for a connection), and no attempt yet.
     */
    rctx = proxy_http_rctx(r);
    rctx->req = NULL;

    /* Read the request body before holding a backend connection, without
     * blocking. On SUSPENDED we wait for the client, and the handler runs
     * again from proxy_http_request_preread_continuation().
     */
    if ((status = proxy_http_request_preread(r, dconf, worker, conf, url,
                                             proxyname, proxyport)) != OK) {
        return status;
    }

    /* create space for state information. On SUSPENDED we wait for a
     * connection, and the handler runs again once one is released.
     */
    if ((status = ap_proxy_acquire_connection_async(scheme, &backend, r,
                                                    proxy_http_handler,
                                                    worker, conf, url,
                                                    proxyname,
                                                    proxyport)) != OK) {
        return status;
    }
    backend->is_ssl = is_ssl;

    req = apr_pcalloc(p, sizeof(*req));
    req->p = p;
    req->r = r;
    req->sconf = conf;
    req->dconf = dconf;
    req->worker = worker;
    req->backend = backend;
    req->proto = scheme;
    req->bucket_alloc = c->bucket_alloc;
    req->can_suspend = ap_proxy_request_can_suspend(r);
    req->rb_method = RB_INIT;

    rctx->req = req;

    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        req->force10 = 1;
    }
    else if (*worker->s->upgrade || *req->proto == 'w') {
        /* Forward Upgrade header if it matches the configured one(s),
         * the default being "WebSocket" for ws[s] schemes.
         */
        const char *upgrade = apr_table_get(r->headers_in, "Upgrade");
        if (upgrade && ap_proxy_worker_can_upgrade(p, worker, upgrade,
                                                   (*req->proto == 'w')
                                                   ? "WebSocket" : NULL)) {
            req->upgrade = upgrade;
        }
    }

    if (req->can_suspend || req->upgrade) {
        /* If ProxyAsyncIdleTimeout is not set, use backend timeout */
        if (req->can_suspend && dconf->async_idle_timeout_set) {
            req->idle_timeout = dconf->async_idle_timeout;
        }
        else if (worker->s->timeout_set) {
            req->idle_timeout = worker->s->timeout;
        }
        else if (conf->timeout_set) {
            req->idle_timeout = conf->timeout;
        }
        else {
            req->idle_timeout = r->server->timeout;
        }
    }

    /* We possibly reuse input data prefetched in previous call(s), e.g. for a
     * balancer fallback scenario, and in this case the 100 continue settings
     * should be consistent between balancer members. If not, we need to ignore
     * Proxy100Continue on=>off once we tried to prefetch already, otherwise
     * the HTTP_IN filter won't send 100 Continue for us anymore, and we might
     * deadlock with the client waiting for each other. Note that off=>on is
     * not an issue because in this case r->expecting_100 is false (the 100
     * Continue is out already), but we make sure that prefetch will be
     * nonblocking to avoid passing more time there. 
     */
    input_brigade = rctx->input;

    /* Should we handle end-to-end or ping 100-continue? */
    if (!req->force10
        && ((r->expecting_100 && (dconf->forward_100_continue || input_brigade))
            || PROXY_SHOULD_PING_100_CONTINUE(worker, r))) {
        /* Tell ap_proxy_create_hdrbrgd() to preserve/add the Expect header */
        apr_table_setn(r->notes, "proxy-100-continue", "1");
        req->do_100_continue = 1;
    }

    /* Should we block while prefetching the body or try nonblocking and flush
     * data to the backend ASAP?
     */
    if (input_brigade
             || req->can_suspend
             || req->do_100_continue
             || apr_table_get(r->subprocess_env,
                              "proxy-prefetch-nonblocking")) {
        req->prefetch_nonblocking = 1;
    }

    /*
     * In the case that we are handling a reverse proxy connection and this
     * is not a request that is coming over an already kept alive connection
     * with the client, do NOT reuse the connection to the backend, because
     * we cannot forward a failure to the client in this case as the client
     * does NOT expect this in this situation.
     * Yes, this creates a performance penalty.
     */
    if ((r->proxyreq == PROXYREQ_REVERSE) && (!c->keepalives)
        && (apr_table_get(r->subprocess_env, "proxy-initial-not-pooled"))) {
        backend->close = 1;
    }

    /* Step One: Determine Who To Connect To */
    uri = apr_palloc(p, sizeof(*uri));
    if ((status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                            uri, &locurl, proxyname,
                                            proxyport, req->server_portstr,
                                            sizeof(req->server_portstr))))
        goto cleanup;

    /* The header is always (re-)built since it depends on worker settings,
     * but the body can be fetched only once (even partially), so it's saved
     * in between proxy_http_handler() calls should we come back here.
     */
    req->header_brigade = apr_brigade_create(p, req->bucket_alloc);
    if (input_brigade == NULL) {
        input_brigade = apr_brigade_create(p, req->bucket_alloc);
        rctx->input = input_brigade;
    }
    req->input_brigade = input_brigade;

    /* Prefetch (nonlocking) the request body so to increase the chance to get
     * the whole (or enough) body and determine Content-Length vs chunked or
     * spooled. By doing this before connecting or reusing the backend, we want
     * to minimize the delay between this connection is considered alive and
     * the first bytes sent (should the client's link be slow or some input
     * filter retain the data). This is a best effort to prevent the backend
     * from closing (from under us) what it thinks is an idle connection, hence
     * to reduce to the minimum the unavoidable local is_socket_connected() vs
     * remote keepalive race condition.
     */
    if ((status = ap_proxy_http_prefetch(req, uri, locurl)) != OK)
        goto cleanup;

    /* We need to reset backend->close now, since ap_proxy_http_prefetch() set
     * it to disable the reuse of the connection *after* this request (no keep-
     * alive), not to close any reusable connection before this request. However
     * assure what is expected later by using a local flag and do the right thing
     * when ap_proxy_connect_backend() below provides the connection to close.
     */
    req->toclose = backend->close;
    backend->close = 0;

    /* Steps Two to Five (on SUSPENDED, they continue asynchronously) */
    req->url = url;
    req->locurl = locurl;
    req->uri = uri;
    req->proxyname = proxyname;
    req->proxyport = proxyport;
    status = proxy_http_process(req);
    if (status == SUSPENDED) {
        return SUSPENDED;
    }

    /* Step Six: Clean Up */
cleanup:
    if (req->backend) {
        if (status != OK)
            req->backend->close = 1;
        ap_proxy_release_connection(scheme, req->backend, r->server);
    }
    return status;
}

/* post_config hook: */
static int proxy_http_post_config(apr_pool_t *pconf, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{
    /* proxy_http_post_config() will be called twice during startup.  So, don't
     * set up the static data the 1st time through. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_proxy_clear_connection_fn =
            APR_RETRIEVE_OPTIONAL_FN(ap_proxy_clear_connection);
    if (!ap_proxy_clear_connection_fn) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02477)
                     "mod_proxy must be loaded for mod_proxy_http");
        return !OK;
    }

    return OK;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    ap_hook_post_config(proxy_http_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_scheme_handler(proxy_http_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http_canon, NULL, NULL, APR_HOOK_FIRST);
    warn_rx = ap_pregcomp(p, "[0-9]{3}[ \t]+[^ \t]+[ \t]+\"[^\"]*\"([ \t]+\"([^\"]+)\")?", 0);
}

AP_DECLARE_MODULE(proxy_http) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    ap_proxy_http_register_hook/* register hooks */
};

