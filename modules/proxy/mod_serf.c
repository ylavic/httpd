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

#include "mod_serf.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"

#include "serf.h"
#include "apr_uri.h"
#include "apr_strings.h"
#include "apr_version.h"
#include "apr_poll.h"

module AP_MODULE_DECLARE_DATA serf_module;

typedef struct {
    int on;
    int preservehost;
    apr_uri_t url;
} modserf_dir_config_t;

typedef struct {
  const char *name;
  const char *provider;
  apr_table_t *params;
} modserf_cluster_t;

typedef struct {
  /* name -> modserf_cluster_t* */
  apr_hash_t *clusters;
} modserf_server_config_t;

/* A socket that serf polls when driven by the request's waits
 * (serf_context_create_ex()), waited for through a wait context made in a
 * pool of its own, for as long as serf has the socket registered.
 */
typedef struct modserf_wait_pfd_t {
    struct modserf_wait_pfd_t *next;
    apr_pool_t *pool;
    apr_pollfd_t pfd;           /* desc and reqevents (copied) */
    void *serf_baton;
    ap_request_waitctx_t *ctx;
} modserf_wait_pfd_t;

typedef struct {
    int rstatus;
    int want_ssl;
    int done_headers;
    int keep_reading;
    int async;                  /* driven by the request's waits */
    request_rec *r;
    apr_pool_t *serf_pool;
    serf_context_t *serf_ctx;
    apr_pool_t *wait_pool;      /* async: the sockets' pools' parent */
    apr_pool_t *iter_pool;      /* async: cleared after each iteration */
    modserf_wait_pfd_t *pfds;   /* async: the sockets serf polls */
    apr_bucket_brigade *tmpbb;
    modserf_dir_config_t *conf;
    serf_ssl_context_t *ssl_ctx;
    serf_bucket_alloc_t *bkt_alloc;
    serf_bucket_t *body_bkt;
} s_baton_t;

#if !APR_VERSION_AT_LEAST(1,4,0)
#define apr_time_from_msec(x) (x * 1000)
#endif

static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    s_baton_t *ctx = closed_baton;

    if (why) {
        /* justin says that error handling isn't done yet. hah. */
        /* XXXXXX: review */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, why, ctx->r, APLOGNO(01120) "Closed Connection Error");
        ctx->rstatus = HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->keep_reading = 0;
}

/* Whether the certificate's name (a subjectAltName DNS entry or the
 * subject's CN) matches the backend's hostname, case-insensitively: a
 * leading "*." in the name stands for one label of the hostname.
 */
static int name_matches(const char *name, const char *hostname)
{
    if (name[0] == '*' && name[1] == '.') {
        const char *dot = ap_strchr_c(hostname, '.');

        return dot && dot != hostname && !ap_cstr_casecmp(name + 1, dot);
    }
    return !ap_cstr_casecmp(name, hostname);
}

/* serf's server certificate callback: serf calls it for the certificate
 * (depth 0) even when OpenSSL accepted it, and for any failure of the
 * chain, and its status replaces OpenSSL's verdict. Fail on the chain's
 * failures, as serf does without a callback, and at depth 0 on a
 * certificate whose names don't match the backend's hostname: those of the
 * subjectAltName DNS entries, else the subject's CN when it has no such
 * entry. serf doesn't give the IP entries: a backend named by an IP
 * address is matched textually against the DNS entries or the CN, so a
 * certificate with only an IP entry is refused.
 */
static apr_status_t server_cert_check(void *baton, int failures,
                                      const serf_ssl_certificate_t *cert)
{
    s_baton_t *ctx = baton;
    const char *hostname = ctx->conf->url.hostname;
    apr_pool_t *pool;
    apr_hash_t *info, *subject;
    apr_array_header_t *sans;
    int found = 0, have_dns = 0;

    if (failures || !cert) {
        return SERF_ERROR_SSL_CERT_FAILED;
    }
    if (serf_ssl_cert_depth(cert) != 0) {
        return APR_SUCCESS;
    }

    apr_pool_create(&pool, ctx->r->pool);
    info = serf_ssl_cert_certificate(cert, pool);
    sans = info ? apr_hash_get(info, "subjectAltName", APR_HASH_KEY_STRING)
                : NULL;
    if (sans) {
        int i;

        for (i = 0; i < sans->nelts && !found; i++) {
            have_dns = 1;
            found = name_matches(APR_ARRAY_IDX(sans, i, const char *),
                                 hostname);
        }
    }
    if (!have_dns) {
        subject = serf_ssl_cert_subject(cert, pool);
        if (subject) {
            const char *cn = apr_hash_get(subject, "CN",
                                          APR_HASH_KEY_STRING);

            found = cn && name_matches(cn, hostname);
        }
    }
    apr_pool_destroy(pool);

    if (!found) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, APLOGNO()
                      "serf: the backend's certificate doesn't match its "
                      "hostname %s", hostname);
        return SERF_ERROR_SSL_CERT_FAILED;
    }
    return APR_SUCCESS;
}

static apr_status_t conn_setup(apr_socket_t *sock,
                               serf_bucket_t **read_bkt,
                               serf_bucket_t **write_bkt,
                               void *setup_baton,
                               apr_pool_t *pool)
{
    serf_bucket_t *c;
    s_baton_t *ctx = setup_baton;

    c = serf_bucket_socket_create(sock, ctx->bkt_alloc);
    if (ctx->want_ssl) {
        apr_status_t rv;

        c = serf_bucket_ssl_decrypt_create(c, ctx->ssl_ctx, ctx->bkt_alloc);
        if (!ctx->ssl_ctx) {
            ctx->ssl_ctx = serf_bucket_ssl_decrypt_context_get(c);
        }

        /* Verify the backend's certificate against the default CAs and
         * its hostname (a failure ends the connection with
         * SERF_ERROR_SSL_CERT_FAILED), and send the name for SNI. */
        rv = serf_ssl_use_default_certificates(ctx->ssl_ctx);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        serf_ssl_server_cert_callback_set(ctx->ssl_ctx, server_cert_check,
                                          ctx);
        serf_ssl_set_hostname(ctx->ssl_ctx, ctx->conf->url.hostname);

        /* Encrypt the write side with the same context */
        *write_bkt = serf_bucket_ssl_encrypt_create(*write_bkt, ctx->ssl_ctx,
                                                    ctx->bkt_alloc);
    }

    *read_bkt = c;
    return APR_SUCCESS;
}

static int copy_headers_in(void *vbaton, const char *key, const char *value)
{
    serf_bucket_t *hdrs_bkt = (serf_bucket_t *)vbaton;

    /* XXXXX: List of headers not to copy to serf. serf's serf_bucket_headers_setn,
     * doesn't actually overwrite a header if we set it once, so we need to ignore anything
     * we might want to toggle or combine.
     */
    switch (key[0]) {
    case 'a':
    case 'A':
        if (ap_cstr_casecmp("Accept-Encoding", key) == 0) {
            return 0;
        }
        break;
    case 'c':
    case 'C':
        if (ap_cstr_casecmp("Connection", key) == 0) {
            return 0;
        }
        break;
    case 'h':
    case 'H':
        if (ap_cstr_casecmp("Host", key) == 0) {
            return 0;
        }
        break;
    case 'k':
    case 'K':
        if (ap_cstr_casecmp("Keep-Alive", key) == 0) {
            return 0;
        }
        break;
    case 't':
    case 'T':
        if (ap_cstr_casecmp("TE", key) == 0) {
            return 0;
        }
        if (ap_cstr_casecmp("Trailer", key) == 0) {
            return 0;
        }
        break;
    case 'u':
    case 'U':
        if (ap_cstr_casecmp("Upgrade", key) == 0) {
            return 0;
        }
        break;
    default:
        break;
    }

    serf_bucket_headers_setn(hdrs_bkt, key, value);
    return 0;
}

static int copy_headers_out(void *vbaton, const char *key, const char *value)
{
    s_baton_t *ctx = vbaton;
    int done = 0;

    /* XXXXX: Special Treatment required for MANY other headers. fixme.*/
    switch (key[0]) {
    case 'c':
    case 'C':
        if (ap_cstr_casecmp("Content-Type", key) == 0) {
            ap_set_content_type(ctx->r, value);
            done = 1;
            break;
        }
        else if (ap_cstr_casecmp("Connection", key) == 0) {
            done = 1;
            break;
        }
        else if (ap_cstr_casecmp("Content-Encoding", key) == 0) {
            done = 1;
            break;
        }
        else if (ap_cstr_casecmp("Content-Length", key) == 0) {
            done = 1;
            break;
        }
        break;
    case 't':
    case 'T':
        if (ap_cstr_casecmp("Transfer-Encoding", key) == 0) {
            done = 1;
            break;
        }
        break;
    default:
            break;
    }

    if (!done) {
        apr_table_addn(ctx->r->headers_out, key, value);
    }

    return 0;
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      serf_bucket_t *stream,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    return serf_bucket_response_create(c, bkt_alloc);
}

static apr_status_t handle_response(serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *vbaton,
                                    apr_pool_t *pool)
{
    apr_status_t rv;
    s_baton_t *ctx = vbaton;
    const char *data;
    apr_size_t len;
    serf_status_line sl;

    if (response == NULL) {
        ctx->rstatus = HTTP_INTERNAL_SERVER_ERROR;
        return APR_EGENERAL;
    }

    /* XXXXXXX: Create better error message. */
    rv = serf_bucket_response_status(response, &sl);
    if (rv) {
        if (APR_STATUS_IS_EAGAIN(rv)) {
            return rv;
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->r, APLOGNO(01121) "serf_bucket_response_status...");

        ctx->rstatus = HTTP_INTERNAL_SERVER_ERROR;

        return rv;
    }

    /**
     * XXXXX: If I understood serf buckets better, it might be possible to not
     * copy all of the data here, and better stream it to the client.
     **/

    do {
        apr_brigade_cleanup(ctx->tmpbb);
        rv = serf_bucket_read(response, AP_IOBUFSIZE, &data, &len);

        if (SERF_BUCKET_READ_ERROR(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->r, APLOGNO(01122) "serf_bucket_read(response)");
            return rv;
        }

        if (!ctx->done_headers) {
            serf_bucket_t *hdrs;
            serf_status_line line;

            /* TODO: improve */
            serf_bucket_response_status(response, &line);
            ctx->r->status = line.code;

            hdrs = serf_bucket_response_get_headers(response);
            serf_bucket_headers_do(hdrs, copy_headers_out, ctx);
            ctx->done_headers = 1;
        }


        if (len > 0) {
            /* TODO: make APR bucket <-> serf bucket stuff more magical. */
            apr_brigade_write(ctx->tmpbb, NULL, NULL, data, len);
        }

        if (APR_STATUS_IS_EOF(rv)) {
            ctx->keep_reading = 0;

            ctx->rstatus = ap_pass_brigade(ctx->r->output_filters, ctx->tmpbb);

            return APR_EOF;
        }

        ctx->rstatus = ap_pass_brigade(ctx->r->output_filters, ctx->tmpbb);

        /* XXXX: Should we send a flush now? */
        if (APR_STATUS_IS_EAGAIN(rv)) {
            return rv;
        }

    } while (1);
}


static apr_status_t setup_request(serf_request_t *request,
                                  void *vbaton,
                                  serf_bucket_t **req_bkt,
                                  serf_response_acceptor_t *acceptor,
                                  void **acceptor_baton,
                                  serf_response_handler_t *handler,
                                  void **handler_baton,
                                  apr_pool_t *pool)
{
    s_baton_t *ctx = vbaton;
    serf_bucket_t *hdrs_bkt;

    *req_bkt = serf_bucket_request_create(ctx->r->method, ctx->r->unparsed_uri,
                                          ctx->body_bkt,
                                          serf_request_get_alloc(request));

    hdrs_bkt = serf_bucket_request_get_headers(*req_bkt);

    apr_table_do(copy_headers_in, hdrs_bkt, ctx->r->headers_in, NULL);

    if (ctx->conf->preservehost) {
        serf_bucket_headers_setn(hdrs_bkt, "Host",
                                 apr_table_get(ctx->r->headers_in, "Host"));
    }
    else {
        serf_bucket_headers_setn(hdrs_bkt, "Host", ctx->conf->url.hostname);
    }

    serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");

    *acceptor = accept_response;
    *acceptor_baton = ctx;
    *handler = handle_response;
    *handler_baton = ctx;

    return APR_SUCCESS;
}

/* serf registers a socket to poll (serf_context_create_ex()): the request
 * will wait for it through a wait context of its own.
 */
static apr_status_t socket_add(void *user_baton, apr_pollfd_t *pfd,
                                       void *serf_baton)
{
    s_baton_t *ctx = user_baton;
    modserf_wait_pfd_t *wp;
    apr_pool_t *p;
    apr_status_t rv;

    rv = apr_pool_create(&p, ctx->wait_pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    apr_pool_tag(p, "mod_serf_wait");
    wp = apr_pcalloc(p, sizeof(*wp));
    wp->pool = p;
    wp->pfd = *pfd;
    wp->pfd.client_data = NULL;
    wp->serf_baton = serf_baton;
    wp->ctx = ap_request_waitctx_pfd(ctx->r, p, pfd);
    wp->next = ctx->pfds;
    ctx->pfds = wp;
    return APR_SUCCESS;
}

/* serf unregisters a socket (before closing it, or to register it again
 * with other events): its wait context is released with its pool.
 */
static apr_status_t socket_remove(void *user_baton, apr_pollfd_t *pfd,
                                          void *serf_baton)
{
    s_baton_t *ctx = user_baton;
    modserf_wait_pfd_t **pwp, *wp;

    for (pwp = &ctx->pfds; (wp = *pwp) != NULL; pwp = &wp->next) {
        if (wp->serf_baton == serf_baton
            && wp->pfd.desc_type == pfd->desc_type
            && wp->pfd.desc.s == pfd->desc.s) {
            *pwp = wp->next;
            ap_request_waitctx_release(wp->ctx);
            apr_pool_destroy(wp->pool);
            return APR_SUCCESS;
        }
    }
    return APR_NOTFOUND;
}

/* The ready sockets, from the request's last wait, in ready (as many as
 * ctx->pfds): their serf batons as client_data, the ready directions as
 * rtnevents, or all the requested ones (but for errors) if none was found
 * ready (an error the next I/O reports). Returns how many.
 */
static int wait_ready(s_baton_t *ctx, apr_pollfd_t *ready)
{
    modserf_wait_pfd_t *wp;
    int all, n = 0;

    for (all = 0; all < 2 && !n; all++) {
        for (wp = ctx->pfds; wp; wp = wp->next) {
            apr_int16_t events = 0;

            if (all) {
                events = wp->pfd.reqevents & (APR_POLLIN | APR_POLLOUT);
            }
            else {
                unsigned int d = ap_request_waitctx_ready(wp->ctx);
                if (d & AP_WAIT_IN) {
                    events |= APR_POLLIN;
                }
                if (d & AP_WAIT_OUT) {
                    events |= APR_POLLOUT;
                }
            }
            if (events) {
                ready[n] = wp->pfd;
                ready[n].rtnevents = events;
                ready[n].client_data = wp->serf_baton;
                n++;
            }
        }
    }
    return n;
}

/* Have serf process the events of its ready sockets, those still registered
 * (an earlier one may have closed another).
 */
static apr_status_t trigger(s_baton_t *ctx, const apr_pollfd_t *ready,
                                    int nready)
{
    int i;

    for (i = 0; i < nready; i++) {
        modserf_wait_pfd_t *wp;
        apr_status_t rv;

        for (wp = ctx->pfds; wp; wp = wp->next) {
            if (wp->serf_baton == ready[i].client_data
                && wp->pfd.desc.s == ready[i].desc.s) {
                break;
            }
        }
        if (!wp) {
            continue;
        }
        rv = serf_event_trigger(ctx->serf_ctx, ready[i].client_data,
                                &ready[i]);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    return APR_SUCCESS;
}

/* The end of an asynchronously driven response: serf's connections closed
 * and their wait contexts released (with serf's pool) while the request is
 * alive. Returns the handler's final status.
 */
static int async_done(s_baton_t *ctx, int rc)
{
    apr_pool_destroy(ctx->serf_pool);
    ctx->serf_ctx = NULL;
    apr_pool_destroy(ctx->wait_pool);
    apr_pool_destroy(ctx->iter_pool);

    if (rc == OK && ctx->rstatus) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, ctx->rstatus, ctx->r, APLOGNO(01119)
                      "serf: request returned: %d", ctx->rstatus);
        ctx->r->status = HTTP_OK;
        rc = ctx->rstatus;
    }
    return rc;
}

static void wait_continuation(request_rec *r, apr_status_t status,
                              void *baton);

/* Drive serf until the response is done or serf waits for its sockets: the
 * request waits for them (ap_request_wait_any()), its continuation coming
 * back here. Returns SUSPENDED while waiting, else the handler's final
 * status (serf done with).
 */
static int drive_async(s_baton_t *ctx)
{
    request_rec *r = ctx->r;
    apr_status_t rv;
    int rc;

    for (;;) {
        modserf_wait_pfd_t *wp;
        apr_pollfd_t *ready;
        ap_request_waitctx_t **ctxs;
        unsigned int *directions;
        int n = 0, nready = 0, i = 0;

        rv = serf_context_prerun(ctx->serf_ctx);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "serf_context_prerun()");
            rc = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        if (!ctx->keep_reading) {
            rc = OK;
            break;
        }
        for (wp = ctx->pfds; wp; wp = wp->next) {
            n++;
        }
        if (!n) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                          "serf: no socket to wait for");
            rc = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        ready = apr_palloc(ctx->iter_pool, n * sizeof(*ready));

        ctxs = apr_palloc(ctx->iter_pool, n * sizeof(*ctxs));
        directions = apr_palloc(ctx->iter_pool, n * sizeof(*directions));
        for (wp = ctx->pfds; wp; wp = wp->next, i++) {
            ctxs[i] = wp->ctx;
            directions[i] = 0;
            if (wp->pfd.reqevents & APR_POLLOUT) {
                directions[i] |= AP_WAIT_OUT;
            }
            if ((wp->pfd.reqevents & APR_POLLIN) || !directions[i]) {
                /* A hangup or an error shows as readable */
                directions[i] |= AP_WAIT_IN;
            }
        }
        rc = ap_request_wait_any(ctxs, n, directions, 0,
                                 wait_continuation, ctx);
        if (rc == SUSPENDED) {
            apr_pool_clear(ctx->iter_pool);
            return SUSPENDED;
        }
        if (rc != OK) {
            /* Not DECLINED: every wait of serf's sockets can suspend once
             * ap_request_can_suspend() was true, and the core logs and
             * asserts why a wait fails otherwise.
             */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                          "serf: waiting for the backend returned %d", rc);
            rc = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        nready = wait_ready(ctx, ready);

        rv = trigger(ctx, ready, nready);
        apr_pool_clear(ctx->iter_pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "serf_event_trigger()");
            rc = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
    }

    return async_done(ctx, rc);
}

/* The continuation of the request's wait for serf's sockets */
static void wait_continuation(request_rec *r, apr_status_t status,
                                      void *baton)
{
    s_baton_t *ctx = baton;
    int rc;

    if (status == APR_SUCCESS) {
        apr_pollfd_t *ready;
        modserf_wait_pfd_t *wp;
        int n = 0, nready;
        apr_status_t rv;

        for (wp = ctx->pfds; wp; wp = wp->next) {
            n++;
        }
        ready = apr_palloc(ctx->iter_pool, (n ? n : 1) * sizeof(*ready));
        nready = wait_ready(ctx, ready);
        rv = trigger(ctx, ready, nready);
        apr_pool_clear(ctx->iter_pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "serf_event_trigger()");
            rc = async_done(ctx, HTTP_INTERNAL_SERVER_ERROR);
        }
        else {
            rc = drive_async(ctx);
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO()
                      "serf: waiting for the backend");
        rc = async_done(ctx, APR_STATUS_IS_TIMEUP(status)
                                  ? HTTP_GATEWAY_TIME_OUT
                                  : HTTP_INTERNAL_SERVER_ERROR);
    }
    if (rc != SUSPENDED) {
        ap_request_finish_suspended(r, rc);
    }
}

static int drive_serf(request_rec *r, modserf_dir_config_t *conf)
{
    apr_status_t rv = 0;
    apr_pool_t *pool;
    apr_sockaddr_t *address;
    apr_uri_t host_info = conf->url;
    s_baton_t *baton = apr_palloc(r->pool, sizeof(s_baton_t));
    /* XXXXX: make persistent/per-process or something.*/
    serf_context_t *serfme;
    serf_connection_t *conn;
    modserf_server_config_t *ctx =
        (modserf_server_config_t *)ap_get_module_config(r->server->module_config,
                                                     &serf_module);

    /* Without holding the thread when the request can suspend: serf
     * driven by the request's waits for its sockets.
     */
    baton->async = ap_request_can_suspend(r);
    if (baton->async) {
        /* Before serf's pool, so destroyed after it with the request's
         * (serf unregistering its sockets then).
         */
        apr_pool_create(&baton->wait_pool, r->pool);
        apr_pool_tag(baton->wait_pool, "mod_serf_waits");
        apr_pool_create(&baton->iter_pool, r->pool);
        apr_pool_tag(baton->iter_pool, "mod_serf_iter");
    }
    baton->pfds = NULL;

    /* Allocate everything out of a subpool, with a shorter lifetime than
     * the main request, so that we can cleanup safely and unregister serf's
     * sockets from the request's waits.
     */
    apr_pool_create(&pool, r->pool);
    apr_pool_tag(pool, "mod_serf_drive");
    if (strcmp(conf->url.scheme, "cluster") == 0) {
        int rc;
        ap_serf_cluster_provider_t *cp;
        modserf_cluster_t *cluster;
        apr_array_header_t *servers = NULL;
        apr_uint32_t pick = 0;
        ap_serf_server_t *choice;

        /* TODO: could this be optimized in post-config to pre-setup the
         * pointers to the right cluster inside the conf structure?
         */
        cluster = apr_hash_get(ctx->clusters,
                               conf->url.hostname,
                               APR_HASH_KEY_STRING);
        if (!cluster) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01123)
                          "SerfCluster: unable to find cluster %s", conf->url.hostname);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        cp = ap_lookup_provider(AP_SERF_CLUSTER_PROVIDER, cluster->provider, "0");

        if (cp == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01124)
                          "SerfCluster: unable to find provider %s", cluster->provider);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (cp->list_servers == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01125)
                          "SerfCluster: %s is missing list servers provider.", cluster->provider);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = cp->list_servers(cp->baton,
                              r,
                              cluster->params,
                              &servers);

        if (rc != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01126)
                          "SerfCluster: %s list servers returned failure", cluster->provider);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (servers == NULL || apr_is_empty_array(servers)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01127)
                          "SerfCluster: %s failed to provide a list of servers", cluster->provider);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* TODO: restructure try all servers in the array !! */
        pick = ap_random_pick(0, servers->nelts-1);
        choice = APR_ARRAY_IDX(servers, pick, ap_serf_server_t *);

        rv = apr_sockaddr_info_get(&address, choice->ip,
                                   APR_UNSPEC, choice->port, 0,
                                   pool);
        host_info.scheme = "http";
        host_info.hostname = (char *)choice->ip;
        host_info.port = choice->port;
        host_info.port_str = apr_itoa(pool, choice->port);
    }
    else {
        /* XXXXX: cache dns? */
        rv = apr_sockaddr_info_get(&address, conf->url.hostname,
                                   APR_UNSPEC, conf->url.port, 0,
                                   pool);
    }

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01128) "Unable to resolve: %s", conf->url.hostname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    baton->r = r;
    if (baton->async) {
        serfme = serf_context_create_ex(baton, socket_add,
                                        socket_remove, pool);
    }
    else {
        serfme = serf_context_create(pool);
    }
    baton->serf_ctx = serfme;

    baton->conf = conf;
    baton->serf_pool = pool;
    baton->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    baton->body_bkt = NULL;
    baton->ssl_ctx = NULL;
    baton->rstatus = OK;

    baton->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    baton->done_headers = 0;
    baton->keep_reading = 1;

    if (ap_cstr_casecmp(conf->url.scheme, "https") == 0) {
        baton->want_ssl = 1;
    }
    else {
        baton->want_ssl = 0;
    }

    rv = ap_setup_client_block(baton->r, REQUEST_CHUNKED_DECHUNK);
    if (rv) {
        return rv;
    }

    /* TODO: create custom serf bucket, which does async request body reads */
    if (ap_should_client_block(r)) {
        apr_size_t len;
        apr_off_t flen = 0;
        char buf[AP_IOBUFSIZE];
        apr_file_t *fp;

        rv = apr_file_mktemp(&fp, "mod_serf_buffer.XXXXXX", 0, pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01130) "Unable to create temp request body buffer file.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        do {
            len = sizeof(buf);
            /* FIXME: ap_get_client_block() returns long, not apr_status_t */
            rv = ap_get_client_block(baton->r, buf, len);
            if (rv > 0) {
                rv = apr_file_write_full(fp, buf, rv, NULL);
                if (rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01131) "failed to read request body");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        } while(rv > 0);

        if (rv < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01132) "failed to read request body");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        apr_file_seek(fp, APR_SET, &flen);
        baton->body_bkt = serf_bucket_file_create(fp, baton->bkt_alloc);
    }

#if SERF_VERSION_AT_LEAST(1, 4, 0)
    /* serf_connection_create() doesn't set up the connection's config
     * since serf 1.4, which serf needs to open it */
    rv = serf_connection_create3(&conn, serfme, host_info, address,
                                 conn_setup, baton,
                                 closed_connection, baton,
                                 pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "serf_connection_create3() for %pI", address);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#else
    conn = serf_connection_create(serfme, address,
                                  conn_setup, baton,
                                  closed_connection, baton,
                                  pool);
#endif

    /* XXX: Is it correct that we don't use the returned serf_request_t? */
    serf_connection_request_create(conn, setup_request, baton);

    if (baton->async) {
        return drive_async(baton);
    }
    else {
        do {
            rv = serf_context_run(serfme, SERF_DURATION_FOREVER, pool);

            /* XXXX: Handle timeouts */
            if (APR_STATUS_IS_TIMEUP(rv)) {
                continue;
            }

            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01133) "serf_context_run() for %pI", address);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            serf_debug__closed_conn(baton->bkt_alloc);
        } while (baton->keep_reading);

        return baton->rstatus;
    }
}

static int serf_handler(request_rec *r)
{
    modserf_dir_config_t *conf = ap_get_module_config(r->per_dir_config,
                                               &serf_module);

    if (conf->on == 0) {
        return DECLINED;
    }

    return drive_serf(r, conf);
}

static int is_true(const char *w)
{
    if (strcasecmp(w, "on") == 0 || strcmp(w, "1") == 0 ||
        strcasecmp(w, "true") == 0)
    {
        return 1;
    }

    return 0;
}
static const char *add_pass(cmd_parms *cmd, void *vconf,
                            int argc, char *const argv[])
{
    int i;
    apr_status_t rv;
    modserf_dir_config_t *conf = (modserf_dir_config_t *) vconf;

    if (argc < 1) {
        return "SerfPass must have at least a URI.";
    }

    rv = apr_uri_parse(cmd->pool, argv[0], &conf->url);

    if (rv != APR_SUCCESS) {
        return "Unable to parse SerfPass url.";
    }

    if (!conf->url.scheme) {
        return "Need scheme part in url.";
    }

    /* XXXX: These are bugs in apr_uri_parse. Fixme. */
    if (!conf->url.port) {
        conf->url.port = apr_uri_port_of_scheme(conf->url.scheme);
    }

    if (!conf->url.path) {
        conf->url.path = "/";
    }

    for (i = 1; i < argc; i++) {
        const char *p = argv[i];
        const char *x = ap_strchr_c(p, '=');

        if (x) {
            if (strncmp(p, "preservehost", x-p) == 0) {
                conf->preservehost = is_true(x+1);
            }
        }
    }

    conf->on = 1;

    return NULL;
}

/* SerfCluster <name> <provider> <key=value_params_to_provider> ... */

static const char *add_cluster(cmd_parms *cmd, void *d,
                               int argc, char *const argv[])
{
    const char *rv;
    ap_serf_cluster_provider_t *backend;
    int i;
    modserf_cluster_t *cluster = NULL;
    modserf_server_config_t *ctx =
        (modserf_server_config_t *)ap_get_module_config(cmd->server->module_config,
                                                     &serf_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (argc < 2) {
        return "SerfCluster must have at least a name and provider.";
    }

    cluster = apr_palloc(cmd->pool, sizeof(modserf_cluster_t));
    cluster->name = apr_pstrdup(cmd->pool, argv[0]);
    cluster->provider = apr_pstrdup(cmd->pool, argv[1]);
    cluster->params = apr_table_make(cmd->pool, 6);

    backend = ap_lookup_provider(AP_SERF_CLUSTER_PROVIDER, cluster->provider, "0");

    if (backend == NULL) {
        return apr_psprintf(cmd->pool, "SerfCluster: unable to find "
                            "provider '%s'", cluster->provider);
    }

    for (i = 2; i < argc; i++) {
        const char *p = argv[i];
        const char *x = ap_strchr_c(p, '=');

        if (x && strlen(p) > 1) {
            apr_table_addn(cluster->params,
                           apr_pstrmemdup(cmd->pool, p, x-p),
                           x+1);
        }
        else {
            apr_table_addn(cluster->params,
                           apr_pstrdup(cmd->pool, p),
                           "");
        }
    }

    if (backend->check_config == NULL) {
        return apr_psprintf(cmd->pool, "SerfCluster: Provider '%s' failed to "
                             "provider a configuration checker",
                            cluster->provider);
    }

    rv = backend->check_config(backend->baton, cmd, cluster->params);

    if (rv) {
        return rv;
    }

    apr_hash_set(ctx->clusters, cluster->name, APR_HASH_KEY_STRING, cluster);

    return NULL;
}

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    modserf_dir_config_t *new = (modserf_dir_config_t *) apr_pcalloc(p, sizeof(modserf_dir_config_t));
    new->on = 0;
    new->preservehost = 1;
    return new;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    modserf_server_config_t *ctx =
        (modserf_server_config_t *) apr_pcalloc(p, sizeof(modserf_server_config_t));

    ctx->clusters = apr_hash_make(p);

    return ctx;
}

static void * merge_server_config(apr_pool_t *p, void *basev, void *overridesv)
{
    modserf_server_config_t *ctx = apr_pcalloc(p, sizeof(modserf_server_config_t));
    modserf_server_config_t *base = (modserf_server_config_t *) basev;
    modserf_server_config_t *overrides = (modserf_server_config_t *) overridesv;

    ctx->clusters = apr_hash_overlay(p, base->clusters, overrides->clusters);
    return ctx;
}

static const command_rec serf_cmds[] =
{
    AP_INIT_TAKE_ARGV("SerfCluster", add_cluster, NULL, RSRC_CONF,
                      "Configure a cluster backend"),
    AP_INIT_TAKE_ARGV("SerfPass", add_pass, NULL, OR_INDEXES,
                      "URL to reverse proxy to"),
    {NULL}
};

typedef struct hb_table_baton_t {
    apr_pool_t *p;
    const char *msg;
} hb_table_baton_t;

static int hb_table_check(void *rec, const char *key, const char *value)
{
    hb_table_baton_t *b = (hb_table_baton_t*)rec;
    if (strcmp(key, "path") != 0) {
        b->msg = apr_psprintf(b->p,
                              "SerfCluster Heartbeat Invalid parameter '%s'",
                              key);
        return 1;
    }

    return 0;
}

static const char* hb_config_check(void *baton,
                                   cmd_parms *cmd,
                                   apr_table_t *params)
{
    hb_table_baton_t b;

    if (apr_is_empty_table(params)) {
        return "SerfCluster Heartbeat requires a path to the heartbeat information.";
    }

    b.p = cmd->pool;
    b.msg = NULL;

    apr_table_do(hb_table_check, &b, params, NULL);

    if (b.msg) {
        return b.msg;
    }

    return NULL;
}

typedef struct hb_server_t {
    const char *ip;
    int busy;
    int ready;
    int seen;
    unsigned int port;
} hb_server_t;

static void
argstr_to_table(apr_pool_t *p, char *str, apr_table_t *parms)
{
    char *key;
    char *value;
    char *strtok_state;

    key = apr_strtok(str, "&", &strtok_state);
    while (key) {
        value = strchr(key, '=');
        if (value) {
            *value = '\0';      /* Split the string in two */
            value++;            /* Skip passed the = */
        }
        else {
            value = "1";
        }
        ap_unescape_url(key);
        ap_unescape_url(value);
        apr_table_set(parms, key, value);
        key = apr_strtok(NULL, "&", &strtok_state);
    }
}

static apr_status_t read_heartbeats(const char *path,
                                    apr_array_header_t *servers,
                                    apr_pool_t *pool)
{
    apr_finfo_t fi;
    apr_status_t rv;
    apr_file_t *fp;

    if (!path) {
        return APR_SUCCESS;
    }

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY|APR_BUFFERED,
                       APR_OS_DEFAULT, pool);

    if (rv) {
        return rv;
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);

    if (rv) {
        return rv;
    }

    {
        char *t;
        int lineno = 0;
        apr_table_t *hbt = apr_table_make(pool, 10);
        char buf[4096];

        while (apr_file_gets(buf, sizeof(buf), fp) == APR_SUCCESS) {
            hb_server_t *server;
            const char *ip;
            lineno++;

            /* comment */
            if (buf[0] == '#') {
                continue;
            }


            /* line format: <IP> <query_string>\n */
            t = strchr(buf, ' ');
            if (!t) {
                continue;
            }

            ip = apr_pstrmemdup(pool, buf, t - buf);
            t++;
            server = apr_pcalloc(pool, sizeof(hb_server_t));
            server->ip = ip;
            server->port = 80;
            server->seen = -1;
            apr_table_clear(hbt);

            argstr_to_table(pool, apr_pstrdup(pool, t), hbt);

            if (apr_table_get(hbt, "busy")) {
                server->busy = atoi(apr_table_get(hbt, "busy"));
            }

            if (apr_table_get(hbt, "ready")) {
                server->ready = atoi(apr_table_get(hbt, "ready"));
            }

            if (apr_table_get(hbt, "lastseen")) {
                server->seen = atoi(apr_table_get(hbt, "lastseen"));
            }

            if (apr_table_get(hbt, "port")) {
                server->port = atoi(apr_table_get(hbt, "port"));
            }

            if (server->busy == 0 && server->ready != 0) {
                /* Server has zero threads active, but lots of them ready,
                 * it likely just started up, so lets /4 the number ready,
                 * to prevent us from completely flooding it with all new
                 * requests.
                 */
                server->ready = server->ready / 4;
            }

            APR_ARRAY_PUSH(servers, hb_server_t *) = server;
        }
    }

    return APR_SUCCESS;
}

static int hb_server_sort(const void *a_, const void *b_)
{
    hb_server_t *a = (hb_server_t*)a_;
    hb_server_t *b = (hb_server_t*)b_;
    if (a->ready == b->ready) {
        return 0;
    }
    else if (a->ready > b->ready) {
        return -1;
    }
    else {
        return 1;
    }
}

static int hb_list_servers(void *baton,
                           request_rec *r,
                           apr_table_t *params,
                           apr_array_header_t **out_servers)
{
    int i;
    hb_server_t *hbs;
    apr_status_t rv;
    apr_pool_t *tpool;
    apr_array_header_t *tmpservers;
    apr_array_header_t *servers;
    const char *path = apr_table_get(params, "path");

    apr_pool_create(&tpool, r->pool);
    apr_pool_tag(tpool, "mod_serf_hb");

    path = ap_server_root_relative(tpool, path);

    tmpservers = apr_array_make(tpool, 32, sizeof(hb_server_t *));
    rv = read_heartbeats(path, tmpservers, tpool);

    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01134)
                      "SerfCluster: Heartbeat unable to read '%s'", path);
        apr_pool_destroy(tpool);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    qsort(tmpservers->elts, tmpservers->nelts, sizeof(hb_server_t *),
          hb_server_sort);

    servers = apr_array_make(r->pool, tmpservers->nelts, sizeof(ap_serf_server_t *));
    for (i = 0;
         i < tmpservers->nelts;
         i++)
    {
        ap_serf_server_t *x;

        hbs = APR_ARRAY_IDX(tmpservers, i, hb_server_t *);
        if (hbs->ready > 0) {
            x = apr_palloc(r->pool, sizeof(ap_serf_server_t));
            x->ip = apr_pstrdup(r->pool, hbs->ip);
            x->port = hbs->port;
            APR_ARRAY_PUSH(servers, ap_serf_server_t *) = x;
        }
    }

    *out_servers = servers;
    apr_pool_destroy(tpool);
    return OK;
}

static const ap_serf_cluster_provider_t builtin_heartbeat =
{
    "heartbeat",
    NULL,
    &hb_config_check,
    &hb_list_servers,
    NULL,
    NULL
};

static int static_table_check(void *rec, const char *key, const char *value)
{
    hb_table_baton_t *b = (hb_table_baton_t*)rec;
    if (strcmp(key, "hosts") != 0 &&
        strcmp(key, "order") != 0) {
        b->msg = apr_psprintf(b->p,
                              "SerfCluster Static Invalid parameter '%s'",
                              key);
        return 1;
    }

    return 0;
}

static const char* static_config_check(void *baton,
                                   cmd_parms *cmd,
                                   apr_table_t *params)
{
    hb_table_baton_t b;

    if (apr_is_empty_table(params)) {
        return "SerfCluster Static requires at least a host list.";
    }

    b.p = cmd->pool;
    b.msg = NULL;

    apr_table_do(static_table_check, &b, params, NULL);

    if (b.msg) {
        return b.msg;
    }

    if (apr_table_get(params, "hosts") == NULL) {
        return "SerfCluster Static requires at least a hosts parameter";
    }
    return NULL;
}

static int static_list_servers(void *baton,
                               request_rec *r,
                               apr_table_t *params,
                               apr_array_header_t **out_servers)
{
    apr_status_t rv;
    char *ip;
    char *strtok_state;
    apr_array_header_t *servers;
    const char *hosts = apr_table_get(params, "hosts");
    const char *order = apr_table_get(params, "order");

    servers = apr_array_make(r->pool, 10, sizeof(ap_serf_server_t *));

    ip = apr_strtok(apr_pstrdup(r->pool, hosts), ",", &strtok_state);
    while (ip) {
        char *host_str;
        char *scope_id;
        apr_port_t port = 0;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port, ip, r->pool);
        if (!rv) {
            ap_serf_server_t *s = apr_palloc(r->pool, sizeof(ap_serf_server_t));
            s->ip = host_str;
            s->port = port ? port : 80;
            APR_ARRAY_PUSH(servers, ap_serf_server_t *) = s;
        }
        ip = apr_strtok(NULL, ",", &strtok_state);
    }

    if (strcmp(order, "random") == 0) {
        /* TODO: support order=random */
    }

    *out_servers = servers;

    return OK;
}

static const ap_serf_cluster_provider_t builtin_static =
{
    "static",
    NULL,
    &static_config_check,
    &static_list_servers,
    NULL,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AP_SERF_CLUSTER_PROVIDER,
                         "heartbeat", "0", &builtin_heartbeat);

    ap_register_provider(p, AP_SERF_CLUSTER_PROVIDER,
                         "static", "0", &builtin_static);

    ap_hook_handler(serf_handler, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(serf) =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    NULL,
    create_server_config,
    merge_server_config,
    serf_cmds,
    register_hooks
};
