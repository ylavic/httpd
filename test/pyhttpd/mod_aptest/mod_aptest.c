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

#include <apr_optional.h>
#include <apr_optional_hooks.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_cstr.h>
#include <apr_md5.h>
#include <apr_thread_proc.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <ap_mpm.h>

/* ap_request_resume_suspended() came with AP_IMPLEMENT_HOOK_RUN_FIRST_FROM */
#ifdef AP_IMPLEMENT_HOOK_RUN_FIRST_FROM
#define APTEST_HAS_RESUME 1
#endif

/* AptestSuspend and AptestSuspend2 (see "the suspending handlers") */
typedef struct {
    int set;
    apr_interval_time_t timer;  /* the wait */
    int result;                 /* the handler's result after it (a status),
                                 * or APTEST_SUSPEND_OK / _FILTER_ERROR */
    unsigned int flags;         /* APTEST_SUSPEND_* */
} aptest_suspend_conf;

/* The per-directory configuration: AptestWait (see "aptest-wait"),
 * AptestSuspend and AptestSuspend2
 */
typedef struct {
    int wait_mode;                  /* APTEST_WAIT_* */
    apr_interval_time_t wait_timer; /* for "timer" */
    int wait_count;                 /* for "pfdpool" */
    aptest_suspend_conf suspend[2]; /* AptestSuspend, AptestSuspend2 */
} aptest_dir_conf;

/* AptestWait's modes */
#define APTEST_WAIT_UNSET  0
#define APTEST_WAIT_TIMER  1
#define APTEST_WAIT_ECHO   2
#define APTEST_WAIT_DIGEST 3
#define APTEST_WAIT_NOTIFIER 4
#define APTEST_WAIT_PFDPOOL  5

static void *aptest_create_dir_conf(apr_pool_t *p, char *dir)
{
    return apr_pcalloc(p, sizeof(aptest_dir_conf));
}

static void *aptest_merge_dir_conf(apr_pool_t *p, void *basev, void *addv)
{
    aptest_dir_conf *base = basev, *add = addv;
    aptest_dir_conf *conf = apr_palloc(p, sizeof(*conf));
    int i;

    if (add->wait_mode != APTEST_WAIT_UNSET) {
        conf->wait_mode = add->wait_mode;
        conf->wait_timer = add->wait_timer;
        conf->wait_count = add->wait_count;
    }
    else {
        conf->wait_mode = base->wait_mode;
        conf->wait_timer = base->wait_timer;
        conf->wait_count = base->wait_count;
    }
    for (i = 0; i < 2; i++) {
        conf->suspend[i] = (add->suspend[i].set) ? add->suspend[i]
                                                 : base->suspend[i];
    }
    return conf;
}

static const char *aptest_set_wait(cmd_parms *cmd, void *dconf,
                                   const char *mode, const char *ms)
{
    aptest_dir_conf *conf = dconf;

    if (strcmp(mode, "timer") == 0) {
        apr_int64_t n = (ms) ? apr_atoi64(ms) : -1;
        if (n < 0) {
            return "AptestWait timer needs a number of milliseconds";
        }
        conf->wait_mode = APTEST_WAIT_TIMER;
        conf->wait_timer = apr_time_from_msec(n);
    }
    else if (strcmp(mode, "echo") == 0 && !ms) {
        conf->wait_mode = APTEST_WAIT_ECHO;
    }
    else if (strcmp(mode, "digest") == 0 && !ms) {
        conf->wait_mode = APTEST_WAIT_DIGEST;
    }
    else if (strcmp(mode, "notifier") == 0 && !ms) {
        conf->wait_mode = APTEST_WAIT_NOTIFIER;
    }
    else if (strcmp(mode, "pfdpool") == 0) {
        apr_int64_t n = (ms) ? apr_atoi64(ms) : 0;
        if (n <= 0 || n > 100000) {
            return "AptestWait pfdpool needs a number of contexts";
        }
        conf->wait_mode = APTEST_WAIT_PFDPOOL;
        conf->wait_count = (int)n;
    }
    else {
        return "AptestWait timer <ms> | echo | digest | notifier | "
               "pfdpool <n>";
    }
    return NULL;
}

#ifdef APTEST_HAS_RESUME
/* AptestSuspend's results besides a status */
#define APTEST_SUSPEND_OK           (-1000) /* a small body, then OK */
#define APTEST_SUSPEND_FILTER_ERROR (-1001) /* an error answered by the
                                             * output filters, then
                                             * AP_FILTER_ERROR */

/* AptestSuspend's options */
#define APTEST_SUSPEND_TWICE (1u << 0) /* resume once more, too early */

static const char *aptest_set_suspend(cmd_parms *cmd, void *dconf,
                                      int argc, char *const argv[])
{
    aptest_dir_conf *conf = dconf;
    aptest_suspend_conf *sc;
    apr_int64_t n;
    int i;

    sc = &conf->suspend[(cmd->info != NULL) ? 1 : 0];
    if (argc < 2) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " <ms> "
                           "declined|ok|filter-error|<status> [twice]",
                           NULL);
    }
    n = apr_atoi64(argv[0]);
    if (n < 0 || !apr_isdigit(*argv[0])) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " needs a number of "
                           "milliseconds", NULL);
    }
    sc->timer = apr_time_from_msec(n);

    if (strcmp(argv[1], "declined") == 0) {
        sc->result = DECLINED;
    }
    else if (strcmp(argv[1], "ok") == 0) {
        sc->result = APTEST_SUSPEND_OK;
    }
    else if (strcmp(argv[1], "filter-error") == 0) {
        sc->result = APTEST_SUSPEND_FILTER_ERROR;
    }
    else {
        n = apr_atoi64(argv[1]);
        if (!apr_isdigit(*argv[1]) || !ap_is_HTTP_VALID_RESPONSE((int)n)) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name, ": unknown "
                               "result ", argv[1], NULL);
        }
        sc->result = (int)n;
    }

    sc->flags = 0;
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "twice") == 0) {
            sc->flags |= APTEST_SUSPEND_TWICE;
        }
        else {
            return apr_pstrcat(cmd->pool, cmd->cmd->name, ": unknown "
                               "option ", argv[i], NULL);
        }
    }
    sc->set = 1;
    return NULL;
}
#endif /* APTEST_HAS_RESUME */

static const command_rec aptest_cmds[] = {
    AP_INIT_TAKE12("AptestWait", aptest_set_wait, NULL, OR_ALL,
                   "how the \"aptest-wait\" handler waits: timer <ms>, echo, "
                   "digest, notifier or pfdpool <n>"),
#ifdef APTEST_HAS_RESUME
    AP_INIT_TAKE_ARGV("AptestSuspend", aptest_set_suspend, NULL, OR_ALL,
                      "the first suspending handler: <ms> "
                      "declined|ok|filter-error|<status> [twice]"),
    AP_INIT_TAKE_ARGV("AptestSuspend2", aptest_set_suspend, "2", OR_ALL,
                      "the second suspending handler: <ms> "
                      "declined|ok|filter-error|<status> [twice]"),
#endif
    {NULL}
};

static void aptest_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(aptest) = {
    STANDARD20_MODULE_STUFF,
    aptest_create_dir_conf, /* func to create per dir config */
    aptest_merge_dir_conf,  /* func to merge per dir config */
    NULL, /* func to create per server config */
    NULL,  /* func to merge per server config */
    aptest_cmds,       /* command handlers */
    aptest_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};


static int aptest_post_read_request(request_rec *r)
{
    const char *test_name = apr_table_get(r->headers_in, "AP-Test-Name");
    if (test_name) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "test[%s]: %s",
                      test_name, r->the_request);
    }
    return DECLINED;
}

/*
 * Register the methods named in an "AP-Test-Allow-Methods" request header
 * via ap_allow_methods(), so a test can check how they are reflected in the
 * Allow response header.
 */
static int aptest_allow_methods(request_rec *r)
{
    const char *methods = apr_table_get(r->headers_in, "AP-Test-Allow-Methods");
    char *list, *name, *last;

    if (methods == NULL) {
        return DECLINED;
    }

    list = apr_pstrdup(r->pool, methods);
    for (name = apr_strtok(list, ", ", &last); name != NULL;
         name = apr_strtok(NULL, ", ", &last)) {
        ap_allow_methods(r, MERGE_ALLOW, name, NULL);
    }

    return DECLINED;
}

/*
 * Handler "aptest-getline-echo": echo the request body back, reading it
 * with AP_MODE_GETLINE rather than AP_MODE_READBYTES.  The Content-Length
 * request header left once the body has been read, if any, is returned in
 * an "AP-Test-Content-Length" response header.
 */
static int aptest_getline_echo(request_rec *r)
{
    apr_bucket_brigade *bb, *body;
    const char *clen;
    char *data;
    apr_size_t len;
    apr_status_t rv;
    int seen_eos = 0;

    if (strcmp(r->handler, "aptest-getline-echo")) {
        return DECLINED;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    body = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    while (!seen_eos) {
        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_GETLINE,
                            APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "aptest-getline-echo: reading body failed");
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }
        if (!APR_BRIGADE_EMPTY(bb)
            && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
            seen_eos = 1;
        }
        rv = apr_brigade_pflatten(bb, &data, &len, r->pool);
        if (rv == APR_SUCCESS) {
            rv = apr_brigade_write(body, NULL, NULL, data, len);
        }
        if (rv != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_brigade_cleanup(bb);
    }

    clen = apr_table_get(r->headers_in, "Content-Length");
    if (clen) {
        apr_table_setn(r->headers_out, "AP-Test-Content-Length", clen);
    }
    ap_set_content_type(r, "text/plain");
    if (apr_brigade_pflatten(body, &data, &len, r->pool) != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_rwrite(data, len, r);

    return OK;
}

/*
 * Handler "aptest-queue": a request with a controlled service time, to test
 * the MPM's queuing. Query arguments (milliseconds, combinable, in this
 * order): "cpu=N" burns N ms of CPU, "block=N" sleeps N ms holding the
 * thread (as a blocking module would), "suspend=N" suspends the request for
 * N ms in the MPM without holding a thread (ap_mpm_register_wait(), or a
 * sleep if the MPM can't), then the response of "size=N" bytes (default 16)
 * is sent.
 */
typedef struct {
    apr_interval_time_t cpu, block, suspend;
    apr_size_t size;
} aptest_queue_t;

static void aptest_queue_args(request_rec *r, aptest_queue_t *q)
{
    char *args, *arg, *last;

    memset(q, 0, sizeof(*q));
    q->size = 16;
    if (!r->args) {
        return;
    }
    args = apr_pstrdup(r->pool, r->args);
    for (arg = apr_strtok(args, "&", &last); arg;
         arg = apr_strtok(NULL, "&", &last)) {
        char *val = strchr(arg, '=');
        apr_int64_t n;
        if (!val) {
            continue;
        }
        *val++ = '\0';
        n = apr_atoi64(val);
        if (n < 0) {
            continue;
        }
        if (strcmp(arg, "cpu") == 0) {
            q->cpu = apr_time_from_msec(n);
        }
        else if (strcmp(arg, "block") == 0) {
            q->block = apr_time_from_msec(n);
        }
        else if (strcmp(arg, "suspend") == 0) {
            q->suspend = apr_time_from_msec(n);
        }
        else if (strcmp(arg, "size") == 0) {
            q->size = (apr_size_t)n;
        }
    }
}

static int aptest_queue_respond(request_rec *r, apr_size_t size)
{
    char *body = apr_palloc(r->pool, size + 1);

    memset(body, 'q', size);
    if (size) {
        body[size - 1] = '\n';
    }
    ap_set_content_type(r, "text/plain");
    ap_set_content_length(r, size);
    ap_rwrite(body, size, r);
    return OK;
}

#ifdef AP_MPMQ_CAN_REGISTER_WAIT
/* The continuation of a suspended "aptest-queue" request: respond and give
 * the connection back to the MPM, as ap_process_async_request() would.
 */
static void aptest_queue_continuation(conn_rec *c, request_rec *r,
                                      ap_mpm_wait_result_e why,
                                      const apr_array_header_t *pfds,
                                      void *baton)
{
    aptest_queue_t *q = baton;
    int status = HTTP_INTERNAL_SERVER_ERROR;

    if (why == AP_MPM_WAIT_TIMEOUT) {
        /* The wait is a timer (nothing writes to the pipe) */
        status = aptest_queue_respond(r, q->size);
    }
    if (status != OK) {
        r->status = HTTP_OK;
    }
    ap_die(status, r);
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
#endif

static int aptest_queue(request_rec *r)
{
    aptest_queue_t *q;

    if (strcmp(r->handler, "aptest-queue") != 0) {
        return DECLINED;
    }
    q = apr_pcalloc(r->pool, sizeof(*q));
    aptest_queue_args(r, q);

    if (q->cpu > 0) {
        apr_time_t end = apr_time_now() + q->cpu;
        volatile unsigned long spin = 0;
        while (apr_time_now() < end) {
            spin++;
        }
    }
    if (q->block > 0) {
        apr_sleep(q->block);
    }
    if (q->suspend > 0) {
#ifdef AP_MPMQ_CAN_REGISTER_WAIT
        int can_wait = 0;
        if (ap_mpm_query(AP_MPMQ_CAN_REGISTER_WAIT, &can_wait) == APR_SUCCESS && can_wait) {
            apr_array_header_t *pfds;
            apr_pollfd_t *pfd;
            apr_file_t *in, *out;
            apr_pool_t *p;

            apr_pool_create(&p, r->pool);
            if (apr_file_pipe_create_ex(&in, &out, APR_FULL_NONBLOCK,
                                        p) == APR_SUCCESS) {
                pfds = apr_array_make(p, 1, sizeof(apr_pollfd_t));
                pfd = apr_array_push(pfds);
                memset(pfd, 0, sizeof(*pfd));
                pfd->p = p;
                pfd->desc_type = APR_POLL_FILE;
                pfd->desc.f = in;
                pfd->reqevents = APR_POLLIN;
                if (ap_mpm_register_wait(r->connection, p, pfds, q->suspend,
                                         NULL, 0, aptest_queue_continuation,
                                         q) == APR_SUCCESS) {
                    return SUSPENDED;
                }
            }
            apr_pool_destroy(p);
        }
#endif
        apr_sleep(q->suspend);
    }
    return aptest_queue_respond(r, q->size);
}

#ifdef AP_REQUEST_WAIT_DRAINED
/*
 * Handler "aptest-wait": a request waiting through the core's request waits
 * (ap_request_wait()) without holding a thread, as its location configures
 * with AptestWait:
 *  - "AptestWait timer <ms>": waits for ms on a timer, then answers a small
 *    body ("waited <ms> ms (<n> async waits)");
 *  - "AptestWait echo": reads the request body without blocking, waiting
 *    for the client to send more, and writes it back as it comes without
 *    FLUSH, waiting for the client to take it while the output filters say
 *    to yield;
 *  - "AptestWait digest": reads the request body likewise, then answers its
 *    length and MD5 ("<length> <md5 hex> (<n> async waits)");
 *  - "AptestWait notifier": one notifier and its context serve several
 *    waits, re-armed in between (see "the notifier waits" below);
 *  - "AptestWait pfdpool <n>": n descriptor contexts, one after the other,
 *    each allocated from a subpool destroyed after two waits (see "the
 *    descriptor contexts in subpools" below).
 * The waits that can't be asynchronous (ap_request_wait() declines, e.g.
 * AsyncRequests Off) block instead, as a synchronous module would. The
 * suspended request is finished by ap_request_finish_suspended().
 */
typedef struct {
    request_rec *r;
    const aptest_dir_conf *conf;
    ap_request_waitctx_t *ctx;  /* the timer, or the client's */
    apr_bucket_brigade *bb;
    apr_md5_ctx_t md5;
    apr_off_t length;
    int waits;                   /* asynchronous waits so far */
    unsigned int blocking :1,    /* a wait declined: block from now on */
                 seen_eos :1;
} aptest_wait_t;

static void aptest_wait_continuation(request_rec *r, apr_status_t status,
                                     void *baton);

/* Wait for the client (direction), asynchronously if possible: SUSPENDED,
 * OK (ready now) or DECLINED (block from now on)
 */
static int aptest_wait_client(aptest_wait_t *w, ap_wait_direction_e direction,
                              unsigned int flags)
{
    int rc;

    if (w->blocking) {
        return DECLINED;
    }
    rc = ap_request_wait(w->ctx, direction, flags, aptest_wait_continuation,
                         w);
    if (rc == SUSPENDED) {
        w->waits++;
    }
    else if (rc == DECLINED) {
        w->blocking = 1;
    }
    return rc;
}

/* Read the request body (and write it back for echo) until its end, waiting
 * for the client as needed: OK once read, SUSPENDED, or an HTTP error
 */
static int aptest_wait_body(aptest_wait_t *w)
{
    request_rec *r = w->r;
    conn_rec *c = r->connection;
    int echo = (w->conf->wait_mode == APTEST_WAIT_ECHO);
    apr_bucket *e;
    apr_status_t rv;
    int rc;

    while (!w->seen_eos) {
        /* Don't read more than the client takes */
        if (echo && !w->blocking
            && ap_filter_should_yield(r->output_filters)) {
            if (c->aborted) {
                return DONE;
            }
            rc = aptest_wait_client(w, AP_WAIT_OUT, 0);
            if (rc == SUSPENDED) {
                return SUSPENDED;
            }
            continue; /* written (by the core's check), or blocking */
        }

        if (!w->blocking && r->expecting_100) {
            /* The 100 Continue on a nonblocking read too */
            r->expecting_100 |= AP_EXPECT_100_NONBLOCK;
        }
        rv = ap_get_brigade(r->input_filters, w->bb, AP_MODE_READBYTES,
                            w->blocking ? APR_BLOCK_READ : APR_NONBLOCK_READ,
                            AP_IOBUFSIZE);
        if (r->expecting_100) {
            r->expecting_100 &= ~AP_EXPECT_100_NONBLOCK;
        }
        if (!w->blocking
            && (APR_STATUS_IS_EAGAIN(rv)
                || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(w->bb)))) {
            if (echo) {
                /* What's echoed so far goes out without blocking */
                apr_brigade_cleanup(w->bb);
                APR_BRIGADE_INSERT_TAIL(w->bb,
                                        ap_bucket_wc_create(c->bucket_alloc));
                if (ap_pass_brigade(r->output_filters, w->bb) != APR_SUCCESS
                    || c->aborted) {
                    return DONE;
                }
                apr_brigade_cleanup(w->bb);
            }
            rc = aptest_wait_client(w, AP_WAIT_IN,
                                    APR_STATUS_IS_EAGAIN(rv)
                                    ? AP_REQUEST_WAIT_DRAINED : 0);
            if (rc == SUSPENDED) {
                return SUSPENDED;
            }
            continue; /* ready, or blocking from now on */
        }
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, APLOGNO()
                          "aptest-wait: reading the body failed");
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }

        for (e = APR_BRIGADE_FIRST(w->bb); e != APR_BRIGADE_SENTINEL(w->bb);
             e = APR_BUCKET_NEXT(e)) {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(e)) {
                w->seen_eos = 1;
                break;
            }
            if (APR_BUCKET_IS_METADATA(e)) {
                continue;
            }
            rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            apr_md5_update(&w->md5, data, len);
            w->length += len;
        }
        if (w->seen_eos) {
            /* The EOS is the handler's (at the end of the response) */
            apr_bucket_delete(e);
        }
        if (echo && !APR_BRIGADE_EMPTY(w->bb)) {
            if (ap_pass_brigade(r->output_filters, w->bb) != APR_SUCCESS
                || c->aborted) {
                return DONE;
            }
        }
        apr_brigade_cleanup(w->bb);
    }
    return OK;
}

/* Respond once done waiting: OK, SUSPENDED, or an HTTP error */
static int aptest_wait_run(aptest_wait_t *w)
{
    request_rec *r = w->r;
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char hex[2 * APR_MD5_DIGESTSIZE + 1];
    int rc, i;

    switch (w->conf->wait_mode) {
    case APTEST_WAIT_TIMER:
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "waited %" APR_TIME_T_FMT " ms (%d async waits)\n",
                   apr_time_as_msec(w->conf->wait_timer), w->waits);
        return OK;

    case APTEST_WAIT_ECHO:
        return aptest_wait_body(w);

    default:
        rc = aptest_wait_body(w);
        if (rc != OK) {
            return rc;
        }
        apr_md5_final(digest, &w->md5);
        for (i = 0; i < APR_MD5_DIGESTSIZE; i++) {
            apr_snprintf(hex + 2 * i, 3, "%02x", digest[i]);
        }
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "%" APR_OFF_T_FMT " %s (%d async waits)\n", w->length,
                   hex, w->waits);
        return OK;
    }
}

static void aptest_wait_continuation(request_rec *r, apr_status_t status,
                                     void *baton)
{
    aptest_wait_t *w = baton;
    int rc;

    if (status == APR_SUCCESS) {
        rc = aptest_wait_run(w);
        if (rc == SUSPENDED) {
            return; /* waiting again */
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO()
                      "aptest-wait: waiting for the %s failed (async)",
                      w->conf->wait_mode == APTEST_WAIT_TIMER ? "timer"
                                                              : "client");
        if (APR_STATUS_IS_TIMEUP(status) && !w->seen_eos
            && w->conf->wait_mode != APTEST_WAIT_TIMER
            && !r->bytes_sent) {
            /* The client is too slow to send the body */
            r->connection->keepalive = AP_CONN_CLOSE;
            rc = HTTP_REQUEST_TIME_OUT;
        }
        else if (w->conf->wait_mode == APTEST_WAIT_TIMER) {
            rc = HTTP_SERVICE_UNAVAILABLE;
        }
        else {
            /* The client doesn't take the response, or the MPM failed to
             * wait: give up the connection
             */
            r->connection->aborted = 1;
            rc = DONE;
        }
    }
    ap_request_finish_suspended(r, rc);
}

/*
 * The notifier waits ("AptestWait notifier"): a notifier and its context
 * serve several waits of the request, the notifier re-armed in between
 * (ap_mpm_notifier_rearm()):
 *  1. notified from another thread 50ms later, re-arming it while that wait
 *     is registered refused (APR_EBUSY);
 *  2. notified after the first wait completed and before the re-arm, a
 *     stale notification that the re-arm drops: the wait times out (300ms);
 *  3. notified after the re-arm, before the wait: it completes right away;
 *  4. not re-armed: the core declines the wait (and logs an error).
 * The response says what each step found: "notifier: busy=EBUSY wait1=ok
 * stale=dropped prenotified=ok unrearmed=declined" when all went as
 * expected, "notifier: declined" when the request can't wait
 * asynchronously (e.g. AsyncRequests Off), "notifier: none" without
 * notifiers in the MPM or threads.
 */
typedef struct {
    request_rec *r;
    ap_mpm_notifier_t *notifier;
    ap_request_waitctx_t *ctx;
#if APR_HAS_THREADS
    apr_thread_t *thread;   /* notifying the first wait, until joined */
#endif
    apr_time_t start;       /* of the current wait */
    int step;               /* the current wait, from 1 */
    const char *report;
} aptest_notifier_t;

static int aptest_notifier_respond(aptest_notifier_t *n)
{
    ap_set_content_type(n->r, "text/plain");
    ap_rprintf(n->r, "notifier:%s\n", n->report);
    return OK;
}

#if APR_HAS_THREADS
static void aptest_notifier_note(aptest_notifier_t *n, const char *what,
                                 const char *result)
{
    n->report = apr_pstrcat(n->r->pool, n->report, " ", what, "=", result,
                            NULL);
}

static void *APR_THREAD_FUNC aptest_notifier_thread(apr_thread_t *thd,
                                                    void *data)
{
    aptest_notifier_t *n = data;

    apr_sleep(apr_time_from_msec(50));
    ap_mpm_notify(n->notifier);
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/* Join the notifying thread if not yet, also when the request goes away (a
 * pre-cleanup: the thread's pool is a subpool of the request's)
 */
static apr_status_t aptest_notifier_join(void *data)
{
    aptest_notifier_t *n = data;
    apr_status_t rv;

    if (n->thread) {
        apr_thread_join(&rv, n->thread);
        n->thread = NULL;
    }
    return APR_SUCCESS;
}

static void aptest_notifier_continuation(request_rec *r, apr_status_t status,
                                         void *baton);

/* The next wait on the context */
static int aptest_notifier_wait(aptest_notifier_t *n,
                                apr_interval_time_t timeout)
{
    n->ctx->timeout = timeout;
    n->start = apr_time_now();
    n->step++;
    return ap_request_wait(n->ctx, AP_WAIT_IN, 0,
                           aptest_notifier_continuation, n);
}

static void aptest_notifier_continuation(request_rec *r, apr_status_t status,
                                         void *baton)
{
    aptest_notifier_t *n = baton;
    apr_interval_time_t took = apr_time_now() - n->start;
    unsigned int ready = ap_request_waitctx_ready(n->ctx);
    int rc;

    switch (n->step) {
    case 1:
        aptest_notifier_join(n);
        aptest_notifier_note(n, "wait1",
                             (status == APR_SUCCESS
                              && ready == (AP_WAIT_IN | AP_WAIT_OUT))
                             ? "ok" : "FAILED");
        /* Stale: after the wait completed, before the re-arm */
        ap_mpm_notify(n->notifier);
        if (ap_mpm_notifier_rearm(n->notifier) != APR_SUCCESS) {
            aptest_notifier_note(n, "rearm1", "FAILED");
            break;
        }
        rc = aptest_notifier_wait(n, apr_time_from_msec(300));
        if (rc == SUSPENDED) {
            return;
        }
        aptest_notifier_note(n, "wait2", "NOT-SUSPENDED");
        break;

    case 2:
        aptest_notifier_note(n, "stale",
                             (APR_STATUS_IS_TIMEUP(status) && !ready
                              && took >= apr_time_from_msec(250))
                             ? "dropped" : "FIRED");
        if (ap_mpm_notifier_rearm(n->notifier) != APR_SUCCESS) {
            aptest_notifier_note(n, "rearm2", "FAILED");
            break;
        }
        /* Before the wait: counts for it */
        ap_mpm_notify(n->notifier);
        rc = aptest_notifier_wait(n, apr_time_from_sec(5));
        if (rc == SUSPENDED) {
            return;
        }
        aptest_notifier_note(n, "wait3", "NOT-SUSPENDED");
        break;

    case 3:
        aptest_notifier_note(n, "prenotified",
                             (status == APR_SUCCESS
                              && took < apr_time_from_sec(1))
                             ? "ok" : "FAILED");
        /* Not re-armed: declined */
        rc = aptest_notifier_wait(n, apr_time_from_msec(100));
        if (rc == SUSPENDED) {
            return;
        }
        aptest_notifier_note(n, "unrearmed",
                             (rc == DECLINED) ? "declined" : "ANSWERED-OK");
        break;

    default:
        aptest_notifier_note(n, "unrearmed", "WAITED");
        break;
    }
    ap_request_finish_suspended(r, aptest_notifier_respond(n));
}
#endif /* APR_HAS_THREADS */

static int aptest_notifier(request_rec *r)
{
    aptest_notifier_t *n = apr_pcalloc(r->pool, sizeof(*n));
#if APR_HAS_THREADS
    apr_status_t rv;
    int rc;
#endif

    n->r = r;
    n->report = " none";
#if APR_HAS_THREADS
    if (!ap_request_can_suspend(r)) {
        n->report = " declined";
        return aptest_notifier_respond(n);
    }
    if (ap_mpm_notifier_create(&n->notifier, r->connection,
                               r->pool) != APR_SUCCESS) {
        return aptest_notifier_respond(n);
    }
    n->ctx = ap_request_waitctx_notifier(r, r->pool, n->notifier);
    n->report = "";
    apr_pool_pre_cleanup_register(r->pool, n, aptest_notifier_join);
    rv = apr_thread_create(&n->thread, NULL, aptest_notifier_thread, n,
                           r->pool);
    if (rv != APR_SUCCESS) {
        n->thread = NULL;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = aptest_notifier_wait(n, apr_time_from_sec(5));
    if (rc != SUSPENDED) {
        aptest_notifier_join(n);
        n->report = " declined";
        return aptest_notifier_respond(n);
    }
    /* Registered, not completed: re-arming is refused */
    rv = ap_mpm_notifier_rearm(n->notifier);
    aptest_notifier_note(n, "busy",
                         APR_STATUS_IS_EBUSY(rv) ? "EBUSY" : "ACCEPTED");
    return SUSPENDED;
#else
    return aptest_notifier_respond(n);
#endif
}

/*
 * The descriptor contexts in subpools ("AptestWait pfdpool <n>"): n
 * descriptor contexts made one after the other, each from a subpool of the
 * request's with its pipe, waited on twice (the second wait keeps the pipe
 * registered in the MPM), then given up with the subpool destroyed: every
 * other context released first (ap_request_waitctx_release()), the others
 * by their pool's cleanup. Answers "pfdpool: <n> contexts, <w> async
 * waits" (blocking when a wait declines).
 */
typedef struct {
    request_rec *r;
    apr_pool_t *sub;              /* of the current context, its pipe */
    apr_file_t *in, *out;
    ap_request_waitctx_t *ctx;
    int count, made;              /* the contexts to make, made so far */
    int waits;                    /* on the current context */
    int async_waits;
    unsigned int blocking :1;     /* a wait declined: block from now on */
} aptest_pfdpool_t;

static void aptest_pfdpool_continuation(request_rec *r, apr_status_t status,
                                        void *baton);

/* The waits of the contexts left: SUSPENDED, else a response status */
static int aptest_pfdpool_run(aptest_pfdpool_t *s)
{
    request_rec *r = s->r;
    apr_pollfd_t pfd;
    apr_size_t len;
    char c = 'p';
    int rc;

    for (;;) {
        if (!s->sub) {
            if (s->made == s->count) {
                break;
            }
            apr_pool_create(&s->sub, r->pool);
            if (apr_file_pipe_create_ex(&s->in, &s->out, APR_FULL_NONBLOCK,
                                        s->sub) != APR_SUCCESS) {
                apr_pool_destroy(s->sub);
                s->sub = NULL;
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            memset(&pfd, 0, sizeof(pfd));
            pfd.desc_type = APR_POLL_FILE;
            pfd.desc.f = s->in;
            s->ctx = ap_request_waitctx_pfd(r, s->sub, &pfd);
            s->ctx->timeout = apr_time_from_sec(5);
            s->made++;
            s->waits = 0;
        }
        if (s->waits == 2) {
            if (s->made % 2) {
                ap_request_waitctx_release(s->ctx);
            }
            apr_pool_destroy(s->sub);
            s->sub = NULL;
            s->ctx = NULL;
            continue;
        }

        len = 1;
        if (apr_file_write(s->out, &c, &len) != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        s->waits++;
        rc = DECLINED;
        if (!s->blocking) {
            rc = ap_request_wait(s->ctx, AP_WAIT_IN, 0,
                                 aptest_pfdpool_continuation, s);
        }
        if (rc == SUSPENDED) {
            s->async_waits++;
            return SUSPENDED;
        }
        if (rc == DECLINED) {
            s->blocking = 1;
        }
        len = 1;
        (void)apr_file_read(s->in, &c, &len);
    }

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "pfdpool: %d contexts, %d async waits\n", s->made,
               s->async_waits);
    return OK;
}

static void aptest_pfdpool_continuation(request_rec *r, apr_status_t status,
                                        void *baton)
{
    aptest_pfdpool_t *s = baton;
    apr_size_t len = 1;
    char c;
    int rc;

    if (status == APR_SUCCESS) {
        (void)apr_file_read(s->in, &c, &len);
        rc = aptest_pfdpool_run(s);
        if (rc == SUSPENDED) {
            return;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO()
                      "aptest-wait: waiting for the pipe failed (async)");
        rc = HTTP_SERVICE_UNAVAILABLE;
    }
    if (s->sub) {
        apr_pool_destroy(s->sub);
        s->sub = NULL;
    }
    ap_request_finish_suspended(r, rc);
}

static int aptest_pfdpool(request_rec *r, const aptest_dir_conf *conf)
{
    aptest_pfdpool_t *s = apr_pcalloc(r->pool, sizeof(*s));

    s->r = r;
    s->count = conf->wait_count;
    return aptest_pfdpool_run(s);
}

static int aptest_wait(request_rec *r)
{
    const aptest_dir_conf *conf;
    aptest_wait_t *w;
    int rc;

    if (strcmp(r->handler, "aptest-wait") != 0) {
        return DECLINED;
    }
    conf = ap_get_module_config(r->per_dir_config, &aptest_module);
    if (!conf || conf->wait_mode == APTEST_WAIT_UNSET) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "aptest-wait: no AptestWait for this location");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (conf->wait_mode == APTEST_WAIT_NOTIFIER) {
        return aptest_notifier(r);
    }
    if (conf->wait_mode == APTEST_WAIT_PFDPOOL) {
        return aptest_pfdpool(r, conf);
    }

    w = apr_pcalloc(r->pool, sizeof(*w));
    w->r = r;
    w->conf = conf;
    if (conf->wait_mode == APTEST_WAIT_TIMER) {
        w->ctx = ap_request_waitctx_timer(r, r->pool);
        w->ctx->timeout = conf->wait_timer;
        rc = ap_request_wait(w->ctx, AP_WAIT_IN, 0, aptest_wait_continuation,
                             w);
        if (rc == SUSPENDED) {
            w->waits++;
            return SUSPENDED;
        }
        if (rc == DECLINED) {
            apr_sleep(conf->wait_timer);
        }
        return aptest_wait_run(w);
    }

    w->ctx = ap_request_waitctx_client(r);
    w->ctx->timeout = AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT;
    w->ctx->delay = 0;
    w->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_md5_init(&w->md5);
    if (conf->wait_mode == APTEST_WAIT_ECHO) {
        ap_set_content_type(r, "application/octet-stream");
    }
    return aptest_wait_run(w);
}
#endif /* AP_REQUEST_WAIT_DRAINED */

#ifdef APTEST_HAS_RESUME
/*
 * The suspending handlers: two handler functions, at APR_HOOK_REALLY_FIRST
 * and APR_HOOK_FIRST (before mod_proxy's), acting on any request whose
 * location configures them, whatever its handler: "AptestSuspend <ms>
 * <result>" for the first one, AptestSuspend2 for the second. Each waits for
 * ms on a timer context without holding a thread, then resumes the request
 * (ap_request_resume_suspended()) with the result:
 *  - "declined": the next handlers run (e.g. the second one, mod_proxy's,
 *    or the default handler);
 *  - "ok": a small body ("aptest-suspend<1|2>: ok"), then OK;
 *  - "filter-error": an error bucket for a 413 down the output filters
 *    (which answer it), then AP_FILTER_ERROR;
 *  - a status, e.g. 403 (an ErrorDocument applies).
 * The option "twice" resumes once more before the handler returns SUSPENDED,
 * which the core refuses (logged; debug builds assert). A request that
 * can't suspend (ap_request_can_suspend(), e.g. AsyncRequests Off or a
 * subrequest) sleeps for ms holding the thread, then returns the result as
 * a synchronous module would. The response header "AP-Test-Suspend<1|2>"
 * says "async" or "sync" for each handler that acted.
 */
typedef struct {
    request_rec *r;
    const aptest_suspend_conf *sc;
    int which;  /* 1 or 2 */
} aptest_suspend_t;

/* The handler's result once done waiting */
static int aptest_suspend_result(aptest_suspend_t *s)
{
    request_rec *r = s->r;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *e;

    switch (s->sc->result) {
    case APTEST_SUSPEND_OK:
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "aptest-suspend%d: ok\n", s->which);
        return OK;

    case APTEST_SUSPEND_FILTER_ERROR:
        /* As HTTP_IN does on httpd 2.4 for a body over LimitRequestBody:
         * the header filter answers the error bucket (ap_die())
         */
        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE, NULL,
                                   r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(c->bucket_alloc));
        (void)ap_pass_brigade(r->output_filters, bb);
        apr_brigade_cleanup(bb);
        return AP_FILTER_ERROR;

    default:
        return s->sc->result;
    }
}

static void aptest_suspend_continuation(request_rec *r, apr_status_t status,
                                        void *baton)
{
    aptest_suspend_t *s = baton;
    int rc;

    if (status == APR_SUCCESS) {
        rc = aptest_suspend_result(s);
    }
    else {
        /* The MPM failed to wait (a timer's wait doesn't time out) */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO()
                      "aptest-suspend%d: waiting interrupted (async)",
                      s->which);
        rc = HTTP_SERVICE_UNAVAILABLE;
    }
    ap_request_resume_suspended(r, rc);
}

static int aptest_suspend_handler(request_rec *r, int which)
{
    const aptest_dir_conf *conf;
    aptest_suspend_t *s;
    ap_request_waitctx_t *ctx;
    int rc;

    conf = ap_get_module_config(r->per_dir_config, &aptest_module);
    if (!conf || !conf->suspend[which - 1].set) {
        return DECLINED;
    }
    s = apr_pcalloc(r->pool, sizeof(*s));
    s->r = r;
    s->sc = &conf->suspend[which - 1];
    s->which = which;

    if (ap_request_can_suspend(r)) {
        ctx = ap_request_waitctx_timer(r, r->pool);
        ctx->timeout = s->sc->timer;
        rc = ap_request_wait(ctx, AP_WAIT_IN, 0, aptest_suspend_continuation,
                             s);
        if (rc == SUSPENDED) {
            apr_table_setn(r->err_headers_out,
                           which == 1 ? "AP-Test-Suspend1"
                                      : "AP-Test-Suspend2",
                           "async");
            if (s->sc->flags & APTEST_SUSPEND_TWICE) {
                /* Too early: refused by the core */
                ap_request_resume_suspended(r, DECLINED);
            }
            return SUSPENDED;
        }
    }
    apr_table_setn(r->err_headers_out,
                   which == 1 ? "AP-Test-Suspend1" : "AP-Test-Suspend2",
                   "sync");
    apr_sleep(s->sc->timer);
    return aptest_suspend_result(s);
}

static int aptest_suspend1(request_rec *r)
{
    return aptest_suspend_handler(r, 1);
}

static int aptest_suspend2(request_rec *r)
{
    return aptest_suspend_handler(r, 2);
}
#endif /* APTEST_HAS_RESUME */

/* Install this module into the apache2 infrastructure.
 */
static void aptest_hooks(apr_pool_t *pool)
{
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool,
                  "installing hooks and handlers");

    /* test case monitoring */
    ap_hook_post_read_request(aptest_post_read_request, NULL,
                              NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(aptest_allow_methods, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(aptest_getline_echo, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(aptest_queue, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef AP_REQUEST_WAIT_DRAINED
    ap_hook_handler(aptest_wait, NULL, NULL, APR_HOOK_MIDDLE);
#endif
#ifdef APTEST_HAS_RESUME
    {
        static const char *const before_proxy[] = { "mod_proxy.c", NULL };
        ap_hook_handler(aptest_suspend1, NULL, NULL, APR_HOOK_REALLY_FIRST);
        ap_hook_handler(aptest_suspend2, NULL, before_proxy, APR_HOOK_FIRST);
    }
#endif

}

