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

/* ap_request_read_body() and the body reader's functions */
#ifdef AP_REQUEST_BODY_SETASIDE
#define APTEST_HAS_BODY 1
#endif

/* ap_run_sub_req_async() */
#ifdef ap_run_sub_req_async
#define APTEST_HAS_SUBREQ 1
#endif

/* Several pending waits of a request, ap_request_wait_cancel() */
#if defined(APTEST_HAS_SUBREQ) && AP_MODULE_MAGIC_AT_LEAST(20260601, 9)
#define APTEST_HAS_MULTI 1
#endif

/* ap_mpm_register_wait()'s flags: per pfd (an array) or for the wait */
#if AP_MODULE_MAGIC_AT_LEAST(20260601, 10)
#define APTEST_WAIT_NO_FLAGS NULL
#define APTEST_HAS_PFDFLAGS 1
#else
#define APTEST_WAIT_NO_FLAGS 0
#endif

/* Request filters holding their output or input (ap_filter_pending_wait()) */
#if AP_MODULE_MAGIC_AT_LEAST(20260601, 15)
#define APTEST_HAS_HOLD 1
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
    const char *wait_uri;           /* for "multi" (its subrequest) */
    aptest_suspend_conf suspend[2]; /* AptestSuspend, AptestSuspend2 */
    int body_mode;                  /* APTEST_BODY_* (AptestBody) */
    int body_block;                 /* read from an output filter, blocking */
    apr_off_t body_limit;           /* for "discard" */
    const char *subreq_uri;         /* AptestSubreq's (see "the
                                     * subrequests' handler") */
    int subreq_n;
    int subreq_capture;             /* "captured", else "passed" */
    int subreq_declined;            /* "declined", else "ok" */
    apr_interval_time_t subreq_timeout; /* "timeout <ms>", else 0 */
    int hold_mode;                  /* APTEST_HOLD_* (AptestHold, see "the
                                     * holding filters") */
    apr_interval_time_t hold_time;  /* how long a hold lasts */
    apr_size_t hold_size;           /* "room": the pieces passed */
    int hold_proto;                 /* "proto": a protocol filter */
} aptest_dir_conf;

/* AptestHold's modes */
#define APTEST_HOLD_UNSET    0
#define APTEST_HOLD_TIMER    1 /* at the EOS, on a timer */
#define APTEST_HOLD_NOTIFIER 2 /* at the EOS, on a notifier */
#define APTEST_HOLD_CHUNK    3 /* each brigade with data, on a timer */
#define APTEST_HOLD_ROOM     4 /* pieces passed, held for room */
#define APTEST_HOLD_INPUT    5 /* each input read, on a timer */

/* AptestBody's modes */
#define APTEST_BODY_UNSET   0
#define APTEST_BODY_PULL    1
#define APTEST_BODY_SINK    2
#define APTEST_BODY_DISCARD 3

/* AptestWait's modes */
#define APTEST_WAIT_UNSET  0
#define APTEST_WAIT_TIMER  1
#define APTEST_WAIT_ECHO   2
#define APTEST_WAIT_DIGEST 3
#define APTEST_WAIT_NOTIFIER 4
#define APTEST_WAIT_PFDPOOL  5
#define APTEST_WAIT_MULTI    6
#define APTEST_WAIT_PFDFLAGS 7

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
        conf->wait_uri = add->wait_uri;
    }
    else {
        conf->wait_mode = base->wait_mode;
        conf->wait_timer = base->wait_timer;
        conf->wait_count = base->wait_count;
        conf->wait_uri = base->wait_uri;
    }
    for (i = 0; i < 2; i++) {
        conf->suspend[i] = (add->suspend[i].set) ? add->suspend[i]
                                                 : base->suspend[i];
    }
    if (add->body_mode != APTEST_BODY_UNSET) {
        conf->body_mode = add->body_mode;
        conf->body_block = add->body_block;
        conf->body_limit = add->body_limit;
    }
    else {
        conf->body_mode = base->body_mode;
        conf->body_block = base->body_block;
        conf->body_limit = base->body_limit;
    }
    if (add->subreq_uri) {
        conf->subreq_uri = add->subreq_uri;
        conf->subreq_n = add->subreq_n;
        conf->subreq_capture = add->subreq_capture;
        conf->subreq_declined = add->subreq_declined;
        conf->subreq_timeout = add->subreq_timeout;
    }
    else {
        conf->subreq_uri = base->subreq_uri;
        conf->subreq_n = base->subreq_n;
        conf->subreq_capture = base->subreq_capture;
        conf->subreq_declined = base->subreq_declined;
        conf->subreq_timeout = base->subreq_timeout;
    }
    if (add->hold_mode != APTEST_HOLD_UNSET) {
        conf->hold_mode = add->hold_mode;
        conf->hold_time = add->hold_time;
        conf->hold_size = add->hold_size;
        conf->hold_proto = add->hold_proto;
    }
    else {
        conf->hold_mode = base->hold_mode;
        conf->hold_time = base->hold_time;
        conf->hold_size = base->hold_size;
        conf->hold_proto = base->hold_proto;
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
#ifdef APTEST_HAS_MULTI
    else if (strcmp(mode, "multi") == 0) {
        conf->wait_mode = APTEST_WAIT_MULTI;
        conf->wait_uri = ms; /* the subrequest's, optional */
    }
#endif
#ifdef APTEST_HAS_PFDFLAGS
    else if (strcmp(mode, "pfdflags") == 0 && !ms) {
        conf->wait_mode = APTEST_WAIT_PFDFLAGS;
    }
#endif
    else {
        return "AptestWait timer <ms> | echo | digest | notifier | "
               "pfdpool <n> | multi [<uri>] | pfdflags";
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
#define APTEST_SUSPEND_READ  (1u << 1) /* read the body first, then replay
                                        * it to the next handlers */

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
                           "declined|ok|filter-error|<status> [twice] "
                           "[read]", NULL);
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
#ifdef APTEST_HAS_BODY
        else if (strcmp(argv[i], "read") == 0) {
            sc->flags |= APTEST_SUSPEND_READ;
        }
#endif
        else {
            return apr_pstrcat(cmd->pool, cmd->cmd->name, ": unknown "
                               "option ", argv[i], NULL);
        }
    }
    sc->set = 1;
    return NULL;
}
#endif /* APTEST_HAS_RESUME */

#ifdef APTEST_HAS_BODY
static const char *aptest_set_body(cmd_parms *cmd, void *dconf,
                                   const char *mode, const char *arg)
{
    aptest_dir_conf *conf = dconf;

    conf->body_block = 0;
    if ((strcmp(mode, "pull") == 0 || strcmp(mode, "sink") == 0)
        && (!arg || strcmp(arg, "block") == 0)) {
        conf->body_mode = (*mode == 'p') ? APTEST_BODY_PULL
                                         : APTEST_BODY_SINK;
        conf->body_block = (arg != NULL);
    }
    else if (strcmp(mode, "discard") == 0 && arg
             && (apr_isdigit(*arg) || *arg == '-')) {
        conf->body_mode = APTEST_BODY_DISCARD;
        conf->body_limit = apr_atoi64(arg);
    }
    else {
        return "AptestBody pull|sink [block] | discard <limit>";
    }
    return NULL;
}
#endif /* APTEST_HAS_BODY */

#ifdef APTEST_HAS_SUBREQ
static const char *aptest_set_subreq(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[])
{
    aptest_dir_conf *conf = dconf;
    apr_int64_t n;
    int i;

    if (argc < 3 || !apr_isdigit(*argv[1])
        || (strcmp(argv[2], "passed") != 0
            && strcmp(argv[2], "captured") != 0)) {
        return "AptestSubreq <uri> <n> passed|captured [ok|declined] "
               "[timeout <ms>]";
    }
    conf->subreq_uri = argv[0];
    conf->subreq_n = (int)apr_atoi64(argv[1]);
    conf->subreq_capture = (*argv[2] == 'c');
    conf->subreq_declined = 0;
    conf->subreq_timeout = 0;
    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "ok") == 0) {
            conf->subreq_declined = 0;
        }
        else if (strcmp(argv[i], "declined") == 0) {
            conf->subreq_declined = 1;
        }
        else if (strcmp(argv[i], "timeout") == 0 && i + 1 < argc
                 && apr_isdigit(*argv[i + 1])) {
            n = apr_atoi64(argv[++i]);
            conf->subreq_timeout = apr_time_from_msec(n);
        }
        else {
            return apr_pstrcat(cmd->pool, "AptestSubreq: unknown option ",
                               argv[i], NULL);
        }
    }
    return NULL;
}
#endif /* APTEST_HAS_SUBREQ */

#ifdef APTEST_HAS_HOLD
static const char *aptest_set_hold(cmd_parms *cmd, void *dconf,
                                   int argc, char *const argv[])
{
    static const char *const modes[] = {
        "", "timer", "notifier", "chunk", "room", "input", NULL
    };
    aptest_dir_conf *conf = dconf;
    apr_int64_t n;
    int i;

    if (argc < 2 || !apr_isdigit(*argv[1])) {
        return "AptestHold timer|notifier|chunk|input <ms> [proto] "
               "or room <bytes>";
    }
    for (i = 1; modes[i]; i++) {
        if (strcmp(argv[0], modes[i]) == 0) {
            break;
        }
    }
    if (!modes[i]) {
        return apr_pstrcat(cmd->pool, "AptestHold: unknown mode ", argv[0],
                           NULL);
    }
    conf->hold_mode = i;
    n = apr_atoi64(argv[1]);
    conf->hold_time = 0;
    conf->hold_size = 0;
    if (i == APTEST_HOLD_ROOM) {
        conf->hold_size = (n > 0) ? (apr_size_t)n : 1;
    }
    else {
        conf->hold_time = apr_time_from_msec(n);
    }
    conf->hold_proto = (argc > 2 && strcmp(argv[2], "proto") == 0);
    if (argc > 3 || (argc > 2 && !conf->hold_proto)) {
        return "AptestHold: unknown option";
    }
    return NULL;
}
#endif /* APTEST_HAS_HOLD */

static const command_rec aptest_cmds[] = {
    AP_INIT_TAKE12("AptestWait", aptest_set_wait, NULL, OR_ALL,
                   "how the \"aptest-wait\" handler waits: timer <ms>, echo, "
                   "digest, notifier, pfdpool <n>, multi [<uri>] or "
                   "pfdflags"),
#ifdef APTEST_HAS_RESUME
    AP_INIT_TAKE_ARGV("AptestSuspend", aptest_set_suspend, NULL, OR_ALL,
                      "the first suspending handler: <ms> "
                      "declined|ok|filter-error|<status> [twice] [read]"),
    AP_INIT_TAKE_ARGV("AptestSuspend2", aptest_set_suspend, "2", OR_ALL,
                      "the second suspending handler: <ms> "
                      "declined|ok|filter-error|<status> [twice] [read]"),
#endif
#ifdef APTEST_HAS_BODY
    AP_INIT_TAKE12("AptestBody", aptest_set_body, NULL, OR_ALL,
                   "how the \"aptest-body\" handler reads the request body: "
                   "pull [block], sink [block] or discard <limit>"),
#endif
#ifdef APTEST_HAS_SUBREQ
    AP_INIT_TAKE_ARGV("AptestSubreq", aptest_set_subreq, NULL, OR_ALL,
                      "the subrequests run before the handlers: <uri> <n> "
                      "passed|captured [ok|declined] [timeout <ms>]"),
#endif
#ifdef APTEST_HAS_HOLD
    AP_INIT_TAKE_ARGV("AptestHold", aptest_set_hold, NULL, OR_ALL,
                      "how the holding filters hold: timer|notifier|chunk|"
                      "input <ms> [proto] or room <bytes>"),
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
                                         NULL, APTEST_WAIT_NO_FLAGS,
                                         aptest_queue_continuation,
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

#ifdef APTEST_HAS_MULTI
static int aptest_multi(request_rec *r, const aptest_dir_conf *conf);
#endif
#ifdef APTEST_HAS_PFDFLAGS
static int aptest_pfdflags(request_rec *r);
#endif

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
#ifdef APTEST_HAS_MULTI
    if (conf->wait_mode == APTEST_WAIT_MULTI) {
        return aptest_multi(r, conf);
    }
#endif
#ifdef APTEST_HAS_PFDFLAGS
    if (conf->wait_mode == APTEST_WAIT_PFDFLAGS) {
        return aptest_pfdflags(r);
    }
#endif

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

#ifdef APTEST_HAS_BODY
/*
 * The body reader's checks: handler "aptest-body", as its location
 * configures with AptestBody:
 *  - "AptestBody pull": reads the request body with ap_request_read_body(),
 *    waiting for the client with ap_request_wait_body(), then answers its
 *    length and MD5 ("<length> <md5 hex> (pull, <n> async waits)");
 *  - "AptestBody sink": likewise through ap_request_body_run() and a sink
 *    ("<length> <md5 hex> (sink, async|sync)": whether the run suspended);
 *  - "AptestBody pull block" or "sink block": the handler writes "block"
 *    and flushes it, so that an output filter reads the body while the
 *    handler runs (the request can suspend then), blocking
 *    (AP_REQUEST_BODY_BLOCK), and puts "<length> <md5 hex> (<pull|sink>
 *    block, <n> AGAIN)" before it;
 *  - "AptestBody discard <limit>": answers "discard" at once (flushed), then
 *    discards the body (ap_request_discard_body()), waiting for the client,
 *    and logs the outcome at info ("aptest-body: discard: OK|DONE (<n> async
 *    waits)").
 * A request that can't suspend (e.g. AsyncRequests Off) reads blocking: the
 * same responses. The suspended request is finished by
 * ap_request_finish_suspended().
 */

/* A pull loop on ap_request_read_body() (also AptestSuspend's "read") */
typedef struct {
    request_rec *r;
    apr_bucket_brigade *tmp;     /* each read */
    apr_bucket_brigade *kept;    /* the body read, if kept (with its EOS) */
    apr_md5_ctx_t md5;
    apr_off_t length;
    unsigned int flags;          /* for ap_request_read_body() */
    int waits;                   /* asynchronous waits so far */
    int again;                   /* reads that said AGAIN */
    ap_request_continuation_fn *fn;  /* the waits' continuation */
    void *baton;
    unsigned int seen_eos :1;
} aptest_pull_t;

static void aptest_pull_init(aptest_pull_t *p, request_rec *r,
                             unsigned int flags, int keep,
                             ap_request_continuation_fn *fn, void *baton)
{
    p->r = r;
    p->tmp = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    p->kept = (keep) ? apr_brigade_create(r->pool,
                                          r->connection->bucket_alloc)
                     : NULL;
    apr_md5_init(&p->md5);
    p->flags = flags;
    p->fn = fn;
    p->baton = baton;
}

/* Digest the buckets of bb, noting the EOS: OK or an HTTP error */
static int aptest_digest(apr_bucket_brigade *bb, apr_md5_ctx_t *md5,
                         apr_off_t *length, int *eos)
{
    apr_bucket *e;

    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        const char *data;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            *eos = 1;
            break;
        }
        if (APR_BUCKET_IS_METADATA(e)) {
            continue;
        }
        if (apr_bucket_read(e, &data, &len, APR_BLOCK_READ) != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_md5_update(md5, data, len);
        *length += len;
    }
    return OK;
}

/* Read the body until its end: OK, SUSPENDED (p->fn reads on later), or an
 * HTTP error
 */
static int aptest_pull(aptest_pull_t *p)
{
    while (!p->seen_eos) {
        int rc, eos = 0;

        rc = ap_request_read_body(p->r, p->tmp, AP_IOBUFSIZE, p->flags);
        if (rc == AGAIN) {
            p->again++;
            rc = ap_request_wait_body(p->r, p->fn, p->baton);
            if (rc == SUSPENDED) {
                p->waits++;
                return SUSPENDED;
            }
            continue; /* ready, or blocking from now on */
        }
        if (rc != OK) {
            return rc;
        }
        rc = aptest_digest(p->tmp, &p->md5, &p->length, &eos);
        if (rc != OK) {
            return rc;
        }
        p->seen_eos = (eos != 0);
        if (p->kept) {
            APR_BRIGADE_CONCAT(p->kept, p->tmp);
        }
        else {
            apr_brigade_cleanup(p->tmp);
        }
    }
    return OK;
}

/* "<length> <md5 hex>" of what was digested */
static const char *aptest_digest_str(apr_pool_t *pool, apr_md5_ctx_t *md5,
                                     apr_off_t length)
{
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char hex[2 * APR_MD5_DIGESTSIZE + 1];
    int i;

    apr_md5_final(digest, md5);
    for (i = 0; i < APR_MD5_DIGESTSIZE; i++) {
        apr_snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
    return apr_psprintf(pool, "%" APR_OFF_T_FMT " %s", length, hex);
}

typedef struct {
    request_rec *r;
    const aptest_dir_conf *conf;
    aptest_pull_t pull;          /* pull, and the sink's digest */
    int sink_async;              /* the run suspended */
    int discard_waits;
} aptest_body_t;

/* The response once the body is read: OK or the error */
static int aptest_body_respond(aptest_body_t *b, int rc)
{
    request_rec *r = b->r;

    if (rc != OK) {
        return rc;
    }
    ap_set_content_type(r, "text/plain");
    if (b->conf->body_mode == APTEST_BODY_PULL) {
        ap_rprintf(r, "%s (pull, %d async waits)\n",
                   aptest_digest_str(r->pool, &b->pull.md5, b->pull.length),
                   b->pull.waits);
    }
    else {
        ap_rprintf(r, "%s (sink, %s)\n",
                   aptest_digest_str(r->pool, &b->pull.md5, b->pull.length),
                   b->sink_async ? "async" : "sync");
    }
    return OK;
}

static void aptest_body_pull_continuation(request_rec *r, apr_status_t status,
                                          void *baton)
{
    aptest_body_t *b = baton;
    int rc;

    /* The next read answers a timeout or an interruption */
    rc = aptest_pull(&b->pull);
    if (rc == SUSPENDED) {
        return;
    }
    ap_request_finish_suspended(r, aptest_body_respond(b, rc));
}

static int aptest_body_sink(request_rec *r, apr_bucket_brigade *bb, int eos,
                            void *baton)
{
    aptest_body_t *b = baton;
    int seen = 0;

    return aptest_digest(bb, &b->pull.md5, &b->pull.length, &seen);
}

static void aptest_body_sink_done(request_rec *r, int status, void *baton)
{
    aptest_body_t *b = baton;

    ap_request_finish_suspended(r, aptest_body_respond(b, status));
}

/* The blocking reads from an output filter ("block"), at its first call */
static apr_status_t aptest_body_block_filter(ap_filter_t *f,
                                             apr_bucket_brigade *bb)
{
    aptest_body_t *b = f->ctx;
    request_rec *r = f->r;
    const char *line;
    int rc;

    if (b->conf->body_mode == APTEST_BODY_PULL) {
        rc = aptest_pull(&b->pull);
    }
    else {
        rc = ap_request_body_run(r, AP_IOBUFSIZE, AP_REQUEST_BODY_BLOCK,
                                 aptest_body_sink, aptest_body_sink_done, b);
    }
    if (rc == SUSPENDED) {
        /* Never with AP_REQUEST_BODY_BLOCK */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "aptest-body: a blocking read suspended");
        return APR_EGENERAL;
    }
    line = (rc == OK)
           ? apr_psprintf(r->pool, "%s (%s block, %d AGAIN)\n",
                          aptest_digest_str(r->pool, &b->pull.md5,
                                            b->pull.length),
                          b->conf->body_mode == APTEST_BODY_PULL ? "pull"
                                                                 : "sink",
                          b->pull.again)
           : apr_psprintf(r->pool, "error %d\n", rc);
    APR_BRIGADE_INSERT_HEAD(bb, apr_bucket_pool_create(line, strlen(line),
                                                       r->pool,
                                                       f->c->bucket_alloc));
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void aptest_body_discard_continuation(request_rec *r,
                                             apr_status_t status,
                                             void *baton);

/* Discard the body, waiting for the client: OK once done, or SUSPENDED */
static int aptest_body_discard(aptest_body_t *b)
{
    request_rec *r = b->r;
    int rc;

    for (;;) {
        rc = ap_request_discard_body(r, b->conf->body_limit);
        if (rc != AGAIN) {
            break;
        }
        rc = ap_request_wait_body(r, aptest_body_discard_continuation, b);
        if (rc == SUSPENDED) {
            b->discard_waits++;
            return SUSPENDED;
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                  "aptest-body: discard: %s (%d async waits)",
                  rc == OK ? "OK" : "DONE", b->discard_waits);
    return OK; /* answered already */
}

static void aptest_body_discard_continuation(request_rec *r,
                                             apr_status_t status,
                                             void *baton)
{
    aptest_body_t *b = baton;

    /* The next read answers a timeout or an interruption */
    if (aptest_body_discard(b) == SUSPENDED) {
        return;
    }
    ap_request_finish_suspended(r, OK);
}

static int aptest_body(request_rec *r)
{
    const aptest_dir_conf *conf;
    aptest_body_t *b;
    int rc;

    if (strcmp(r->handler, "aptest-body") != 0) {
        return DECLINED;
    }
    conf = ap_get_module_config(r->per_dir_config, &aptest_module);
    if (!conf || conf->body_mode == APTEST_BODY_UNSET) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "aptest-body: no AptestBody for this location");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    b = apr_pcalloc(r->pool, sizeof(*b));
    b->r = r;
    b->conf = conf;

    if (conf->body_mode == APTEST_BODY_DISCARD) {
        ap_set_content_type(r, "text/plain");
        ap_rputs("discard\n", r);
        if (ap_rflush(r) != APR_SUCCESS) {
            return DONE;
        }
        return aptest_body_discard(b);
    }

    aptest_pull_init(&b->pull, r,
                     conf->body_block ? AP_REQUEST_BODY_BLOCK : 0, 0,
                     aptest_body_pull_continuation, b);
    if (conf->body_block) {
        ap_set_content_type(r, "text/plain");
        ap_add_output_filter("APTEST_BODY_BLOCK", b, r, r->connection);
        ap_rputs("block\n", r);
        if (ap_rflush(r) != APR_SUCCESS) {
            return DONE;
        }
        return OK;
    }

    if (conf->body_mode == APTEST_BODY_PULL) {
        rc = aptest_pull(&b->pull);
    }
    else {
        rc = ap_request_body_run(r, AP_IOBUFSIZE, 0, aptest_body_sink,
                                 aptest_body_sink_done, b);
        b->sink_async = (rc == SUSPENDED);
    }
    if (rc == SUSPENDED) {
        return SUSPENDED;
    }
    return aptest_body_respond(b, rc);
}

/* AptestSuspend's "read": the body read is served to the next handlers by
 * this input filter, as a module checking the body before them would
 */
static apr_status_t aptest_replay_filter(ap_filter_t *f,
                                         apr_bucket_brigade *bb,
                                         ap_input_mode_t mode,
                                         apr_read_type_e block,
                                         apr_off_t readbytes)
{
    apr_bucket_brigade *kept = f->ctx;
    apr_bucket *after;
    apr_status_t rv;

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return APR_ENOTIMPL;
    }
    if (APR_BRIGADE_EMPTY(kept)) {
        /* All served: the end again */
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
        return APR_SUCCESS;
    }
    if (mode == AP_MODE_GETLINE) {
        return apr_brigade_split_line(bb, kept, APR_BLOCK_READ,
                                      HUGE_STRING_LEN);
    }
    rv = apr_brigade_partition(kept, readbytes, &after);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
        return rv;
    }
    while (APR_BRIGADE_FIRST(kept) != after) {
        apr_bucket *e = APR_BRIGADE_FIRST(kept);
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    return APR_SUCCESS;
}
#endif /* APTEST_HAS_BODY */

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
 * which the core refuses (logged; debug builds assert). The option "read"
 * reads the whole request body first (ap_request_read_body(), set aside,
 * waiting for the client with ap_request_wait_body()), then serves it to
 * the next handlers with an input filter ("APTEST_REPLAY"), as a module
 * checking the body before them would, then waits: the response header
 * "AP-Test-Read<1|2>" gives the length read and the waits for it, a read
 * failing is the handler's result. A request that can't suspend
 * (ap_request_can_suspend(), e.g. AsyncRequests Off or a subrequest not run
 * by ap_run_sub_req_async()) reads
 * and sleeps for ms holding the thread, then returns the result as a
 * synchronous module would. The response header "AP-Test-Suspend<1|2>"
 * says "async" or "sync" for each handler that acted (the timer's wait).
 */
typedef struct {
    request_rec *r;
    const aptest_suspend_conf *sc;
    int which;  /* 1 or 2 */
#ifdef APTEST_HAS_BODY
    aptest_pull_t pull;          /* "read" */
#endif
    unsigned int read_done :1,
                 suspended :1;   /* the handler returned SUSPENDED */
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

/* Read the body if configured, then wait for the timer: the handler's
 * result, or SUSPENDED (a continuation goes on)
 */
static int aptest_suspend_run(aptest_suspend_t *s)
{
    request_rec *r = s->r;
    ap_request_waitctx_t *ctx;
    const char *hdr = (s->which == 1) ? "AP-Test-Suspend1"
                                      : "AP-Test-Suspend2";
    int rc;

#ifdef APTEST_HAS_BODY
    if ((s->sc->flags & APTEST_SUSPEND_READ) && !s->read_done) {
        rc = aptest_pull(&s->pull);
        if (rc == SUSPENDED) {
            s->suspended = 1;
            return SUSPENDED;
        }
        s->read_done = 1;
        apr_table_setn(r->err_headers_out,
                       s->which == 1 ? "AP-Test-Read1" : "AP-Test-Read2",
                       apr_psprintf(r->pool, "%" APR_OFF_T_FMT " %d",
                                    s->pull.length, s->pull.waits));
        if (rc != OK) {
            return rc;
        }
        ap_add_input_filter("APTEST_REPLAY", s->pull.kept, r,
                            r->connection);
    }
#endif

    if (ap_request_can_suspend(r)) {
        ctx = ap_request_waitctx_timer(r, r->pool);
        ctx->timeout = s->sc->timer;
        rc = ap_request_wait(ctx, AP_WAIT_IN, 0, aptest_suspend_continuation,
                             s);
        if (rc == SUSPENDED) {
            apr_table_setn(r->err_headers_out, hdr, "async");
            if ((s->sc->flags & APTEST_SUSPEND_TWICE) && !s->suspended) {
                /* Too early: refused by the core */
                ap_request_resume_suspended(r, DECLINED);
            }
            s->suspended = 1;
            return SUSPENDED;
        }
    }
    apr_table_setn(r->err_headers_out, hdr, "sync");
    apr_sleep(s->sc->timer);
    return aptest_suspend_result(s);
}

#ifdef APTEST_HAS_BODY
static void aptest_suspend_read_continuation(request_rec *r,
                                             apr_status_t status,
                                             void *baton)
{
    aptest_suspend_t *s = baton;
    int rc;

    /* The next read answers a timeout or an interruption */
    rc = aptest_suspend_run(s);
    if (rc == SUSPENDED) {
        return;
    }
    ap_request_resume_suspended(r, rc);
}
#endif

static int aptest_suspend_handler(request_rec *r, int which)
{
    const aptest_dir_conf *conf;
    aptest_suspend_t *s;

    conf = ap_get_module_config(r->per_dir_config, &aptest_module);
    if (!conf || !conf->suspend[which - 1].set) {
        return DECLINED;
    }
    s = apr_pcalloc(r->pool, sizeof(*s));
    s->r = r;
    s->sc = &conf->suspend[which - 1];
    s->which = which;
#ifdef APTEST_HAS_BODY
    if (s->sc->flags & APTEST_SUSPEND_READ) {
        aptest_pull_init(&s->pull, r, AP_REQUEST_BODY_SETASIDE, 1,
                         aptest_suspend_read_continuation, s);
    }
#endif
    return aptest_suspend_run(s);
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

#ifdef APTEST_HAS_SUBREQ
/*
 * The subrequests' handler: a handler function at APR_HOOK_REALLY_FIRST
 * acting on any request whose location configures "AptestSubreq <uri> <n>
 * passed|captured [ok|declined] [timeout <ms>]", whatever its handler. It
 * runs n subrequests of uri in turn with ap_run_sub_req_async(), the next
 * one from the done function of the previous one when it suspended (e.g.
 * mod_proxy waiting for its backend), then:
 *  - "ok" (the default): answers a line "aptest-subreq: <summary>";
 *  - "declined": the next handlers run (e.g. the default handler).
 * The subrequests' output is "passed" to the client (before the request's
 * own), or "captured" by an output filter of the subrequest
 * ("APTEST_CAPTURE", which passes nothing on, as guardian's does). The
 * timeout caps each subrequest (HTTP_GATEWAY_TIME_OUT once reached). The
 * summary, "n=<n> async=<suspended> statuses=<s1,s2,...>" plus for captured
 * output " captured=<bytes>:<md5 prefix>", is also the response header
 * "AP-Test-Subreq" when the output is captured (the header isn't sent yet).
 * A request that can't suspend (AsyncRequests Off) runs the subrequests
 * blocking: the same responses, async=0.
 */
typedef struct {
    request_rec *r;
    const aptest_dir_conf *conf;
    int i;                      /* subrequests run */
    int nasync;                 /* of which suspended */
    apr_off_t captured;         /* bytes captured */
    apr_md5_ctx_t md5;          /* of the bytes captured */
    char statuses[128];         /* "s1,s2,..." (truncated) */
    apr_size_t slen;
    apr_bucket_brigade *bb;     /* the answer, made once */
} aptest_subreq_t;

static ap_filter_rec_t *aptest_capture_handle;

/* Capture a subrequest's output: counted and digested, passed nowhere */
static apr_status_t aptest_capture_filter(ap_filter_t *f,
                                          apr_bucket_brigade *bb)
{
    aptest_subreq_t *s = f->ctx;
    apr_bucket *e;
    const char *data;
    apr_size_t len;
    apr_status_t rv;

    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        if (APR_BUCKET_IS_METADATA(e)) {
            continue;
        }
        rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            apr_brigade_cleanup(bb);
            return rv;
        }
        apr_md5_update(&s->md5, data, len);
        s->captured += len;
    }
    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

/* A subrequest done (inline or from done): its status recorded (its
 * response's for OK, as mod_include reads it), destroyed
 */
static void aptest_subreq_record(aptest_subreq_t *s, request_rec *rsub,
                                 int status)
{
    if (status == OK) {
        status = rsub->status;
    }
    if (s->slen + 8 < sizeof(s->statuses)) {
        s->slen += apr_snprintf(s->statuses + s->slen,
                                sizeof(s->statuses) - s->slen, "%s%d",
                                s->slen ? "," : "", status);
    }
    ap_destroy_sub_req(rsub);
}

/* The handler's result once the subrequests are done */
static int aptest_subreq_result(aptest_subreq_t *s)
{
    request_rec *r = s->r;
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char summary[256];
    apr_size_t len;

    len = apr_snprintf(summary, sizeof(summary), "n=%d async=%d statuses=%s",
                       s->i, s->nasync, s->statuses);
    if (s->conf->subreq_capture) {
        apr_md5_final(digest, &s->md5);
        apr_snprintf(summary + len, sizeof(summary) - len,
                     " captured=%" APR_OFF_T_FMT ":%02x%02x%02x%02x",
                     s->captured, digest[0], digest[1], digest[2], digest[3]);
        apr_table_set(r->headers_out, "AP-Test-Subreq", summary);
    }
    if (s->conf->subreq_declined) {
        return DECLINED;
    }
    if (s->conf->subreq_capture) {
        ap_set_content_type(r, "text/plain");
    }
    s->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_brigade_printf(s->bb, NULL, NULL, "aptest-subreq: %s\n", summary);
    if (ap_pass_brigade(r->output_filters, s->bb) != APR_SUCCESS) {
        apr_brigade_cleanup(s->bb);
        return AP_FILTER_ERROR;
    }
    apr_brigade_cleanup(s->bb);
    return OK;
}

static void aptest_subreq_done(request_rec *rsub, int status, void *baton);

/* Run the next subrequests: the handler's result, or SUSPENDED (done goes
 * on)
 */
static int aptest_subreq_run(aptest_subreq_t *s)
{
    request_rec *r = s->r;
    request_rec *rsub;
    int rc;

    while (s->i < s->conf->subreq_n) {
        s->i++;
        if (s->conf->subreq_capture) {
            rsub = ap_sub_req_lookup_uri(s->conf->subreq_uri, r, NULL);
            ap_add_output_filter_handle(aptest_capture_handle, s, rsub,
                                        rsub->connection);
        }
        else {
            rsub = ap_sub_req_lookup_uri(s->conf->subreq_uri, r,
                                         r->output_filters);
        }
        if (rsub->status != HTTP_OK) {
            aptest_subreq_record(s, rsub, rsub->status);
            continue;
        }
        rc = ap_run_sub_req_async(rsub, s->conf->subreq_timeout,
                                  aptest_subreq_done, s);
        if (rc == SUSPENDED) {
            s->nasync++;
            return SUSPENDED;
        }
        aptest_subreq_record(s, rsub, rc);
    }
    return aptest_subreq_result(s);
}

static void aptest_subreq_done(request_rec *rsub, int status, void *baton)
{
    aptest_subreq_t *s = baton;
    int rc;

    aptest_subreq_record(s, rsub, status);
    rc = aptest_subreq_run(s);
    if (rc != SUSPENDED) {
        ap_request_resume_suspended(s->r, rc);
    }
}

static int aptest_subreq(request_rec *r)
{
    const aptest_dir_conf *conf;
    aptest_subreq_t *s;

    conf = ap_get_module_config(r->per_dir_config, &aptest_module);
    if (!conf || !conf->subreq_uri) {
        return DECLINED;
    }
    s = apr_pcalloc(r->pool, sizeof(*s));
    s->r = r;
    s->conf = conf;
    apr_md5_init(&s->md5);
    return aptest_subreq_run(s);
}
#endif /* APTEST_HAS_SUBREQ */

#ifdef APTEST_HAS_MULTI
/*
 * Several waits of a request pending at once ("AptestWait multi [<uri>]"),
 * made by the handler in its run, each with its own continuation, all in
 * the MPM's one wait for the connection:
 *  - N: a notifier context, notified by another thread 50ms later; its
 *    continuation runs a subrequest of <uri> if given (its output captured,
 *    as "aptest-subreq" does) with ap_run_sub_req_async() while the others
 *    are pending: it suspends, its waits pending with the others, and its
 *    done function (S) is called once it completes;
 *  - P1, P2: two descriptor contexts on the read end of the same pipe (one
 *    pfd for both in the MPM's wait), which that thread writes 20ms after
 *    the notification: they complete together, called in that order;
 *  - T1, T2: two timers of 100ms, made one after the other: they complete
 *    together, called in that order;
 *  - C: a timer of 30ms canceled at once (ap_request_wait_cancel()): never
 *    called, and canceling it again finds no wait;
 *  - D: a timer of 10s left pending: the request's end drops it (never
 *    called, an error is logged if it is);
 *  - F: a timer of 300ms, ending the request once the others are done.
 * The response: "multi: order=<the continuations called, in order>
 * cancel=<ok|...> notifier=<ok|...> pipes=<ok|...> timers=<ok|...>
 * subreq=<status>:<async|inline|none|pending> final=<ok|...>", e.g.
 * "multi: order=N,P1,P2,T1,T2,F cancel=ok notifier=ok pipes=ok timers=ok
 * subreq=-:none final=ok" when all went as expected without a subrequest,
 * "subreq=200:inline" with a subrequest run blocking ("200:async" and S, its
 * done function, in the order if it suspended), "multi: declined" when the
 * request can't wait asynchronously (e.g. AsyncRequests Off), "multi: none"
 * without notifiers in the MPM or threads.
 */
typedef struct {
    request_rec *r;
    const aptest_dir_conf *conf;
    ap_mpm_notifier_t *notifier;
    ap_request_waitctx_t *n, *p1, *p2, *t1, *t2, *c, *d, *f;
    apr_file_t *pipe_in, *pipe_out;
#if APR_HAS_THREADS
    apr_thread_t *thread;       /* notifying, then writing, until joined */
#endif
    apr_time_t start;
    aptest_subreq_t sub;        /* the subrequest's capture (its filter's
                                 * context) */
    int sub_status;             /* its final status, -1 until done */
    const char *sub_how;        /* "async", "inline", "none" */
    char order[64];             /* the continuations called, in order */
    apr_size_t olen;
    const char *report;
} aptest_multi_t;

static void aptest_multi_note(aptest_multi_t *m, const char *what,
                              const char *result)
{
    m->report = apr_pstrcat(m->r->pool, m->report, " ", what, "=", result,
                            NULL);
}

/* A continuation called: noted in order, the time since the start (ms) */
static apr_interval_time_t aptest_multi_called(aptest_multi_t *m,
                                               const char *which)
{
    if (m->olen + strlen(which) + 2 < sizeof(m->order)) {
        m->olen += apr_snprintf(m->order + m->olen,
                                sizeof(m->order) - m->olen, "%s%s",
                                m->olen ? "," : "", which);
    }
    return apr_time_as_msec(apr_time_now() - m->start);
}

#if APR_HAS_THREADS
static void *APR_THREAD_FUNC aptest_multi_thread(apr_thread_t *thd,
                                                 void *data)
{
    aptest_multi_t *m = data;
    apr_size_t len = 1;

    apr_sleep(apr_time_from_msec(50));
    ap_mpm_notify(m->notifier);
    apr_sleep(apr_time_from_msec(20));
    apr_file_write(m->pipe_out, "x", &len);
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static apr_status_t aptest_multi_join(void *data)
{
    aptest_multi_t *m = data;
    apr_status_t rv;

    if (m->thread) {
        apr_thread_join(&rv, m->thread);
        m->thread = NULL;
    }
    return APR_SUCCESS;
}

static void aptest_multi_sub_done(request_rec *rsub, int status, void *baton)
{
    aptest_multi_t *m = baton;

    aptest_multi_called(m, "S");
    m->sub_status = (status == OK) ? rsub->status : status;
    ap_destroy_sub_req(rsub);
}

static void aptest_multi_n(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_t *m = baton;
    apr_interval_time_t ms = aptest_multi_called(m, "N");
    request_rec *rsub;
    int rc;

    aptest_multi_note(m, "notifier",
                      (status == APR_SUCCESS && ms >= 40 && ms < 90)
                      ? "ok" : apr_psprintf(r->pool, "%d@%" APR_TIME_T_FMT,
                                            status, ms));
    if (!m->conf->wait_uri) {
        m->sub_how = "none";
        return;
    }

    /* While the others are pending */
    rsub = ap_sub_req_lookup_uri(m->conf->wait_uri, r, NULL);
    ap_add_output_filter_handle(aptest_capture_handle, &m->sub, rsub,
                                rsub->connection);
    if (rsub->status != HTTP_OK) {
        m->sub_status = rsub->status;
        m->sub_how = "inline";
        ap_destroy_sub_req(rsub);
        return;
    }
    rc = ap_run_sub_req_async(rsub, 0, aptest_multi_sub_done, m);
    if (rc == SUSPENDED) {
        m->sub_how = "async";
        return;
    }
    m->sub_how = "inline";
    m->sub_status = (rc == OK) ? rsub->status : rc;
    ap_destroy_sub_req(rsub);
}

/* P1 or P2 (which), ready together */
static void aptest_multi_p(aptest_multi_t *m, int which, apr_status_t status)
{
    apr_interval_time_t ms = aptest_multi_called(m, which ? "P2" : "P1");
    ap_request_waitctx_t *ctx = which ? m->p2 : m->p1;

    if (status != APR_SUCCESS || ap_request_waitctx_ready(ctx) != AP_WAIT_IN
        || ms < 60 || ms >= 150) {
        aptest_multi_note(m, which ? "pipe2" : "pipe1",
                          apr_psprintf(m->r->pool, "%d@%" APR_TIME_T_FMT,
                                       status, ms));
    }
    ap_request_waitctx_release(ctx);
}

static void aptest_multi_p1(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_p(baton, 0, status);
}

static void aptest_multi_p2(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_p(baton, 1, status);
}

static void aptest_multi_t1(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_t *m = baton;
    apr_interval_time_t ms = aptest_multi_called(m, "T1");

    if (status != APR_SUCCESS || ms < 90 || ms >= 200) {
        aptest_multi_note(m, "timer1",
                          apr_psprintf(r->pool, "%d@%" APR_TIME_T_FMT,
                                       status, ms));
    }
}

static void aptest_multi_t2(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_t *m = baton;
    apr_interval_time_t ms = aptest_multi_called(m, "T2");

    if (status != APR_SUCCESS || ms < 90 || ms >= 200) {
        aptest_multi_note(m, "timer2",
                          apr_psprintf(r->pool, "%d@%" APR_TIME_T_FMT,
                                       status, ms));
    }
}

/* C (canceled) and D (dropped): never called */
static void aptest_multi_never(request_rec *r, apr_status_t status,
                               void *baton)
{
    aptest_multi_t *m = baton;

    aptest_multi_called(m, "X");
    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO()
                  "aptest-wait: multi: a canceled or dropped wait's "
                  "continuation called");
}

static void aptest_multi_f(request_rec *r, apr_status_t status, void *baton)
{
    aptest_multi_t *m = baton;
    apr_interval_time_t ms = aptest_multi_called(m, "F");
    const char *pipes, *timers;

    aptest_multi_join(m);
    pipes = (ap_strstr_c(m->report, "pipe")) ? "FAILED" : "ok";
    timers = (ap_strstr_c(m->report, "timer")) ? "FAILED" : "ok";
    aptest_multi_note(m, "pipes", pipes);
    aptest_multi_note(m, "timers", timers);
    aptest_multi_note(m, "subreq",
                      (m->sub_status < 0)
                      ? apr_pstrcat(r->pool, "-:", m->sub_how, NULL)
                      : apr_psprintf(r->pool, "%d:%s", m->sub_status,
                                     m->sub_how));
    aptest_multi_note(m, "final",
                      (status == APR_SUCCESS && ms >= 290 && ms < 600)
                      ? "ok" : apr_psprintf(r->pool, "%d@%" APR_TIME_T_FMT,
                                            status, ms));

    /* D is still pending: the end drops it */
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "multi: order=%s%s\n", m->order, m->report);
    ap_request_finish_suspended(r, OK);
}

/* A timer's wait, its context made from r->pool */
static int aptest_multi_timer(aptest_multi_t *m, ap_request_waitctx_t **ctx,
                              apr_interval_time_t ms,
                              ap_request_continuation_fn *fn)
{
    *ctx = ap_request_waitctx_timer(m->r, m->r->pool);
    (*ctx)->timeout = apr_time_from_msec(ms);
    return ap_request_wait(*ctx, AP_WAIT_IN, 0, fn, m);
}
#endif /* APR_HAS_THREADS */

static int aptest_multi(request_rec *r, const aptest_dir_conf *conf)
{
    aptest_multi_t *m = apr_pcalloc(r->pool, sizeof(*m));
#if APR_HAS_THREADS
    apr_pollfd_t pfd;
    apr_status_t rv;
    int rc;
#endif

    m->r = r;
    m->conf = conf;
    m->sub_status = -1;
    m->sub_how = "pending";
    m->report = " none";
#if APR_HAS_THREADS
    if (!ap_request_can_suspend(r)) {
        m->report = " declined";
        goto respond;
    }
    if (ap_mpm_notifier_create(&m->notifier, r->connection,
                               r->pool) != APR_SUCCESS
        || apr_file_pipe_create_pools(&m->pipe_in, &m->pipe_out,
                                      APR_FULL_NONBLOCK, r->pool,
                                      r->pool) != APR_SUCCESS) {
        goto respond;
    }
    m->report = "";
    apr_md5_init(&m->sub.md5);
    m->sub.r = r;
    m->sub.conf = conf;

    m->n = ap_request_waitctx_notifier(r, r->pool, m->notifier);
    m->n->timeout = apr_time_from_sec(5);
    rc = ap_request_wait(m->n, AP_WAIT_IN, 0, aptest_multi_n, m);
    if (rc != SUSPENDED) {
        m->report = " declined";
        goto respond;
    }
    m->start = apr_time_now();
    apr_pool_pre_cleanup_register(r->pool, m, aptest_multi_join);
    rv = apr_thread_create(&m->thread, NULL, aptest_multi_thread, m,
                           r->pool);
    if (rv != APR_SUCCESS) {
        m->thread = NULL;
        return HTTP_INTERNAL_SERVER_ERROR; /* the wait dropped */
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.desc_type = APR_POLL_FILE;
    pfd.desc.f = m->pipe_in;
    m->p1 = ap_request_waitctx_pfd(r, r->pool, &pfd);
    m->p2 = ap_request_waitctx_pfd(r, r->pool, &pfd);
    if (ap_request_wait(m->p1, AP_WAIT_IN, 0, aptest_multi_p1,
                        m) != SUSPENDED
        || ap_request_wait(m->p2, AP_WAIT_IN, 0, aptest_multi_p2,
                           m) != SUSPENDED
        || aptest_multi_timer(m, &m->t1, 100, aptest_multi_t1) != SUSPENDED
        || aptest_multi_timer(m, &m->t2, 100, aptest_multi_t2) != SUSPENDED
        || aptest_multi_timer(m, &m->c, 30, aptest_multi_never) != SUSPENDED
        || aptest_multi_timer(m, &m->d, 10000,
                              aptest_multi_never) != SUSPENDED
        || aptest_multi_timer(m, &m->f, 300, aptest_multi_f) != SUSPENDED) {
        return HTTP_INTERNAL_SERVER_ERROR; /* the waits dropped */
    }

    rv = ap_request_wait_cancel(m->c);
    aptest_multi_note(m, "cancel",
                      (rv == APR_SUCCESS
                       && APR_STATUS_IS_NOTFOUND(ap_request_wait_cancel(m->c)))
                      ? "ok" : "FAILED");
    return SUSPENDED;

respond:
#endif
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "multi:%s\n", m->report);
    return OK;
}
#endif /* APTEST_HAS_MULTI */

#ifdef APTEST_HAS_PFDFLAGS
/*
 * The MPM's keep and drained flags per descriptor ("AptestWait pfdflags"):
 * waits on two pipes, A and B, whose MPM waits (one per run, the union of
 * the pending waits) give each pipe its own flags, which mpm_event traces
 * (trace7) per pollfd as it arms them:
 *  1. the handler waits for A (a, drained): A not kept (its first wait);
 *  2. A written at 20ms: a's continuation (A1) reads A until EAGAIN, waits
 *     for it again (drained) and for B (b, not drained): A kept (its second
 *     wait) and drained, B not kept;
 *  3. B written at 60ms: b's continuation (B1) reads B until EAGAIN and
 *     waits for it again (not drained): A (carried) kept and drained, B kept
 *     and not drained;
 *  4. A written at 100ms: a's continuation (A2) reads A until EAGAIN, waits
 *     for it again (drained) and with a new context on it (a2, its first
 *     wait, drained), and for B with a new context (b2, with
 *     ap_request_wait_any(): kept from the first, drained): A neither kept
 *     nor drained (a2 doesn't allow keeping, the MPM keeps it already), B
 *     kept but not drained (b didn't drain it);
 *  5. A written at 140ms: a's then a2's continuations (A3, A3b): B kept,
 *     not drained (b and b2 carried);
 * then a timer of 300ms (F) ends the request, b's and b2's waits dropped.
 * The response: "pfdflags: order=<the continuations called, in order>
 * A=<fd> B=<fd>", e.g. "pfdflags: order=A1,B1,A2,A3,A3b,F A=12 B=14",
 * "pfdflags: declined" when the request can't wait asynchronously (e.g.
 * AsyncRequests Off), "pfdflags: none" without threads.
 */
typedef struct {
    request_rec *r;
    ap_request_waitctx_t *a, *a2, *b, *b2, *f;
    apr_file_t *a_in, *a_out, *b_in, *b_out;
#if APR_HAS_THREADS
    apr_thread_t *thread;       /* writing, until joined */
#endif
    char order[64];             /* the continuations called, in order */
    apr_size_t olen;
    int failed;
} aptest_pfdflags_t;

static void aptest_pfdflags_called(aptest_pfdflags_t *m, const char *which,
                                   apr_status_t status)
{
    if (m->olen + strlen(which) + 2 < sizeof(m->order)) {
        m->olen += apr_snprintf(m->order + m->olen,
                                sizeof(m->order) - m->olen, "%s%s",
                                m->olen ? "," : "", which);
    }
    if (status != APR_SUCCESS) {
        m->failed = 1;
    }
}

/* Read a pipe until EAGAIN (drained) */
static void aptest_pfdflags_drain(apr_file_t *f)
{
    char buf[64];
    apr_size_t len;

    do {
        len = sizeof(buf);
    } while (apr_file_read(f, buf, &len) == APR_SUCCESS);
}

#if APR_HAS_THREADS
static void *APR_THREAD_FUNC aptest_pfdflags_thread(apr_thread_t *thd,
                                                    void *data)
{
    aptest_pfdflags_t *m = data;
    apr_size_t len;

    apr_sleep(apr_time_from_msec(20));
    len = 1;
    apr_file_write(m->a_out, "a", &len);
    apr_sleep(apr_time_from_msec(40));
    len = 1;
    apr_file_write(m->b_out, "b", &len);
    apr_sleep(apr_time_from_msec(40));
    len = 1;
    apr_file_write(m->a_out, "a", &len);
    apr_sleep(apr_time_from_msec(40));
    len = 1;
    apr_file_write(m->a_out, "a", &len);
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static apr_status_t aptest_pfdflags_join(void *data)
{
    aptest_pfdflags_t *m = data;
    apr_status_t rv;

    if (m->thread) {
        apr_thread_join(&rv, m->thread);
        m->thread = NULL;
    }
    return APR_SUCCESS;
}

static void aptest_pfdflags_check(aptest_pfdflags_t *m, int rc)
{
    if (rc != SUSPENDED) {
        m->failed = 1;
    }
}

/* b's and b2's last waits: dropped by the request's end, never called */
static void aptest_pfdflags_never(request_rec *r, apr_status_t status,
                                  void *baton)
{
    aptest_pfdflags_t *m = baton;

    aptest_pfdflags_called(m, "X", status);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO()
                  "aptest-wait: pfdflags: a dropped wait's continuation "
                  "called");
}

static void aptest_pfdflags_a3(request_rec *r, apr_status_t status,
                               void *baton)
{
    aptest_pfdflags_t *m = baton;

    aptest_pfdflags_called(m, "A3", status);
    aptest_pfdflags_drain(m->a_in);
}

static void aptest_pfdflags_a3b(request_rec *r, apr_status_t status,
                                void *baton)
{
    aptest_pfdflags_called(baton, "A3b", status);
}

static void aptest_pfdflags_a2(request_rec *r, apr_status_t status,
                               void *baton)
{
    aptest_pfdflags_t *m = baton;
    unsigned int in = AP_WAIT_IN;
    apr_pollfd_t pfd;

    aptest_pfdflags_called(m, "A2", status);
    aptest_pfdflags_drain(m->a_in);
    memset(&pfd, 0, sizeof(pfd));
    pfd.desc_type = APR_POLL_FILE;
    pfd.desc.f = m->a_in;
    m->a2 = ap_request_waitctx_pfd(r, r->pool, &pfd);
    pfd.desc.f = m->b_in;
    m->b2 = ap_request_waitctx_pfd(r, r->pool, &pfd);
    aptest_pfdflags_check(m, ap_request_wait(m->a, AP_WAIT_IN,
                                             AP_REQUEST_WAIT_DRAINED,
                                             aptest_pfdflags_a3, m));
    aptest_pfdflags_check(m, ap_request_wait(m->a2, AP_WAIT_IN,
                                             AP_REQUEST_WAIT_DRAINED,
                                             aptest_pfdflags_a3b, m));
    aptest_pfdflags_check(m, ap_request_wait_any(&m->b2, 1, &in,
                                                 AP_REQUEST_WAIT_DRAINED,
                                                 aptest_pfdflags_never, m));
}

static void aptest_pfdflags_b1(request_rec *r, apr_status_t status,
                               void *baton)
{
    aptest_pfdflags_t *m = baton;

    aptest_pfdflags_called(m, "B1", status);
    aptest_pfdflags_drain(m->b_in);
    aptest_pfdflags_check(m, ap_request_wait(m->b, AP_WAIT_IN, 0,
                                             aptest_pfdflags_never, m));
}

static void aptest_pfdflags_a1(request_rec *r, apr_status_t status,
                               void *baton)
{
    aptest_pfdflags_t *m = baton;

    aptest_pfdflags_called(m, "A1", status);
    aptest_pfdflags_drain(m->a_in);
    aptest_pfdflags_check(m, ap_request_wait(m->a, AP_WAIT_IN,
                                             AP_REQUEST_WAIT_DRAINED,
                                             aptest_pfdflags_a2, m));
    aptest_pfdflags_check(m, ap_request_wait(m->b, AP_WAIT_IN, 0,
                                             aptest_pfdflags_b1, m));
}

static void aptest_pfdflags_f(request_rec *r, apr_status_t status,
                              void *baton)
{
    aptest_pfdflags_t *m = baton;
    apr_os_file_t a = -1, b = -1;

    aptest_pfdflags_called(m, "F", status);
    aptest_pfdflags_join(m);
    (void)apr_os_file_get(&a, m->a_in);
    (void)apr_os_file_get(&b, m->b_in);
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "pfdflags: order=%s A=%d B=%d%s\n", m->order, (int)a,
               (int)b, m->failed ? " FAILED" : "");
    ap_request_finish_suspended(r, OK);
}
#endif /* APR_HAS_THREADS */

static int aptest_pfdflags(request_rec *r)
{
    const char *report = "none";
#if APR_HAS_THREADS
    aptest_pfdflags_t *m = apr_pcalloc(r->pool, sizeof(*m));
    apr_pollfd_t pfd;

    m->r = r;
    if (!ap_request_can_suspend(r)) {
        report = "declined";
        goto respond;
    }
    if (apr_file_pipe_create_pools(&m->a_in, &m->a_out, APR_FULL_NONBLOCK,
                                   r->pool, r->pool) != APR_SUCCESS
        || apr_file_pipe_create_pools(&m->b_in, &m->b_out,
                                      APR_FULL_NONBLOCK, r->pool,
                                      r->pool) != APR_SUCCESS) {
        goto respond;
    }
    memset(&pfd, 0, sizeof(pfd));
    pfd.desc_type = APR_POLL_FILE;
    pfd.desc.f = m->a_in;
    m->a = ap_request_waitctx_pfd(r, r->pool, &pfd);
    pfd.desc.f = m->b_in;
    m->b = ap_request_waitctx_pfd(r, r->pool, &pfd);
    m->f = ap_request_waitctx_timer(r, r->pool);
    m->f->timeout = apr_time_from_msec(300);
    if (ap_request_wait(m->a, AP_WAIT_IN, AP_REQUEST_WAIT_DRAINED,
                        aptest_pfdflags_a1, m) != SUSPENDED) {
        report = "declined";
        goto respond;
    }
    if (ap_request_wait(m->f, AP_WAIT_IN, 0, aptest_pfdflags_f,
                        m) != SUSPENDED) {
        return HTTP_INTERNAL_SERVER_ERROR; /* the waits dropped */
    }
    apr_pool_pre_cleanup_register(r->pool, m, aptest_pfdflags_join);
    if (apr_thread_create(&m->thread, NULL, aptest_pfdflags_thread, m,
                          r->pool) != APR_SUCCESS) {
        m->thread = NULL;
        return HTTP_INTERNAL_SERVER_ERROR; /* the waits dropped */
    }
    return SUSPENDED;

respond:
#endif
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "pfdflags: %s\n", report);
    return OK;
}
#endif /* APTEST_HAS_PFDFLAGS */

#ifdef APTEST_HAS_HOLD
/*
 * The holding filters ("AptestHold"), request filters holding their output
 * or input without holding the thread (ap_filter_pending_wait()), inserted
 * by the insert_filter hook:
 *  - "timer <ms>": the output filter keeps the EOS (and what comes with
 *    it) and holds it on a timer context of ms, then passes it;
 *  - "notifier <ms>": the same on a notifier, notified by a thread after ms
 *    (ap_filter_pending_notify(), the notifier re-armed for each hold);
 *  - "chunk <ms>": each brigade with data is held on the timer, then passed
 *    (holds mid-stream, the producer backing off meanwhile);
 *  - "room <bytes>": what it's passed goes on in pieces of bytes with a WC
 *    bucket each, the rest held for room when the filters after it have
 *    pending output (ap_filter_pending_wait() without a context, the rest
 *    given to the core to hold);
 *  - "input <ms>": the input filter keeps what each nonblocking read gets
 *    and holds it on the timer (EAGAIN meanwhile), then returns it.
 * With "proto" the output filter is a protocol filter (AP_FTYPE_PROTOCOL):
 * it sees ap_die()'s error responses too (the second hold point). A hold
 * refused (e.g. AsyncRequests Off, a subrequest of the request in progress)
 * or not made (a FLUSH bucket) sleeps ms instead, as a synchronous filter
 * would: the same bytes in every mode. What each filter did is logged at
 * the request's end (aptest:info): holds, refusals, sleeps.
 */
static ap_filter_rec_t *aptest_hold_handle;
static ap_filter_rec_t *aptest_hold_proto_handle;
static ap_filter_rec_t *aptest_hold_in_handle;

typedef struct {
    ap_filter_t *f;
    const aptest_dir_conf *conf;
    apr_bucket_brigade *kept;      /* what it holds itself */
    ap_request_waitctx_t *timer;  /* made once */
#if APR_HAS_THREADS
    ap_mpm_notifier_t *notifier;   /* made once, re-armed for each hold */
    apr_thread_t *thread;          /* notifying it */
#endif
    int holds, refused, sleeps, failed;
    unsigned int holding :1;
} aptest_hold_t;

static apr_status_t aptest_hold_report(void *data)
{
    aptest_hold_t *h = data;

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, h->f->r, APLOGNO()
                  "aptest-hold: '%s' filter: holds=%d refused=%d sleeps=%d "
                  "failed=%d", h->f->frec->name, h->holds, h->refused,
                  h->sleeps, h->failed);
    return APR_SUCCESS;
}

#if APR_HAS_THREADS
static void *APR_THREAD_FUNC aptest_hold_thread(apr_thread_t *thd, void *data)
{
    aptest_hold_t *h = data;

    apr_sleep(h->conf->hold_time);
    ap_mpm_notify(h->notifier);
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static apr_status_t aptest_hold_join(void *data)
{
    aptest_hold_t *h = data;
    apr_status_t rv;

    if (h->thread) {
        apr_thread_join(&rv, h->thread);
        h->thread = NULL;
    }
    return APR_SUCCESS;
}
#endif

static aptest_hold_t *aptest_hold_get(ap_filter_t *f)
{
    aptest_hold_t *h = f->ctx;
    request_rec *r = f->r;

    if (!h) {
        f->ctx = h = apr_pcalloc(r->pool, sizeof(*h));
        h->f = f;
        h->conf = ap_get_module_config(r->per_dir_config, &aptest_module);
        h->kept = apr_brigade_create(r->pool, f->c->bucket_alloc);
        h->timer = ap_request_waitctx_timer(r, r->pool);
        apr_pool_cleanup_register(r->pool, h, aptest_hold_report,
                                  apr_pool_cleanup_null);
#if APR_HAS_THREADS
        apr_pool_pre_cleanup_register(r->pool, h, aptest_hold_join);
#endif
    }
    return h;
}

/* Hold on the timer or the notifier: APR_SUCCESS if held */
static apr_status_t aptest_hold_wait(aptest_hold_t *h)
{
    apr_status_t rv;

#if APR_HAS_THREADS
    if (h->conf->hold_mode == APTEST_HOLD_NOTIFIER) {
        aptest_hold_join(h);
        if (!h->notifier) {
            rv = ap_mpm_notifier_create(&h->notifier, h->f->c, h->f->r->pool);
            if (rv != APR_SUCCESS) {
                h->notifier = NULL;
                return rv;
            }
        }
        else if ((rv = ap_mpm_notifier_rearm(h->notifier)) != APR_SUCCESS) {
            return rv;
        }
        rv = ap_filter_pending_notify(h->f, NULL, h->notifier);
        if (rv == APR_SUCCESS) {
            rv = apr_thread_create(&h->thread, NULL, aptest_hold_thread, h,
                                   h->f->r->pool);
            if (rv != APR_SUCCESS) {
                h->thread = NULL;
                ap_mpm_notify(h->notifier); /* the hold ends at once */
                rv = APR_SUCCESS;
            }
        }
        return rv;
    }
#endif
    h->timer->timeout = h->conf->hold_time;
    return ap_filter_pending_wait(h->f, NULL, h->timer, 0, 0);
}

static apr_status_t aptest_hold_room(aptest_hold_t *h, apr_bucket_brigade *bb)
{
    ap_filter_t *f = h->f;
    apr_bucket *e;
    apr_status_t rv;

    while (!APR_BRIGADE_EMPTY(bb)) {
        rv = apr_brigade_partition(bb, h->conf->hold_size, &e);
        if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
            return rv;
        }
        apr_brigade_split_ex(bb, e, h->kept);
        if (!APR_BRIGADE_EMPTY(h->kept)) {
            APR_BRIGADE_INSERT_TAIL(bb, ap_bucket_wc_create(f->c->bucket_alloc));
        }
        rv = ap_pass_brigade(f->next, bb);
        apr_brigade_cleanup(bb);
        if (rv != APR_SUCCESS) {
            apr_brigade_cleanup(h->kept);
            return rv;
        }
        APR_BRIGADE_CONCAT(bb, h->kept);
        if (!APR_BRIGADE_EMPTY(bb) && ap_filter_should_yield(f->next)) {
            rv = ap_filter_pending_wait(f, bb, NULL, 0, 0);
            if (rv == APR_SUCCESS) {
                h->holds++;
                return APR_SUCCESS;
            }
            if (rv != APR_EAGAIN) {
                h->refused++;
            }
        }
    }
    return APR_SUCCESS;
}

static apr_status_t aptest_hold_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    aptest_hold_t *h = aptest_hold_get(f);
    int want = 0, flush = 0, eos = 0, data = 0;
    apr_bucket *e;
    apr_status_t rv;

    if (h->conf->hold_mode == APTEST_HOLD_ROOM) {
        return aptest_hold_room(h, bb);
    }
    if (h->holding) {
        if (!APR_BRIGADE_EMPTY(bb)) {
            /* More from a producer not backing off: behind what's held
             * (metadata buckets without setaside are kept as is)
             */
            rv = ap_save_brigade(f, &h->kept, &bb, f->r->pool);
            return APR_STATUS_IS_ENOTIMPL(rv) ? APR_SUCCESS : rv;
        }
        /* Called again by the core (an empty brigade): what's held goes on,
         * as is
         */
        h->holding = 0;
        if (h->conf->hold_mode != APTEST_HOLD_NOTIFIER
            && !ap_request_waitctx_ready(h->timer)) {
            h->failed++;
        }
        APR_BRIGADE_CONCAT(bb, h->kept);
        return ap_pass_brigade(f->next, bb);
    }
    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        if (APR_BUCKET_IS_EOS(e)) {
            eos = 1;
        }
        else if (APR_BUCKET_IS_FLUSH(e) && !AP_BUCKET_IS_WC(e)) {
            flush = 1;
        }
        else if (!APR_BUCKET_IS_METADATA(e)) {
            data = 1;
        }
    }
    switch (h->conf->hold_mode) {
    case APTEST_HOLD_CHUNK:
        want = data;
        break;
    case APTEST_HOLD_TIMER:
    case APTEST_HOLD_NOTIFIER:
        want = eos;
        break;
    }
    if (want && !flush) {
        rv = ap_save_brigade(f, &h->kept, &bb, f->r->pool);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_ENOTIMPL(rv)) {
            return rv;
        }
        rv = aptest_hold_wait(h);
        if (rv == APR_SUCCESS) {
            h->holds++;
            h->holding = 1;
            return APR_SUCCESS;
        }
        h->refused++;
        APR_BRIGADE_CONCAT(bb, h->kept);
    }
    if (want) {
        h->sleeps++;
        apr_sleep(h->conf->hold_time);
    }
    return ap_pass_brigade(f->next, bb);
}

static apr_status_t aptest_hold_in_filter(ap_filter_t *f,
                                          apr_bucket_brigade *bb,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
    aptest_hold_t *h = aptest_hold_get(f);
    apr_status_t rv;
    apr_bucket *e;
    int data = 0;

    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    if (h->holding) {
        if (!ap_request_waitctx_ready(h->timer) && block == APR_NONBLOCK_READ) {
            return APR_EAGAIN; /* still held */
        }
        h->holding = 0;
    }
    if (APR_BRIGADE_EMPTY(h->kept)) {
        rv = ap_get_brigade(f->next, h->kept, mode, block, readbytes);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        for (e = APR_BRIGADE_FIRST(h->kept);
             e != APR_BRIGADE_SENTINEL(h->kept); e = APR_BUCKET_NEXT(e)) {
            if (!APR_BUCKET_IS_METADATA(e)) {
                data = 1;
            }
        }
        if (data) {
            /* What's read is checked before it's returned */
            for (e = APR_BRIGADE_FIRST(h->kept);
                 e != APR_BRIGADE_SENTINEL(h->kept); e = APR_BUCKET_NEXT(e)) {
                rv = apr_bucket_setaside(e, f->r->pool);
                if (APR_STATUS_IS_ENOTIMPL(rv)) {
                    const char *str;
                    apr_size_t len;
                    rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
                    if (rv == APR_SUCCESS) {
                        rv = apr_bucket_setaside(e, f->r->pool);
                    }
                }
                if (rv != APR_SUCCESS && !APR_STATUS_IS_ENOTIMPL(rv)) {
                    return rv;
                }
            }
            if (block == APR_NONBLOCK_READ) {
                h->timer->timeout = h->conf->hold_time;
                rv = ap_filter_pending_wait(f, NULL, h->timer, 0, 0);
                if (rv == APR_SUCCESS) {
                    h->holds++;
                    h->holding = 1;
                    return APR_EAGAIN;
                }
                h->refused++;
            }
            h->sleeps++;
            apr_sleep(h->conf->hold_time);
        }
    }
    APR_BRIGADE_CONCAT(bb, h->kept);
    return APR_SUCCESS;
}

static void aptest_hold_insert(request_rec *r)
{
    const aptest_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                       &aptest_module);

    if (r->main || conf->hold_mode == APTEST_HOLD_UNSET) {
        return;
    }
    if (conf->hold_mode == APTEST_HOLD_INPUT) {
        ap_add_input_filter_handle(aptest_hold_in_handle, NULL, r,
                                   r->connection);
    }
    else {
        ap_add_output_filter_handle(conf->hold_proto ? aptest_hold_proto_handle
                                                     : aptest_hold_handle,
                                    NULL, r, r->connection);
    }
}
#endif /* APTEST_HAS_HOLD */

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
#ifdef APTEST_HAS_BODY
    ap_hook_handler(aptest_body, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter("APTEST_BODY_BLOCK", aptest_body_block_filter,
                              NULL, AP_FTYPE_RESOURCE);
    ap_register_input_filter("APTEST_REPLAY", aptest_replay_filter, NULL,
                             AP_FTYPE_RESOURCE);
#endif
#ifdef APTEST_HAS_RESUME
    {
        static const char *const before_proxy[] = { "mod_proxy.c", NULL };
        ap_hook_handler(aptest_suspend1, NULL, NULL, APR_HOOK_REALLY_FIRST);
        ap_hook_handler(aptest_suspend2, NULL, before_proxy, APR_HOOK_FIRST);
    }
#endif
#ifdef APTEST_HAS_SUBREQ
    ap_hook_handler(aptest_subreq, NULL, NULL, APR_HOOK_REALLY_FIRST);
    aptest_capture_handle = ap_register_output_filter("APTEST_CAPTURE",
                                                      aptest_capture_filter,
                                                      NULL,
                                                      AP_FTYPE_RESOURCE);
#endif
#ifdef APTEST_HAS_HOLD
    ap_hook_insert_filter(aptest_hold_insert, NULL, NULL, APR_HOOK_MIDDLE);
    aptest_hold_handle = ap_register_output_filter("APTEST_HOLD",
                                                   aptest_hold_filter, NULL,
                                                   AP_FTYPE_CONTENT_SET);
    aptest_hold_proto_handle = ap_register_output_filter("APTEST_HOLD_PROTO",
                                                         aptest_hold_filter,
                                                         NULL,
                                                         AP_FTYPE_PROTOCOL);
    aptest_hold_in_handle = ap_register_input_filter("APTEST_HOLD_IN",
                                                     aptest_hold_in_filter,
                                                     NULL,
                                                     AP_FTYPE_CONTENT_SET);
#endif

}

