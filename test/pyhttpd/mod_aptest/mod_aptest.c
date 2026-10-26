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
#include <apr_strings.h>
#include <apr_cstr.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <ap_mpm.h>

static void aptest_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(aptest) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* func to create per dir config */
    NULL,  /* func to merge per dir config */
    NULL, /* func to create per server config */
    NULL,  /* func to merge per server config */
    NULL,              /* command handlers */
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
                                         NULL, aptest_queue_continuation,
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

}

