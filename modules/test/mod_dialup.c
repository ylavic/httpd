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



#include "httpd.h"
#include "http_core.h"

#include "util_filter.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"


module AP_MODULE_DECLARE_DATA dialup_module;

typedef struct dialup_dcfg_t {
    apr_size_t bytes_per_second;
} dialup_dcfg_t;

typedef struct dialup_baton_t {
    apr_size_t bytes_per_second;
    request_rec *r;
    apr_file_t *fd;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmpbb;
    ap_request_waitctx_t *timer; /* a second between the pulses */
    int response_sent;
    int blocking;                 /* the request can't suspend: sleep */
} dialup_baton_t;

static int
dialup_send_pulse(dialup_baton_t *db)
{
    int status;
    apr_off_t len = 0;
    apr_size_t bytes_sent = 0;

    while (!APR_BRIGADE_EMPTY(db->bb) && bytes_sent < db->bytes_per_second) {
        apr_bucket *e;

        status = apr_brigade_partition(db->bb, db->bytes_per_second, &e);

        if (status != APR_SUCCESS && status != APR_INCOMPLETE) {
            /* XXXXXX: Log me. */
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (e != APR_BRIGADE_SENTINEL(db->bb)) {
            apr_bucket *f;
            apr_bucket *b = APR_BUCKET_PREV(e);
            f = APR_RING_FIRST(&db->bb->list);
            APR_RING_UNSPLICE(f, b, link);
            APR_RING_SPLICE_HEAD(&db->tmpbb->list, f, b, apr_bucket, link);
        }
        else {
            APR_BRIGADE_CONCAT(db->tmpbb, db->bb);
        }

        /* Without blocking on the client when the request waits for the
         * next pulse asynchronously (WC), otherwise a FLUSH
         */
        e = (db->blocking)
            ? apr_bucket_flush_create(db->r->connection->bucket_alloc)
            : ap_bucket_wc_create(db->r->connection->bucket_alloc);

        APR_BRIGADE_INSERT_TAIL(db->tmpbb, e);

        apr_brigade_length(db->tmpbb, 1, &len);
        bytes_sent += len;

        status = ap_pass_brigade(db->r->output_filters, db->tmpbb);
        apr_brigade_cleanup(db->tmpbb);
        db->response_sent = 1;

        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, db->r, APLOGNO(01867)
                          "dialup: pulse: ap_pass_brigade failed:");
            return AP_FILTER_ERROR;
        }
    }
    if (!APR_BRIGADE_EMPTY(db->bb)) {
        return SUSPENDED;
    }

    return DONE;
}

static void
dialup_continuation(request_rec *r, apr_status_t status, void *baton);

/* Send the pulses a second apart, waiting for each second on a timer
 * without holding the thread (or sleeping if the request can't suspend):
 * SUSPENDED while waiting, else the pulses' final status
 */
static int
dialup_run(dialup_baton_t *db)
{
    int status, rc;

    for (;;) {
        status = dialup_send_pulse(db);
        if (status != SUSPENDED) {
            break;
        }
        if (!db->blocking) {
            db->timer->timeout = apr_time_from_sec(1);
            rc = ap_request_wait(db->timer, 0, 0, dialup_continuation, db);
            if (rc == SUSPENDED) {
                return SUSPENDED;
            }
            if (rc == OK) {
                continue;
            }
            db->blocking = 1; /* can't wait asynchronously */
        }
        apr_sleep(apr_time_from_sec(1));
    }

    if (status != DONE && db->response_sent) {
        db->r->connection->keepalive = AP_CONN_CLOSE;
        status = DONE;
    }
    if (status != DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, db->r, APLOGNO(01868)
                      "dialup: pulse returned: %d", status);
    }
    return status;
}

static void
dialup_continuation(request_rec *r, apr_status_t status, void *baton)
{
    dialup_baton_t *db = baton;
    int rc;

    if (status != APR_SUCCESS) {
        /* The MPM failed to wait (e.g. stopping): what's sent is the
         * response
         */
        r->connection->keepalive = AP_CONN_CLOSE;
        ap_request_finish_suspended(r, DONE);
        return;
    }
    rc = dialup_run(db);
    if (rc == SUSPENDED) {
        return;
    }
    ap_request_finish_suspended(r, rc);
}

static int
dialup_handler(request_rec *r)
{
    int status;
    apr_status_t rv;
    dialup_dcfg_t *dcfg;
    core_dir_config *ccfg;
    apr_file_t *fd;
    dialup_baton_t *db;
    apr_bucket *e;

    /* See core.c, default handler for all of the cases we just decline. */
    if (r->method_number != M_GET ||
        r->finfo.filetype == APR_NOFILE ||
        r->finfo.filetype == APR_DIR) {
        return DECLINED;
    }

    dcfg = ap_get_module_config(r->per_dir_config,
                                &dialup_module);

    if (dcfg->bytes_per_second == 0) {
        return DECLINED;
    }

    ccfg = ap_get_core_module_config(r->per_dir_config);


    rv = apr_file_open(&fd, r->filename, APR_READ | APR_BINARY
#if APR_HAS_SENDFILE
                           | AP_SENDFILE_ENABLED(ccfg->enable_sendfile)
#endif
                       , 0, r->pool);

    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10631)
                      "dialup: declined since open() failed %s",
                      r->filename);
        return DECLINED;
    }

    /* copied from default handler: */
    ap_update_mtime(r, r->finfo.mtime);
    ap_set_last_modified(r);
    ap_set_etag_fd(r, fd);
    ap_set_accept_ranges(r);
    ap_set_content_length(r, r->finfo.size);

    status = ap_meets_conditions(r);
    if (status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01869)
                      "dialup: declined, meets conditions, good luck core handler");
        return DECLINED;
    }

    db = apr_pcalloc(r->pool, sizeof(dialup_baton_t));

    db->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    db->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    e = apr_brigade_insert_file(db->bb, fd, 0, r->finfo.size, r->pool);

#if APR_HAS_MMAP
    if (ccfg->enable_mmap == ENABLE_MMAP_OFF) {
        apr_bucket_file_enable_mmap(e, 0);
    }
#endif


    db->bytes_per_second = dcfg->bytes_per_second;
    db->r = r;
    db->fd = fd;
    db->timer = ap_request_waitctx_timer(r, r->pool);
    db->blocking = !ap_request_can_suspend(r);

    e = apr_bucket_eos_create(r->connection->bucket_alloc);

    APR_BRIGADE_INSERT_TAIL(db->bb, e);

    status = dialup_run(db);
    if (status == SUSPENDED) {
        return SUSPENDED;
    }
    if (status != DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01870)
                      "dialup: failed, send pulse");
        return status;
    }
    return OK;
}

#ifndef APR_HOOK_ALMOST_LAST
#define APR_HOOK_ALMOST_LAST (APR_HOOK_REALLY_LAST - 1)
#endif

static void
dialup_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(dialup_handler, NULL, NULL, APR_HOOK_ALMOST_LAST);
}

typedef struct modem_speed_t {
    const char *name;
    apr_size_t bytes_per_second;
} modem_speed_t;

#ifndef BITRATE_TO_BYTES
#define BITRATE_TO_BYTES(x) ((1000 * x)/8)
#endif

static const modem_speed_t modem_bitrates[] =
{
    {"V.21",    BITRATE_TO_BYTES(0.1)},
    {"V.26bis", BITRATE_TO_BYTES(2.4)},
    {"V.32",    BITRATE_TO_BYTES(9.6)},
    {"V.34",    BITRATE_TO_BYTES(28.8)},
    {"V.92",    BITRATE_TO_BYTES(56.0)},
    {"i-was-rich-and-got-a-leased-line", BITRATE_TO_BYTES(1500)},
    {NULL, 0}
};

static const char *
cmd_modem_standard(cmd_parms *cmd,
             void *dconf,
             const char *input)
{
    const modem_speed_t *standard;
    int i = 0;
    dialup_dcfg_t *dcfg = (dialup_dcfg_t*)dconf;

    dcfg->bytes_per_second = 0;

    while (modem_bitrates[i].name != NULL) {
        standard = &modem_bitrates[i];
        if (strcasecmp(standard->name, input) == 0) {
            dcfg->bytes_per_second = standard->bytes_per_second;
            break;
        }
        i++;
    }

    if (dcfg->bytes_per_second == 0) {
        return "mod_dialup: Unknown Modem Standard specified.";
    }

    return NULL;
}

static void *
dialup_dcfg_create(apr_pool_t *p, char *dummy)
{
    dialup_dcfg_t *cfg = apr_palloc(p, sizeof(dialup_dcfg_t));

    cfg->bytes_per_second = 0;

    return cfg;
}


static const command_rec dialup_cmds[] =
{
    AP_INIT_TAKE1("ModemStandard", cmd_modem_standard, NULL, ACCESS_CONF,
                  "Modem Standard to.. simulate. "
                  "Must be one of: 'V.21', 'V.26bis', 'V.32', 'V.34', or 'V.92'"),
    {NULL}
};

AP_DECLARE_MODULE(dialup) =
{
    STANDARD20_MODULE_STUFF,
    dialup_dcfg_create,
    NULL,
    NULL,
    NULL,
    dialup_cmds,
    dialup_register_hooks
};
