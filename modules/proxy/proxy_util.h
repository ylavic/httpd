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

#ifndef PROXY_UTIL_H_
#define PROXY_UTIL_H_

/**
 * @file  proxy_util.h
 * @brief Internal interfaces private to mod_proxy.
 *
 * @defgroup MOD_PROXY_PRIVATE Private
 * @ingroup MOD_PROXY
 * @{
 */

PROXY_DECLARE(int) ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p);

extern PROXY_DECLARE_DATA int proxy_lb_workers;
extern PROXY_DECLARE_DATA const apr_strmatch_pattern *ap_proxy_strmatch_path;
extern PROXY_DECLARE_DATA const apr_strmatch_pattern *ap_proxy_strmatch_domain;

/**
 * Register optional functions declared within proxy_util.c.
 */
void proxy_util_register_hooks(apr_pool_t *p);

/*
 * Get the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @return      apr_size_t value atomically read for the worker.
 */
PROXY_DECLARE(apr_size_t) ap_proxy_get_busy_count(proxy_worker *worker);

/*
 * Set the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @param to value to set the busy counter.
 * @return      void
 */
PROXY_DECLARE(void) ap_proxy_set_busy_count(proxy_worker *worker, apr_size_t to);

/*
 * decrement the busy counter from the shared worker memory
 * note it is called by apr_pool_cleanup_register()
 * therfore the void * and apr_status_t.
 *
 * @param worker_ Pointer to the worker structure.
 * @return      apr_status_t returns APR_SUCCESS.
 */
PROXY_DECLARE(apr_status_t) ap_proxy_decrement_busy_count(void *worker_);

/*
 * increment the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @return      void
 */
PROXY_DECLARE(void) ap_proxy_increment_busy_count(proxy_worker *worker);


/*
 * interpolate an env str in a configuration string
 *
 * @param r    current request
 * @param str  the string to interpolcate
 * @return     the interpolated string
 */
PROXY_DECLARE(const char *) ap_proxy_interpolate(request_rec *r,
                                                 const char *str);

/*
 * Canonicalize the URL in r->filename
 * @param r           current request
 * @return            OK or an HTTP_XXX error
 */
PROXY_DECLARE(int) ap_proxy_canon_url(request_rec *r);

/* The states of a request's asynchronous processing, in its proxy_req_conf
 * (request_config rather than r->pool's userdata, which an internally
 * redirected request shares)
 */
struct proxy_req_async {
    struct proxy_handler_ctx *handler;  /* proxy_handler() suspended, see
                                         * ap_proxy_handler_resume() */
    struct proxy_backend_wait *backend_wait; /* ap_proxy_wait()'s context
                                              * for the backend */
    struct proxy_acquire_wait *acquire; /* waiting for a connection, see
                                         * ap_proxy_acquire_connection_async() */
    proxy_conn_rec *held;               /* acquired by the request and not
                                         * released yet, see
                                         * ap_proxy_hold_connection() */
    int held_cleanup;                   /* its r->pool cleanup is registered */
};

/*
 * Get the request's proxy_req_conf, created (zeroed) if needed
 * @param r    current request
 * @return     the request's proxy_req_conf
 */
proxy_req_conf *ap_proxy_req_conf(request_rec *r);

/*
 * Get the request's asynchronous states, created (zeroed) if needed
 * @param r    current request
 * @return     the request's proxy_req_async
 */
struct proxy_req_async *ap_proxy_req_async(request_rec *r);

/* A waiter for a connection of an exhausted pool, see
 * ap_proxy_acquire_connection_ex()
 */
struct ap_proxy_conn_pool_waiter {
    ap_proxy_conn_pool_waiter_fn *fn;            /* Called on release */
    void *baton;                                 /* For fn */
    APR_RING_ENTRY(ap_proxy_conn_pool_waiter) link; /* In the pool's queue */
    int queued;
    int notified;                                /* Dequeued by a release,
                                                  * not acquired yet */
};

/* The waiters of a connection pool (FIFO) */
struct proxy_conn_pool_waiters {
#if APR_HAS_THREADS
    apr_thread_mutex_t *mutex; /* Protects the queue and the waiters' state */
#endif
    APR_RING_HEAD(proxy_conn_pool_waiter_ring, ap_proxy_conn_pool_waiter) ring;
    /* Connections promised to the notified waiters or the acquirers, not
     * acquired yet
     */
    /*atomic*/ apr_uint32_t reserved;
    /* Connections acquired from the reslist */
    /*atomic*/ apr_uint32_t acquired;
    /* Waiters queued, or checking whether they have to */
    /*atomic*/ apr_uint32_t nqueued;
};

/** @} */

#endif /* PROXY_UTIL_H_ */
